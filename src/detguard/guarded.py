"""The delivery layer — enforcement you install rather than reimplement.

``engine`` gives you four functions. Calling them in the right order, with the
right arguments, at the right points, is the part a host application has to get
right, and ``docs/integration.md`` currently asks the client to reproduce that
sequence by hand. Every one of these is silent when done wrong:

* forgetting the second ``before_input`` for retrieved content — the entire
  indirect-injection defence, gone;
* not threading ``user_prompt`` through every hook — ``ungrounded_arg``, the
  condition that catches an injected destination, declines to fire;
* ignoring ``Verdict.redacted`` — the trace reports a redaction and the agent
  forwards the original;
* treating ``requires_approval`` as ``allow=False`` — a pause a human could
  clear becomes a hard refusal.

A client who makes any of those mistakes gets a weaker guardrail than the one
the report measured, and nothing tells them. So detguard owns the ordering:

    result = guarded.run(user_prompt, policy, decide=..., execute=..., summarise=...)

Two shapes are offered, because agents come in two shapes.

:func:`run` is for an agent whose loop **you** own — a hand-rolled while-loop,
a scripted planner, anything where you decide when tools are called. It gives
you all four hooks.

:func:`guard` is a decorator for an agent whose loop a **framework** owns —
LangChain, LangGraph, the OpenAI Agents SDK. It attaches to the tool rather
than to the orchestration, which is why the same decorator works across all
three: a tool is a plain Python callable in every one of them. It gives you
``before_tool`` and ``after_tool`` — the two hooks that distinguish detguard
from a text filter — and not the other two, which need per-framework wiring.

Because the decorator has no way to see the original request, :func:`guard`
reads it from a context variable that :func:`run` sets automatically and a
framework host sets with :func:`set_turn`. Without it ``ungrounded_arg`` cannot
ground anything, and rather than guess it declines — so a host that forgets
``set_turn`` loses that condition silently. Set it.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from . import engine
from .events import ToolCall, Verdict
from .policy import PolicySet

__all__ = [
    "ApprovalRequired",
    "Blocked",
    "GuardrailStop",
    "TurnResult",
    "current_turn",
    "guard",
    "run",
    "set_turn",
    "turn",
]

#: Hard ceiling on decide→execute rounds in one turn. An agent that keeps
#: asking for tools forever is a bug or a denial-of-service, and a loop with no
#: bound turns either into an unkillable process holding a policy lock.
MAX_ROUNDS = 8


# ---------------------------------------------------------------------------
# turn context
# ---------------------------------------------------------------------------

_TURN_PROMPT: contextvars.ContextVar[str] = contextvars.ContextVar(
    "detguard_turn_prompt", default=""
)


def set_turn(user_prompt: str):
    """Record the original user request for the current turn.

    Returns the ``contextvars`` token, so a host that manages its own scopes can
    reset it. :func:`run` does this for you; a framework host must do it itself,
    once per turn, before the agent starts calling decorated tools.
    """
    return _TURN_PROMPT.set(user_prompt or "")


def current_turn() -> str:
    """The current turn's user prompt, or ``""`` when none was set."""
    return _TURN_PROMPT.get()


@contextlib.contextmanager
def turn(user_prompt: str):
    """Scope a turn's prompt::

        with guarded.turn(user_text):
            result = agent.invoke(user_text)
    """
    token = set_turn(user_prompt)
    try:
        yield
    finally:
        _TURN_PROMPT.reset(token)


# ---------------------------------------------------------------------------
# outcomes
# ---------------------------------------------------------------------------


class GuardrailStop(Exception):
    """Enforcement stopped a decorated tool. Carries the deciding verdict."""

    def __init__(self, verdict: Verdict, tool: str = ""):
        self.verdict = verdict
        self.tool = tool
        detail = verdict.blocked_by or verdict.hook
        super().__init__(f"{tool or 'tool call'} stopped by {detail}")


class Blocked(GuardrailStop):
    """A hard stop. No human can clear this one."""


class ApprovalRequired(GuardrailStop):
    """A human-in-the-loop pause. A human may still say yes.

    Deliberately a different type from :class:`Blocked`. Conflating them was a
    real scoring bug in the predecessor project, and a host that catches only
    ``GuardrailStop`` will still see the distinction on the instance.
    """


@dataclass
class TurnResult:
    """What one guarded turn did, and every decision taken along the way."""

    allowed: bool = True
    output: str = ""
    tool_calls: list = field(default_factory=list)
    verdicts: list = field(default_factory=list)
    decisions: list = field(default_factory=list)
    retrieved: str = ""
    """The retrieved document as the agent actually saw it — post-redaction."""

    blocked_at_hook: str = ""
    blocked_by: str = ""
    severity: str = ""
    requires_approval: bool = False

    @property
    def refused(self) -> bool:
        return not self.allowed

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "output": self.output,
            "tool_calls": [c.to_dict() for c in self.tool_calls],
            "decisions": list(self.decisions),
            "retrieved": self.retrieved,
            "blocked_at_hook": self.blocked_at_hook,
            "blocked_by": self.blocked_by,
            "severity": self.severity,
            "requires_approval": self.requires_approval,
        }


# ---------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------


def _as_call(item: Any) -> ToolCall:
    """Accept ``ToolCall``, ``(name, args)``, ``{"name":…, "args":…}`` or a name."""
    if isinstance(item, ToolCall):
        return item
    if isinstance(item, str):
        return ToolCall(name=item, args={})
    if isinstance(item, Mapping):
        return ToolCall(name=str(item.get("name", "")), args=dict(item.get("args") or {}))
    if isinstance(item, (tuple, list)) and item:
        args = dict(item[1]) if len(item) > 1 and item[1] else {}
        return ToolCall(name=str(item[0]), args=args)
    raise TypeError(f"cannot read a tool call from {type(item).__name__}")


def _bind_args(fn: Callable, args: tuple, kwargs: dict) -> dict:
    """Resolve a call's arguments to a name→value mapping.

    Positional arguments are bound to their parameter names, because a policy
    condition reads ``args["destination"]`` and a tool invoked positionally
    would otherwise present as having no arguments at all — every argument-level
    rule silently inert.
    """
    try:
        bound = inspect.signature(fn).bind(*args, **kwargs)
        bound.apply_defaults()
        return {k: v for k, v in bound.arguments.items() if k != "self"}
    except (TypeError, ValueError):  # builtins, C callables, genuine mismatch
        return dict(kwargs)


def _dispatch(execute: Callable | Mapping[str, Callable], call: ToolCall) -> Any:
    """Run one tool, exactly once."""
    if isinstance(execute, Mapping):
        fn = execute.get(call.name)
        if fn is None:
            # An agent asking for a tool that does not exist is a real thing
            # that happens. Record it; do not invent a result.
            return None
        return fn(**call.args)
    return execute(call)


# ---------------------------------------------------------------------------
# the loop
# ---------------------------------------------------------------------------


def run(
    user_prompt: str,
    policy: PolicySet,
    decide: Callable[..., Sequence[Any]],
    execute: Callable[[ToolCall], Any] | Mapping[str, Callable],
    summarise: Callable[..., str] | None = None,
    *,
    retrieved: str = "",
    mode: str = "on",
    max_rounds: int = MAX_ROUNDS,
) -> TurnResult:
    """Run one guarded turn. detguard owns the hook ordering; you supply the agent.

    Parameters
    ----------
    decide
        ``fn(user_prompt, calls_so_far, retrieved) -> [(name, args), ...]``.
        Called repeatedly until it returns nothing, so an agent that reads a
        document and *then* decides what to do with it works — which is what
        real agents do, and what a single decide-then-execute batch cannot
        express. Two-parameter functions are also accepted.
    execute
        Either ``fn(ToolCall) -> result`` or a ``{name: callable}`` mapping.
        Called exactly once per call; the result is authoritative from then on.
    summarise
        ``fn(user_prompt, calls) -> str``, the final answer. Optional: an agent
        that only acts has nothing to say.
    retrieved
        A document fetched before the turn started. Checked with
        ``is_retrieved=True`` — the flag that separates "the user said this"
        from "a document said this".

    Returns a :class:`TurnResult`. It never raises on a block; enforcement
    stopping the turn is an outcome, not an error.
    """
    result = TurnResult(retrieved=retrieved)

    def absorb(verdict: Verdict) -> bool:
        """Record a verdict. Returns True when it stops the turn."""
        result.verdicts.append(verdict)
        result.decisions.extend(d.to_dict() for d in verdict.decisions)
        if verdict.requires_approval:
            result.requires_approval = True
        if not verdict.allow:
            result.allowed = False
            result.blocked_at_hook = verdict.hook
            result.blocked_by = verdict.blocked_by
            result.severity = verdict.severity
            return True
        return False

    token = set_turn(user_prompt)
    try:
        v = engine.before_input(user_prompt, policy, mode=mode)
        if absorb(v):
            return result
        prompt = v.text if v.redacted else user_prompt

        if retrieved:
            v = engine.before_input(
                retrieved, policy, user_prompt=user_prompt, is_retrieved=True, mode=mode
            )
            if absorb(v):
                return result
            if v.redacted:
                # The masked document is what the agent must actually receive.
                # Reporting a redaction and then handing over the original would
                # make the whole decision trace fiction.
                result.retrieved = v.text

        wants_retrieved = _arity(decide) >= 3
        for _ in range(max_rounds):
            batch = decide(prompt, list(result.tool_calls), result.retrieved) \
                if wants_retrieved else decide(prompt, list(result.tool_calls))
            calls = [_as_call(item) for item in (batch or [])]
            if not calls:
                break

            # Before anything runs. A block here means no side effect occurred.
            if absorb(engine.before_tool(calls, policy, user_prompt=user_prompt, mode=mode)):
                return result

            for call in calls:
                call.result = _dispatch(execute, call)
                result.tool_calls.append(call)
                # The call has already run. after_tool contains the damage — it
                # keeps a leaked value out of the agent's context and out of the
                # answer; it cannot un-send a payment. That is a property of
                # where the hook sits, and it is why before_tool matters more.
                v = engine.after_tool(call, policy, user_prompt=user_prompt, mode=mode)
                if v.redacted:
                    call.result = v.text
                if absorb(v):
                    return result
        else:
            raise RuntimeError(
                f"agent asked for tools in more than {max_rounds} rounds; "
                "raise max_rounds if this is legitimate"
            )

        answer = summarise(user_prompt, list(result.tool_calls)) if summarise else ""
        v = engine.before_output(
            answer or "", policy, user_prompt=user_prompt,
            tool_calls=result.tool_calls, mode=mode,
        )
        stopped = absorb(v)
        result.output = v.text if v.redacted else (answer or "")
        if stopped:
            result.output = ""
        return result
    finally:
        _TURN_PROMPT.reset(token)


def _arity(fn: Callable) -> int:
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):  # pragma: no cover - exotic callables
        return 2
    return sum(
        1
        for p in params.values()
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    )


# ---------------------------------------------------------------------------
# the decorator
# ---------------------------------------------------------------------------


def guard(
    policy: PolicySet,
    *,
    mode: str = "on",
    name: str = "",
) -> Callable[[Callable], Callable]:
    """Enforce ``before_tool`` and ``after_tool`` around one tool.

    For agents whose loop belongs to a framework. Works unchanged on a
    LangChain/LangGraph ``@tool`` function and an Agents SDK
    ``@function_tool`` — put it **below** the framework's decorator so it wraps
    the plain function:

        @tool
        @guarded.guard(policy_set)
        def send_money(destination: str, amount: float) -> str: ...

    Raises :class:`Blocked` or :class:`ApprovalRequired` instead of returning a
    verdict, because a framework's tool-calling machinery has no place to put
    one — an exception is the only signal it will reliably propagate.

    Two limits, stated because a silent gap is worse than a documented one:

    * It sees **one call, not the batch**, so conditions that reason over a
      whole decided batch — ``call_budget``, ``repeated_call``, tool chaining —
      cannot do their job here. Use :func:`run`, or wire the framework's own
      batch hook, when those matter.
    * ``ungrounded_arg`` needs the original request, which reaches it only via
      :func:`set_turn`. Set it once per turn or that condition declines.
    """

    def decorator(fn: Callable) -> Callable:
        tool_name = name or getattr(fn, "__name__", "tool")

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            prompt = current_turn()
            call = ToolCall(name=tool_name, args=_bind_args(fn, args, kwargs))

            verdict = engine.before_tool([call], policy, user_prompt=prompt, mode=mode)
            _raise_if_stopped(verdict, tool_name)

            call.result = fn(*args, **kwargs)

            verdict = engine.after_tool(call, policy, user_prompt=prompt, mode=mode)
            _raise_if_stopped(verdict, tool_name)
            return verdict.text if verdict.redacted else call.result

        wrapper.__detguard_guarded__ = True  # type: ignore[attr-defined]
        return wrapper

    return decorator


def _raise_if_stopped(verdict: Verdict, tool: str) -> None:
    if verdict.allow:
        return
    if verdict.requires_approval:
        raise ApprovalRequired(verdict, tool)
    raise Blocked(verdict, tool)
