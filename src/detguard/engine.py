"""The four canonical hooks — detguard's public entrypoint.

These are the only functions a host application needs. Everything else in the
package exists to make these four correct, testable, and provable.

::

    v = engine.before_input(user_text, policy)
    v = engine.before_tool(calls, policy, user_prompt=user_text)
    v = engine.after_tool(call, policy, user_prompt=user_text)
    v = engine.before_output(answer, policy, user_prompt=user_text)

``mode="off"`` is a clean passthrough: allow, zero decisions, text unchanged.
That is what makes the guardrail-off comparison run honest — the same corpus,
the same agent, the enforcement layer genuinely absent rather than merely
lenient.

``user_prompt`` should be threaded through at *every* hook. Several conditions
(``ungrounded_arg`` above all) can only do their job with the original request
in hand, and without it they decline to fire rather than guess.
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from . import policy as policy_mod
from .events import GuardContext, ToolCall, Verdict

MODES = ("on", "off")


def _passthrough(hook: str, text: str = "") -> Verdict:
    return Verdict(allow=True, hook=hook, decisions=[], text=text, requires_approval=False)


def _check_mode(mode: str) -> str:
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}; must be 'on' or 'off'")
    return mode


def _as_calls(tool_calls: Iterable[Any] | None) -> list[ToolCall]:
    """Accept ToolCall objects or plain dicts, never re-executing anything."""
    out: list[ToolCall] = []
    for item in tool_calls or []:
        if isinstance(item, ToolCall):
            out.append(item)
        elif isinstance(item, dict):
            out.append(
                ToolCall(
                    name=str(item.get("name", "")),
                    args=dict(item.get("args") or {}),
                    result=item.get("result"),
                )
            )
        else:
            raise TypeError(f"tool_calls must contain ToolCall or dict, got {type(item).__name__}")
    return out


# ---------------------------------------------------------------------------
# the four hooks
# ---------------------------------------------------------------------------


def before_input(
    text: str,
    policy: policy_mod.PolicySet,
    *,
    user_prompt: str | None = None,
    is_retrieved: bool = False,
    metadata: dict | None = None,
    mode: str = "on",
) -> Verdict:
    """Inspect text entering the agent — the user's message, or a retrieved
    document about to be placed in context.

    Set ``is_retrieved=True`` for the latter. That flag is what separates "the
    user said this" from "a document the user asked me to read said this", and
    it is the whole basis of the indirect-injection defence.
    """
    if _check_mode(mode) == "off":
        return _passthrough("before_input", text)

    ctx = GuardContext(
        hook="before_input",
        text=text or "",
        user_prompt=(user_prompt if user_prompt is not None else text) or "",
        is_retrieved=is_retrieved,
        metadata=dict(metadata or {}),
    )
    return policy_mod.evaluate(policy, ctx)


def before_tool(
    tool_calls: Sequence[Any],
    policy: policy_mod.PolicySet,
    *,
    user_prompt: str = "",
    text: str = "",
    metadata: dict | None = None,
    mode: str = "on",
) -> Verdict:
    """Inspect the decided batch of tool calls *before any of them executes*.

    This is the placement point that distinguishes detguard from an input/output
    text filter: the arguments are concrete here, so the check can be exact
    rather than probabilistic.
    """
    if _check_mode(mode) == "off":
        return _passthrough("before_tool", text)

    ctx = GuardContext(
        hook="before_tool",
        text=text or "",
        user_prompt=user_prompt or "",
        tool_calls=_as_calls(tool_calls),
        metadata=dict(metadata or {}),
    )
    return policy_mod.evaluate(policy, ctx)


def after_tool(
    tool_call: Any,
    policy: policy_mod.PolicySet,
    *,
    user_prompt: str = "",
    is_retrieved: bool = True,
    metadata: dict | None = None,
    mode: str = "on",
) -> Verdict:
    """Inspect a tool's return value before it re-enters agent context.

    The call has already run. ``tool_call.result`` is authoritative and is never
    recomputed here — a tool is executed exactly once.

    ``is_retrieved`` defaults to True because a tool result is, by definition,
    content the agent did not author.
    """
    if _check_mode(mode) == "off":
        return _passthrough("after_tool")

    call = _as_calls([tool_call])[0]
    result = call.result
    ctx = GuardContext(
        hook="after_tool",
        text=result if isinstance(result, str) else ("" if result is None else str(result)),
        user_prompt=user_prompt or "",
        tool_calls=[call],
        tool_name=call.name,
        tool_result=result,
        is_retrieved=is_retrieved,
        metadata=dict(metadata or {}),
    )
    return policy_mod.evaluate(policy, ctx)


def before_output(
    text: str,
    policy: policy_mod.PolicySet,
    *,
    user_prompt: str = "",
    tool_calls: Sequence[Any] | None = None,
    metadata: dict | None = None,
    mode: str = "on",
) -> Verdict:
    """Inspect the final natural-language answer before the user sees it.

    This is the hook that catches an agent stating a secret in prose rather than
    leaking it through a tool call — the case no tool-call check can see.
    """
    if _check_mode(mode) == "off":
        return _passthrough("before_output", text)

    ctx = GuardContext(
        hook="before_output",
        text=text or "",
        user_prompt=user_prompt or "",
        tool_calls=_as_calls(tool_calls),
        metadata=dict(metadata or {}),
    )
    return policy_mod.evaluate(policy, ctx)
