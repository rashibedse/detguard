"""OpenAI Agents SDK adapter.

Same shape as the LangGraph adapter and for the same reason: the SDK already
records what was called and what came back, so this reads its run items and
translates them into the canonical model. It adds no behaviour.

``openai-agents`` is optional::

    pip install "detguard[openai]"

The adapter deliberately does **not** put a model anywhere near the enforcement
path. It runs the client's agent so the corpus has something to attack; every
decision about that run is still made by deterministic conditions.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from .base import UNREADABLE, AgentRun, BaseAdapter, ToolGuard

_IMPORT_HINT = (
    "OpenAI Agents SDK support needs the optional extra: "
    'pip install "detguard[openai]"'
)


class OpenAIAgentsAdapter(BaseAdapter):
    """Wrap an Agents SDK ``Agent``.

    Parameters
    ----------
    agent
        A configured ``agents.Agent``.
    reset_hook
        Restores fresh state before each attack. Required, for the same reason
        as in the LangGraph adapter: state leaking between attacks makes every
        number in the report meaningless.
    state_reader
        ``fn(path) -> value`` for success checks, reading whatever backing store
        the agent's tools actually mutate.
    inject
        ``fn(user_prompt, injected_context) -> str``, placing untrusted content
        where this agent would encounter it. Defaults to prepending it as a
        labelled block.
    runner
        Override for the SDK's ``Runner``, for tests or a custom run loop.
    """

    name = "openai_agents"

    def __init__(
        self,
        agent: Any,
        reset_hook: Callable[[], None] | None = None,
        state_reader: Callable[[str], Any] | None = None,
        inject: Callable[[str, dict | None], str] | None = None,
        agent_name: str | None = None,
        principal: str = "the account holder",
        runner: Any = None,
        run_config: dict | None = None,
    ):
        self.agent = agent
        self.reset_hook = reset_hook
        self.state_reader = state_reader
        self.inject = inject
        self.agent_name = agent_name or getattr(agent, "name", "openai-agent")
        self.principal = principal
        self.run_config = dict(run_config or {})
        self._runner = runner
        self._tool_guard: ToolGuard | None = None
        self._guard_denials: list[dict] = []

    # -- discovery ---------------------------------------------------------

    @property
    def runner(self):
        if self._runner is not None:
            return self._runner
        try:
            from agents import Runner
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise ImportError(_IMPORT_HINT) from exc
        self._runner = Runner
        return self._runner

    def introspect(self) -> dict:
        """Draft a manifest from the agent's own tool schemas.

        The SDK already holds a JSON Schema per tool — the exact artifact a
        client would publish in their API docs, and the reason onboarding never
        needs their source code.
        """
        tools = []
        for tool in getattr(self.agent, "tools", None) or []:
            tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "")
            if not tool_name:
                continue
            schema = (
                getattr(tool, "params_json_schema", None)
                or getattr(tool, "parameters", None)
                or {}
            )
            tools.append(
                {
                    "name": tool_name,
                    "description": (getattr(tool, "description", "") or "").strip(),
                    "params": _params_from_schema(schema),
                }
            )
        tools.sort(key=lambda t: t["name"])

        return {
            "agent": self.agent_name,
            "framework": "openai_agents",
            "principal": self.principal,
            "tools": tools,
            "untrusted_sources": [],
            "state_paths": {},
        }

    # -- interception ------------------------------------------------------

    def set_tool_guard(self, guard: ToolGuard | None) -> bool:
        """Attach the guard to every tool's ``tool_input_guardrails``.

        The SDK runs those *before* the tool body, which is the property that
        matters: a denial here means the transfer never happens, rather than
        being noticed once the balance has already moved. ``reject_content``
        feeds the refusal back to the model as the call's result, so the agent
        can react to being stopped the way it would in a real deployment.

        Returns False — leaving :attr:`intercepts` False — on any SDK that
        lacks this API, so an older install degrades to post-hoc detection
        instead of silently reporting prevention it cannot perform.
        """
        self._tool_guard = guard
        tools = list(getattr(self.agent, "tools", None) or [])
        if not tools:
            return False

        try:
            from agents import ToolGuardrailFunctionOutput, ToolInputGuardrail
        except ImportError:
            return False

        if guard is None:
            for tool in tools:
                if hasattr(tool, "tool_input_guardrails"):
                    tool.tool_input_guardrails = [
                        g
                        for g in (tool.tool_input_guardrails or [])
                        if getattr(g, "name", "") != _GUARD_NAME
                    ]
            self.intercepts = False
            return False

        def _screen(data: Any) -> Any:
            ctx = getattr(data, "context", None)
            name = str(getattr(ctx, "tool_name", "") or "")
            args = _decode_args(getattr(ctx, "tool_arguments", None))
            try:
                allow, reason = guard(name, args)
            except Exception as exc:  # a broken guard must not silently permit
                return ToolGuardrailFunctionOutput.reject_content(
                    message=f"blocked: guard raised {exc.__class__.__name__}",
                )
            if allow:
                return ToolGuardrailFunctionOutput.allow()
            self._guard_denials.append({"name": name, "args": args, "reason": reason})
            return ToolGuardrailFunctionOutput.reject_content(message=reason or "blocked by policy")

        attached = False
        for tool in tools:
            if not hasattr(tool, "tool_input_guardrails"):
                continue
            existing = [
                g
                for g in (tool.tool_input_guardrails or [])
                if getattr(g, "name", "") != _GUARD_NAME
            ]
            tool.tool_input_guardrails = existing + [
                ToolInputGuardrail(guardrail_function=_screen, name=_GUARD_NAME)
            ]
            attached = True

        self.intercepts = attached
        return attached

    def take_denials(self) -> list[dict]:
        """Drain the calls this turn's guard refused, and forget them."""
        drained, self._guard_denials = list(self._guard_denials), []
        return drained

    # -- contract ----------------------------------------------------------

    def reset(self) -> None:
        if self.reset_hook is None:
            raise RuntimeError(
                "OpenAIAgentsAdapter needs a reset_hook: without fresh state per "
                "attack, results leak between cases and the run cannot be trusted."
            )
        self.reset_hook()

    def get_state(self, path: str) -> Any:
        # Without a reader this adapter cannot observe post-run state at all.
        # UNREADABLE says so; None would be taken as "unchanged" and reported as
        # a defence the policy never actually provided.
        return self.state_reader(path) if self.state_reader else UNREADABLE

    def invoke(self, user_prompt: str, injected_context: dict | None = None) -> AgentRun:
        prompt = user_prompt
        if self.inject is not None:
            prompt = self.inject(user_prompt, injected_context)
        elif injected_context and injected_context.get("content"):
            label = injected_context.get("name", "document")
            prompt = f"[{label}]\n{injected_context['content']}\n\n{user_prompt}"

        result = self.runner.run_sync(self.agent, prompt, **self.run_config)

        return AgentRun(
            tool_calls=_calls_from_items(result, self.make_call),
            final_output=str(getattr(result, "final_output", "") or ""),
            metadata={"framework": "openai_agents"},
        )


# ---------------------------------------------------------------------------
# run-item translation
# ---------------------------------------------------------------------------

#: Names the guardrail this adapter installs, so re-attaching replaces its own
#: previous one rather than stacking a fresh copy on every ``reset()``.
_GUARD_NAME = "detguard_tool_guard"


def _decode_args(raw: Any) -> dict:
    """The SDK hands arguments over as a JSON string; conditions want a dict."""
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            return {"_raw": raw}
        return parsed if isinstance(parsed, dict) else {"_raw": raw}
    return {}


def _params_from_schema(schema: Any) -> dict:
    if not isinstance(schema, dict):
        return {}
    properties = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    return {
        key: {"type": spec.get("type", "any") if isinstance(spec, dict) else "any",
              "required": key in required}
        for key, spec in properties.items()
    }


def _calls_from_items(result: Any, make_call: Callable) -> list:
    """Pair tool-call items with their output items.

    Results come from the run's own record. Nothing is re-executed here.
    """
    import json

    requested: list[tuple[str, str, dict]] = []
    outputs: dict[str, Any] = {}

    for item in getattr(result, "new_items", None) or []:
        raw = getattr(item, "raw_item", item)
        item_type = getattr(item, "type", "") or type(item).__name__

        if "ToolCallOutput" in type(item).__name__ or "tool_call_output" in item_type:
            call_id = str(_first_attr(raw, "call_id", "id") or "")
            outputs[call_id] = getattr(item, "output", None) or _first_attr(raw, "output")
            continue

        if "ToolCall" in type(item).__name__ or "tool_call" in item_type:
            call_id = str(_first_attr(raw, "call_id", "id") or "")
            tool_name = str(_first_attr(raw, "name", "function_name") or "")
            arguments = _first_attr(raw, "arguments", "args") or {}
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except (ValueError, TypeError):
                    arguments = {"_raw": arguments}
            requested.append((call_id, tool_name, dict(arguments)))

    return [make_call(name, args, outputs.get(call_id)) for call_id, name, args in requested]


def _first_attr(obj: Any, *names: str) -> Any:
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        if hasattr(obj, name):
            return getattr(obj, name)
    return None
