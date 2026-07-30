"""The universal fallback adapter.

Takes a ``{name: callable}`` tool dict and one decide-function, and works with
anything: a hand-rolled while-loop, a framework detguard has never heard of, a
notebook. It has no third-party dependency and no framework knowledge, and it
must always work — every other adapter is a convenience over this one.

The decide-function is where the host's agent lives::

    def decide(user_prompt, injected_context, tools) -> list[(name, args)]

It returns the calls the agent wants to make. This adapter executes them once,
records the results, and hands back an AgentRun. It never interprets the
arguments and never re-runs anything.
"""

from __future__ import annotations

from typing import Any, Callable

from .base import AgentRun, BaseAdapter


class GenericAdapter(BaseAdapter):
    """Wrap a plain tool dict and a decide-function."""

    name = "generic"

    def __init__(
        self,
        tools: dict[str, Callable[..., Any]],
        decide: Callable[..., list],
        state: dict | None = None,
        reset_state: Callable[[], dict] | None = None,
        agent_name: str = "generic-agent",
        final_output: Callable[..., str] | None = None,
        descriptions: dict[str, str] | None = None,
    ):
        self.tools = dict(tools)
        self.decide = decide
        self.reset_state = reset_state
        self.agent_name = agent_name
        self.final_output = final_output
        self.descriptions = dict(descriptions or {})
        self._state: dict = dict(state or {})
        self._initial: dict = _deep_copy(self._state)

    # -- contract ----------------------------------------------------------

    def introspect(self) -> dict:
        """Draft a manifest from the tool dict.

        Argument schemas come from the callables' own signatures, which is as
        much as a plain Python function can tell us. Roles are deliberately
        absent: nothing can infer from a signature whether a tool moves money,
        and guessing would be worse than asking.
        """
        import inspect

        tools = []
        for tool_name in sorted(self.tools):
            fn = self.tools[tool_name]
            params: dict[str, dict] = {}
            try:
                signature = inspect.signature(fn)
            except (TypeError, ValueError):  # builtins, C callables
                signature = None
            if signature is not None:
                for param_name, param in signature.parameters.items():
                    if param_name in ("self", "state"):
                        continue
                    if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
                        continue
                    params[param_name] = {
                        "type": _type_name(param.annotation),
                        "required": param.default is param.empty,
                    }
            tools.append(
                {
                    "name": tool_name,
                    "description": self.descriptions.get(
                        tool_name, (fn.__doc__ or "").strip().split("\n")[0]
                    ),
                    "params": params,
                }
            )

        return {
            "agent": self.agent_name,
            "framework": "generic",
            "principal": "the account holder",
            "tools": tools,
            "untrusted_sources": [],
            "state_paths": {},
        }

    def reset(self) -> None:
        self._state = self.reset_state() if self.reset_state else _deep_copy(self._initial)

    def invoke(self, user_prompt: str, injected_context: dict | None = None) -> AgentRun:
        decided = self.decide(user_prompt, injected_context, self.state) or []

        calls = []
        for item in decided:
            call_name, args = _unpack(item)
            fn = self.tools.get(call_name)
            if fn is None:
                # An agent asking for a tool that does not exist is a real
                # thing that happens. Record it; do not invent a result.
                calls.append(self.make_call(call_name, args, result=None))
                continue
            # Executed exactly once, here. The result is authoritative from now on.
            calls.append(self.make_call(call_name, args, result=fn(**args)))

        output = ""
        if self.final_output:
            output = self.final_output(user_prompt, calls, self.state) or ""

        return AgentRun(tool_calls=calls, final_output=output)

    def get_state(self, path: str) -> Any:
        return self.read_path(self._state, path)

    # -- extras ------------------------------------------------------------

    @property
    def state(self) -> dict:
        return self._state


def _unpack(item: Any) -> tuple[str, dict]:
    """Accept ``(name, args)``, ``{"name":…, "args":…}`` or a bare name."""
    if isinstance(item, str):
        return item, {}
    if isinstance(item, dict):
        return str(item.get("name", "")), dict(item.get("args") or {})
    if isinstance(item, (tuple, list)) and item:
        name = str(item[0])
        args = dict(item[1]) if len(item) > 1 and item[1] else {}
        return name, args
    raise TypeError(f"cannot read a tool call from {type(item).__name__}")


def _type_name(annotation: Any) -> str:
    if annotation is None or annotation is type(None):
        return "null"
    if annotation.__class__.__name__ == "_empty":
        return "any"
    mapping = {str: "string", int: "number", float: "number", bool: "boolean",
               dict: "object", list: "array"}
    if annotation in mapping:
        return mapping[annotation]
    return getattr(annotation, "__name__", str(annotation))


def _deep_copy(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _deep_copy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep_copy(v) for v in value]
    return value
