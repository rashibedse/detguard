"""The adapter contract.

An adapter is a translation layer and nothing more: it turns one framework's
call shape into detguard's canonical model and back. All four methods are
deliberately narrow, and none of them may assume in-process execution — the
contract has to stay satisfiable by a future MCP proxy adapter, where "invoke"
means forwarding an HTTP request and the tool runs on somebody else's machine.
Anything that assumes a Python function is about to be called in this process
is a design error here, not a convenience.

    introspect()      -> a manifest dict, drafted from the framework's own
                         tool registry. This is the client's integration
                         contract: names and argument schemas, no source.

    reset()           -> fresh state. The runner calls this before every
                         attack, so results cannot leak between cases.

    invoke(prompt, injected_context) -> AgentRun. Runs one turn. Tools execute
                         exactly once here; whatever they returned is recorded
                         on the ToolCall and is authoritative forever after.

    get_state(path)   -> the value at a dotted path, for success checks that
                         must verify real post-run state rather than trusting
                         the agent's own account of what it did.

``invoke``'s second argument is a mapping describing the untrusted carrier and
the content to place in it::

    {"name": "message_body", "kind": "record",
     "injection_point": "body", "content": "...", "position": "end"}

``None`` means this attack has no injected content — the carrier is the prompt
itself.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

# AgentRun is part of the canonical event model, not of the adapter layer —
# core has to be able to reason about a turn without importing anything from
# here. Re-exported so adapters can keep importing it from their own package.
from ..events import AgentRun, ToolCall

__all__ = ["AgentRun", "BaseAdapter"]


class BaseAdapter(ABC):
    """What every adapter must provide. Four methods, no more."""

    name: str = "base"

    @abstractmethod
    def introspect(self) -> dict:
        """Draft a manifest dict from the framework's own tool registry."""

    @abstractmethod
    def reset(self) -> None:
        """Restore a fresh environment. Called before every attack."""

    @abstractmethod
    def invoke(self, user_prompt: str, injected_context: dict | None = None) -> AgentRun:
        """Run one turn and report what the agent did."""

    @abstractmethod
    def get_state(self, path: str) -> Any:
        """Read the value at a dotted path, or None when it does not exist."""

    # -- shared helpers ----------------------------------------------------

    @staticmethod
    def read_path(state: Any, path: str) -> Any:
        """Walk a dotted path through nested mappings. Missing → None.

        Provided here so that every adapter resolves ``customer.address`` the
        same way; a success check that means different things to different
        adapters is not a check.
        """
        if not path:
            return None
        current = state
        for part in str(path).split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif hasattr(current, part):
                current = getattr(current, part)
            else:
                return None
        return current

    @staticmethod
    def make_call(name: str, args: dict | None = None, result: Any = None) -> ToolCall:
        return ToolCall(name=name, args=dict(args or {}), result=result)
