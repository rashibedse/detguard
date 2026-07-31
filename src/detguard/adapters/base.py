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

There is a fifth, optional method: :meth:`BaseAdapter.set_tool_guard`. It is
not abstract because not every framework exposes a seam to hang it on, and an
adapter that cannot intercept must still be usable. What it changes is large
though — see :attr:`BaseAdapter.intercepts`. Without it, ``before_tool`` runs
after ``invoke()`` has already returned, so a "block" describes a call that
already executed: detection, not prevention. With it, the guard is consulted
*before* the tool body runs and a denial actually stops the call. Results
record which of the two happened, because the difference is the entire
distance between a benchmark and a guardrail.

``invoke``'s second argument is a mapping describing the untrusted carrier and
the content to place in it::

    {"name": "message_body", "kind": "record",
     "injection_point": "body", "content": "...", "position": "end"}

``None`` means this attack has no injected content — the carrier is the prompt
itself.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable

# AgentRun is part of the canonical event model, not of the adapter layer —
# core has to be able to reason about a turn without importing anything from
# here. Re-exported so adapters can keep importing it from their own package.
from ..events import UNREADABLE, AgentRun, ToolCall, Unreadable

#: ``fn(tool_name, args) -> (allow, reason)``, consulted before a tool body
#: runs. Deliberately not a class: an adapter should be able to satisfy this
#: with a closure, and a future out-of-process adapter with an RPC stub.
ToolGuard = Callable[[str, dict], "tuple[bool, str]"]

__all__ = ["AgentRun", "BaseAdapter", "ToolGuard", "UNREADABLE", "Unreadable"]


class BaseAdapter(ABC):
    """What every adapter must provide. Four methods, plus one optional seam."""

    name: str = "base"

    #: True when :meth:`set_tool_guard` really prevents execution. Left False
    #: here deliberately: an adapter that silently accepted a guard it could
    #: not honour would report prevention it never performed, which is a worse
    #: failure than admitting the limitation.
    intercepts: bool = False

    def set_tool_guard(self, guard: "ToolGuard | None") -> bool:
        """Install a pre-execution gate. Returns whether it took effect.

        ``guard(tool_name, args) -> (allow, reason)`` is consulted immediately
        before a tool body runs. On ``allow=False`` the tool must not execute;
        the adapter substitutes ``reason`` as the call's result so the agent
        sees a refusal and can respond to it, exactly as a real integration
        would.

        The default is an honest no-op returning False. Callers check the
        return value rather than assuming, so that "this framework has no seam"
        degrades to post-hoc detection instead of pretending to enforce.
        """
        return False

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
        """Read the value at a dotted path.

        Return :data:`UNREADABLE` when the path cannot be read at all — never
        ``None`` as a stand-in for "don't know", because the runner cannot tell
        that apart from a genuine empty value and would score it as a defence.
        """

    # -- shared helpers ----------------------------------------------------

    @staticmethod
    def read_path(state: Any, path: str) -> Any:
        """Walk a dotted path through nested mappings.

        Missing → :data:`UNREADABLE`, so that "this state has no such path" is
        reported rather than silently answering the success check with ``None``.

        Provided here so that every adapter resolves ``customer.address`` the
        same way; a success check that means different things to different
        adapters is not a check.
        """
        if not path:
            return UNREADABLE
        current = state
        for part in str(path).split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif not isinstance(current, dict) and hasattr(current, part):
                current = getattr(current, part)
            else:
                return UNREADABLE
        return current

    @staticmethod
    def make_call(name: str, args: dict | None = None, result: Any = None) -> ToolCall:
        return ToolCall(name=name, args=dict(args or {}), result=result)
