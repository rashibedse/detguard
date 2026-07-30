"""Canonical event model.

Every adapter, every condition and every policy speaks this vocabulary. It is
deliberately framework-free: nothing here knows what LangGraph or the OpenAI
Agents SDK is, and nothing here assumes in-process execution — a future MCP
proxy adapter must be able to satisfy the same contract by mapping an inbound
request to ``before_tool`` and an outbound response to ``after_tool``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: The four placement points. Order is the order they occur in an agent turn.
HOOKS = ("before_input", "before_tool", "after_tool", "before_output")

#: Severity vocabulary, ordered least → most severe. Used to pick which of
#: several triggered blocking rules is reported as *the* blocker.
SEVERITIES = ("low", "medium", "high", "critical")

#: Rank lookup for severity comparison.
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}


@dataclass
class ToolCall:
    """One tool invocation.

    ``result`` is populated by whoever executed the call and is authoritative:
    detguard never re-executes a tool to find out what it returned. A tool call
    is executed exactly once.
    """

    name: str
    args: dict = field(default_factory=dict)
    result: Any = None

    def to_dict(self) -> dict:
        return {"name": self.name, "args": dict(self.args), "result": self.result}


@dataclass
class GuardContext:
    """Everything a condition is allowed to look at.

    A condition receives this and a params dict, and returns
    ``(fired: bool, reason: str)``. Only conditions listed in
    ``registry.TRANSFORMING`` may mutate the context, and only via
    ``redacted_text``.
    """

    hook: str = ""
    text: str = ""
    """Input text, output text, or result text — whichever the hook inspects."""

    user_prompt: str = ""
    """ALWAYS the original user request, at every hook. This is what
    ``ungrounded_arg`` grounds against; without it that condition cannot run."""

    tool_calls: list = field(default_factory=list)
    tool_name: str = ""
    """``after_tool``: which tool returned."""

    tool_result: Any = None
    """``after_tool``: the return value."""

    is_retrieved: bool = False
    """True when ``text`` came from untrusted content rather than the user.
    ``pii_redact`` with ``applies_to: retrieved`` keys off this."""

    pattern_sets: dict = field(default_factory=dict)
    redacted_text: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class AgentRun:
    """One turn's worth of agent behaviour.

    Lives here rather than with the adapters because it is pure event data —
    what was called, what came back, what was said — and core must be able to
    reason about a turn without importing anything that knows what a framework
    is. ``tool_calls`` carries results already populated; nothing re-executes a
    call to find out what it returned.
    """

    tool_calls: list = field(default_factory=list)
    final_output: str = ""
    metadata: dict = field(default_factory=dict)

    def names(self) -> list[str]:
        return [c.name for c in self.tool_calls]

    def calls_to(self, tools) -> list:
        wanted = set(tools or [])
        return [c for c in self.tool_calls if c.name in wanted]

    def to_dict(self) -> dict:
        return {
            "tool_calls": [c.to_dict() for c in self.tool_calls],
            "final_output": self.final_output,
            "metadata": dict(self.metadata),
        }


@dataclass
class Decision:
    """The outcome of evaluating one policy rule. Recorded whether or not it
    fired — a rule that did not trigger is evidence too."""

    name: str
    triggered: bool
    reason: str = ""
    action: str = ""
    severity: str = ""
    layer: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "triggered": self.triggered,
            "reason": self.reason,
            "action": self.action,
            "severity": self.severity,
            "layer": self.layer,
        }


@dataclass
class Verdict:
    """The result of one hook call.

    ``requires_approval`` is deliberately distinct from ``allow=False``. A HITL
    pause and a hard block are different outcomes and the runner and dashboard
    must be able to tell them apart — conflating them was a real scoring bug in
    the predecessor project. Both stop unattended execution; only one of them
    means "a human may still say yes".
    """

    allow: bool
    hook: str = ""
    decisions: list = field(default_factory=list)
    text: str = ""
    blocked_by: str = ""
    severity: str = ""
    requires_approval: bool = False

    @property
    def triggered(self) -> list:
        return [d for d in self.decisions if d.triggered]

    def to_dict(self) -> dict:
        return {
            "allow": self.allow,
            "hook": self.hook,
            "decisions": [d.to_dict() for d in self.decisions],
            "text": self.text,
            "blocked_by": self.blocked_by,
            "severity": self.severity,
            "requires_approval": self.requires_approval,
        }
