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


class Unreadable:
    """Type of the :data:`UNREADABLE` sentinel.

    Recognised by type, not by identity — every consumer tests ``isinstance``,
    so a second instance is just as unreadable as the canonical one. There is
    deliberately no singleton machinery here: it would imply an identity
    contract nothing actually relies on.
    """

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "UNREADABLE"

    def __bool__(self) -> bool:
        return False


#: Returned by ``BaseAdapter.get_state`` when a path cannot be read *at all* —
#: no reader was configured for it, or it does not resolve.
#:
#: It lives here rather than in the adapter package because the runner has to
#: recognise it, and core does not import from ``adapters``.
#:
#: It exists because ``None`` was doing two jobs. A ``field_changed`` check
#: comparing ``None != None`` concludes the state did not change, and the runner
#: records that as the attack having failed — which the report presents as a
#: defence. So an adapter that simply cannot see the state produced the same
#: output as an agent that was successfully blocked, and a real breach could sit
#: in a report as a green row. "I cannot answer" is not "no".
UNREADABLE = Unreadable()


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

    It describes **the rule that actually won blocker selection**, not "some
    HITL rule somewhere in this hook also fired". Those are different facts: a
    critical hard block firing alongside a low-severity HITL rule is a block,
    and reporting it as "awaiting a human" understates the enforcement that
    happened. ``hitl_also_fired`` keeps the weaker fact available for the
    decision trace without letting it overwrite the outcome.

    ``redacted`` says a ``redact`` action fired *and changed the text*. The
    caller must write :attr:`text` back into whatever the consumer reads —
    reporting a redaction and then forwarding the original is how a masked
    secret reaches the user with a green row next to it.
    """

    allow: bool
    hook: str = ""
    decisions: list = field(default_factory=list)
    text: str = ""
    blocked_by: str = ""
    severity: str = ""
    requires_approval: bool = False
    hitl_also_fired: bool = False
    redacted: bool = False

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
            "hitl_also_fired": self.hitl_also_fired,
            "redacted": self.redacted,
        }
