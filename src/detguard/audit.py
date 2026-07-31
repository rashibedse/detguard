"""Append-only decision log.

Every decision the engine makes, one JSON object per line, never rewritten.
This is the compliance evidence artifact: "show me your controls" is answered
by the policy file, and "show me they were enforced" is answered by this.

Off by default. A guardrail that starts writing logs nobody asked for is a
data-retention problem wearing a helpful expression — switch it on in the
policy's ``audit`` block or with ``--audit-log``.

Retention is the operator's business, not this module's. Note only that under
DPDP a decision log of this kind carries a one-year obligation, and that a
``notify`` action here is the natural trigger for a 72-hour breach workflow.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .events import Verdict

SCHEMA_VERSION = 1


@dataclass
class AuditLog:
    """Append-only JSONL sink.

    Appends only. There is no update method and no delete method, and that is
    the point: an evidence trail you can edit is not evidence.
    """

    path: str
    enabled: bool = True
    _lock: Any = field(default_factory=threading.Lock, repr=False)

    def record(
        self,
        verdict: Verdict,
        *,
        attack_id: str = "",
        tool: str = "",
        policy_hash: str = "",
        extra: dict | None = None,
    ) -> int:
        """Write one line per decision. Returns how many lines were written."""
        if not self.enabled or not self.path:
            return 0

        stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        lines = []
        for decision in verdict.decisions:
            lines.append(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "timestamp": stamp,
                        "hook": verdict.hook,
                        "tool": tool,
                        "policy": decision.name,
                        "policy_hash": policy_hash,
                        "layer": decision.layer,
                        "triggered": decision.triggered,
                        "action": decision.action,
                        "severity": decision.severity,
                        "verdict": _verdict_word(verdict, decision),
                        "reason": decision.reason,
                        "case": attack_id,
                        **(extra or {}),
                    },
                    sort_keys=True,
                    default=str,
                )
            )

        if not lines:
            return 0

        with self._lock:
            directory = os.path.dirname(os.path.abspath(self.path))
            if directory:
                Path(directory).mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
        return len(lines)


def _verdict_word(verdict: Verdict, decision) -> str:
    if not decision.triggered:
        return "pass"
    if decision.action == "require_hitl":
        return "approval_required"
    if decision.action == "block":
        return "blocked"
    return decision.action


def from_policy(policy, override_path: str | None = None) -> AuditLog | None:
    """Build a log from a policy's ``audit`` block, or None when it is off.

    ``override_path`` is the CLI flag, and supplying it switches auditing on —
    asking for a log file is an unambiguous request for a log.
    """
    settings = getattr(policy, "audit", None) or {}
    path = override_path or settings.get("path", "")
    enabled = bool(override_path) or bool(settings.get("enabled", False))
    if not enabled or not path:
        return None
    return AuditLog(path=path, enabled=True)
