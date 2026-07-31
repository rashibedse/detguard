"""Policy loading, strict validation, and evaluation.

The policy file *is* the control documentation: versioned, diffable, reviewed,
and enforced on every commit by CI. That only works if loading it is strict —
an unknown condition, action or hook is a hard load-time error, never a rule
that silently never fires. A guardrail that fails silently is worse than none.

File shape::

    version: 1
    pattern_sets:
      injection: ["(?i)ignore (all )?previous instructions"]
    rules:
      - id: prompt_injection_scan
        hook: before_input
        condition: content_scan
        params: {pattern_set: injection}
        action: block
        severity: critical
        layer: content_scan        # optional; defaults to the condition name
        enabled: true              # optional; defaults to true
    audit:
      enabled: false
      path: audit.jsonl
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from .events import (
    HOOKS,
    SEVERITIES,
    SEVERITY_RANK,
    Decision,
    GuardContext,
    Verdict,
)
from .registry import (
    ACTIONS,
    BLOCKING_ACTIONS,
    CONDITIONS,
    REQUIRES_PATTERN_SET,
    TRANSFORMING,
)

_RULE_KEYS = {
    "id",
    "hook",
    "condition",
    "params",
    "action",
    "severity",
    "layer",
    "enabled",
    "description",
}

_TOP_LEVEL_KEYS = {"version", "pattern_sets", "rules", "audit", "metadata"}


class PolicyError(ValueError):
    """Raised on any invalid policy file. Always fatal — never downgraded."""


@dataclass
class Rule:
    id: str
    hook: str
    condition: str
    action: str
    severity: str
    params: dict = field(default_factory=dict)
    layer: str = ""
    enabled: bool = True
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "hook": self.hook,
            "condition": self.condition,
            "action": self.action,
            "severity": self.severity,
            "params": dict(self.params),
            "layer": self.layer,
            "enabled": self.enabled,
            "description": self.description,
        }


@dataclass
class PolicySet:
    version: int
    rules: list[Rule] = field(default_factory=list)
    pattern_sets: dict = field(default_factory=dict)
    audit: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    source_path: str = ""
    policy_hash: str = ""

    def rules_for(self, hook: str) -> list[Rule]:
        """Enabled rules bound to one hook, in file order."""
        return [r for r in self.rules if r.hook == hook and r.enabled]

    @property
    def layers_enabled(self) -> list[str]:
        """Distinct layer labels currently switched on. Recorded in results.json
        so a run can be attributed to a configuration after the fact."""
        return sorted({r.layer for r in self.rules if r.enabled})

    @property
    def short_hash(self) -> str:
        return self.policy_hash[:12]


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------


def load(path: str | Path, enable_layers: Iterable[str] = ()) -> PolicySet:
    """Load and strictly validate a policy file.

    ``enable_layers`` turns on rules that ship ``enabled: false`` — this is what
    ``detguard run --enable-layer llm_judge`` drives. There is exactly one
    policy file; nightly runs never load a second one, they enable a layer in
    the same file. Two files drift apart, and then the gate is testing
    something the client does not run.
    """
    p = Path(path)
    if not p.is_file():
        raise PolicyError(f"policy file not found: {p}")

    raw_bytes = p.read_bytes()
    try:
        data = yaml.safe_load(raw_bytes.decode("utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{p}: not valid YAML: {exc}") from exc

    policy = loads(data, source_path=str(p), enable_layers=enable_layers)
    policy.policy_hash = hashlib.sha256(raw_bytes).hexdigest()
    return policy


def loads(
    data: Any,
    source_path: str = "<memory>",
    enable_layers: Iterable[str] = (),
) -> PolicySet:
    """Validate an already-parsed policy document."""
    if not isinstance(data, dict):
        raise PolicyError(f"{source_path}: policy must be a mapping at the top level")

    unknown_top = set(data) - _TOP_LEVEL_KEYS
    if unknown_top:
        raise PolicyError(
            f"{source_path}: unknown top-level key(s): {', '.join(sorted(unknown_top))}"
        )

    version = data.get("version")
    if not isinstance(version, int):
        raise PolicyError(f"{source_path}: 'version' must be an integer")

    pattern_sets = data.get("pattern_sets") or {}
    if not isinstance(pattern_sets, dict):
        raise PolicyError(f"{source_path}: 'pattern_sets' must be a mapping")
    for name, patterns in pattern_sets.items():
        if not isinstance(patterns, list) or not all(isinstance(x, str) for x in patterns):
            raise PolicyError(
                f"{source_path}: pattern_set {name!r} must be a list of regex strings"
            )

    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise PolicyError(f"{source_path}: 'rules' must be a non-empty list")

    wanted_layers = {str(x) for x in enable_layers}
    seen_ids: set[str] = set()
    rules: list[Rule] = []

    for index, raw in enumerate(raw_rules):
        where = f"{source_path}: rule #{index + 1}"
        if not isinstance(raw, dict):
            raise PolicyError(f"{where}: must be a mapping")

        unknown = set(raw) - _RULE_KEYS
        if unknown:
            raise PolicyError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")

        rule_id = raw.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise PolicyError(f"{where}: 'id' must be a non-empty string")
        if rule_id in seen_ids:
            raise PolicyError(f"{source_path}: duplicate rule id {rule_id!r}")
        seen_ids.add(rule_id)

        hook = raw.get("hook")
        if hook not in HOOKS:
            raise PolicyError(
                f"{where} ({rule_id}): unknown hook {hook!r}; must be one of {', '.join(HOOKS)}"
            )

        condition = raw.get("condition")
        if condition not in CONDITIONS:
            raise PolicyError(
                f"{where} ({rule_id}): unknown condition {condition!r}; "
                f"must be one of {', '.join(sorted(CONDITIONS))}"
            )

        action = raw.get("action")
        if action not in ACTIONS:
            raise PolicyError(
                f"{where} ({rule_id}): unknown action {action!r}; "
                f"must be one of {', '.join(sorted(ACTIONS))}"
            )

        severity = raw.get("severity", "medium")
        if severity not in SEVERITIES:
            raise PolicyError(
                f"{where} ({rule_id}): unknown severity {severity!r}; "
                f"must be one of {', '.join(SEVERITIES)}"
            )

        params = raw.get("params") or {}
        if not isinstance(params, dict):
            raise PolicyError(f"{where} ({rule_id}): 'params' must be a mapping")

        if condition in REQUIRES_PATTERN_SET:
            set_name = params.get("pattern_set")
            if not set_name:
                raise PolicyError(
                    f"{where} ({rule_id}): condition {condition!r} requires a 'pattern_set' param"
                )
            if set_name not in pattern_sets:
                raise PolicyError(
                    f"{where} ({rule_id}): pattern_set {set_name!r} is not defined in 'pattern_sets'"
                )

        if action == "redact" and condition not in TRANSFORMING:
            raise PolicyError(
                f"{where} ({rule_id}): action 'redact' requires a transforming condition "
                f"({', '.join(sorted(TRANSFORMING))}), got {condition!r}"
            )

        layer = raw.get("layer") or condition
        if not isinstance(layer, str):
            raise PolicyError(f"{where} ({rule_id}): 'layer' must be a string")

        enabled = raw.get("enabled", True)
        if not isinstance(enabled, bool):
            raise PolicyError(f"{where} ({rule_id}): 'enabled' must be true or false")
        if not enabled and (layer in wanted_layers or condition in wanted_layers):
            enabled = True

        description = raw.get("description", "")
        if not isinstance(description, str):
            raise PolicyError(f"{where} ({rule_id}): 'description' must be a string")

        rules.append(
            Rule(
                id=rule_id,
                hook=hook,
                condition=condition,
                action=action,
                severity=severity,
                params=params,
                layer=layer,
                enabled=enabled,
                description=description,
            )
        )

    audit = data.get("audit") or {}
    if not isinstance(audit, dict):
        raise PolicyError(f"{source_path}: 'audit' must be a mapping")

    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise PolicyError(f"{source_path}: 'metadata' must be a mapping")

    return PolicySet(
        version=version,
        rules=rules,
        pattern_sets=pattern_sets,
        audit=audit,
        metadata=metadata,
        source_path=source_path,
    )


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------


def evaluate(policy: PolicySet, ctx: GuardContext) -> Verdict:
    """Run every enabled rule bound to ``ctx.hook`` and fold them into a Verdict.

    All rules run — evaluation never short-circuits on the first block, because
    the decision trace is the audit evidence and "which layers *would* have
    caught this" is the defence-in-depth argument the dashboard makes.

    Blocker selection is severity-ranked: a triggered critical rule is reported
    as the blocker over a triggered high one, and file order breaks ties.
    """
    ctx.pattern_sets = policy.pattern_sets
    decisions: list[Decision] = []

    blocker: Rule | None = None
    requires_approval = False
    text = ctx.text or ""

    for rule in policy.rules_for(ctx.hook):
        fn = CONDITIONS[rule.condition]
        fired, reason = fn(ctx, rule.params)
        decisions.append(
            Decision(
                name=rule.id,
                triggered=bool(fired),
                reason=reason,
                action=rule.action,
                severity=rule.severity,
                layer=rule.layer,
            )
        )
        if not fired:
            continue

        if rule.action == "redact" and ctx.redacted_text is not None:
            text = ctx.redacted_text

        if rule.action == "require_hitl":
            requires_approval = True

        if rule.action in BLOCKING_ACTIONS:
            if blocker is None or _outranks(rule, blocker):
                blocker = rule

    if blocker is None:
        return Verdict(
            allow=True,
            hook=ctx.hook,
            decisions=decisions,
            text=text,
            requires_approval=False,
        )

    # require_hitl stops unattended execution just as a block does; the flag is
    # what tells the caller a human may still say yes.
    return Verdict(
        allow=False,
        hook=ctx.hook,
        decisions=decisions,
        text=text,
        blocked_by=blocker.id,
        severity=blocker.severity,
        requires_approval=requires_approval,
    )


def _outranks(candidate: Rule, incumbent: Rule) -> bool:
    """Higher severity wins; a hard block wins over a HITL pause at equal severity."""
    c_rank = SEVERITY_RANK.get(candidate.severity, 0)
    i_rank = SEVERITY_RANK.get(incumbent.severity, 0)
    if c_rank != i_rank:
        return c_rank > i_rank
    if candidate.action == "block" and incumbent.action != "block":
        return True
    return False
