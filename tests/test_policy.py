"""Policy loading is strict, and these are the errors that make it so.

Every one of these tests asserts a *refusal*. That is the point: a policy file
that cannot be understood must be a hard load-time error, never a rule that
quietly never fires. The silent version produces a green CI gate over an
undefended agent, which is worse than having no gate at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import detguard
from detguard.events import GuardContext, ToolCall
from detguard.policy import PolicyError, evaluate, load, loads

DEFAULT_POLICY_PATH = Path(detguard.__file__).resolve().parent / "policies" / "default.yaml"


def minimal(**overrides) -> dict:
    document = {
        "version": 1,
        "pattern_sets": {"injection": [r"(?i)ignore all previous instructions"]},
        "rules": [
            {
                "id": "overt_injection",
                "hook": "before_input",
                "condition": "content_scan",
                "params": {"pattern_set": "injection"},
                "action": "block",
                "severity": "critical",
            }
        ],
    }
    document.update(overrides)
    return document


# ---------------------------------------------------------------------------
# the happy path
# ---------------------------------------------------------------------------


def test_loads_a_valid_policy():
    policy = loads(minimal())
    assert policy.version == 1
    assert len(policy.rules) == 1
    assert policy.rules[0].id == "overt_injection"


def test_layer_defaults_to_the_condition_name():
    assert loads(minimal()).rules[0].layer == "content_scan"


def test_shipped_default_policy_loads():
    policy = load(DEFAULT_POLICY_PATH)
    assert policy.rules
    assert policy.policy_hash, "a loaded policy must carry a hash for provenance"


def test_llm_judge_ships_disabled_in_the_default_policy():
    """No LLM in the enforcement path. This is a hard invariant, not a default."""
    policy = load(DEFAULT_POLICY_PATH)
    judges = [r for r in policy.rules if r.condition == "llm_judge"]
    assert judges, "the default policy should carry an llm_judge rule to enable later"
    assert all(not r.enabled for r in judges)


def test_enable_layer_switches_on_a_disabled_rule():
    policy = load(
        DEFAULT_POLICY_PATH, enable_layers=["llm_judge"]
    )
    judges = [r for r in policy.rules if r.condition == "llm_judge"]
    assert all(r.enabled for r in judges)


def test_policy_hash_changes_when_the_file_changes(tmp_path):
    first = tmp_path / "a.yaml"
    first.write_text("version: 1\nrules:\n  - {id: a, hook: before_tool, "
                     "condition: call_budget, params: {max_calls: 5}, action: block}\n")
    second = tmp_path / "b.yaml"
    second.write_text("version: 1\nrules:\n  - {id: a, hook: before_tool, "
                      "condition: call_budget, params: {max_calls: 6}, action: block}\n")
    assert load(first).policy_hash != load(second).policy_hash


# ---------------------------------------------------------------------------
# refusals
# ---------------------------------------------------------------------------


def test_raises_on_unknown_condition():
    document = minimal()
    document["rules"][0]["condition"] = "vibe_check"
    with pytest.raises(PolicyError, match="unknown condition"):
        loads(document)


def test_raises_on_unknown_action():
    document = minimal()
    document["rules"][0]["action"] = "deny"
    with pytest.raises(PolicyError, match="unknown action"):
        loads(document)


def test_raises_on_unknown_hook():
    document = minimal()
    document["rules"][0]["hook"] = "after"
    with pytest.raises(PolicyError, match="unknown hook"):
        loads(document)


def test_raises_on_unknown_severity():
    document = minimal()
    document["rules"][0]["severity"] = "catastrophic"
    with pytest.raises(PolicyError, match="unknown severity"):
        loads(document)


def test_raises_on_duplicate_rule_id():
    document = minimal()
    document["rules"].append(dict(document["rules"][0]))
    with pytest.raises(PolicyError, match="duplicate rule id"):
        loads(document)


def test_raises_when_a_pattern_set_param_is_missing():
    document = minimal()
    document["rules"][0]["params"] = {}
    with pytest.raises(PolicyError, match="requires a 'pattern_set' param"):
        loads(document)


def test_raises_when_a_pattern_set_is_referenced_but_not_defined():
    document = minimal()
    document["rules"][0]["params"] = {"pattern_set": "nonexistent"}
    with pytest.raises(PolicyError, match="not defined in 'pattern_sets'"):
        loads(document)


def test_raises_on_an_unknown_rule_key():
    document = minimal()
    document["rules"][0]["sevrity"] = "critical"  # typo
    with pytest.raises(PolicyError, match="unknown key"):
        loads(document)


def test_raises_on_an_unknown_top_level_key():
    with pytest.raises(PolicyError, match="unknown top-level key"):
        loads(minimal(ruels=[]))


def test_raises_on_an_empty_rule_list():
    with pytest.raises(PolicyError, match="non-empty list"):
        loads(minimal(rules=[]))


def test_raises_when_redact_is_paired_with_a_non_transforming_condition():
    """Only pii_redact can redact. Anything else silently redacts nothing."""
    document = minimal()
    document["rules"][0]["action"] = "redact"
    with pytest.raises(PolicyError, match="requires a transforming condition"):
        loads(document)


def test_raises_on_a_missing_file():
    with pytest.raises(PolicyError, match="not found"):
        load("no/such/policy.yaml")


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------


def two_blockers() -> dict:
    return {
        "version": 1,
        "pattern_sets": {"any": [r"."]},
        "rules": [
            {
                "id": "high_rule",
                "hook": "before_input",
                "condition": "content_scan",
                "params": {"pattern_set": "any"},
                "action": "block",
                "severity": "high",
            },
            {
                "id": "critical_rule",
                "hook": "before_input",
                "condition": "content_scan",
                "params": {"pattern_set": "any"},
                "action": "block",
                "severity": "critical",
            },
        ],
    }


def test_blocker_selection_prefers_critical_over_high():
    """Both fire; the reported blocker is the more severe one, not the first."""
    verdict = evaluate(loads(two_blockers()), GuardContext(hook="before_input", text="x"))
    assert not verdict.allow
    assert verdict.blocked_by == "critical_rule"
    assert verdict.severity == "critical"


def test_every_rule_is_evaluated_even_after_one_blocks():
    """The decision trace is the audit evidence; short-circuiting would lose it."""
    verdict = evaluate(loads(two_blockers()), GuardContext(hook="before_input", text="x"))
    assert len(verdict.decisions) == 2
    assert all(d.triggered for d in verdict.decisions)


def test_a_hard_block_outranks_a_hitl_pause_at_equal_severity():
    document = two_blockers()
    document["rules"][0]["severity"] = "critical"
    document["rules"][0]["action"] = "require_hitl"
    verdict = evaluate(loads(document), GuardContext(hook="before_input", text="x"))
    # At equal severity a hard block is reported over a HITL pause, on the
    # grounds that the stricter outcome is the honest headline — and
    # `requires_approval` has to follow that choice rather than contradict it.
    # It previously ORed over every fired rule, so the HITL rule that *lost*
    # blocker selection still relabelled the verdict "awaiting a human", which
    # is a softer claim than the block that actually decided the case.
    assert verdict.blocked_by == "critical_rule"
    assert verdict.requires_approval is False
    # The weaker fact is kept, just not allowed to overwrite the outcome.
    assert verdict.hitl_also_fired is True


def test_requires_approval_when_the_hitl_rule_is_the_one_that_wins():
    """The flag is not merely suppressed — it tracks the winning rule."""
    document = two_blockers()
    document["rules"] = [document["rules"][0]]
    document["rules"][0]["action"] = "require_hitl"
    verdict = evaluate(loads(document), GuardContext(hook="before_input", text="x"))
    assert not verdict.allow
    assert verdict.requires_approval is True


def test_rules_only_run_at_their_own_hook():
    policy = loads(minimal())
    verdict = evaluate(policy, GuardContext(hook="before_tool", tool_calls=[ToolCall("x")]))
    assert verdict.allow
    assert verdict.decisions == []


def test_disabled_rules_do_not_run():
    document = minimal()
    document["rules"][0]["enabled"] = False
    verdict = evaluate(
        loads(document), GuardContext(hook="before_input", text="ignore all previous instructions")
    )
    assert verdict.allow
    assert verdict.decisions == []
