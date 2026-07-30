"""Unobserved is not defended.

A success check that cannot be evaluated used to score as ``passed=False``, which
the runner read as "the attack did not achieve its objective" and the report
presented as a defence. Three distinct facts collapsed into one green row:

* the agent refused;
* the agent emitted no tool call at all (a model limitation, not a policy win);
* detguard could not read the state the check asks about.

The measured consequence, on detguard's own corpus: an adapter whose
``get_state`` returns ``None`` hides **12** real breaches out of 35 and still
reports 100% coverage. That number is the reason this module exists.
"""

from __future__ import annotations

import pytest

from detguard import report as report_mod
from detguard.adapters.base import UNREADABLE
from detguard.events import AgentRun
from detguard.instantiate import build, load_corpus
from detguard.policy import load as load_policy
from detguard.runner import (
    NO_FINAL_OUTPUT,
    NO_TOOL_CALLS,
    STATE_UNREADABLE,
    evaluate_success,
    run,
)

from .fixture_agent import FixtureAgent


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    out = tmp_path_factory.mktemp("attacks")
    build(
        manifest_path="tests/fixture_manifest.yaml",
        roles_path="tests/fixture_roles.yaml",
        out_dir=str(out),
    )
    return load_corpus(str(out))


@pytest.fixture(scope="module")
def policy():
    return load_policy("tests/fixture_policy.yaml")


class BlindReturningNone(FixtureAgent):
    """The old failure mode: cannot read state, but says ``None``."""

    def get_state(self, path):
        return None


class BlindButHonest(FixtureAgent):
    """The fix: cannot read state, and says so."""

    def get_state(self, path):
        return UNREADABLE


# ---------------------------------------------------------------------------
# the headline regression
# ---------------------------------------------------------------------------


def test_an_adapter_that_cannot_see_state_does_not_report_defences(corpus, policy):
    """The 12 hidden breaches must surface, and coverage must admit the gap."""
    seeing = run(corpus, FixtureAgent(), policy, mode="off")["summary"]
    blind = run(corpus, BlindButHonest(), policy, mode="off")["summary"]

    assert seeing["succeeded"] == 35, "fixture corpus changed; update these numbers"
    assert seeing["coverage"] == 1.0
    assert seeing["inconclusive"] == 0

    # The same 12 cases the old code scored as not-succeeded are now named.
    assert blind["inconclusive"] == 12
    assert blind["inconclusive_by_cause"] == {STATE_UNREADABLE: 12}
    assert blind["succeeded"] == seeing["succeeded"] - 12

    # And the run no longer claims to have measured what it could not see.
    assert blind["coverage"] < 1.0
    assert blind["coverage"] == round(
        (blind["total"] - 12) / blind["total"], 4
    )


def test_unreadable_state_is_never_counted_as_a_defence(corpus, policy):
    blind = run(corpus, BlindButHonest(), policy, mode="off")
    unmeasured = [r for r in blind["results"] if r["outcome"] == "inconclusive"]

    assert unmeasured, "expected some unevaluatable cases"
    for record in unmeasured:
        assert record["succeeded"] is False
        assert record["outcome"] not in ("blocked", "approval_required", "not_complied")
        assert record["reason_code"] == STATE_UNREADABLE
    # defended counts only what was actually stopped
    assert blind["summary"]["defended"] == blind["summary"]["blocked"] + blind[
        "summary"
    ]["requires_approval"]


def test_returning_none_still_cannot_be_detected(corpus, policy):
    """Honest about the limit of the fix.

    detguard cannot tell a client's ``state_reader`` returning ``None`` from a
    genuinely empty value — which is exactly why ``state.mapping_reader`` returns
    UNREADABLE for unmapped paths instead of leaving it to each user to remember.
    """
    blind = run(corpus, BlindReturningNone(), policy, mode="off")["summary"]
    assert blind["inconclusive"] == 0
    assert blind["coverage"] == 1.0  # the misleading result this documents


# ---------------------------------------------------------------------------
# per-cause behaviour
# ---------------------------------------------------------------------------


def test_no_tool_calls_is_inconclusive_not_refusal():
    """A model that cannot emit the call is not a policy that stopped it."""
    check = {"type": "field_changed", "path": "account.balance"}
    resolved = evaluate_success(check, AgentRun(tool_calls=[]), FixtureAgent(), {})

    assert resolved["passed"] is False
    assert resolved["inconclusive"] is True
    assert resolved["reason_code"] == NO_TOOL_CALLS


def test_must_allow_still_passes_with_no_tool_calls():
    """The benign control asserts the absence of a block, so doing nothing is fine."""
    resolved = evaluate_success({"type": "must_allow"}, AgentRun(tool_calls=[]), FixtureAgent(), {})
    assert resolved["passed"] is True
    assert not resolved.get("inconclusive")


def test_empty_final_output_is_inconclusive_for_output_checks():
    """TPL-12's failure mode: no final answer means the question was never asked."""
    call = FixtureAgent().make_call("get_profile", {}, "ok")
    run_result = AgentRun(tool_calls=[call], final_output="")

    resolved = evaluate_success(
        {"type": "output_contains", "expected": "SECRET"}, run_result, FixtureAgent(), {}
    )

    assert resolved["passed"] is False
    assert resolved["reason_code"] == NO_FINAL_OUTPUT


def test_output_check_still_works_when_there_is_output():
    call = FixtureAgent().make_call("get_profile", {}, "ok")
    run_result = AgentRun(tool_calls=[call], final_output="the code is SECRET-1")

    resolved = evaluate_success(
        {"type": "output_contains", "expected": "SECRET-1"}, run_result, FixtureAgent(), {}
    )

    assert resolved["passed"] is True
    assert not resolved.get("inconclusive")


def test_read_path_reports_a_missing_path_rather_than_none():
    state = {"customer": {"address": "1 High St"}}
    assert FixtureAgent.read_path(state, "customer.address") == "1 High St"
    assert FixtureAgent.read_path(state, "customer.nonexistent") is UNREADABLE
    assert FixtureAgent.read_path(state, "") is UNREADABLE


def test_a_genuine_none_is_still_a_real_answer():
    """``None`` stored in state must not be confused with an unreadable path."""
    state = {"account": {"last_transfer_destination": None}}
    assert FixtureAgent.read_path(state, "account.last_transfer_destination") is None


# ---------------------------------------------------------------------------
# the report
# ---------------------------------------------------------------------------


def test_report_warns_when_the_unguarded_baseline_is_zero(corpus, policy):
    """`prevented 0 of 0` states a fact and implies a conclusion it cannot support."""

    class RefusesEverything(FixtureAgent):
        def invoke(self, user_prompt, injected_context=None):
            return AgentRun(tool_calls=[], final_output="I can't help with that.")

    guarded = run(corpus, RefusesEverything(), policy, mode="on")
    unguarded = run(corpus, RefusesEverything(), policy, mode="off")

    built = report_mod.build(guarded, unguarded=unguarded)
    kinds = {w["kind"] for w in built["measurement"]["warnings"]}

    assert "POLICY_NOT_EXERCISED" in kinds
    assert built["delta"]["meaningful"] is False
    assert built["measurement"]["trustworthy"] is False

    markdown = report_mod.to_markdown(built)
    assert "not measurable" in markdown
    assert "prevented **0**" not in markdown


def test_report_states_coverage_and_causes(corpus, policy):
    built = report_mod.build(run(corpus, BlindButHonest(), policy, mode="off"))

    measurement = built["measurement"]
    assert measurement["inconclusive"] == 12
    assert measurement["coverage"] < 1.0
    warning = next(w for w in measurement["warnings"] if w["kind"] == "INCOMPLETE_MEASUREMENT")
    assert warning["causes"][0]["code"] == STATE_UNREADABLE
    assert warning["causes"][0]["explanation"]

    markdown = report_mod.to_markdown(built)
    assert "Incomplete Measurement" in markdown
    # The caveat has to precede the number it qualifies.
    assert markdown.index("Incomplete Measurement") < markdown.index("defense rate")


def test_blindness_hides_in_the_unguarded_run_where_it_does_most_damage(corpus, policy):
    """The trap this whole module is built around.

    A blocked attack never reaches its state check, so a *guarded* run over a
    blind adapter reports 100% coverage and looks impeccable. The unguarded run
    is where the same adapter goes dark — and the unguarded run is what the delta
    is computed from. So the guarded number a client reads is clean, while the
    baseline underneath it is not, and nothing in the old report said so.
    """
    guarded = run(corpus, BlindButHonest(), policy, mode="on")
    unguarded = run(corpus, BlindButHonest(), policy, mode="off")

    assert guarded["summary"]["coverage"] == 1.0, "guarded run looks perfectly measured"
    assert unguarded["summary"]["coverage"] < 1.0, "the baseline is the blind one"

    built = report_mod.build(guarded, unguarded=unguarded)
    # The report must surface the baseline's blindness even though the guarded
    # run it is reporting on has none.
    assert built["delta"]["unguarded_breaches"] == 23
    assert report_mod.build(unguarded)["measurement"]["trustworthy"] is False


def test_a_clean_run_carries_no_warnings(corpus, policy):
    built = report_mod.build(
        run(corpus, FixtureAgent(), policy, mode="on"),
        unguarded=run(corpus, FixtureAgent(), policy, mode="off"),
    )
    assert built["measurement"]["warnings"] == []
    assert built["measurement"]["trustworthy"] is True
    assert built["measurement"]["coverage"] == 1.0
    assert built["delta"]["meaningful"] is True


# ---------------------------------------------------------------------------
# the baseline
# ---------------------------------------------------------------------------


def test_a_breach_becoming_unmeasurable_is_not_a_fix(corpus, policy):
    """The most dangerous possible misreport: a broken check as security progress."""
    from detguard.baseline import MEASUREMENT_LOST, compare, snapshot

    before = snapshot(run(corpus, FixtureAgent(), policy, mode="off"))
    after = run(corpus, BlindButHonest(), policy, mode="off")

    outcome = compare(after, before)
    kinds = {f["kind"] for f in outcome["findings"]}

    assert MEASUREMENT_LOST in kinds
    assert "FIXED" not in kinds and "GAP_CLOSED" not in kinds
    lost = [f for f in outcome["findings"] if f["kind"] == MEASUREMENT_LOST]
    assert len(lost) == 12
    assert all(f["fails"] for f in lost), "a lost check must fail the gate"
    assert outcome["exit_code"] != 0
