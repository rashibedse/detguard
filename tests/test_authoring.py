"""``detguard derive`` — deriving policy.yaml from a hand-written manifest + roles.

Nothing here calls a model. These tests pin the guarantees that matter: the
policy is *derived* by rule from the role map, never guessed; nothing is
written unless it survives the real validators; and the derived file carries
provenance so a reviewer never mistakes it for something hand-edited.
"""

from __future__ import annotations

import pytest

from detguard import authoring
from detguard.policy import loads as load_policy

ROLES_MAP = {
    "get_balance": ["read_internal"],
    "read_ticket": ["read_untrusted"],
    "update_address": ["mutate_identity"],
    "send_money": ["move_value"],
    "send_email": ["external_send"],
}

MANIFEST_YAML = """\
agent: demo
framework: generic
principal: the account holder
tools:
  - name: send_money
    description: Move funds.
    params:
      amount: {type: number, required: true}
untrusted_sources:
  - name: ticket_body
    kind: record
    injection_point: body
state_paths:
  move_value: account.balance
"""

ROLES_YAML = """\
roles:
  # why: transfers funds out of the principal's account
  send_money: [move_value]
"""

ARG_HINTS_YAML = """\
send_money:
  amount_arg: amount
"""


# ---------------------------------------------------------------------------
# derivation — no model involved
# ---------------------------------------------------------------------------


def test_human_in_loop_gets_every_gated_tool():
    policy = authoring.derive_policy(ROLES_MAP)
    rule = authoring.policy_rule(policy, "human_in_loop")
    assert rule["params"]["tools"] == ["send_email", "send_money", "update_address"]


def test_mutating_and_read_only_are_disjoint_and_complete():
    assert authoring.mutating_tools(ROLES_MAP) == ["send_money", "update_address"]
    assert authoring.read_only_tools(ROLES_MAP) == ["get_balance", "read_ticket"]


def test_unrequested_mutation_is_filled_from_roles():
    policy = authoring.derive_policy(ROLES_MAP)
    params = authoring.policy_rule(policy, "unrequested_mutation")["params"]
    assert params["mutating_tools"] == ["send_money", "update_address"]
    assert params["allowed_tools"] == ["get_balance", "read_ticket"]


def test_amount_bound_binds_to_the_sole_move_value_tool_and_stays_disabled():
    policy = authoring.derive_policy(
        ROLES_MAP, arg_hints={"send_money": {"amount_arg": "amount"}}
    )
    rule = authoring.policy_rule(policy, "amount_bound")
    assert rule["params"]["tool"] == "send_money"
    assert rule["params"]["arg"] == "amount"
    # A ceiling that does not match the business is worse than no ceiling.
    assert rule["enabled"] is False
    assert rule["params"]["min"] == 0


def test_two_candidates_means_no_binding_rather_than_a_guess():
    """A rule bound to the wrong tool never fires, and reads exactly like one
    that works. Ambiguity must stay visible."""
    two_movers = dict(ROLES_MAP, wire_transfer=["move_value"])
    policy = authoring.derive_policy(two_movers)
    assert authoring.policy_rule(policy, "amount_bound")["params"]["tool"] == ""


def test_egress_binding_covers_send_and_fetch():
    policy = authoring.derive_policy(
        {"post_webhook": ["external_fetch"]},
        arg_hints={"post_webhook": {"destination_arg": "url"}},
    )
    params = authoring.policy_rule(policy, "external_destination_allowlist")["params"]
    assert params["tool"] == "post_webhook"
    assert params["arg"] == "url"


def test_allowlist_is_never_auto_filled():
    """Empty blocks every external destination. A list somebody forgot to fill
    must not read as 'everywhere is fine'."""
    policy = authoring.derive_policy(ROLES_MAP)
    assert authoring.policy_rule(policy, "external_destination_allowlist")["params"]["allowlist"] == []


def test_derived_policy_always_validates():
    policy = authoring.derive_policy(ROLES_MAP)
    assert load_policy(policy, source_path="<derived>").rules


def test_derivation_is_deterministic():
    assert authoring.derive_policy(ROLES_MAP) == authoring.derive_policy(ROLES_MAP)


def test_derivation_does_not_mutate_the_shipped_default():
    first = authoring.derive_policy(ROLES_MAP)
    second = authoring.derive_policy({"only_read": ["read_internal"]})
    assert authoring.policy_rule(first, "human_in_loop")["params"]["tools"]
    assert authoring.policy_rule(second, "human_in_loop")["params"]["tools"] == []


# ---------------------------------------------------------------------------
# unfilled — which gaps are real
# ---------------------------------------------------------------------------


def test_empty_tool_is_not_reported_as_a_gap():
    """`tool: ''` means *any tool* — the broader, stricter binding. Reporting it
    would push a reviewer to narrow a rule sitting at its safest setting."""
    policy = authoring.derive_policy(ROLES_MAP, arg_hints={"send_money": {"destination_arg": "to"}})
    gaps = authoring.unfilled(policy)
    assert not any(gap.startswith("ungrounded_destination.tool") for gap in gaps)


def test_disabled_rules_are_not_reported_as_gaps():
    """Switching on `llm_judge` is a deliberate act, not a to-do item. Listing
    it would put 'no LLM in the enforcement path' on a checklist."""
    gaps = authoring.unfilled(authoring.derive_policy(ROLES_MAP))
    assert not any(gap.startswith("llm_judge_intent") for gap in gaps)


def test_an_unbound_arg_is_reported():
    gaps = authoring.unfilled(authoring.derive_policy(ROLES_MAP))
    assert "ungrounded_destination.arg" in gaps


# ---------------------------------------------------------------------------
# the validation gate — build_bundle reads hand-written manifest + roles text
# ---------------------------------------------------------------------------


def test_a_good_bundle_validates_and_derives_its_own_policy():
    bundle = authoring.build_bundle(MANIFEST_YAML, ROLES_YAML, ARG_HINTS_YAML)
    assert bundle.ok, bundle.problems
    # The policy was derived from roles.yaml, not written alongside it.
    assert authoring.policy_rule(bundle.policy, "human_in_loop")["params"]["tools"] == ["send_money"]
    assert authoring.policy_rule(bundle.policy, "amount_bound")["params"]["arg"] == "amount"


def test_roles_naming_a_tool_absent_from_the_manifest_is_caught():
    bundle = authoring.build_bundle(MANIFEST_YAML, "roles:\n  nonexistent_tool: [move_value]\n")
    assert not bundle.ok
    assert any("roles.yaml" in p for p in bundle.problems)


def test_an_invented_role_is_caught():
    bundle = authoring.build_bundle(MANIFEST_YAML, "roles:\n  send_money: [steals_money]\n")
    assert not bundle.ok


def test_a_manifest_with_no_tools_is_caught():
    bundle = authoring.build_bundle("agent: demo\nframework: generic\ntools: []\n", ROLES_YAML)
    assert not bundle.ok


def test_arg_hints_are_optional():
    bundle = authoring.build_bundle(MANIFEST_YAML, ROLES_YAML)
    assert bundle.ok, bundle.problems
    assert bundle.arg_hints == {}


# ---------------------------------------------------------------------------
# writing
# ---------------------------------------------------------------------------


def test_write_refuses_a_bundle_that_failed_validation(tmp_path):
    bundle = authoring.Bundle(problems=["something is wrong"])
    with pytest.raises(authoring.AuthoringError):
        authoring.write_policy(bundle, tmp_path / "config" / "policy.yaml")
    assert not (tmp_path / "config").exists()


def test_write_refuses_to_clobber_without_overwrite(tmp_path):
    bundle = authoring.build_bundle(MANIFEST_YAML, ROLES_YAML, ARG_HINTS_YAML)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("# mine\n", encoding="utf-8")
    with pytest.raises(authoring.AuthoringError):
        authoring.write_policy(bundle, policy_path)
    assert policy_path.read_text(encoding="utf-8") == "# mine\n"


def test_written_policy_carries_provenance(tmp_path):
    bundle = authoring.build_bundle(MANIFEST_YAML, ROLES_YAML, ARG_HINTS_YAML)
    path = authoring.write_policy(bundle, tmp_path / "policy.yaml")
    body = path.read_text(encoding="utf-8")
    assert "DERIVED by `detguard derive`" in body
    assert "detguard.authoring.unfilled" in body


def test_written_policy_still_loads_through_the_real_loader(tmp_path):
    from detguard.policy import load as load_policy_file

    bundle = authoring.build_bundle(MANIFEST_YAML, ROLES_YAML, ARG_HINTS_YAML)
    path = authoring.write_policy(bundle, tmp_path / "policy.yaml")
    assert load_policy_file(path).rules


# ---------------------------------------------------------------------------
# the command, end to end — no model involved
# ---------------------------------------------------------------------------


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "manifest.yaml").write_text(MANIFEST_YAML, encoding="utf-8")
    (tmp_path / "roles.yaml").write_text(ROLES_YAML, encoding="utf-8")
    (tmp_path / "arg_hints.yaml").write_text(ARG_HINTS_YAML, encoding="utf-8")
    return tmp_path


def test_derive_writes_policy_and_workflow(project):
    from detguard import cli

    assert cli.main(
        [
            "derive",
            "--manifest", "manifest.yaml",
            "--roles", "roles.yaml",
            "--arg-hints", "arg_hints.yaml",
            "--adapter-import", "myapp.detguard_adapter:build_adapter",
        ]
    ) == 0

    assert (project / "config" / "policy.yaml").is_file()
    assert (project / ".github/workflows/detguard-gate.yml").is_file()
    # Nothing that was hand-written gets touched or copied.
    assert not (project / "detguard_adapter.py").exists()


def test_derived_config_actually_builds_a_corpus(project):
    """The end that matters. A policy that validates but binds no attacks would
    be a derivation that produces paperwork rather than an integration."""
    from detguard import cli
    from detguard.instantiate import build

    cli.main(
        [
            "derive",
            "--manifest", "manifest.yaml",
            "--roles", "roles.yaml",
            "--adapter-import", "myapp.detguard_adapter:build_adapter",
        ]
    )
    result = build(
        manifest_path=str(project / "manifest.yaml"),
        roles_path=str(project / "roles.yaml"),
        out_dir=str(project / "corpus" / "attacks"),
    )
    assert result.attacks


def test_derived_workflow_carries_the_adapter_import(project):
    from detguard import cli

    cli.main(
        [
            "derive",
            "--manifest", "manifest.yaml",
            "--roles", "roles.yaml",
            "--adapter-import", "myapp.detguard_adapter:build_adapter",
        ]
    )
    workflow = (project / ".github/workflows/detguard-gate.yml").read_text(encoding="utf-8")
    assert "myapp.detguard_adapter:build_adapter" in workflow


def test_dry_run_writes_nothing(project):
    from detguard import cli

    assert cli.main(
        [
            "derive",
            "--manifest", "manifest.yaml",
            "--roles", "roles.yaml",
            "--adapter-import", "myapp.detguard_adapter:build_adapter",
            "--dry-run",
        ]
    ) == 0
    assert not (project / "config").exists()


def test_a_failed_validation_leaves_nothing_behind(project):
    """Half a written integration is worse than none: the next command fails
    somewhere unrelated and the cause is three steps back."""
    from detguard import cli

    (project / "roles.yaml").write_text("roles:\n  send_money: [not_a_real_role]\n", encoding="utf-8")

    assert cli.main(
        [
            "derive",
            "--manifest", "manifest.yaml",
            "--roles", "roles.yaml",
            "--adapter-import", "myapp.detguard_adapter:build_adapter",
        ]
    ) == 2
    assert not (project / "config").exists()


def test_a_missing_manifest_is_a_config_error(project):
    from detguard import cli

    assert cli.main(
        [
            "derive",
            "--manifest", "nope.yaml",
            "--roles", "roles.yaml",
            "--adapter-import", "myapp.detguard_adapter:build_adapter",
        ]
    ) == 2
