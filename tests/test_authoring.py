"""``detguard scaffold`` — generation, derivation, and the guarantees around them.

The model-backed half cannot be unit tested without a key, so these tests pin
the parts that must hold regardless of what a model returns: the policy is
*derived* by rule and never guessed; nothing is written unless it survives the
real validators; and generated files reach disk with their review material
intact.
"""

from __future__ import annotations

import pytest
import yaml

from detguard import authoring
from detguard.policy import loads as load_policy

ROLES_MAP = {
    "get_balance": ["read_internal"],
    "read_ticket": ["read_untrusted"],
    "update_address": ["mutate_identity"],
    "send_money": ["move_value"],
    "send_email": ["external_send"],
}


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
# response parsing
# ---------------------------------------------------------------------------


RESPONSE = """\
Here is what I generated.

--- BEGIN detguard_adapter.py ---
```python
from detguard.adapters.base import AgentRun, BaseAdapter


class MyAdapter(BaseAdapter):
    name = "demo"

    def introspect(self):
        return {}

    def reset(self):
        pass

    def invoke(self, user_prompt, injected_context=None):
        return AgentRun()

    def get_state(self, path):
        return None


def build_adapter():
    return MyAdapter()
```
--- END detguard_adapter.py ---

--- BEGIN manifest.yaml ---
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
--- END manifest.yaml ---

--- BEGIN roles.yaml ---
roles:
  # why: transfers funds out of the principal's account
  send_money: [move_value]
--- END roles.yaml ---

--- BEGIN ARG_HINTS ---
send_money:
  amount_arg: amount
--- END ARG_HINTS ---

NOTES:
- no reset function found in the source; reset() raises a TODO
"""


def test_parse_response_extracts_every_file():
    files = authoring.parse_response(RESPONSE)
    assert set(files) == {"detguard_adapter.py", "manifest.yaml", "roles.yaml", "ARG_HINTS"}


def test_parse_response_strips_the_code_fence():
    files = authoring.parse_response(RESPONSE)
    assert files["detguard_adapter.py"].startswith("from detguard.adapters.base")
    assert "```" not in files["detguard_adapter.py"]


def test_parse_response_refuses_an_empty_result():
    with pytest.raises(authoring.AuthoringError):
        authoring.parse_response("I could not do that.")


def test_extract_notes():
    assert "no reset function" in authoring.extract_notes(RESPONSE)


# ---------------------------------------------------------------------------
# the validation gate
# ---------------------------------------------------------------------------


def test_a_good_bundle_validates_and_derives_its_own_policy():
    bundle = authoring.build_bundle(authoring.parse_response(RESPONSE), model="test-model")
    assert bundle.ok, bundle.problems
    # The policy was derived from the generated roles, not generated alongside them.
    assert authoring.policy_rule(bundle.policy, "human_in_loop")["params"]["tools"] == ["send_money"]
    assert authoring.policy_rule(bundle.policy, "amount_bound")["params"]["arg"] == "amount"


def test_broken_adapter_syntax_is_a_problem_not_a_write():
    files = authoring.parse_response(RESPONSE)
    files["detguard_adapter.py"] = "def build_adapter(:\n    pass\n"
    bundle = authoring.build_bundle(files)
    assert not bundle.ok
    assert any("does not parse" in p for p in bundle.problems)


def test_roles_naming_a_tool_absent_from_the_manifest_is_caught():
    files = authoring.parse_response(RESPONSE)
    files["roles.yaml"] = "roles:\n  nonexistent_tool: [move_value]\n"
    bundle = authoring.build_bundle(files)
    assert not bundle.ok
    assert any("roles.yaml" in p for p in bundle.problems)


def test_an_invented_role_is_caught():
    files = authoring.parse_response(RESPONSE)
    files["roles.yaml"] = "roles:\n  send_money: [steals_money]\n"
    bundle = authoring.build_bundle(files)
    assert not bundle.ok


def test_a_manifest_with_no_tools_is_caught():
    files = authoring.parse_response(RESPONSE)
    files["manifest.yaml"] = "agent: demo\nframework: generic\ntools: []\n"
    bundle = authoring.build_bundle(files)
    assert not bundle.ok


# ---------------------------------------------------------------------------
# writing
# ---------------------------------------------------------------------------


def test_write_refuses_a_bundle_that_failed_validation(tmp_path):
    bundle = authoring.Bundle(problems=["something is wrong"])
    with pytest.raises(authoring.AuthoringError):
        authoring.write_bundle(bundle, tmp_path / "config", tmp_path / "adapter.py")
    assert not (tmp_path / "config").exists()


def test_write_refuses_to_clobber_without_overwrite(tmp_path):
    bundle = authoring.build_bundle(authoring.parse_response(RESPONSE), model="test-model")
    adapter = tmp_path / "detguard_adapter.py"
    adapter.write_text("# mine\n", encoding="utf-8")
    with pytest.raises(authoring.AuthoringError):
        authoring.write_bundle(bundle, tmp_path / "config", adapter)
    assert adapter.read_text(encoding="utf-8") == "# mine\n"


def test_written_roles_keep_their_reasoning_comments(tmp_path):
    """The prompt asks for a `# why:` line per role so a reviewer checks the
    classification instead of trusting it. Round-tripping through safe_dump
    would strip every one of them — deleting the review material on the way to
    disk."""
    bundle = authoring.build_bundle(authoring.parse_response(RESPONSE), model="test-model")
    authoring.write_bundle(bundle, tmp_path / "config", tmp_path / "detguard_adapter.py")
    written = (tmp_path / "config" / "roles.yaml").read_text(encoding="utf-8")
    assert "# why: transfers funds out of the principal's account" in written


def test_every_written_file_carries_provenance(tmp_path):
    bundle = authoring.build_bundle(authoring.parse_response(RESPONSE), model="test-model")
    written = authoring.write_bundle(bundle, tmp_path / "config", tmp_path / "detguard_adapter.py")
    for path in written:
        body = path.read_text(encoding="utf-8")
        assert "GENERATED by `detguard scaffold`" in body
        assert "test-model" in body
        assert "DRAFT" in body


def test_written_config_still_loads_through_the_real_loaders(tmp_path):
    from detguard.manifest import load_pair
    from detguard.policy import load as load_policy_file

    bundle = authoring.build_bundle(authoring.parse_response(RESPONSE), model="test-model")
    config = tmp_path / "config"
    authoring.write_bundle(bundle, config, tmp_path / "detguard_adapter.py")

    manifest, role_map = load_pair(config / "manifest.yaml", config / "roles.yaml")
    assert manifest.tool_names == ["send_money"]
    assert role_map.tools_for("move_value") == ["send_money"]
    assert load_policy_file(config / "policy.yaml").rules


# ---------------------------------------------------------------------------
# source collection
# ---------------------------------------------------------------------------


def test_collect_sources_skips_dependency_directories(tmp_path):
    (tmp_path / "agent.py").write_text("x = 1\n", encoding="utf-8")
    vendored = tmp_path / ".venv" / "lib"
    vendored.mkdir(parents=True)
    (vendored / "noise.py").write_text("y = 2\n", encoding="utf-8")

    found = authoring.collect_sources(tmp_path)
    assert [s.path for s in found] == ["agent.py"]


def test_collect_sources_records_truncation(tmp_path):
    (tmp_path / "big.py").write_text("# pad\n" * 5000, encoding="utf-8")
    found = authoring.collect_sources(tmp_path, max_bytes=200)
    assert found[0].truncated
    assert "truncated by detguard scaffold" in found[0].text


def test_collect_sources_is_loud_about_finding_nothing(tmp_path):
    with pytest.raises(authoring.AuthoringError):
        authoring.collect_sources(tmp_path)


# ---------------------------------------------------------------------------
# provider selection
# ---------------------------------------------------------------------------


def test_provider_inferred_from_model_name():
    assert authoring.infer_provider("claude-sonnet-5") == "anthropic"
    assert authoring.infer_provider("gpt-4o") == "openai"
    assert authoring.infer_provider("llama-3.1-8b-instant") == "openai"


def test_a_missing_key_is_an_error_before_any_network_call(monkeypatch):
    for name in ("DETGUARD_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(authoring.AuthoringError, match="no API key"):
        authoring.call_model("prompt", model="claude-sonnet-5", api_key="")


def test_explicit_key_beats_the_environment(monkeypatch):
    monkeypatch.setenv("DETGUARD_API_KEY", "from-env")
    assert authoring.resolve_api_key("explicit") == "explicit"
    assert authoring.resolve_api_key("") == "from-env"


# ---------------------------------------------------------------------------
# the prompt
# ---------------------------------------------------------------------------


def test_prompt_carries_the_closed_role_vocabulary_and_the_gated_set():
    from detguard.roles import GATED_BY_DEFAULT, ROLES

    prompt = authoring.build_prompt(
        [authoring.SourceFile(path="agent.py", text="pass\n")], entry="agent:run"
    )
    for role in ROLES:
        assert role in prompt
    for role in GATED_BY_DEFAULT:
        assert role in prompt


def test_prompt_demands_the_known_factory_name():
    """Everything downstream addresses the adapter as
    `detguard_adapter:build_adapter`."""
    prompt = authoring.build_prompt(
        [authoring.SourceFile(path="agent.py", text="pass\n")], entry="agent:run"
    )
    assert "build_adapter()" in prompt


def test_prompt_warns_against_double_execution():
    prompt = authoring.build_prompt(
        [authoring.SourceFile(path="agent.py", text="pass\n")], entry="agent:run"
    )
    assert "executed exactly once" in prompt
    assert "doubles every real side effect" in prompt


# ---------------------------------------------------------------------------
# the command, end to end with the model stubbed
# ---------------------------------------------------------------------------


@pytest.fixture
def project(tmp_path, monkeypatch):
    (tmp_path / "agent.py").write_text("def run_agent(msg):\n    return 'ok'\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(authoring, "call_model", lambda *a, **k: RESPONSE)
    return tmp_path


def test_scaffold_writes_a_complete_working_integration(project):
    from detguard import cli

    assert cli.main(["scaffold", "--source-dir", ".", "--entry", "agent:run_agent"]) == 0

    for relative in (
        "detguard_adapter.py",
        "config/manifest.yaml",
        "config/roles.yaml",
        "config/policy.yaml",
        ".github/workflows/detguard-gate.yml",
    ):
        assert (project / relative).is_file(), relative


def test_scaffolded_config_actually_builds_a_corpus(project):
    """The end that matters. Files that validate but bind no attacks would be a
    scaffolder that produces paperwork rather than an integration."""
    from detguard import cli
    from detguard.instantiate import build

    cli.main(["scaffold", "--source-dir", ".", "--entry", "agent:run_agent"])
    result = build(
        manifest_path=str(project / "config" / "manifest.yaml"),
        roles_path=str(project / "config" / "roles.yaml"),
        out_dir=str(project / "corpus" / "attacks"),
    )
    assert result.attacks


def test_scaffolded_workflow_carries_no_windows_separators(project):
    from detguard import cli

    cli.main(["scaffold", "--source-dir", ".", "--entry", "agent:run_agent"])
    workflow = (project / ".github/workflows/detguard-gate.yml").read_text(encoding="utf-8")
    # Trailing `\` is a shell line-continuation; anywhere else it is a path
    # separator that breaks on ubuntu-latest.
    assert not [ln for ln in workflow.splitlines() if "\\" in ln.rstrip().removesuffix("\\")]
    assert "--agent detguard_adapter:build_adapter" in workflow


def test_dry_run_writes_nothing(project):
    from detguard import cli

    assert cli.main(
        ["scaffold", "--source-dir", ".", "--entry", "agent:run_agent", "--dry-run"]
    ) == 0
    assert not (project / "config").exists()
    assert not (project / "detguard_adapter.py").exists()


def test_print_prompt_needs_no_key_and_calls_no_model(project, monkeypatch):
    from detguard import cli

    def explode(*args, **kwargs):
        raise AssertionError("--print-prompt must not reach the model")

    monkeypatch.setattr(authoring, "call_model", explode)
    assert cli.main(
        ["scaffold", "--source-dir", ".", "--entry", "agent:run_agent", "--print-prompt"]
    ) == 0


def test_a_failed_generation_leaves_nothing_behind(project, monkeypatch):
    """Half a written integration is worse than none: the next command fails
    somewhere unrelated and the cause is three steps back."""
    from detguard import cli

    broken = RESPONSE.replace("send_money: [move_value]", "send_money: [not_a_real_role]")
    monkeypatch.setattr(authoring, "call_model", lambda *a, **k: broken)

    assert cli.main(["scaffold", "--source-dir", ".", "--entry", "agent:run_agent"]) == 2
    assert not (project / "config").exists()
    assert not (project / "detguard_adapter.py").exists()
