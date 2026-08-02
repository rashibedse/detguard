"""``detguard/scaffold.py`` — the config-authoring helpers behind dashboard/setup.py.

These are plain-data transformations (command strings, a CI workflow document)
with no Streamlit dependency, so they get real unit tests rather than relying
on manually clicking through the app. The one property that matters most:
whatever setup.py generates must be a workflow that actually parses and whose
`detguard run` invocations are ones the CLI would accept.
"""

from __future__ import annotations

import yaml

from detguard.scaffold import (
    DETGUARD_REQUIREMENT,
    AdapterConfig,
    RunConfig,
    build_commands,
    generate_workflow,
)


def test_adapter_config_generic_flags():
    cfg = AdapterConfig(kind="generic", agent="myapp.adapter:build")
    assert cfg.cli_flags() == ["--adapter", "generic", "--agent", "myapp.adapter:build"]
    assert cfg.problems() == []


def test_adapter_config_langgraph_needs_reset():
    cfg = AdapterConfig(kind="langgraph", graph="myapp.graph:graph")
    problems = cfg.problems()
    assert any("--reset" in p for p in problems)


def test_adapter_config_langgraph_full_flags():
    cfg = AdapterConfig(
        kind="langgraph",
        graph="myapp.graph:graph",
        reset="myapp.db:seed",
        tools="myapp.tools:ALL_TOOLS",
        state_reader="myapp.state:read",
    )
    assert cfg.problems() == []
    assert cfg.cli_flags() == [
        "--adapter", "langgraph",
        "--graph", "myapp.graph:graph",
        "--reset", "myapp.db:seed",
        "--tools", "myapp.tools:ALL_TOOLS",
        "--state-reader", "myapp.state:read",
    ]


def test_adapter_config_missing_everything():
    cfg = AdapterConfig(kind="generic")
    assert cfg.problems()


def test_build_commands_fills_in_config():
    cfg = RunConfig(
        manifest="guardrail/manifest.yaml",
        roles="guardrail/roles.yaml",
        policy="guardrail/policy.yaml",
        corpus="corpus/attacks",
        run_dir="runs/demo",
        adapter=AdapterConfig(kind="generic", agent="myapp.adapter:build"),
    )
    commands = build_commands(cfg)
    assert commands["corpus_build"] == (
        "detguard corpus build --manifest guardrail/manifest.yaml "
        "--roles guardrail/roles.yaml --out corpus/attacks"
    )
    assert "--guardrail off" in commands["run_off"]
    assert "--guardrail on" in commands["run_on"]
    assert "runs/demo/results-on.json" in commands["report"]
    assert "runs/demo/results-off.json" in commands["report"]
    for cmd in commands.values():
        assert "--adapter generic" in cmd or cmd.startswith("detguard corpus") or cmd.startswith("detguard report")


def test_generate_workflow_rejects_unrunnable_adapter():
    cfg = RunConfig(adapter=AdapterConfig(kind="generic"))
    try:
        generate_workflow(cfg)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "adapter config is not runnable" in str(exc)


def test_generate_workflow_generic_pr_only_parses():
    cfg = RunConfig(adapter=AdapterConfig(kind="generic", agent="myapp.adapter:build"))
    text = generate_workflow(cfg, include_nightly=False)
    doc = yaml.safe_load(text)
    assert set(doc["jobs"]) == {"pr"}
    assert "schedule" not in text


def test_generate_workflow_langgraph_with_nightly_parses_and_has_both_jobs():
    cfg = RunConfig(
        manifest="guardrail/manifest.yaml",
        roles="guardrail/roles.yaml",
        adapter=AdapterConfig(kind="langgraph", graph="myapp.graph:graph", reset="myapp.db:seed"),
    )
    text = generate_workflow(cfg, include_nightly=True)
    doc = yaml.safe_load(text)
    assert set(doc["jobs"]) == {"pr", "nightly"}
    assert "--graph myapp.graph:graph" in text
    assert "--reset myapp.db:seed" in text
    # Every `detguard run` invocation must carry the adapter flags: one in the
    # PR job (guardrail on, PR subset) and two in nightly (on and off).
    assert text.count("--graph myapp.graph:graph") == 3


def test_windows_paths_are_posixified_for_ci():
    """A config assembled on Windows must not emit `config\\manifest.yaml` into
    a workflow that runs on ubuntu-latest — it is a valid local path and a
    broken CI job, failing in the runner long after anyone is watching."""
    cfg = RunConfig(
        manifest="config\\manifest.yaml",
        roles="config\\roles.yaml",
        corpus="corpus\\attacks",
        run_dir="runs\\demo",
        adapter=AdapterConfig(kind="generic", agent="myapp.adapter:build"),
    )
    text = generate_workflow(cfg, include_nightly=False)
    # A trailing `\` is a shell line-continuation and belongs there; a
    # backslash anywhere else is a path separator that will not survive CI.
    assert not [ln for ln in text.splitlines() if "\\" in ln.rstrip().removesuffix("\\")]
    assert "--manifest config/manifest.yaml" in text
    assert "--roles config/roles.yaml" in text
    assert "corpus/attacks" in build_commands(cfg)["corpus_build"]


def test_generate_workflow_uses_manifest_and_roles_paths():
    cfg = RunConfig(
        manifest="config/manifest.yaml",
        roles="config/roles.yaml",
        adapter=AdapterConfig(kind="generic", agent="myapp.adapter:build"),
    )
    text = generate_workflow(cfg, include_nightly=False)
    assert "--manifest config/manifest.yaml" in text
    assert "--roles config/roles.yaml" in text


def test_generated_workflow_installs_detguard_from_somewhere_it_exists():
    """`pip install detguard` resolves to nothing — it is not on PyPI.

    The generator hardcoded it anyway, so every workflow the CI tab produced
    died on the install step before running a single attack. Nothing asserted
    on the install lines, which is why it survived: the YAML parsed, both jobs
    were present, and every other test passed.
    """
    cfg = RunConfig(adapter=AdapterConfig(kind="generic", agent="myapp.adapter:build"))
    text = generate_workflow(cfg)

    assert DETGUARD_REQUIREMENT in text
    install_lines = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("pip install")]
    assert install_lines, "the workflow installs nothing at all"
    # The bare-name form is the bug. Anything carrying a source (a URL, a path,
    # a -r/-e flag) is fine; `pip install detguard` on its own is not.
    assert "pip install detguard" not in install_lines


def test_generated_workflow_installs_client_dependencies_per_config():
    """`pip install -e .` only works if the client's repo is a package.

    Most agent repos are not, and the failure lands in the runner after a green
    checkout. `deps` makes it the caller's choice instead of the generator's
    assumption.
    """
    def installs_in(deps):
        """Only the lines CI will actually execute — commented examples do not count."""
        text = generate_workflow(
            RunConfig(deps=deps, adapter=AdapterConfig(kind="generic", agent="a.b:c")),
            include_nightly=False,
        )
        return [ln.strip() for ln in text.splitlines() if ln.strip().startswith("pip install")]

    assert "pip install -r requirements.txt" in installs_in("requirements.txt")
    assert "pip install -r deps/ci.txt" in installs_in("deps/ci.txt")
    # A non-.txt value is a package root, so the editable install is right here.
    assert "pip install -e ." in installs_in(".")
    # Empty means "we do not know": detguard still gets installed, but nothing
    # is guessed about the client's own deps — the suggestion stays commented.
    blank = installs_in("")
    assert blank == [f"pip install {DETGUARD_REQUIREMENT}"]


def test_generated_workflow_does_not_split_credentials_across_run_modes():
    """A key on the guarded run and not the unguarded one measures the key.

    The template used to set OPENAI_API_KEY on the guarded nightly step only,
    which reads like working config and silently makes the delta meaningless
    for any agent that needs credentials to answer at all.
    """
    cfg = RunConfig(adapter=AdapterConfig(kind="generic", agent="myapp.adapter:build"))
    doc = yaml.safe_load(generate_workflow(cfg))
    for job in doc["jobs"].values():
        step_envs = [s["env"] for s in job["steps"] if isinstance(s, dict) and s.get("env")]
        assert not step_envs, f"credentials belong at job level, found step env: {step_envs}"
