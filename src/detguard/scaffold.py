"""Config-authoring helpers for ``dashboard/setup.py``.

Deliberately free of a Streamlit import: the command strings and the CI
workflow text are plain-data transformations, so they can be unit tested
without a Streamlit runtime and reused anywhere a filled-in ``detguard``
invocation is needed. ``setup.py`` is the thin UI layer on top of this module
plus the validators that already exist (``manifest.parse_manifest``,
``manifest.parse_roles``, ``policy.loads``) — no second schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ADAPTER_KINDS = ("generic", "langgraph", "openai_agents")


@dataclass
class AdapterConfig:
    """How to reach the agent under test — one of two shapes.

    Either ``agent`` (a ``module:factory`` string — required for
    ``generic``/``openai_agents``, optional for ``langgraph`` if you wrote your
    own factory), or ``graph`` (+ ``reset``, and optionally ``tools`` /
    ``state_reader``) for the langgraph fast path where detguard builds the
    adapter itself and no factory module is needed at all.
    """

    kind: str = "generic"
    agent: str = ""
    graph: str = ""
    reset: str = ""
    tools: str = ""
    state_reader: str = ""

    def cli_flags(self) -> list[str]:
        flags = ["--adapter", self.kind]
        if self.kind == "langgraph" and self.graph:
            flags += ["--graph", self.graph]
            if self.reset:
                flags += ["--reset", self.reset]
            if self.tools:
                flags += ["--tools", self.tools]
            if self.state_reader:
                flags += ["--state-reader", self.state_reader]
        elif self.agent:
            flags += ["--agent", self.agent]
        return flags

    def problems(self) -> list[str]:
        """Reasons this config could not actually be run, if any."""
        issues = []
        if self.kind not in ADAPTER_KINDS:
            issues.append(f"unknown adapter kind {self.kind!r}")
        using_graph = self.kind == "langgraph" and self.graph
        if using_graph and not self.reset:
            issues.append("--graph needs --reset — without fresh state per attack, "
                           "results leak between attacks")
        if not using_graph and not self.agent:
            issues.append("needs either --agent module:factory, or (langgraph only) "
                           "--graph module:graph plus --reset module:function")
        return issues


@dataclass
class RunConfig:
    manifest: str = "guardrail/manifest.yaml"
    roles: str = "guardrail/roles.yaml"
    policy: str = "guardrail/policy.yaml"
    corpus: str = "corpus/attacks"
    run_dir: str = "runs/demo"
    adapter: AdapterConfig = field(default_factory=AdapterConfig)

    def __post_init__(self) -> None:
        """Force POSIX separators on every path.

        These strings end up on a shell command line inside a workflow that
        runs on ``ubuntu-latest``. A config assembled on Windows yields
        ``config\\manifest.yaml`` from ``pathlib``, which is a valid local path
        and a broken CI job — and it breaks in the runner, long after the
        person who generated it has stopped looking. Forward slashes work on
        both, so there is no case for preserving the native separator.
        """
        for name in ("manifest", "roles", "policy", "corpus", "run_dir"):
            setattr(self, name, str(getattr(self, name)).replace("\\", "/"))


def build_commands(cfg: RunConfig) -> dict[str, str]:
    """The four commands quickstart.md walks through, filled in from ``cfg``.

    Assembled for display only — nothing here executes a command. Running an
    agent's tools is exactly the side effect ``setup.py`` exists to stay away
    from; ``run`` belongs in a terminal or in CI, where its output is
    reviewable before anything downstream trusts it.
    """
    adapter_flags = " ".join(cfg.adapter.cli_flags())
    return {
        "corpus_build": (
            f"detguard corpus build --manifest {cfg.manifest} --roles {cfg.roles} "
            f"--out {cfg.corpus}"
        ),
        "run_off": (
            f"detguard run --corpus {cfg.corpus} --policy {cfg.policy} {adapter_flags} "
            f"--guardrail off --run-dir {cfg.run_dir}"
        ),
        "run_on": (
            f"detguard run --corpus {cfg.corpus} --policy {cfg.policy} {adapter_flags} "
            f"--guardrail on --run-dir {cfg.run_dir}"
        ),
        "report": (
            f"detguard report --results {cfg.run_dir}/results-on.json "
            f"--unguarded {cfg.run_dir}/results-off.json --run-dir {cfg.run_dir}"
        ),
    }


# ---------------------------------------------------------------------------
# CI workflow generation
# ---------------------------------------------------------------------------


def _install_steps() -> str:
    return (
        "      - uses: actions/checkout@v4\n\n"
        "      - uses: actions/setup-python@v5\n"
        '        with:\n'
        '          python-version: "3.12"\n\n'
        "      - name: Install\n"
        "        run: |\n"
        "          python -m pip install --upgrade pip\n"
        "          pip install detguard\n"
        "          pip install -e .\n"
    )


def _run_step_body(cfg: RunConfig, *, guardrail: str, run_dir: str, extra: str = "") -> str:
    flags = cfg.adapter.cli_flags()
    pairs = [f"{flags[i]} {flags[i + 1]}" for i in range(0, len(flags), 2)]
    adapter_lines = "\n".join(f"            {pair} \\" for pair in pairs)
    return (
        f"        run: |\n"
        f"          detguard run \\\n"
        f"            --corpus \"$DETGUARD_CORPUS\" \\\n"
        f"            --policy \"$DETGUARD_POLICY\" \\\n"
        f"{adapter_lines}\n"
        f"            --guardrail {guardrail} \\\n"
        f"{extra}"
        f"            --run-dir {run_dir}\n"
    )


def _run_step(name: str, cfg: RunConfig, *, guardrail: str, run_dir: str, extra: str = "") -> str:
    return f"      - name: {name}\n" + _run_step_body(cfg, guardrail=guardrail, run_dir=run_dir, extra=extra)


def generate_workflow(cfg: RunConfig, include_nightly: bool = True) -> str:
    """A filled-in copy of ``.github/workflows/client-gate-template.yml``.

    Unlike the template — which stays generic and uses shell conditionals so
    it is copy-pasteable for any adapter shape — this fills in one concrete
    adapter configuration, because ``setup.py`` already knows which one you
    picked. Reruns of this function are idempotent for the same ``cfg``.
    """
    problems = cfg.adapter.problems()
    if problems:
        raise ValueError("adapter config is not runnable: " + "; ".join(problems))

    header = (
        "# detguard client gate — generated by dashboard/setup.py from the config\n"
        "# entered in the Manifest/Roles/Policy/Run tabs. Regenerate after changing\n"
        "# any of those rather than hand-editing the env block below.\n\n"
        "name: detguard\n\n"
        "on:\n"
        "  pull_request:\n"
    )
    if include_nightly:
        header += '  schedule:\n    - cron: "0 3 * * *"\n'
    header += "  workflow_dispatch:\n\n"

    header += (
        "env:\n"
        f"  DETGUARD_POLICY: {cfg.policy}\n"
        f"  DETGUARD_CORPUS: {cfg.corpus}\n\n"
    )

    pr_job = (
        "jobs:\n"
        "  # Blocking gate on every pull request: deterministic layers, PR subset.\n"
        "  pr:\n"
        "    if: github.event_name == 'pull_request'\n"
        "    runs-on: ubuntu-latest\n\n"
        "    steps:\n"
        f"{_install_steps()}\n"
        "      - name: Rebuild corpus from the manifest\n"
        "        run: |\n"
        "          detguard corpus build \\\n"
        f"            --manifest {cfg.manifest} \\\n"
        f"            --roles {cfg.roles} \\\n"
        '            --out "$DETGUARD_CORPUS"\n\n'
        f"{_run_step('Run the PR subset', cfg, guardrail='on', run_dir='runs/pr', extra='            --pr-subset \\\n')}\n"
        "      - name: Compare against the baseline\n"
        "        run: |\n"
        "          detguard baseline compare \\\n"
        "            --results runs/pr/results-on.json \\\n"
        "            --baseline corpus/baseline.json\n\n"
        "      - name: Report\n"
        "        if: always()\n"
        "        run: |\n"
        "          detguard report \\\n"
        "            --results runs/pr/results-on.json \\\n"
        "            --baseline corpus/baseline.json \\\n"
        "            --run-dir runs/pr\n"
        '          cat runs/pr/ci_report.md >> "$GITHUB_STEP_SUMMARY"\n\n'
        "      - uses: actions/upload-artifact@v4\n"
        "        if: always()\n"
        "        with:\n"
        "          name: detguard-pr\n"
        "          path: runs/pr/\n"
    )

    if not include_nightly:
        return header + pr_job

    nightly_job = (
        "\n  # Non-blocking: full corpus, llm_judge enabled, uploads artifacts.\n"
        "  nightly:\n"
        "    if: github.event_name != 'pull_request'\n"
        "    runs-on: ubuntu-latest\n"
        "    continue-on-error: true\n\n"
        "    steps:\n"
        f"{_install_steps()}\n"
        "      - name: Rebuild corpus\n"
        "        run: |\n"
        "          detguard corpus build \\\n"
        f"            --manifest {cfg.manifest} \\\n"
        f"            --roles {cfg.roles} \\\n"
        '            --out "$DETGUARD_CORPUS"\n\n'
        "      - name: Full corpus, guardrail on, llm_judge enabled\n"
        "        env:\n"
        "          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n"
        f"{_run_step_body(cfg, guardrail='on', run_dir='runs/nightly', extra='            --enable-layer llm_judge \\\n            --audit-log audit.jsonl \\\n')}\n"
        f"{_run_step('Same corpus, guardrail off', cfg, guardrail='off', run_dir='runs/nightly')}\n"
        "      - name: Report with the guarded/unguarded delta\n"
        "        run: |\n"
        "          detguard report \\\n"
        "            --results runs/nightly/results-on.json \\\n"
        "            --unguarded runs/nightly/results-off.json \\\n"
        "            --baseline corpus/baseline.json \\\n"
        "            --run-dir runs/nightly\n"
        '          cat runs/nightly/ci_report.md >> "$GITHUB_STEP_SUMMARY"\n\n'
        "      - uses: actions/upload-artifact@v4\n"
        "        if: always()\n"
        "        with:\n"
        "          name: detguard-nightly\n"
        "          path: |\n"
        "            runs/nightly/\n"
        "            corpus/attacks/\n"
    )
    return header + pr_job + nightly_job
