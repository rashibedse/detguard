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

    deps: str = "requirements.txt"
    """How the generated workflow installs the *client's own* dependencies.

    A path ending ``.txt`` becomes ``pip install -r <deps>``; anything else
    becomes ``pip install -e <deps>``, so ``"."`` gives the editable install a
    packaged repo wants. Empty emits a commented placeholder instead of a
    guess.

    It exists because the generator used to hardcode ``pip install -e .``,
    which only works if the client's repo is a distributable package. Most
    agent repos are not, and the failure landed in the CI runner — after a
    green checkout, with a message about a missing pyproject.toml that says
    nothing about detguard.
    """

    def __post_init__(self) -> None:
        """Force POSIX separators on every path.

        These strings end up on a shell command line inside a workflow that
        runs on ``ubuntu-latest``. A config assembled on Windows yields
        ``config\\manifest.yaml`` from ``pathlib``, which is a valid local path
        and a broken CI job — and it breaks in the runner, long after the
        person who generated it has stopped looking. Forward slashes work on
        both, so there is no case for preserving the native separator.
        """
        for name in ("manifest", "roles", "policy", "corpus", "run_dir", "deps"):
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


#: How a generated workflow installs detguard itself.
#:
#: Alpha, and not published to PyPI — ``pip install detguard`` resolves to
#: nothing and the job dies on the install step. One constant, so the day it
#: does ship to PyPI is a one-line change here rather than a hunt through
#: generated YAML in repos nobody is going to regenerate.
DETGUARD_REQUIREMENT = "git+https://github.com/rashibedse/detguard.git@main"


def _deps_install_line(deps: str) -> str:
    """The line installing the client's own dependencies. See ``RunConfig.deps``."""
    deps = (deps or "").strip()
    if not deps:
        return (
            "          # Your agent's own dependencies go here — e.g.\n"
            "          #   pip install -r requirements.txt\n"
            "          #   pip install -e .          # only if this repo is a package\n"
        )
    if deps.endswith(".txt"):
        return f"          pip install -r {deps}\n"
    return f"          pip install -e {deps}\n"


def _install_steps(cfg: RunConfig) -> str:
    return (
        "      - uses: actions/checkout@v4\n\n"
        "      - uses: actions/setup-python@v5\n"
        '        with:\n'
        '          python-version: "3.12"\n\n'
        "      - name: Install\n"
        "        run: |\n"
        "          python -m pip install --upgrade pip\n"
        f"          pip install {DETGUARD_REQUIREMENT}\n"
        f"{_deps_install_line(cfg.deps)}"
    )


#: Commented rather than filled in: the generator cannot know what your agent
#: authenticates with. Job-level on purpose — a key present on the guarded run
#: and absent from the unguarded one yields a delta that measures the missing
#: credential rather than the policy, which is a mistake this template shipped
#: for a while and which reads exactly like a working gate.
_AGENT_CREDENTIALS = (
    "    # Uncomment if your agent needs credentials to run. Keep them at job\n"
    "    # level so every step gets them: an agent that can authenticate for the\n"
    "    # guarded run but not the unguarded one produces a delta that measures\n"
    "    # the missing key, not the policy.\n"
    "    # env:\n"
    "    #   OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n"
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


#: A backslash cannot appear inside an f-string's ``{...}`` expression before
#: Python 3.12 (PEP 701) — this repo supports 3.10+, so the line-continuation
#: literal is built here, outside any f-string, rather than inline as an
#: ``extra=`` argument at the call site.
_PR_SUBSET_EXTRA = "            --pr-subset \\\n"


def _pr_subset_run_step(cfg: RunConfig) -> str:
    return _run_step(
        "Run the PR subset", cfg, guardrail="on", run_dir="runs/pr", extra=_PR_SUBSET_EXTRA
    )


_NIGHTLY_EXTRA = (
    "            --enable-layer llm_judge \\\n"
    "            --audit-log audit.jsonl \\\n"
)


def _nightly_run_step_body(cfg: RunConfig) -> str:
    return _run_step_body(cfg, guardrail="on", run_dir="runs/nightly", extra=_NIGHTLY_EXTRA)


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
        f"{_AGENT_CREDENTIALS}\n"
        "    steps:\n"
        f"{_install_steps(cfg)}\n"
        "      - name: Rebuild corpus from the manifest\n"
        "        run: |\n"
        "          detguard corpus build \\\n"
        f"            --manifest {cfg.manifest} \\\n"
        f"            --roles {cfg.roles} \\\n"
        '            --out "$DETGUARD_CORPUS"\n\n'
        f"{_pr_subset_run_step(cfg)}\n"
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
        "\n  # Non-blocking: full corpus both ways, uploads artifacts.\n"
        "  nightly:\n"
        "    if: github.event_name != 'pull_request'\n"
        "    runs-on: ubuntu-latest\n"
        "    continue-on-error: true\n\n"
        f"{_AGENT_CREDENTIALS}\n"
        "    steps:\n"
        f"{_install_steps(cfg)}\n"
        "      - name: Rebuild corpus\n"
        "        run: |\n"
        "          detguard corpus build \\\n"
        f"            --manifest {cfg.manifest} \\\n"
        f"            --roles {cfg.roles} \\\n"
        '            --out "$DETGUARD_CORPUS"\n\n'
        "      # --enable-layer llm_judge switches on the one rule in the policy\n"
        "      # that is not deterministic. It does nothing until you wire a\n"
        "      # backend: detguard never sets registry.JUDGE_BACKEND, so with\n"
        "      # none configured the rule records 'unavailable - failed open'\n"
        "      # and changes no verdict. Left on so the trace shows it was asked;\n"
        "      # remove it if a permanently inert layer in the log annoys you.\n"
        "      - name: Full corpus, guardrail on\n"
        f"{_nightly_run_step_body(cfg)}\n"
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
