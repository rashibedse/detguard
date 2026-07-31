"""``run``/``report`` output location: one directory per run, by default.

Before this, ``manifest.yaml``, two ``results*.json``, ``ci_report.*`` and
``audit.jsonl`` all competed for the same handful of filenames in whatever
directory the command happened to run from — a second run silently overwrote
the first, and nothing recorded which corpus, policy or adapter flags produced
a given ``results.json`` after the fact.

Three rules, tested below: an explicit ``--out`` is honoured exactly and skips
directory bookkeeping entirely (the escape hatch back to old behaviour);
``--run-dir`` picks the directory; and with neither, a fresh
``runs/<timestamp>/`` is created — never the current working directory.
"""

from __future__ import annotations

import json

import pytest
import yaml

from detguard import cli


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    yield tmp_path


def _write_fixture_corpus(project) -> None:
    """Copy the repo's own fixture corpus in, sidestepping template lookup by
    relative path from whatever cwd the test happens to run in."""
    import shutil
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    example = repo / "examples" / "banking_agent"
    shutil.copy(example / "manifest.yaml", project / "manifest.yaml")
    shutil.copy(example / "roles.yaml", project / "roles.yaml")
    shutil.copy(example / "policy.yaml", project / "policy.yaml")

    rc = cli.main(
        [
            "corpus",
            "build",
            "--manifest",
            "manifest.yaml",
            "--roles",
            "roles.yaml",
            "--out",
            "corpus/attacks",
        ]
    )
    assert rc == cli.EXIT_OK


def _run(*extra: str) -> int:
    return cli.main(
        [
            "run",
            "--corpus",
            "corpus/attacks",
            "--policy",
            "policy.yaml",
            "--agent",
            "examples.banking_agent.agent:FixtureAgent",
            "--guardrail",
            "on",
            *extra,
        ]
    )


# ---------------------------------------------------------------------------
# run: default creates runs/<timestamp>/
# ---------------------------------------------------------------------------


def test_run_with_no_out_or_run_dir_creates_a_fresh_runs_directory(project):
    _write_fixture_corpus(project)

    assert not (project / "runs").exists()
    assert _run() == cli.EXIT_OK

    created = list((project / "runs").iterdir())
    assert len(created) == 1, "exactly one runs/<timestamp>/ directory"
    run_dir = created[0]
    assert (run_dir / "results-on.json").is_file()
    assert (run_dir / "run.yaml").is_file()
    # Nothing was written to the project root.
    assert not (project / "results-on.json").exists()


def test_two_default_runs_get_two_different_directories(project):
    """Never silently overwrite yesterday's results."""
    _write_fixture_corpus(project)
    assert _run() == cli.EXIT_OK
    assert _run() == cli.EXIT_OK
    assert len(list((project / "runs").iterdir())) == 2


def test_explicit_out_skips_run_dir_bookkeeping_entirely(project):
    """The escape hatch: old flat behaviour, unchanged."""
    _write_fixture_corpus(project)

    assert _run("--out", "flat-results.json") == cli.EXIT_OK

    assert (project / "flat-results.json").is_file()
    assert not (project / "runs").exists(), "no runs/ directory for an explicit --out"


def test_explicit_run_dir_is_created_and_reused_by_both_sides_of_a_pair(project):
    _write_fixture_corpus(project)

    assert _run("--guardrail", "off", "--run-dir", "runs/paired") == cli.EXIT_OK
    assert _run("--guardrail", "on", "--run-dir", "runs/paired") == cli.EXIT_OK

    run_dir = project / "runs" / "paired"
    assert (run_dir / "results-off.json").is_file()
    assert (run_dir / "results-on.json").is_file()
    # Both invocations append to the same run.yaml as separate documents.
    docs = list(yaml.safe_load_all((run_dir / "run.yaml").read_text()))
    assert len(docs) == 2
    assert {d["command"]["guardrail"] for d in docs} == {"off", "on"}


def test_run_yaml_records_enough_to_reproduce_the_invocation(project):
    _write_fixture_corpus(project)
    _run("--run-dir", "runs/r", "--enable-layer", "llm_judge")

    doc = next(yaml.safe_load_all((project / "runs" / "r" / "run.yaml").read_text()))
    assert doc["command"]["corpus"] == "corpus/attacks"
    assert doc["command"]["policy"] == "policy.yaml"
    assert doc["command"]["agent"] == "examples.banking_agent.agent:FixtureAgent"
    assert doc["command"]["enable_layer"] == ["llm_judge"]
    assert doc["summary"]["total"] == 36
    assert doc["policy_hash"]


def test_relative_audit_path_resolves_inside_the_run_directory(project):
    _write_fixture_corpus(project)
    _run("--run-dir", "runs/audited", "--audit-log", "audit.jsonl")

    assert (project / "runs" / "audited" / "audit.jsonl").is_file()
    assert not (project / "audit.jsonl").exists()


def test_absolute_audit_path_is_left_alone(project, tmp_path_factory):
    _write_fixture_corpus(project)
    elsewhere = tmp_path_factory.mktemp("elsewhere") / "audit.jsonl"

    _run("--run-dir", "runs/audited", "--audit-log", str(elsewhere))

    assert elsewhere.is_file()
    assert not (project / "runs" / "audited" / "audit.jsonl").exists()


# ---------------------------------------------------------------------------
# report: infers its directory from --results when --run-dir is not given
# ---------------------------------------------------------------------------


def test_report_defaults_beside_the_results_file_it_was_given(project):
    _write_fixture_corpus(project)
    _run("--guardrail", "off", "--run-dir", "runs/paired")
    _run("--guardrail", "on", "--run-dir", "runs/paired")

    rc = cli.main(
        [
            "report",
            "--results",
            "runs/paired/results-on.json",
            "--unguarded",
            "runs/paired/results-off.json",
        ]
    )

    assert rc in (0, 1)  # exit code reflects findings, not a config failure
    run_dir = project / "runs" / "paired"
    assert (run_dir / "ci_report.json").is_file()
    assert (run_dir / "ci_report.md").is_file()


def test_report_explicit_out_is_still_honoured(project):
    _write_fixture_corpus(project)
    _run("--run-dir", "runs/r")

    cli.main(
        [
            "report",
            "--results",
            "runs/r/results-on.json",
            "--out",
            "custom/report.json",
        ]
    )

    assert (project / "custom" / "report.json").is_file()
    # --markdown was not given either, but its default still follows --run-dir
    # (inferred here from --results' parent), not the custom --out location.
    assert (project / "runs" / "r" / "ci_report.md").is_file()


def test_report_markdown_is_always_written_now(project):
    """Previously opt-in; now defaults to a path instead of defaulting to off."""
    _write_fixture_corpus(project)
    _run("--run-dir", "runs/r")

    cli.main(["report", "--results", "runs/r/results-on.json"])

    # encoding is explicit because the report is written as UTF-8 and contains
    # non-ASCII (the warning callouts). Without it this reads as cp1252 on
    # Windows and raises, which is a bug in the reader, not in the report.
    markdown = (project / "runs" / "r" / "ci_report.md").read_text(encoding="utf-8")
    assert markdown.startswith("## detguard")
