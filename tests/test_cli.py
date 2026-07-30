"""CLI wiring: import resolution and adapter construction.

Two failures these lock down, both of which cost a client an onboarding
session before they were fixed:

* the installed ``detguard`` console script could not import the user's own
  project, because pip's wrapper does not put the invocation directory on
  ``sys.path`` the way ``python -m`` does. The symptom was
  "No module named 'agent'" with ``agent/`` sitting right there;
* pointing ``init`` at a LangGraph agent required hand-writing a throwaway
  module whose only job was to call ``LangGraphAdapter(...)``.
"""

from __future__ import annotations

import argparse
import os
import sys

import pytest
import yaml

from detguard import cli


# --------------------------------------------------------------------------
# module:attribute resolution
# --------------------------------------------------------------------------


def test_resolve_import_reads_the_attribute_off_the_module():
    assert cli._resolve_import("detguard.cli:EXIT_OK", "--agent") == cli.EXIT_OK


@pytest.mark.parametrize("spec", ["detguard.cli", "", ":thing", "detguard.cli:"])
def test_resolve_import_rejects_a_spec_that_is_not_module_colon_attribute(spec):
    with pytest.raises(ValueError, match="must be 'module:attribute'"):
        cli._resolve_import(spec, "--graph")


def test_cwd_is_importable_even_when_absent_from_sys_path(tmp_path, monkeypatch):
    """The console-script condition: cwd missing from sys.path.

    ``python -m`` inserts the invocation directory for free, so this only ever
    bites the installed entry point — which is exactly the invocation a client
    uses. Reproduced here by stripping cwd rather than by trusting it is absent.
    """
    (tmp_path / "client_project.py").write_text("VALUE = 'imported from cwd'\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys, "path", [p for p in sys.path if os.path.abspath(p or ".") != str(tmp_path)]
    )
    sys.modules.pop("client_project", None)

    with pytest.raises(ModuleNotFoundError):
        cli._resolve_import("client_project:VALUE", "--agent")

    cli._ensure_cwd_importable()
    assert cli._resolve_import("client_project:VALUE", "--agent") == "imported from cwd"

    sys.modules.pop("client_project", None)


def test_ensure_cwd_importable_does_not_duplicate_an_existing_entry(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "path", [str(tmp_path), "/somewhere/else"])
    cli._ensure_cwd_importable()
    assert sys.path.count(str(tmp_path)) == 1


# --------------------------------------------------------------------------
# init --graph: no user-authored adapter file
# --------------------------------------------------------------------------


class _StubAdapter:
    """Stands in for LangGraphAdapter so these tests need no langgraph install."""

    def __init__(self, graph, reset_hook=None, agent_name="langgraph-agent"):
        self.graph = graph
        self.reset_hook = reset_hook
        self.agent_name = agent_name

    def introspect(self) -> dict:
        return {
            "agent": self.agent_name,
            "framework": "langgraph",
            "tools": [{"name": "send_money", "description": "", "params": {}}],
        }


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A client project laid out the way a real one is: graph here, reset there."""
    (tmp_path / "agent").mkdir()
    (tmp_path / "agent" / "__init__.py").write_text("")
    (tmp_path / "agent" / "graph.py").write_text("graph = 'compiled-graph'\n")
    (tmp_path / "db").mkdir()
    (tmp_path / "db" / "__init__.py").write_text("")
    (tmp_path / "db" / "seed.py").write_text("CALLED = []\ndef seed():\n    CALLED.append(1)\n")
    monkeypatch.chdir(tmp_path)
    cli._ensure_cwd_importable()
    for name in ("agent", "agent.graph", "db", "db.seed"):
        sys.modules.pop(name, None)
    yield tmp_path
    for name in ("agent", "agent.graph", "db", "db.seed"):
        sys.modules.pop(name, None)


def _init_args(**overrides) -> argparse.Namespace:
    args = dict(
        framework="langgraph",
        out="manifest.yaml",
        agent=None,
        graph=None,
        reset=None,
        agent_name=None,
    )
    args.update(overrides)
    return argparse.Namespace(**args)


def test_init_builds_the_adapter_from_graph_and_reset(project, monkeypatch, capsys):
    monkeypatch.setattr(
        "detguard.adapters.langgraph.LangGraphAdapter", _StubAdapter, raising=True
    )

    rc = cli._cmd_init(
        _init_args(
            graph="agent.graph:graph",
            reset="db.seed:seed",
            agent_name="email-assistant",
        )
    )

    assert rc == cli.EXIT_OK
    manifest = yaml.safe_load((project / "manifest.yaml").read_text())
    assert manifest["agent"] == "email-assistant"
    assert manifest["framework"] == "langgraph"
    assert [t["name"] for t in manifest["tools"]] == ["send_money"]
    assert "wrote 1 tool(s)" in capsys.readouterr().out


def test_init_graph_passes_the_reset_hook_through_to_the_adapter(project, monkeypatch):
    built = {}

    def _capture(graph, reset_hook=None, agent_name="langgraph-agent"):
        built.update(graph=graph, reset_hook=reset_hook, agent_name=agent_name)
        return _StubAdapter(graph, reset_hook, agent_name)

    monkeypatch.setattr("detguard.adapters.langgraph.LangGraphAdapter", _capture)
    cli._cmd_init(_init_args(graph="agent.graph:graph", reset="db.seed:seed"))

    import db.seed

    assert built["graph"] == "compiled-graph"
    built["reset_hook"]()
    assert db.seed.CALLED == [1], "the resolved reset hook must be the client's own"


def test_init_graph_without_reset_is_allowed_because_introspection_is_read_only(
    project, monkeypatch
):
    monkeypatch.setattr("detguard.adapters.langgraph.LangGraphAdapter", _StubAdapter)
    assert cli._cmd_init(_init_args(graph="agent.graph:graph")) == cli.EXIT_OK


@pytest.mark.parametrize(
    "overrides, expected",
    [
        (dict(graph="agent.graph:graph", agent="a:b"), "not both"),
        (dict(graph="agent.graph:graph", framework="generic"), "langgraph-specific"),
        (dict(agent="a:b", reset="db.seed:seed"), "only applies alongside --graph"),
        (dict(graph="agent.graph"), "must be 'module:attribute'"),
        (dict(graph="no_such_module:graph"), "could not build"),
    ],
)
def test_init_rejects_incoherent_flag_combinations(project, overrides, expected, capsys):
    assert cli._cmd_init(_init_args(**overrides)) == cli.EXIT_CONFIG
    assert expected in capsys.readouterr().err


def test_init_agent_factory_remains_the_fallback(project, capsys):
    """--agent must keep working, for custom input_key / inject / tools."""
    (project / "custom.py").write_text(
        "class A:\n"
        "    def introspect(self):\n"
        "        return {'agent': 'hand-built', 'tools': []}\n"
        "def make():\n"
        "    return A()\n"
    )
    sys.modules.pop("custom", None)

    rc = cli._cmd_init(_init_args(agent="custom:make"))

    assert rc == cli.EXIT_OK
    manifest = yaml.safe_load((project / "manifest.yaml").read_text())
    assert manifest["agent"] == "hand-built"
    # framework is filled in from the flag, not guessed
    assert manifest["framework"] == "langgraph"
    assert "no tools discovered" in capsys.readouterr().err
    sys.modules.pop("custom", None)


def test_init_without_agent_or_graph_still_writes_a_skeleton(project, capsys):
    assert cli._cmd_init(_init_args(framework="generic")) == cli.EXIT_OK
    text = (project / "manifest.yaml").read_text()
    assert text.startswith("# detguard could not introspect")
    assert yaml.safe_load(text)["framework"] == "generic"


# --------------------------------------------------------------------------
# run: the same flags reach _load_adapter
# --------------------------------------------------------------------------


def _run_args(**overrides) -> argparse.Namespace:
    args = dict(adapter="langgraph", agent=None, graph=None, reset=None, agent_name=None)
    args.update(overrides)
    return argparse.Namespace(**args)


def test_load_adapter_builds_a_langgraph_adapter_from_flags(project, monkeypatch):
    monkeypatch.setattr("detguard.adapters.langgraph.LangGraphAdapter", _StubAdapter)
    adapter = cli._load_adapter(
        _run_args(graph="agent.graph:graph", reset="db.seed:seed", agent_name="email")
    )
    assert adapter.agent_name == "email"
    assert adapter.reset_hook is not None


def test_load_adapter_requires_reset_for_run_not_just_at_first_attack(project):
    """A missing hook must fail before the run, not 30 attacks into it."""
    with pytest.raises(ValueError, match="--graph needs --reset"):
        cli._load_adapter(_run_args(graph="agent.graph:graph"))


@pytest.mark.parametrize(
    "overrides, expected",
    [
        (dict(graph="agent.graph:graph", agent="a:b"), "not both"),
        (
            dict(adapter="generic", graph="agent.graph:graph", reset="db.seed:seed"),
            "langgraph-specific",
        ),
        (dict(), "needs either --graph"),
        (dict(adapter="generic"), "needs --agent module:factory"),
        (dict(adapter="openai_agents"), "needs --agent module:factory"),
    ],
)
def test_load_adapter_rejects_incoherent_flag_combinations(project, overrides, expected):
    with pytest.raises(ValueError, match=expected):
        cli._load_adapter(_run_args(**overrides))


def test_load_adapter_agent_factory_remains_the_fallback(project):
    (project / "custom_run.py").write_text("def make():\n    return 'the-adapter'\n")
    sys.modules.pop("custom_run", None)
    assert cli._load_adapter(_run_args(agent="custom_run:make")) == "the-adapter"
    sys.modules.pop("custom_run", None)


# --------------------------------------------------------------------------
# main() wiring
# --------------------------------------------------------------------------


def test_main_makes_cwd_importable_before_dispatching(tmp_path, monkeypatch):
    """The fix has to land in main(), so every subcommand inherits it."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys, "path", [p for p in sys.path if os.path.abspath(p or ".") != str(tmp_path)]
    )
    seen: dict = {}

    def _handler(args):
        seen["cwd_on_path"] = str(tmp_path) in sys.path
        return cli.EXIT_OK

    parser = cli.build_parser()
    monkeypatch.setattr(cli, "build_parser", lambda: parser)
    monkeypatch.setattr(
        parser, "parse_args", lambda argv: argparse.Namespace(_handler=_handler)
    )

    assert cli.main([]) == cli.EXIT_OK
    assert seen["cwd_on_path"] is True


def test_package_is_runnable_as_python_dash_m_detguard():
    """``python -m detguard`` must work, not just ``python -m detguard.cli``.

    A user who cannot get the console script working reaches for ``-m`` next,
    and ``-m detguard`` is the form they try first. Without __main__.py it
    fails with "No module named detguard.__main__", which reads like a broken
    install rather than a wrong incantation.
    """
    import importlib.util

    assert importlib.util.find_spec("detguard.__main__") is not None

    import detguard.__main__ as entry

    assert entry.main is cli.main


def test_dash_m_invocation_reports_the_right_program_name():
    """argparse must not leak '__main__.py' into usage text."""
    assert cli.build_parser().prog == "detguard"


def test_init_parser_accepts_the_langgraph_shortcut():
    args = cli.build_parser().parse_args(
        [
            "init",
            "--framework",
            "langgraph",
            "--graph",
            "agent.graph:graph",
            "--reset",
            "db.seed:seed",
            "--agent-name",
            "email-assistant",
        ]
    )
    assert (args.graph, args.reset, args.agent_name) == (
        "agent.graph:graph",
        "db.seed:seed",
        "email-assistant",
    )


def test_run_parser_accepts_the_langgraph_shortcut():
    args = cli.build_parser().parse_args(
        [
            "run",
            "--corpus",
            "c",
            "--policy",
            "p",
            "--adapter",
            "langgraph",
            "--graph",
            "agent.graph:graph",
            "--reset",
            "db.seed:seed",
        ]
    )
    assert (args.graph, args.reset) == ("agent.graph:graph", "db.seed:seed")
