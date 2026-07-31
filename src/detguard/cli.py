"""The ``detguard`` command.

The full subcommand surface is registered here from build step 1 so that
``detguard --help`` describes the real target rather than a moving one.
Handlers whose module does not exist yet exit 2 with an explicit
"not implemented" message — they never report success.

Exit codes (spec §13):
    0  pass
    1  regression / findings
    2  config error, or not-yet-implemented command
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Sequence

from . import __version__

EXIT_OK = 0
EXIT_REGRESSION = 1
EXIT_CONFIG = 2


def _ensure_utf8_output() -> None:
    """Make stdout/stderr able to carry non-ASCII.

    Windows consoles default to a legacy codepage (cp1252 here), and writing a
    character outside it raises ``UnicodeEncodeError`` mid-print — so a report
    containing an em-dash, a warning glyph, or simply a tool description in a
    non-Latin script would crash the command rather than print. Reports are
    client-facing artifacts; they cannot depend on the operator's codepage.

    ``errors="replace"`` is the backstop: if the stream cannot be reconfigured,
    losing a glyph is acceptable, but losing the report is not.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # pragma: no cover - stream already detached
            pass


def _ensure_cwd_importable() -> None:
    """Put the invocation directory on ``sys.path``.

    ``python -m detguard.cli`` does this for free; the installed console script
    does not, because pip's wrapper is an ordinary script living in ``bin/``.
    Without this, ``--agent agent.detguard_adapter:make_adapter`` fails with
    "No module named 'agent'" while ``agent/`` sits right there in the
    directory the user is standing in — and the only workaround is telling
    people to type ``python -m detguard.cli`` instead, which is not an answer.
    """
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)


def _resolve_import(spec: str, flag: str) -> Any:
    """Resolve a ``module:attribute`` string to the attribute itself."""
    import importlib

    module_name, _, attr = spec.partition(":")
    if not module_name or not attr:
        raise ValueError(f"{flag} must be 'module:attribute', got {spec!r}")
    return getattr(importlib.import_module(module_name), attr)


def _pending(command: str, step: int) -> int:
    """Placeholder handler for a command whose module lands in a later step."""
    print(
        f"detguard: `{command}` is not implemented yet (arrives in build step {step}).",
        file=sys.stderr,
    )
    return EXIT_CONFIG


# --------------------------------------------------------------------------
# handlers
# --------------------------------------------------------------------------


def _cmd_corpus_build(args: argparse.Namespace) -> int:
    """Instantiate the shipped templates against a manifest and role map."""
    from .instantiate import build
    from .manifest import ManifestError

    try:
        result = build(
            manifest_path=args.manifest,
            roles_path=args.roles,
            out_dir=args.out,
            template_dir=args.templates,
        )
    except (ManifestError, ValueError) as exc:
        print(f"detguard: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)

    print(f"wrote {len(result.attacks)} concrete attack(s) to {args.out}")

    # Skipped templates are coverage information, not noise. They are printed
    # every time, because "not applicable to this agent" is a claim the client
    # should see rather than a row that quietly vanished.
    if result.skipped:
        print(f"\nskipped {len(result.skipped)} template(s) — not applicable to this agent:")
        for entry in result.skipped:
            print(f"  {entry['id']}: {entry['reason']}")
    if result.skipped_mutations:
        print(f"\nskipped {len(result.skipped_mutations)} mutation variant(s):")
        for entry in result.skipped_mutations:
            print(f"  {entry['id']} / {entry['mutation']}: {entry['reason']}")
    return EXIT_OK


def _read_json(path: str) -> dict:
    import json

    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _cmd_baseline_snapshot(args: argparse.Namespace) -> int:
    from .baseline import snapshot, write

    try:
        results = _read_json(args.results)
    except (OSError, ValueError) as exc:
        print(f"detguard: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    path = write(snapshot(results), args.out)
    print(f"wrote {path} ({len(results.get('results', []))} case(s))")
    return EXIT_OK


def _cmd_baseline_compare(args: argparse.Namespace) -> int:
    from .baseline import BaselineError, compare, load

    try:
        results = _read_json(args.results)
        recorded = load(args.baseline)
    except (OSError, ValueError, BaselineError) as exc:
        print(f"detguard: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    outcome = compare(results, recorded)
    for kind, count in outcome["counts"].items():
        print(f"  {kind:16} {count}")
    for finding in outcome["findings"]:
        if finding["fails"]:
            print(f"FAIL  {finding['kind']}  {finding['id']}: {finding['detail']}", file=sys.stderr)
    print("\npassed" if outcome["passed"] else "\nREGRESSION")
    return outcome["exit_code"]


def _cmd_report(args: argparse.Namespace) -> int:
    from .baseline import BaselineError
    from .baseline import load as load_baseline
    from .report import build, to_markdown, write

    try:
        results = _read_json(args.results)
        recorded = load_baseline(args.baseline) if args.baseline else None
        unguarded = _read_json(args.unguarded) if args.unguarded else None
    except (OSError, ValueError, BaselineError) as exc:
        print(f"detguard: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    report = build(results, baseline=recorded, unguarded=unguarded)
    write(report, args.out)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as handle:
            handle.write(to_markdown(report))
    print(to_markdown(report))
    return report["exit_code"]


def _build_langgraph_adapter(args: argparse.Namespace):
    """Construct a ``LangGraphAdapter`` from ``--graph`` / ``--reset``.

    This is the boilerplate that every LangGraph user used to hand-write into a
    throwaway ``detguard_adapter.py`` — import the graph, import the reset
    function, instantiate the adapter — so the CLI does it instead. Anyone who
    needs a non-default ``input_key``, a custom ``inject``, or an explicit
    ``tools`` list still writes a factory and passes ``--agent``.
    """
    from .adapters.langgraph import LangGraphAdapter

    graph = _resolve_import(args.graph, "--graph")
    reset_hook = _resolve_import(args.reset, "--reset") if args.reset else None

    kwargs: dict = {"graph": graph, "reset_hook": reset_hook}
    if getattr(args, "agent_name", None):
        kwargs["agent_name"] = args.agent_name
    if getattr(args, "tools", None):
        kwargs["tools"] = _resolve_tools(args.tools)
    if getattr(args, "state_reader", None):
        kwargs["state_reader"] = _resolve_import(args.state_reader, "--state-reader")
    return LangGraphAdapter(**kwargs)


def _resolve_tools(spec: str) -> list:
    """Resolve ``--tools`` to a list, accepting a list/tuple or a name->tool dict.

    Both shapes are common in real projects (``ALL_TOOLS`` and ``TOOLS_BY_NAME``),
    and making the user care which one they happened to write is exactly the kind
    of friction this flag exists to remove.
    """
    resolved = _resolve_import(spec, "--tools")
    if isinstance(resolved, dict):
        return list(resolved.values())
    if isinstance(resolved, (list, tuple)):
        return list(resolved)
    raise ValueError(
        f"--tools must name a list or a dict of tools, got {type(resolved).__name__} "
        f"from {spec!r}"
    )


def _cmd_init(args: argparse.Namespace) -> int:
    """Draft manifest.yaml by introspecting a live adapter — pure metadata,
    no side effects.

    ``introspect()`` never calls ``.invoke()`` and never touches
    ``reset_hook``; it only reads tool names and argument schemas off
    whatever the factory returns. If your factory needs a live DB
    connection or API key just to construct the adapter, that is a design
    issue in the factory/adapter, not something this command works around.
    """
    import yaml

    if args.graph and args.agent:
        print(
            "detguard: pass either --graph (the CLI builds the adapter) or "
            "--agent module:factory (you build it), not both",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    if args.graph and args.framework != "langgraph":
        print(
            f"detguard: --graph is langgraph-specific; got --framework {args.framework}",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    for flag in ("reset", "tools", "state_reader"):
        if getattr(args, flag, None) and not args.graph:
            name = "--" + flag.replace("_", "-")
            print(f"detguard: {name} only applies alongside --graph", file=sys.stderr)
            return EXIT_CONFIG

    if args.graph:
        try:
            adapter = _build_langgraph_adapter(args)
        except Exception as exc:  # noqa: BLE001 - surface whatever the import raised
            print(f"detguard: could not build a LangGraphAdapter: {exc}", file=sys.stderr)
            return EXIT_CONFIG
        return _write_manifest(adapter, args)

    if not args.agent:
        skeleton = {
            "agent": "your-agent",
            "framework": args.framework,
            "principal": "the account holder",
            "tools": [],
            "untrusted_sources": [],
            "state_paths": {},
        }
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(
                "# detguard could not introspect your agent: no --agent "
                "module:factory was given.\n"
                "# Fill this skeleton in by hand, or rerun with "
                "--agent module:factory_function.\n"
            )
            yaml.safe_dump(skeleton, handle, sort_keys=False)
        print(f"detguard: no --agent given; wrote a commented skeleton to {args.out}")
        return EXIT_OK

    try:
        factory = _resolve_import(args.agent, "--agent")
        adapter = factory()
    except ValueError as exc:
        print(f"detguard: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except Exception as exc:  # noqa: BLE001 - surface whatever the factory raised
        print(f"detguard: could not construct adapter from {args.agent!r}: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    if not hasattr(adapter, "introspect"):
        print(f"detguard: adapter from {args.agent!r} has no introspect() method", file=sys.stderr)
        return EXIT_CONFIG

    return _write_manifest(adapter, args)


def _write_manifest(adapter, args: argparse.Namespace) -> int:
    """Introspect an adapter and write the drafted manifest to ``--out``.

    A manifest with no tools is not a draft — ``parse_manifest`` rejects it
    ("'tools' must be a non-empty list"), so every downstream command fails or
    skips everything. Discovering nothing is therefore a config error and exits
    2; it used to warn and exit 0, which left the user holding a broken file and
    reading it as their own fault.
    """
    import yaml

    manifest = adapter.introspect()
    manifest.setdefault("framework", args.framework)

    if not manifest.get("tools"):
        _report_no_tools(args)
        return EXIT_CONFIG

    with open(args.out, "w", encoding="utf-8") as handle:
        yaml.safe_dump(manifest, handle, sort_keys=False)

    tools = manifest["tools"]
    print(f"wrote {len(tools)} tool(s) to {args.out}")
    for tool in tools:
        origin = tool.get("discovered_from")
        print(f"  {tool['name']:24} {'from ' + origin if origin else ''}")

    # Where a tool came from is part of the claim this manifest makes. A guess
    # that nobody can see is a guess nobody can correct.
    if any(str(t.get("discovered_from", "")).startswith("module_global") for t in tools):
        # stdout is block-buffered when piped while stderr is not, so without
        # this the caveat appears above the list it refers to.
        sys.stdout.flush()
        print(
            "\nnote: some tools were found by scanning a graph node's module for a "
            "tool list. That is a heuristic — check the names above, and pass "
            "--tools module:LIST to state them explicitly if it guessed wrong.",
            file=sys.stderr,
        )
    return EXIT_OK


def _report_no_tools(args: argparse.Namespace) -> None:
    """Say what was tried, and the exact flag that fixes it."""
    print("detguard: no tools discovered — cannot draft a manifest.", file=sys.stderr)

    if args.graph:
        from .adapters.langgraph import DISCOVERY_STRATEGIES

        print("\nTried, in order:", file=sys.stderr)
        for strategy in DISCOVERY_STRATEGIES:
            print(f"  - {strategy}", file=sys.stderr)
        print(
            "\nIf your tools live somewhere else, name them directly:\n"
            "  --tools mypackage.tools:ALL_TOOLS\n"
            "It accepts a list of tools or a dict of name -> tool.",
            file=sys.stderr,
        )
    else:
        print(
            f"\nThe adapter from {args.agent!r} returned no tools. Check that its "
            "factory wraps a real tool registry — for LangGraph you can skip the "
            "factory entirely with --graph module:graph.",
            file=sys.stderr,
        )


def _load_adapter(args: argparse.Namespace):
    """Resolve --adapter / --graph / --agent into a live BaseAdapter."""
    if args.graph and args.agent:
        raise ValueError(
            "pass either --graph (the CLI builds the adapter) or --agent "
            "module:factory (you build it), not both"
        )

    if args.graph:
        if args.adapter != "langgraph":
            raise ValueError(
                f"--graph is langgraph-specific; got --adapter {args.adapter}"
            )
        if not args.reset:
            # Checked here rather than at the first attack: LangGraphAdapter.reset
            # raises without a hook, and discovering that mid-run wastes the run.
            raise ValueError(
                "--graph needs --reset module:function — without fresh state per "
                "attack, results leak between cases and the run cannot be trusted"
            )
        return _build_langgraph_adapter(args)

    if args.agent:
        return _resolve_import(args.agent, "--agent")()

    if args.adapter == "langgraph":
        raise ValueError(
            "--adapter langgraph needs either --graph module:graph --reset "
            "module:function, or --agent module:factory returning a configured "
            "LangGraphAdapter"
        )
    if args.adapter == "openai_agents":
        raise ValueError(
            "--adapter openai_agents needs --agent module:factory returning a "
            "configured OpenAIAgentsAdapter"
        )
    raise ValueError(
        "--adapter generic needs --agent module:factory, e.g. "
        "--agent tests.fixture_agent:FixtureAgent"
    )


def _cmd_run(args: argparse.Namespace) -> int:
    """Execute a corpus against an agent and write results.json."""
    import json

    from .instantiate import load_corpus, load_skipped
    from .policy import PolicyError, load
    from .runner import RunnerError, filter_attacks, run

    try:
        policy_set = load(args.policy, enable_layers=args.enable_layer)
        attacks = filter_attacks(
            load_corpus(args.corpus), attack_id=args.id, pr_subset=args.pr_subset
        )
        adapter = _load_adapter(args)
    except (PolicyError, RunnerError, ValueError, ImportError, AttributeError) as exc:
        print(f"detguard: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    if not attacks:
        print("detguard: no attacks selected", file=sys.stderr)
        return EXIT_CONFIG

    skipped = load_skipped(args.corpus).get("skipped_templates") or []

    from .audit import from_policy

    audit_log = from_policy(policy_set, override_path=args.audit_log)

    try:
        results = run(
            attacks,
            adapter,
            policy_set,
            mode=args.guardrail,
            skipped_templates=skipped,
            audit_log=audit_log,
        )
    except RunnerError as exc:
        # Infrastructure failure is not a clean sweep. It must be loud.
        print(f"detguard: runner error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, sort_keys=True, default=str)

    s = results["summary"]
    print(
        f"guardrail={results['guardrail']}  adapter={results['adapter']}  "
        f"policy={policy_set.short_hash}"
    )
    print(
        f"  {s['total']} attacks · {s['succeeded']} breached · {s['blocked']} blocked"
        f" · {s['requires_approval']} held for approval · {s['not_complied']} not complied"
        f" · defense rate {s['defense_rate']:.1%}"
    )
    if s["succeeded"]:
        print("\n  breaches:")
        for r in results["results"]:
            if r["succeeded"]:
                print(f"    {r['id']:28} {r['severity']:8} {r['success_check'].get('reason', '')}")
    print(f"\nwrote {args.out}")
    return EXIT_OK


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detguard",
        description=(
            "Policy-as-code enforcement for AI agent tool calls, plus an "
            "adversarial regression suite that proves the policy still works "
            "after every change."
        ),
        epilog="Enforcement is deterministic: no LLM sits in the enforcement path.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"detguard {__version__}",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # detguard init ---------------------------------------------------------
    p_init = sub.add_parser(
        "init",
        help="draft a tool manifest by introspecting an agent framework",
        description=(
            "Introspect a framework's tool registry and write manifest.yaml. "
            "If the framework cannot be introspected, a commented skeleton is "
            "emitted for hand-filling."
        ),
    )
    p_init.add_argument(
        "--framework",
        required=True,
        choices=["langgraph", "openai_agents", "generic"],
        help="which adapter performs the introspection",
    )
    p_init.add_argument("--out", default="manifest.yaml", help="output path")
    p_init.add_argument(
        "--agent",
        default=None,
        metavar="module:factory",
        help="import path to a zero-arg callable returning a BaseAdapter; "
        "omit to emit a hand-fillable skeleton instead",
    )
    p_init.add_argument(
        "--graph",
        default=None,
        metavar="module:graph",
        help="langgraph only: import path to a compiled graph. detguard builds "
        "the LangGraphAdapter for you, so no adapter file is needed",
    )
    p_init.add_argument(
        "--reset",
        default=None,
        metavar="module:function",
        help="langgraph only: import path to the per-attack state reset hook",
    )
    p_init.add_argument(
        "--tools",
        default=None,
        metavar="module:LIST",
        help="langgraph only: import path to a list or name->tool dict. Only "
        "needed when automatic discovery guesses wrong or finds nothing",
    )
    p_init.add_argument(
        "--state-reader",
        default=None,
        metavar="module:function",
        help="langgraph only: fn(path) -> value, for success checks that read "
        "post-attack state",
    )
    p_init.add_argument(
        "--agent-name",
        default=None,
        metavar="NAME",
        help="name recorded in the manifest (default: the adapter's own)",
    )
    p_init.set_defaults(_handler=_cmd_init)

    # detguard corpus ------------------------------------------------------
    p_corpus = sub.add_parser(
        "corpus",
        help="build a concrete attack corpus from templates + manifest",
    )
    corpus_sub = p_corpus.add_subparsers(dest="corpus_command", metavar="<subcommand>")
    p_corpus_build = corpus_sub.add_parser(
        "build",
        help="instantiate shipped templates against a manifest and role map",
        description=(
            "For every shipped template, resolve its required roles against "
            "roles.yaml, bind placeholders to the manifest's tools, and emit "
            "concrete attacks. Templates whose roles are unmet are skipped and "
            "REPORTED — never silently dropped."
        ),
    )
    p_corpus_build.add_argument("--manifest", required=True, help="path to manifest.yaml")
    p_corpus_build.add_argument("--roles", required=True, help="path to roles.yaml")
    p_corpus_build.add_argument(
        "--out",
        default="corpus/attacks",
        help="directory to write concrete attack YAML into",
    )
    p_corpus_build.add_argument(
        "--templates",
        default=None,
        help="template directory (defaults to the shipped corpus)",
    )
    p_corpus_build.set_defaults(_handler=_cmd_corpus_build)
    p_corpus.set_defaults(_handler=lambda args: _pending("corpus", 4))

    # detguard run ---------------------------------------------------------
    p_run = sub.add_parser(
        "run",
        help="execute an attack corpus against an agent and emit results.json",
    )
    p_run.add_argument("--corpus", required=True, help="directory of concrete attacks")
    p_run.add_argument("--policy", required=True, help="path to policy.yaml")
    p_run.add_argument(
        "--adapter",
        default="generic",
        choices=["generic", "langgraph", "openai_agents"],
        help="which adapter drives the agent",
    )
    p_run.add_argument(
        "--guardrail",
        default="on",
        choices=["on", "off"],
        help="enforcement on, or off for the unguarded comparison run",
    )
    p_run.add_argument("--id", default=None, help="run a single attack by id")
    p_run.add_argument(
        "--pr-subset",
        action="store_true",
        help="only attacks whose template is flagged pr_subset (the blocking gate)",
    )
    p_run.add_argument(
        "--enable-layer",
        action="append",
        default=[],
        metavar="LAYER",
        help="enable a layer that ships disabled, e.g. --enable-layer llm_judge",
    )
    p_run.add_argument("--out", default="results.json", help="results output path")
    p_run.add_argument(
        "--agent",
        default=None,
        metavar="module:factory",
        help="import path to a zero-arg callable returning a BaseAdapter "
        "(required for --adapter generic)",
    )
    p_run.add_argument(
        "--graph",
        default=None,
        metavar="module:graph",
        help="--adapter langgraph only: import path to a compiled graph, built "
        "into a LangGraphAdapter here instead of in a factory of your own",
    )
    p_run.add_argument(
        "--reset",
        default=None,
        metavar="module:function",
        help="--adapter langgraph only: per-attack state reset hook, required "
        "with --graph",
    )
    p_run.add_argument(
        "--tools",
        default=None,
        metavar="module:LIST",
        help="--adapter langgraph only: import path to a list or name->tool dict, "
        "when automatic discovery needs overriding",
    )
    p_run.add_argument(
        "--state-reader",
        default=None,
        metavar="module:function",
        help="--adapter langgraph only: fn(path) -> value. Without it, state-based "
        "success checks cannot be evaluated and are reported as such",
    )
    p_run.add_argument(
        "--agent-name",
        default=None,
        metavar="NAME",
        help="name recorded for the adapter (default: the adapter's own)",
    )
    p_run.add_argument(
        "--audit-log",
        default=None,
        metavar="PATH",
        help="append every decision to this JSONL file (switches auditing on)",
    )
    p_run.set_defaults(_handler=_cmd_run)

    # detguard baseline ----------------------------------------------------
    p_baseline = sub.add_parser(
        "baseline",
        help="snapshot a known-good result set, or compare against one",
    )
    baseline_sub = p_baseline.add_subparsers(
        dest="baseline_command", metavar="<subcommand>"
    )
    p_snap = baseline_sub.add_parser("snapshot", help="write baseline.json from results")
    p_snap.add_argument("--results", required=True, help="path to results.json")
    p_snap.add_argument("--out", default="baseline.json", help="baseline output path")
    p_snap.set_defaults(_handler=_cmd_baseline_snapshot)
    p_cmp = baseline_sub.add_parser("compare", help="compare results against a baseline")
    p_cmp.add_argument("--results", required=True, help="path to results.json")
    p_cmp.add_argument("--baseline", required=True, help="path to baseline.json")
    p_cmp.set_defaults(_handler=_cmd_baseline_compare)
    p_baseline.set_defaults(_handler=lambda args: _pending("baseline", 10))

    # detguard report ------------------------------------------------------
    p_report = sub.add_parser(
        "report",
        help="turn results.json into a CI report",
    )
    p_report.add_argument("--results", required=True, help="path to results.json")
    p_report.add_argument("--baseline", default=None, help="optional baseline.json")
    p_report.add_argument(
        "--unguarded",
        default=None,
        help="optional results.json from a --guardrail off run, for the delta",
    )
    p_report.add_argument("--out", default="ci_report.json", help="report output path")
    p_report.add_argument("--markdown", default=None, help="also write a markdown summary")
    p_report.set_defaults(_handler=_cmd_report)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    _ensure_utf8_output()

    # Before any `module:attribute` string is resolved: the installed console
    # script and `python -m detguard.cli` must import the user's project the
    # same way. See _ensure_cwd_importable.
    _ensure_cwd_importable()

    handler = getattr(args, "_handler", None)
    if handler is None:
        parser.print_help()
        return EXIT_CONFIG
    return handler(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
