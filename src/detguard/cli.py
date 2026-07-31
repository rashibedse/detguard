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
from pathlib import Path
from typing import Any, Sequence

from . import __version__

EXIT_OK = 0
EXIT_REGRESSION = 1
EXIT_CONFIG = 2


def _new_run_dir() -> Path:
    """Create and return a fresh, never-before-used ``runs/<timestamp>/``.

    The default destination for ``run`` and ``report`` output, so that a
    manifest, two result files, an audit log and a report stop competing for
    the same three filenames in the project root. Colons are excluded from the
    timestamp on purpose — Windows paths cannot contain them, and a directory
    name that only works on POSIX is not a cross-platform default.

    Second-resolution timestamps collide inside a fast loop or a script that
    fires ``run`` twice in a row, and reusing a directory here would mean
    silently overwriting the very thing this default exists to stop
    overwriting — so a numeric suffix is appended until the name is free,
    rather than trusting the clock alone.
    """
    from datetime import datetime, timezone

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    base = Path("runs") / stamp
    candidate = base
    suffix = 1
    while True:
        try:
            candidate.mkdir(parents=True, exist_ok=False)
            return candidate
        except FileExistsError:
            suffix += 1
            candidate = Path(f"{base}-{suffix}")


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

    # Same rule as `run`: an explicit --out is honoured exactly; otherwise the
    # report joins whatever directory --run-dir names, or — absent that — the
    # directory --results already lives in, so `detguard report --results
    # runs/<ts>/results-on.json ...` puts ci_report.* in that same run
    # directory without having to be told to.
    run_dir = Path(args.run_dir) if args.run_dir else Path(args.results).resolve().parent
    out = args.out or str(run_dir / "ci_report.json")
    markdown = args.markdown or str(run_dir / "ci_report.md")

    report = build(results, baseline=recorded, unguarded=unguarded)
    write(report, out)
    Path(markdown).parent.mkdir(parents=True, exist_ok=True)
    with open(markdown, "w", encoding="utf-8") as handle:
        handle.write(to_markdown(report))
    print(to_markdown(report))
    print(f"\nwrote {out}\nwrote {markdown}")
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


def _cmd_scaffold(args: argparse.Namespace) -> int:
    """Generate the adapter, manifest, roles, policy and CI workflow.

    The split matters and is visible in the output: the policy and the workflow
    are *derived* from the role map by rule, and only the adapter and the role
    classification come from a model. Enforcement still runs deterministic
    conditions over a file a human reviewed and committed.
    """
    from . import authoring
    from .scaffold import AdapterConfig, RunConfig, generate_workflow

    try:
        sources = authoring.collect_sources(args.source_dir)
    except authoring.AuthoringError as exc:
        print(f"detguard: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    print(f"read {len(sources)} source file(s) from {args.source_dir}")
    for source in sources:
        print(f"  {source.path}{'  (truncated)' if source.truncated else ''}")

    prompt = authoring.build_prompt(
        sources, entry=args.entry, reset=args.reset or "", agent_name=args.agent_name or ""
    )

    if args.print_prompt:
        print(prompt)
        return EXIT_OK

    api_key = authoring.resolve_api_key(args.api_key or "")
    print(f"\ngenerating with {args.model} — this reads your source, it never runs it")
    try:
        raw = authoring.call_model(
            prompt,
            model=args.model,
            api_key=api_key,
            provider=args.provider or "",
            base_url=args.base_url or "",
        )
    except authoring.AuthoringError as exc:
        print(f"detguard: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except Exception as exc:  # noqa: BLE001 - surface whatever the SDK raised
        print(f"detguard: model call failed: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    try:
        files = authoring.parse_response(raw)
    except authoring.AuthoringError as exc:
        print(f"detguard: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    bundle = authoring.build_bundle(
        files, notes=authoring.extract_notes(raw), model=args.model
    )

    if bundle.notes:
        print("\nthe model flagged:")
        for line in bundle.notes.splitlines():
            if line.strip():
                print(f"  {line.rstrip()}")

    if not bundle.ok:
        print("\ndetguard: generated files did not validate — nothing written:", file=sys.stderr)
        for problem in bundle.problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nRe-run to try again. Validation happens before any write, so a "
            "failed generation never leaves a half-built integration behind.",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    if args.dry_run:
        for name, body in (
            ("detguard_adapter.py", bundle.adapter_code),
            ("manifest.yaml", bundle.manifest_text),
            ("roles.yaml", bundle.roles_text),
        ):
            print(f"\n{'=' * 70}\n{name}\n{'=' * 70}\n{body}")
        print(f"\n{'=' * 70}\npolicy.yaml (derived, not generated)\n{'=' * 70}")
        import yaml as _yaml

        print(_yaml.safe_dump(bundle.policy, sort_keys=False))
        print("dry run — nothing written")
        return EXIT_OK

    try:
        written = authoring.write_bundle(
            bundle,
            config_dir=args.config_dir,
            adapter_path=args.adapter_out,
            overwrite=args.overwrite,
        )
    except authoring.AuthoringError as exc:
        print(f"detguard: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    # Deterministic, and deliberately not part of what the model produced.
    workflow = Path(args.workflow)
    run_config = RunConfig(
        manifest=str(Path(args.config_dir) / "manifest.yaml"),
        roles=str(Path(args.config_dir) / "roles.yaml"),
        policy=str(Path(args.config_dir) / "policy.yaml"),
        adapter=AdapterConfig(
            kind="generic",
            agent=f"{Path(args.adapter_out).stem}:build_adapter",
        ),
    )
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(generate_workflow(run_config), encoding="utf-8")
    written.append(workflow)

    print("\nwrote:")
    for path in written:
        print(f"  {path}")

    gaps = authoring.unfilled(bundle.policy)
    if gaps:
        print("\nstill yours to fill in — each of these is a rule that loads and never fires:")
        for gap in gaps:
            print(f"  {gap}")

    print(
        "\nRead the adapter and roles.yaml before committing. A role classified\n"
        "too loosely is a gate that never fires, and it looks exactly like one\n"
        "that works. Then:\n"
        f"  detguard corpus build --manifest {Path(args.config_dir) / 'manifest.yaml'} "
        f"--roles {Path(args.config_dir) / 'roles.yaml'} --out corpus/attacks"
    )
    return EXIT_OK


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
        "--agent examples.banking_agent.agent:FixtureAgent"
    )


def _resolve_run_output(args: argparse.Namespace, default_name: str) -> tuple[str, "Path | None"]:
    """Where a ``run``/``report`` artifact goes, and which run directory (if any)
    now owns it.

    Three cases, in priority order:

    * ``--out`` given explicitly — used exactly as given, no directory created.
      This is the escape hatch back to the old flat behaviour.
    * ``--run-dir`` given — that directory is created (or reused) and the
      artifact goes inside it under ``default_name``.
    * neither given — a fresh ``runs/<timestamp>/`` is created. This is the
      default now, because ``manifest.yaml``, two ``results*.json``, an audit
      log and a report used to all compete for the project root, and a client
      re-running a corpus would silently overwrite yesterday's evidence.

    Returns ``(path, run_dir)`` — ``run_dir`` is ``None`` in the first case, so
    callers know not to write a ``run.yaml`` next to a path they were not asked
    to organise.
    """
    if args.out:
        return args.out, None
    run_dir = Path(args.run_dir) if getattr(args, "run_dir", None) else _new_run_dir()
    run_dir.mkdir(parents=True, exist_ok=True)
    return str(run_dir / default_name), run_dir


def _cmd_run(args: argparse.Namespace) -> int:
    """Execute a corpus against an agent and write results-<mode>.json."""
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

    out, run_dir = _resolve_run_output(args, f"results-{args.guardrail}.json")

    skipped = load_skipped(args.corpus).get("skipped_templates") or []

    from .audit import from_policy

    audit_log = from_policy(policy_set, override_path=args.audit_log)
    if audit_log is not None and run_dir is not None and not os.path.isabs(audit_log.path):
        # A relative audit path from the policy file (``audit.jsonl`` by
        # default) used to land in whatever the cwd happened to be. It belongs
        # with the results it was recorded alongside.
        audit_log.path = str(run_dir / audit_log.path)

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

    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, sort_keys=True, default=str)

    if run_dir is not None:
        _write_run_manifest(run_dir, args, results, out, audit_log)

    s = results["summary"]
    print(
        f"guardrail={results['guardrail']}  adapter={results['adapter']}  "
        f"policy={policy_set.short_hash}"
    )
    print(
        f"  {s['total']} attacks · {s['succeeded']} breached · {s['blocked']} blocked"
        f" · {s['requires_approval']} held for approval · {s['not_complied']} not complied"
        f" · {s.get('inconclusive', 0)} inconclusive · coverage {s.get('coverage', 1.0):.1%}"
        f" · defense rate {s['defense_rate']:.1%}"
    )
    if s["succeeded"]:
        print("\n  breaches:")
        for r in results["results"]:
            if r["succeeded"]:
                print(f"    {r['id']:28} {r['severity']:8} {r['success_check'].get('reason', '')}")
    print(f"\nwrote {out}")
    if run_dir is not None:
        print(f"run directory: {run_dir}")
    return EXIT_OK


def _write_run_manifest(run_dir: Path, args: argparse.Namespace, results: dict, out: str, audit_log) -> None:
    """Record what produced this run, next to the results it produced.

    ``results.json`` says what happened; nothing previously said *how it was
    invoked* — which corpus, which policy, which adapter flags. Re-deriving
    that from shell history is exactly the kind of thing a client asks for six
    weeks later and nobody can reconstruct.
    """
    import yaml

    s = results.get("summary", {})
    manifest = {
        "generated_at": results.get("generated_at", ""),
        "command": {
            "corpus": args.corpus,
            "policy": args.policy,
            "adapter": args.adapter,
            "guardrail": args.guardrail,
            "graph": getattr(args, "graph", None),
            "tools": getattr(args, "tools", None),
            "reset": getattr(args, "reset", None),
            "state_reader": getattr(args, "state_reader", None),
            "agent": getattr(args, "agent", None),
            "enable_layer": list(getattr(args, "enable_layer", []) or []),
            "id": getattr(args, "id", None),
            "pr_subset": bool(getattr(args, "pr_subset", False)),
        },
        "adapter_name": results.get("adapter", ""),
        "policy_hash": results.get("policy_hash", ""),
        "results_path": out,
        "audit_log_path": audit_log.path if audit_log is not None else None,
        "summary": {
            "total": s.get("total"),
            "succeeded": s.get("succeeded"),
            "defense_rate": s.get("defense_rate"),
            "coverage": s.get("coverage"),
        },
    }
    with open(run_dir / "run.yaml", "a", encoding="utf-8") as handle:
        handle.write("---\n")
        yaml.safe_dump(manifest, handle, sort_keys=False)


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

    # detguard scaffold -----------------------------------------------------
    p_scaffold = sub.add_parser(
        "scaffold",
        help="generate an adapter, manifest, roles, policy and CI workflow from source",
        description=(
            "Read an agent's source and generate the integration files. The "
            "adapter and the role classification come from a model; the policy "
            "is derived from the roles by rule and the CI workflow is "
            "generated deterministically. Everything is validated before it is "
            "written, and everything is a DRAFT for you to review — a role "
            "classified too loosely is a gate that never fires."
        ),
    )
    p_scaffold.add_argument(
        "--source-dir",
        default=".",
        help="directory holding the agent's source (default: the current one)",
    )
    p_scaffold.add_argument(
        "--entry",
        required=True,
        metavar="module:function",
        help="how the agent is invoked, e.g. agent:run_agent",
    )
    p_scaffold.add_argument(
        "--reset",
        default=None,
        metavar="module:function",
        help="the per-attack state reset, if you already know it. Inferred from "
        "source when omitted",
    )
    p_scaffold.add_argument("--agent-name", default=None, help="name recorded in the manifest")
    p_scaffold.add_argument(
        "--model",
        default="claude-sonnet-5",
        help="model that writes the adapter and classifies roles",
    )
    p_scaffold.add_argument(
        "--provider",
        default=None,
        choices=["anthropic", "openai"],
        help="inferred from --model when omitted",
    )
    p_scaffold.add_argument(
        "--base-url",
        default=None,
        help="OpenAI-compatible endpoint, for Groq/Together/a local server",
    )
    p_scaffold.add_argument(
        "--api-key",
        default=None,
        help="default: DETGUARD_API_KEY, then ANTHROPIC_API_KEY / OPENAI_API_KEY",
    )
    p_scaffold.add_argument("--config-dir", default="config", help="where the YAML goes")
    p_scaffold.add_argument(
        "--adapter-out", default="detguard_adapter.py", help="where the adapter goes"
    )
    p_scaffold.add_argument(
        "--workflow",
        default=".github/workflows/detguard-gate.yml",
        help="where the CI workflow goes",
    )
    p_scaffold.add_argument(
        "--dry-run", action="store_true", help="print everything, write nothing"
    )
    p_scaffold.add_argument(
        "--print-prompt",
        action="store_true",
        help="print the prompt and exit without calling a model — no key needed",
    )
    p_scaffold.add_argument(
        "--overwrite", action="store_true", help="replace files that already exist"
    )
    p_scaffold.set_defaults(_handler=_cmd_scaffold)

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
        help="execute an attack corpus against an agent and emit results-<mode>.json",
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
    p_run.add_argument(
        "--out",
        default=None,
        help="results output path; overrides --run-dir and skips run.yaml when given",
    )
    p_run.add_argument(
        "--run-dir",
        default=None,
        metavar="DIR",
        help="directory to write results-<mode>.json and run.yaml into. Default: "
        "a fresh runs/<timestamp>/. Pass the SAME --run-dir to both the "
        "--guardrail off and --guardrail on runs of a pair so `report` and the "
        "dashboard find them together",
    )
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
    p_report.add_argument(
        "--out",
        default=None,
        help="report output path; default ci_report.json inside --run-dir, or "
        "next to --results when --run-dir is not given",
    )
    p_report.add_argument(
        "--markdown",
        default=None,
        help="markdown summary path; default ci_report.md alongside --out "
        "(pass an explicit path to relocate just this one)",
    )
    p_report.add_argument(
        "--run-dir",
        default=None,
        metavar="DIR",
        help="directory --out/--markdown default into. Default: the directory "
        "--results already lives in",
    )
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
