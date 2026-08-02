# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

DetGuard is a policy-as-code enforcement engine for AI agent tool calls, plus an
adversarial regression corpus that proves a policy still works after every change.
It checks the **tool call itself** — concrete arguments, deterministic conditions —
rather than filtering input/output text like most guardrail products. Alpha, not
published to PyPI; install from source or `git+https://github.com/rashibedse/detguard.git@main`.

Two things ship together: an **enforcement library** (`engine.py`'s four hooks —
`before_input`, `before_tool`, `after_tool`, `before_output`) and a **corpus runner**
(`runner.py` + `instantiate.py` + templates) that measures whether a policy actually
holds against a role-parameterised attack corpus, with a baseline/regression gate for CI.

## Commands

```bash
pip install -e ".[dashboard,dev]"     # editable install, all extras used in dev
pytest                                 # full suite (~360 tests, ~25-30s, no network)
pytest tests/test_engine.py -q         # one file
pytest tests/test_engine.py::test_name # one test
python -m detguard --help              # subcommands: init, derive, corpus, run, baseline, report
                                        # NOTE: there is no `detguard scaffold` — it doesn't exist,
                                        # despite older docs/prose implying it once did.
streamlit run dashboard/app.py         # results/KPI viewer — reads results*.json only
streamlit run dashboard/setup.py       # config-authoring wizard — a different tool, same folder
```

No lint/format command is configured (no ruff/black config in `pyproject.toml`) — match
the existing style rather than reaching for a formatter.

`detguard` on `PATH` may not exist right after `pip install -e .` (common on Windows);
`python -m detguard` is the same entry point and always works.

## Architecture

**Core never imports an adapter or a framework.** `engine.py`, `policy.py`,
`registry.py`, `events.py` are pure — no I/O, no framework types, testable without
mocking anything. This is a design commitment enforced by convention, not by a lint
rule, so don't add a framework import to any of those four files.

**The four hooks are the entire public contract.** `engine.before_input` /
`before_tool` / `after_tool` / `before_output` each take a `GuardContext` and a
`PolicySet`, return a `Verdict`. `policy.evaluate()` runs every enabled rule bound to
one hook, never short-circuits on the first block (the full decision trace is the
audit evidence), and picks a "blocker" by severity rank when multiple rules fire.
`registry.py` holds the 12 condition functions (`content_scan`, `ungrounded_arg`,
`sensitive_tool_call`, etc.) — the contract is `fn(ctx, params) -> (bool, str)`, fired
means "flagged," not "blocked"; the rule's `action` decides what happens.

**Two independent implementations of the same hook-sequencing exist, on purpose, and
they drift.** `guarded.py` (the delivery layer — `guarded.run()` for a hand-rolled
loop, `guarded.guard()` as a tool decorator) and `runner.py` (drives a corpus against
someone else's adapter for measurement) both re-implement "call before_tool, execute,
call after_tool, write back a redaction if one fired." There is no shared helper. A fix
to one — e.g. "a fired `redact` action must overwrite what the caller sees" — has to be
checked against both files, never assumed to carry over.

**`prevented` vs `detected` is the single most important distinction in the runner.**
An adapter that exposes `set_tool_guard` (only `OpenAIAgentsAdapter` does today, via the
SDK's own `tool_input_guardrails`) gets real pre-execution enforcement during a corpus
run — a block stops the call. Adapters without that seam (`LangGraphAdapter`,
`GenericAdapter`) fall back to evaluating hooks *after* `invoke()` returns: the side
effect already happened, and `blocked` there means "a live integration would have
stopped this," not "did." Every `results.json` records which mode a run used
(`runner.py` sets `enforcement: "prevented"`/`"detected"` per attack and in the
summary) — don't average over both when reading a defense rate.

**Non-obvious:** a corpus run's `enforcement` field reflects the *runner's own*
measurement guard attaching to the agent's tools, independent of whether the target
app's own live code path calls DetGuard at all. An app with zero guardrail wiring in
its production loop can still show `enforcement: prevented` when *measured* via
`detguard run` against an `OpenAIAgentsAdapter` — the runner's `set_tool_guard`
attaches to the same tool objects regardless. Don't conflate "this corpus run measured
well" with "this app is protected in production" when narrating results.

**Scoring has hard-won invariants** (each one a real bug in a predecessor project,
documented in comments where it's enforced): a success check never passes on an empty
tool-call list; `not_complied` (agent didn't fall for it) is never counted as a
defense; `inconclusive` (state genuinely unobservable — the `UNREADABLE` sentinel
exists so `None` can't be mistaken for "unchanged") is never counted as a pass or a
fail; `defense_rate` counts hard blocks only, `containment_rate` adds HITL pauses, and
they are never summed into one number; a `redact` action that fires must overwrite what
the consumer actually receives, or the trace reports a masked secret that still leaked.
`baseline.py`'s `compare()` classifies regressions into named classes
(`NEW_BREACH`, `GAP_CLOSED`, `BENIGN_BLOCKED` fail the build; `LAYER_DRIFT`,
`NEW_CASE`/`MISSING_CASE`, `POLICY_DRIFT` only warn) — read the class names before
changing scoring logic, they encode which failures are supposed to be loud.

**Corpus generation is deterministic by construction.** `instantiate.py` binds 16
shipped templates (`src/detguard/templates/`) to a client's `manifest.yaml` +
`roles.yaml` via role matching, not tool names — a template requiring `move_value`
binds to whatever tool in the manifest carries that role. `mutations.py`'s 8 transforms
(zero-width insertion, homoglyph substitution, `politeness_wrap` rewriting imperative
mood to declarative, etc.) are pure functions, no LLM, so the corpus is byte-identical
across regenerations — a design commitment (`CI` asserts this explicitly). A template
that can't bind to the manifest's roles is recorded in `_skipped.yaml` with a reason,
never silently dropped.

**Three files are deliberately hand-written, not generated**, and this is a frequent
point of confusion: `detguard_adapter.py`, `manifest.yaml`, `roles.yaml`. `detguard
derive` only derives `policy.yaml` + a CI workflow from those three, by rule, no model
call. `detguard init --agent-obj`/`--graph` can build a plain adapter *in memory* with
no file at all, for the common case — but any app needing custom glue (injecting
attack payloads into its own data layer, for example) still needs a hand-written
subclass, and there's no generator for that gap today (see "Deferred" in the demo plan
under `~/.claude/plans/` for the fix that isn't built yet).

## Testing conventions

Tests exercise the pure core against a scripted `FixtureAgent`
(`examples/banking_agent/agent.py`) — deterministic, no network, no API key. The CI
workflow (`.github/workflows/detguard-ci.yml`) additionally asserts the corpus builds
byte-identically twice and that the fixture agent is genuinely vulnerable unguarded
(defense rate must be 0% with `--guardrail off`) — a guardrail number is meaningless
against an agent that wouldn't have complied anyway.

## Dashboard

`dashboard/app.py` reads `results*.json` and, optionally, `manifest.yaml`/
`roles.yaml`/`policy.yaml`/`baseline.json`/`audit.jsonl` from sidebar-configurable
paths — it never invokes an agent, never evaluates a policy against live traffic. Seven
tabs: Overview (guarded-vs-unguarded + trend), Coverage by tool (cross-references
roles/rules/outcomes per tool, flags sensitive tools with zero covering rules),
Coverage & layers (per-family/severity breakdown, mutation effectiveness), Regression
gate (calls `baseline.compare()` directly), Per-attack detail, Audit log, Export.
`dashboard/setup.py` is unrelated — a config-authoring wizard, not a results viewer.
