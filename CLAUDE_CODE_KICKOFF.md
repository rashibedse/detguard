# Kickoff prompt for Claude Code

Put `BUILD_SPEC.md`, `RE_EVALUATION.md`, and `CLIENT_FLOW.md` in the empty
repo root first. Then `cd` into it and run `claude`.

Paste this as your first message:

---

I'm building `detguard` from scratch in this repo — a policy-as-code guardrail
and adversarial regression suite for AI agent tool calls.

Read all three of these before writing any code:
- `BUILD_SPEC.md` — the authoritative build document. It wins on any conflict.
- `RE_EVALUATION.md` — strategy, the 16 attack templates in table form, and
  why each design decision is what it is.
- `CLIENT_FLOW.md` — how a customer adopts the tool; explains what the
  manifest/roles/instantiation pieces are for.

Rules for this session:

1. **Build only. Do not run any test suite.** Write the test files specified
   in BUILD_SPEC §14 with real assertions, but do not execute them. I run and
   record all tests myself. You may run `pip install -e .`, an import
   smoke-check, and `detguard --help` to confirm packaging works — nothing
   else.
2. Follow the build order in §16 exactly. Do not skip ahead.
3. **Stop and report at the checkpoint after step 4** (`instantiate.py`).
   Show me the concrete attacks it generated from the fixture manifest before
   continuing. Everything downstream depends on that being right.
4. Every design decision is already made in §0. Do not redesign, do not
   substitute libraries, do not "improve" the architecture. If something in
   the spec looks wrong or contradictory, stop and ask me.
5. Hard invariants — never violate these:
   - No LLM in the enforcement path (`llm_judge` ships `enabled: false`)
   - A tool call is executed exactly once; `ToolCall.result` is authoritative
   - A `success_check` must never pass on an empty tool-call list
   - Never silently skip a template — skipped templates are reported output
   - Core (`detguard/*.py`) must never import an adapter or a framework
6. Show me a diff or file list before each numbered step, then implement it.

Start with step 1: scaffold the repo, write `pyproject.toml`, and get
`pip install -e .` plus `detguard --help` working. Show me the layout before
you create files.

---

## Follow-up prompts, in order

After each step completes and you've eyeballed it:

- `Step 2. Show me events.py, roles.py, registry.py, policy.py, engine.py before writing.`
- `Step 3. Write the 16 templates. Show me TPL-07 and TPL-08 in full first — those two are the most important and the payloads must contain zero imperative language.`
- `Step 4. Build instantiate.py. When done, run it against tests/fixture_manifest.yaml and show me every generated attack file. Stop here.`
- `Step 5. mutations.py — implement zero_width, homoglyph, politeness_wrap first. Show me politeness_wrap's rule table before implementing.`
- `Step 6. fixture_agent.py, adapters/base.py, adapters/generic.py, runner.py. Show me the BaseAdapter contract first.`
- `Step 7. dashboard/app.py. All nine sections from BUILD_SPEC §12.`
- `Step 8/9. LangGraph then OpenAI Agents adapters.`
- `Step 10. baseline.py, report.py, audit.py, both workflow files.`
- `Step 11. Write all test files from §14. Do not run them.`
- `Step 12. Docs. quickstart.md first and make it genuinely copy-pasteable.`

## If it goes sideways

- If it starts redesigning: *"BUILD_SPEC §0 is locked. Implement as specified
  or stop and ask."*
- If it runs tests anyway: *"Do not execute tests. Write them only."*
- If instantiation is broken at the checkpoint: don't let it patch forward —
  come back to me with the actual output and we'll fix the spec.
- If it's behind schedule: *"Finish step 6 and 7, then stop. Skip 8-10."*
