# Scaffolding an integration

```bash
export DETGUARD_API_KEY=...
detguard scaffold --source-dir . --entry agent:run_agent
```

Reads your agent's source and writes five files: `detguard_adapter.py`,
`config/manifest.yaml`, `config/roles.yaml`, `config/policy.yaml`, and
`.github/workflows/detguard-gate.yml`.

This exists for agents that are **not** on a framework detguard already adapts.
LangGraph and the OpenAI Agents SDK both maintain their own execution record as
a side effect of running, so their adapters just read it back. A hand-rolled
loop has no such record — nothing is written down for an adapter to read — and
somebody has to write the bookkeeping by hand. That is the job this replaces.

## Generated, derived, and neither

The distinction is load-bearing, and it is visible in the command's output.

| File | Where it comes from |
|---|---|
| `detguard_adapter.py` | **model** — codegen against your dispatch structure |
| `manifest.yaml` | **model** — reading tool signatures out of source |
| `roles.yaml` | **model** — the classification judgement |
| `policy.yaml` | **derived** from `roles.yaml`, by rule |
| `detguard-gate.yml` | **derived** — the same generator `dashboard/setup.py` uses |

The policy is not generated. `human_in_loop.tools` is every gated tool in your
role map; `unrequested_mutation.mutating_tools` is every tool carrying a role
that changes state. Those follow from the roles, so a model is not asked. Two
fields are never filled at all:

- **`external_destination_allowlist.allowlist` stays empty**, because empty
  blocks every external destination. A list somebody forgot to fill must not
  read as "everywhere is fine".
- **`amount_bound.min` keeps its default and the rule stays disabled.** A
  ceiling that does not match your business is worse than no ceiling, and no
  model knows what that number is.

Where the choice is not forced, nothing is chosen. Two `move_value` tools and
no way to pick between them leaves `amount_bound.tool` empty — a rule bound to
the wrong tool never fires, and reads exactly like one that works.

## This does not put a model in the enforcement path

detguard's central claim is that **no LLM sits in the enforcement path**.
Scaffolding happens at authoring time. The output is YAML and Python that you
read, edit, commit and diff; enforcement then runs deterministic conditions
over that committed file. A model that helped write a policy in March has no
part in the decision made in June.

That holds only because the output is treated as a draft:

- every file carries a provenance header naming the model and the date;
- `roles.yaml` carries a `# why:` line per tool, so you check the judgement
  instead of trusting it;
- everything round-trips through the real validators (`parse_manifest`,
  `parse_roles`, `policy.loads`, and a syntax compile of the adapter) **before
  anything is written** — a failed generation leaves nothing behind;
- classification errs **gated**: an uncertain tool gets the more restrictive
  role.

That last one is the asymmetry that matters. A tool wrongly classed
`read_internal` is never gated by anything and fails **silently**. A tool
wrongly classed `external_send` causes a visible, fixable false positive. These
are not errors of the same kind, so the prompt does not treat them as such.

## Read the adapter

The generated adapter is the part most worth your attention, because the
failure mode produces working-looking code:

**A tool must be executed exactly once.** `invoke()` has to run your loop once
and *record* what it did. An adapter that collects intended calls and then
executes them itself doubles every real side effect — rows inserted twice,
emails sent twice — and every number in the report becomes fiction.

**The trace has to survive dispatch.** If your loop maps tool names to
functions through a dict built at import time, patching the module attribute
does nothing; the dict already holds the original reference. The result is an
empty trace, which reports as `no_tool_calls` and reads as a perfect defense.

**`reset()` has to genuinely reset.** An idempotent seed ("only seed if empty")
is not usable as a reset hook: state from attack 1 leaks into attack 2, and
every result after the first is measured against contaminated state. If your
source only has the idempotent version, the model is told to generate a real
one and flag it in NOTES.

## Flags worth knowing

| Flag | Why |
|---|---|
| `--print-prompt` | Prints the prompt and exits. No key needed, no model called. |
| `--dry-run` | Prints every generated file, writes nothing. |
| `--overwrite` | Required to replace files that already exist. |
| `--base-url` | Any OpenAI-compatible endpoint — Groq, Together, a local server. |
| `--reset module:function` | Supply the reset hook instead of having it inferred. |

`--provider` is inferred from `--model` (`claude-*` → Anthropic, everything
else → OpenAI-compatible). The key is read from `DETGUARD_API_KEY`, then
`ANTHROPIC_API_KEY`, then `OPENAI_API_KEY`.

Needs the optional extra:

```bash
pip install "detguard[authoring]"
```

## Then

```bash
detguard corpus build --manifest config/manifest.yaml --roles config/roles.yaml \
  --out corpus/attacks
detguard run --corpus corpus/attacks --policy config/policy.yaml \
  --agent detguard_adapter:build_adapter --guardrail off --run-dir runs/first
detguard run --corpus corpus/attacks --policy config/policy.yaml \
  --agent detguard_adapter:build_adapter --guardrail on --run-dir runs/first
detguard report --results runs/first/results-on.json \
  --unguarded runs/first/results-off.json --run-dir runs/first
```

Read `coverage` before `defense_rate`. Below 1.0, some attacks were never
observed — and a defense rate over partial coverage describes only the attacks
underneath it.
