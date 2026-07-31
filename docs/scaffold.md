# Hand-writing an integration, then deriving policy.yaml

```bash
detguard derive --manifest config/manifest.yaml --roles config/roles.yaml \
  --adapter-import myapp.detguard_adapter:build_adapter
```

Validates a hand-written `manifest.yaml` and `roles.yaml`, then writes two
files: `config/policy.yaml` (derived from `roles.yaml` by rule) and
`.github/workflows/detguard-gate.yml` (generated deterministically, the same
generator `dashboard/setup.py` uses). No model, no network call, no API key.

This exists for agents that are **not** on a framework detguard already
adapts. LangGraph and the OpenAI Agents SDK both maintain their own execution
record as a side effect of running, so their adapters just read it back (see
`docs/integration.md`). A hand-rolled loop has no such record — nothing is
written down for an adapter to read — and somebody has to write the
bookkeeping by hand: `detguard_adapter.py`, `manifest.yaml`, and `roles.yaml`.

## Why these three are hand-written, not generated

Classifying a tool's role and finding the one place in *your* agent loop where
a call can be recorded without executing it twice are both reading-
comprehension tasks over code nobody but you has seen. There is no mechanical
shortcut for either — see `docs/integration.md#hand-writing-an-adapter` for
the adapter contract and `docs/integration.md#hand-writing-rolesyaml` for the
role-classification checklist.

## Generated, derived, and neither

| File | Where it comes from |
|---|---|
| `detguard_adapter.py` | **hand-written** — you know your own dispatch structure |
| `manifest.yaml` | **hand-written** — you know your own tool signatures |
| `roles.yaml` | **hand-written** — the classification judgement is yours |
| `policy.yaml` | **derived** from `roles.yaml`, by rule |
| `detguard-gate.yml` | **derived** — the same generator `dashboard/setup.py` uses |

The policy is mechanical once the role map exists. `human_in_loop.tools` is
every gated tool in your role map; `unrequested_mutation.mutating_tools` is
every tool carrying a role that changes state. Those follow from the roles by
rule — that is the whole point of `derive_policy`. Two fields are never filled
at all:

- **`external_destination_allowlist.allowlist` stays empty**, because empty
  blocks every external destination. A list somebody forgot to fill must not
  read as "everywhere is fine".
- **`amount_bound.min` keeps its default and the rule stays disabled.** A
  ceiling that does not match your business is worse than no ceiling, and
  nothing can know what that number is except you.

Where the choice is not forced, nothing is chosen. Two `move_value` tools and
no way to pick between them leaves `amount_bound.tool` empty — a rule bound to
the wrong tool never fires, and reads exactly like one that works.

## No model anywhere in this

detguard's central claim is that **no LLM sits in the enforcement path** — and
as of this command, no LLM sits anywhere in the authoring path either.
`detguard derive` is pure YAML-in, YAML-out: `parse_manifest`, `parse_roles`,
`derive_policy`, `policy.loads`, all mechanical, all run **before anything is
written** — a failed validation leaves nothing behind.

`roles.yaml` should still carry a `# why:` line per tool (a convention worth
keeping even without a model to hold accountable — see
`docs/integration.md#hand-writing-rolesyaml`), so a reviewer checks the
judgement instead of trusting it. **When uncertain, assign the more
restrictive role.** A tool wrongly classed `read_internal` is never gated by
anything and fails **silently**; a tool wrongly classed `external_send` causes
a visible, fixable false positive. These are not errors of the same kind.

## Flags worth knowing

| Flag | Why |
|---|---|
| `--arg-hints path` | Names each tool's `destination_arg` / `amount_arg` — see `docs/integration.md`. |
| `--dry-run` | Prints the derived policy, writes nothing. |
| `--overwrite` | Required to replace files that already exist. |
| `--adapter-import module:factory` | Recorded in the generated CI workflow only — this command never reads or executes your adapter. |

## Then

```bash
detguard corpus build --manifest config/manifest.yaml --roles config/roles.yaml \
  --out corpus/attacks
detguard run --corpus corpus/attacks --policy config/policy.yaml \
  --agent myapp.detguard_adapter:build_adapter --guardrail off --run-dir runs/first
detguard run --corpus corpus/attacks --policy config/policy.yaml \
  --agent myapp.detguard_adapter:build_adapter --guardrail on --run-dir runs/first
detguard report --results runs/first/results-on.json \
  --unguarded runs/first/results-off.json --run-dir runs/first
```

Read `coverage` before `defense_rate`. Below 1.0, some attacks were never
observed — and a defense rate over partial coverage describes only the attacks
underneath it.
