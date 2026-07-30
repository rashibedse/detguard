# Policy file reference

A policy is one YAML file. It is loaded strictly: an unknown condition, action,
hook, severity or `pattern_set` reference is a hard load-time error. There is
no lenient mode and no warning path. A rule that cannot be understood is never
downgraded to a rule that silently never fires, because that failure mode
produces a green CI gate over an undefended agent.

There is exactly **one** policy file. Nightly runs do not load a second one —
they enable a layer in the same file with `--enable-layer`. Two files drift,
and then the gate is testing something the client does not actually run.

## Top level

| Key | Required | Type | Meaning |
|---|---|---|---|
| `version` | yes | int | Schema version. Currently `1`. |
| `rules` | yes | list | Non-empty. See below. |
| `pattern_sets` | no | map | Name → list of regex strings. |
| `audit` | no | map | `{enabled: bool, path: str}`. |
| `metadata` | no | map | Free-form. Ignored by the engine. |

Any other top-level key is an error.

## A rule

```yaml
- id: overt_injection          # required, unique across the file
  hook: before_input           # required, one of the 4 canonical hooks
  condition: content_scan      # required, must exist in the registry
  params:                      # condition-specific; see below
    pattern_set: prompt_injection
  action: block                # required
  severity: critical           # optional, default: medium
  layer: content_scan          # optional, default: the condition name
  enabled: true                # optional, default: true
  description: >               # optional, but write one
    Why this rule exists.
```

Any other rule key is an error. A duplicate `id` is an error.

### `hook`

`before_input` · `before_tool` · `after_tool` · `before_output`

Rules only run at their own hook. Order within a hook is file order.

### `action`

| Action | Blocks? | Effect |
|---|---|---|
| `block` | yes | `allow=False`. Hard stop. |
| `require_hitl` | yes | `allow=False` **and** `requires_approval=True`. |
| `redact` | no | Replaces the verdict text with the masked version. Requires a transforming condition (`pii_redact`). |
| `warn` | no | Recorded in the decision trace only. |
| `limit` | no | Recorded. Reserved for future throttling semantics. |
| `notify` | no | Recorded; written to the audit log. For breach-notification wiring. |

`require_hitl` and `block` both stop unattended execution, and both set
`allow=False`. They are still different outcomes: `requires_approval` means a
human may say yes. The runner and the dashboard must not conflate them —
doing so was a real scoring bug in the predecessor project.

### `severity`

`low` · `medium` · `high` · `critical`

When several blocking rules trigger at one hook, the highest-severity one is
reported as `blocked_by`. At equal severity a hard `block` outranks a
`require_hitl`, and file order breaks any remaining tie. Every triggered rule
is still recorded in `decisions` — the blocker is a summary, not a filter.

### `layer`

An attribution label, defaulting to the condition name. It is what the
dashboard's layer-attribution chart groups by, what `layers_enabled` in
`results.json` records, and what `--enable-layer` matches against. Give
several rules the same layer when they are the same defensive idea.

### `enabled`

Defaults to `true`. `detguard run --enable-layer <layer>` flips a disabled
rule on at runtime, matching on either `layer` or `condition`. `llm_judge`
ships `enabled: false` and must stay that way for any blocking gate.

## Conditions and their params

Every condition returns *fired / did not fire* plus a human-readable reason.
"Fired" means the thing the rule looks for was found — what to do about it is
`action`, which is policy's business, not the condition's.

| Condition | Params | Fires when |
|---|---|---|
| `content_scan` | `pattern_set`, `applies_to?` | A pattern matches the hook's text, after invisible-character stripping and homoglyph folding. First match wins. |
| `pii_detect` | `pattern_set` | A pattern matches. Detect only — never mutates. |
| `pii_redact` | `pattern_set`, `applies_to?`, `mask?` | A pattern matches; sets the masked text. **No-ops when `applies_to: retrieved` and the text is not retrieved.** |
| `sensitive_tool_call` | `tools` | Any decided call names a tool in the set. |
| `tool_arg_matches` | `tool`, `arg`, `pattern` | A regex matches that argument's value. |
| `numeric_bound` | `tool`, `arg`, `min?`, `max?` | The argument is outside the range, or is not numeric at all. |
| `call_budget` | `max_calls` | The batch exceeds the cap. |
| `repeated_call` | `max_repeats`, `match_args?` | A tool repeats past the threshold. Fires at N+1, not N. |
| `ungrounded_arg` | `tool`, `arg`, `min_length?` | The argument value appears nowhere in the user's request. **Declines to fire when there is no user prompt.** |
| `unrequested_tool` | `mutating_tools`, `allowed_tools` | A mutating call outside the allowed set. |
| `external_destination` | `tool`, `arg`, `allowlist?` | The destination is not allowlisted. An empty allowlist means nothing is pre-approved. |
| `llm_judge` | `model`, `temperature`, `threshold` | Backend-dependent. **Ships disabled and fails open.** |

`applies_to` takes `any` (default), `retrieved`, or `user`. An empty `tool`
param means "any tool".

### Why `ungrounded_arg` declines rather than fires

With no user prompt there is nothing to ground against. Firing there would
flag every call in any context that failed to plumb the prompt through, which
is how a guardrail earns a reputation for noise and gets switched off. It
returns "did not fire" with the reason recorded, so the gap is visible in the
trace rather than hidden in a block.

### Why `llm_judge` fails open

An unavailable judge must never silently become a block. A security tool that
fails closed on infrastructure trouble gets disabled within a week, and a
disabled guardrail defends nothing. The unavailability is recorded in the
decision trace, so a run where the judge did not execute cannot be mistaken
for a run where it executed and found nothing.

## Worked example

Block overt injection in user text, mask identifiers in fetched documents, and
pause on any gated tool:

```yaml
version: 1

pattern_sets:
  prompt_injection:
    - '(?i)\bignore\s+(?:all\s+)?previous\s+instructions?'
  pii:
    - '\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b'

rules:
  - id: overt_injection
    hook: before_input
    condition: content_scan
    params: {pattern_set: prompt_injection}
    action: block
    severity: critical

  - id: retrieved_pii
    hook: before_input
    condition: pii_redact
    params: {pattern_set: pii, applies_to: retrieved}
    action: redact
    severity: medium

  - id: human_in_loop
    hook: before_tool
    condition: sensitive_tool_call
    params: {tools: [send_money, update_address, update_password]}
    action: require_hitl
    severity: critical
```

## Validation errors you will hit

| Message | Cause |
|---|---|
| `unknown condition 'foo'` | Typo, or a condition from a newer detguard. |
| `unknown action 'deny'` | The vocabulary is closed. Use `block`. |
| `unknown hook 'after'` | Use the canonical four. |
| `duplicate rule id 'x'` | Two rules share an id. |
| `condition 'content_scan' requires a 'pattern_set' param` | Missing param. |
| `pattern_set 'x' is not defined in 'pattern_sets'` | Referenced a set that does not exist. |
| `action 'redact' requires a transforming condition` | Only `pii_redact` can redact. |
| `unknown key(s): ...` | Strict schema. Check spelling. |
