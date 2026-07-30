# Policy reference

A policy is one YAML file. It is your control documentation: versioned,
diffable, reviewed in pull requests, and enforced on every commit. That is a
rare artifact and auditors like it — but it only works if loading is strict.

**An unknown condition, action, hook, severity or `pattern_set` reference is a
hard load-time error.** There is no lenient mode. A rule that cannot be
understood is never downgraded to a rule that quietly never fires, because that
failure mode produces a green CI gate over an undefended agent.

## Structure

```yaml
version: 1

pattern_sets:
  injection:
    - '(?i)\bignore\s+(?:all\s+)?previous\s+instructions?'

rules:
  - id: overt_injection          # required, unique
    hook: before_input           # required, one of the canonical four
    condition: content_scan      # required, must exist in the registry
    params:
      pattern_set: injection
    action: block                # required
    severity: critical           # optional, default: medium
    layer: content_scan          # optional, default: the condition name
    enabled: true                # optional, default: true
    description: >               # optional, but write one
      Why this rule exists.

audit:
  enabled: false
  path: audit.jsonl
```

Any other top-level key, or any other rule key, is an error. So is a duplicate
`id`.

## Hooks

`before_input` · `before_tool` · `after_tool` · `before_output`

Rules run only at their own hook, in file order. See
[integration.md](integration.md) for what each one sees.

## Actions

| Action | Blocks? | Effect |
|---|---|---|
| `block` | yes | `allow=False`. Hard stop. |
| `require_hitl` | yes | `allow=False` **and** `requires_approval=True`. |
| `redact` | no | Replaces the verdict text with the masked version. Requires a transforming condition. |
| `warn` | no | Recorded in the decision trace. |
| `limit` | no | Recorded. Reserved for future throttling semantics. |
| `notify` | no | Recorded; written to the audit log. For breach-notification wiring. |

`require_hitl` and `block` both set `allow=False` — nothing proceeds
unattended. They are still different outcomes, and `requires_approval` is the
flag that says a human may proceed. Conflating them was a real scoring bug: it
turns every approval prompt into a reported breach and hides what the gate
costs in friction.

`redact` is only valid with a transforming condition (`pii_redact`). Pairing it
with anything else is a load error, because it would silently redact nothing.

## Severity and blocker selection

`low` · `medium` · `high` · `critical`

When several blocking rules fire at one hook, the highest-severity one is
reported as `blocked_by`. At equal severity a hard `block` outranks a
`require_hitl`, and file order breaks any remaining tie.

Every rule still runs and every outcome is recorded in `decisions`, including
rules that did not fire. Evaluation never short-circuits: the trace is the
audit evidence, and "which layers looked at this and passed" is what the
dashboard's attribution view is built from.

## Conditions

Every condition has the signature `fn(ctx, params) -> (fired, reason)`. "Fired"
means the thing the rule looks for was found. What to do about it is `action`,
which is policy's business, not the condition's.

To regenerate this list against your installed version:

```python
from detguard.registry import CONDITIONS, ACTIONS, TRANSFORMING
print(sorted(CONDITIONS), sorted(ACTIONS), sorted(TRANSFORMING))
```

### `content_scan`

`pattern_set` · `applies_to?`

Regex match against the hook's text, after invisible-character stripping and
homoglyph folding. First match wins.

`applies_to` takes `any` (default), `retrieved`, or `user`. This is not a
convenience: "the outstanding item should be settled to X" is an attack inside
a fetched document and an ordinary sentence in a user's own request. A rule
that cannot tell those apart is a false-positive generator, and the FP number
is the one that decides whether anyone leaves the guardrail switched on.

```yaml
- id: retrieved_instruction
  hook: before_input
  condition: content_scan
  params: {pattern_set: data_instruction, applies_to: retrieved}
  action: block
  severity: high
```

**Write patterns that match instruction-shaped grammar, not the vocabulary of
any particular attack.** A regex tuned to the exact wording of a corpus payload
catches that payload and nothing else that will ever be written — and a corpus
whose attacks are caught by regexes derived from those same attacks proves
nothing.

### `pii_detect`

`pattern_set`

Detects sensitive values. Never mutates. Use at `after_tool` and
`before_output`.

### `pii_redact`

`pattern_set` · `applies_to?` · `mask?`

Masks and continues. **No-ops when `applies_to: retrieved` and the text is not
retrieved** — otherwise the agent's own trusted state gets shredded on its way
to the user. The only condition permitted to mutate the context.

### `sensitive_tool_call`

`tools`

Fires if any decided call names a tool in the set. This is the
human-in-the-loop gate, and the set is yours: generated from your role
classification, edited by you, validated by the loader.

An empty set never fires. That is deliberate — an unconfigured gate must not
pretend to defend you.

### `tool_arg_matches`

`tool` · `arg` · `pattern`

Regex on one argument value. An empty `tool` means any tool.

### `numeric_bound`

`tool` · `arg` · `min?` · `max?`

Fires outside the range. A non-numeric value also fires: an amount you cannot
parse is not an amount you should be moving.

### `call_budget`

`max_calls`

Total call-count cap for one turn. Tune against your benign corpus before you
trust it — a budget below your agent's normal working range is a false-positive
factory.

### `repeated_call`

`max_repeats` · `match_args?`

Same tool, optionally with the same arguments, past a threshold. **Fires at
N+1, not N**: `max_repeats: 3` permits three and objects to the fourth. This is
the structuring check, and it is why a total-count budget is not enough — every
individual call is comfortably within every individual limit.

### `ungrounded_arg`

`tool` · `arg` · `min_length?`

Fires when an argument value appears nowhere in the user's own request. This is
the destination-substitution check: the user asked to settle an invoice, and
the agent is about to send money to an account the user never mentioned. That
account came from somewhere else — usually the document.

**Returns "did not fire" when there is no user prompt**, with the reason
recorded. Firing there would flag every call in any integration that failed to
thread the prompt through, which is how a guardrail earns a reputation for
noise. Thread `user_prompt` through every hook.

### `unrequested_tool`

`mutating_tools` · `allowed_tools`

A mutating call outside what this turn licensed. Overreach rather than attack —
and the shape most real incidents take. `allowed_tools` is per-turn context, so
supply it from your integration rather than hard-coding it.

### `external_destination`

`tool` · `arg` · `allowlist?`

Fires when a destination is not allowlisted. **An empty or absent allowlist
fires on everything.** A list somebody forgot to fill in must not read as
"everywhere is fine".

### `llm_judge`

`model` · `temperature` · `threshold`

Model-based. **Ships `enabled: false` and must stay that way for any blocking
gate** — no LLM sits in the enforcement path in v1.

With no backend configured it records why it could not run and returns "did not
fire". It **fails open**, deliberately: an unavailable judge must never silently
become a block, because a security tool that fails closed on infrastructure
trouble gets disabled within a week, and a disabled guardrail defends nothing.
The unavailability is in the trace, so a run where the judge did not execute
cannot be mistaken for one where it executed and found nothing.

Enable it for non-blocking nightly runs:

```bash
detguard run ... --enable-layer llm_judge
```

`--enable-layer` matches on `layer` or `condition`, and flips `enabled: false`
rules on at runtime. There is exactly one policy file; nightly never loads a
second one.

## Layers

`layer` is an attribution label, defaulting to the condition name. It is what
the dashboard groups by, what `layers_enabled` records, and what
`--enable-layer` matches. Give several rules the same layer when they are the
same defensive idea.

A defense-rate chart where one layer catches everything is a warning, not a
result: it means you have one line of defence and a single regex edit away from
none.

## Worked example

```yaml
version: 1

pattern_sets:
  prompt_injection:
    - '(?i)\bignore\s+(?:all\s+)?previous\s+instructions?'
    - '(?i)\b(?:system|admin(?:istrator)?)\s+(?:override|mode|authority)\b'
  credential:
    - '(?i)\b(?:password|api[_-]?key|secret)\b\s*(?:is|=|:)\s*\S{4,}'

rules:
  - id: overt_injection
    hook: before_input
    condition: content_scan
    params: {pattern_set: prompt_injection}
    action: block
    severity: critical
    layer: content_scan

  - id: human_in_loop
    hook: before_tool
    condition: sensitive_tool_call
    params: {tools: [refund_order, update_address, update_password]}
    action: require_hitl
    severity: critical
    layer: hitl
    description: >
      Everything classed move_value, mutate_identity or change_credential.
      Tuned down from the default only with a recorded reason.

  - id: ungrounded_destination
    hook: before_tool
    condition: ungrounded_arg
    params: {tool: refund_order, arg: destination}
    action: block
    severity: high
    layer: grounding

  - id: structuring
    hook: before_tool
    condition: repeated_call
    params: {max_repeats: 3, match_args: false}
    action: block
    severity: high
    layer: budget

  - id: output_credential_disclosure
    hook: before_output
    condition: pii_detect
    params: {pattern_set: credential}
    action: block
    severity: critical
    layer: output_guard

audit:
  enabled: true
  path: audit.jsonl
```

## Validation errors

| Message | Cause |
|---|---|
| `unknown condition 'foo'` | Typo, or a condition from a newer detguard. |
| `unknown action 'deny'` | Closed vocabulary. Use `block`. |
| `unknown hook 'after'` | Use the canonical four. |
| `unknown severity 'catastrophic'` | `low`/`medium`/`high`/`critical`. |
| `duplicate rule id 'x'` | Two rules share an id. |
| `condition 'content_scan' requires a 'pattern_set' param` | Missing param. |
| `pattern_set 'x' is not defined in 'pattern_sets'` | Dangling reference. |
| `action 'redact' requires a transforming condition` | Only `pii_redact` redacts. |
| `unknown key(s): ...` | Strict schema. Check spelling. |
| `'rules' must be a non-empty list` | A policy with no rules defends nothing. |
