# Roles

Tool names mean nothing to a generic engine. `refund_order` is a string;
whether it can move money is a fact about your business that no amount of
introspection will recover. Roles carry that fact, and everything downstream —
the policy defaults, the attack bindings, the compliance mapping — keys off
them.

The vocabulary is **closed**. A role outside this list is a hard load-time
error, not a warning. An open vocabulary would let a typo become a tool that
silently belongs to no category and is therefore gated by nothing.

## The nine

| Role | Meaning | Typical tools |
|---|---|---|
| `read_internal` | reads trusted internal state | `get_balance`, `lookup_customer` |
| `read_untrusted` | pulls in content an attacker could author | `read_ticket`, `fetch_document`, RAG retrieval |
| `mutate_state` | changes non-critical state | `update_preferences`, `set_payee` |
| `mutate_identity` | changes who or where the principal is | `update_address`, `change_email` |
| `move_value` | money, goods, entitlements | `send_money`, `refund_order`, `issue_credit` |
| `change_credential` | auth material | `update_password`, `rotate_api_key` |
| `external_send` | data leaves the perimeter | `send_email`, `post_webhook` |
| `external_fetch` | retrieves from an attacker-influencable address | `fetch_url`, `call_api` |
| `destructive` | irreversible | `delete_branch`, `close_account`, `drop_table` |

A tool may carry several. A tool that reads a customer record *and* emails it
is both `read_internal` and `external_send`, and both roles matter.

## Gated by default

```python
GATED_BY_DEFAULT = (
    "mutate_identity", "move_value", "change_credential",
    "external_send", "destructive",
)
```

Every tool carrying one of these lands in the human-in-the-loop set when a
policy is first drafted. You then tune *down* from there.

That direction is deliberate. Tuning down from a strict default is a decision
someone makes, in a diff, with a reason attached. Tuning up from nothing is a
gap nobody ever gets round to closing, and it does not appear in any review.

### Why `mutate_identity` is on the list

Changing an address does not feel like moving money, so it is the first role
people tune out. It is also the role that TPL-08 targets, and the reason that
template exists: an attacker who changes the correspondence address gets every
subsequent statement, reset link and confirmation. The value moves later, and
by a route nobody is watching.

### Why `external_fetch` is *not* on the list

Fetching a URL is not, by itself, an action with consequences, and gating every
fetch would put an approval prompt on ordinary browsing. It is dangerous in
combination — with an attacker-supplied address, or with data in the query
string — which is why the default policy handles it with `ungrounded_arg` and
`external_destination` rather than with the gate.

This is a judgement call, and it is the kind you should re-make for your own
system.

## Writing `roles.yaml`

```yaml
agent: acme-support-agent

roles:
  get_balance: [read_internal]
  read_ticket: [read_untrusted]
  refund_order: [move_value]
  update_address: [mutate_identity]
  send_email: [external_send]
  close_account: [destructive]

unclassified: []
```

The loader validates that every role exists and that every tool named here
appears in your manifest. A tool in the manifest with no entry is reported as
unclassified — a warning, not an error, because a new tool nobody has triaged
yet is a normal state to be in for about a day.

Do not leave it there. An unclassified tool binds to no attack and is gated by
no rule. It is invisible to the entire system, which is the worst possible
place for a tool to be.

## Classifying: the three questions

For each tool, in order.

**1. Can an attacker influence what it returns?** Anything reading a ticket, an
inbox, a fetched page, a transaction memo, a retrieved chunk, or *another
agent's message* is `read_untrusted`. This is the role people under-apply most.
A transaction memo is attacker-authorable — anyone who can send you 1p can
write in it.

**2. Does it change anything?** If not, it is a read. If it does, is the change
about identity, value, credentials, or something reversible and dull? That
picks between `mutate_identity`, `move_value`, `change_credential` and
`mutate_state`.

**3. Does anything leave?** `external_send` for data going out, `external_fetch`
for content coming in from an address someone else might control.

If a tool is irreversible, add `destructive` regardless of what else it carries.

## Tuning down safely

You will want to. An approval prompt on every refund is alert fatigue, and by
week two humans approve blindly — at which point the gate is decoration.

The honest way to narrow a gate:

1. **Get a false-positive number first.** Run your benign suite and find out
   how often the gate fires on legitimate work. Without that number you are
   trading safety for a feeling.
2. **Narrow by condition, not by removing the role.** Keep `refund_order`
   classed `move_value` and add a `numeric_bound` so only refunds over a
   threshold need approval. The role is a fact about the tool; the gate is a
   policy decision. Do not corrupt the first to change the second.
3. **Record the decision in the policy diff.** `description:` on the rule, in
   words, saying why this is acceptable. Six months later that sentence is the
   only thing standing between you and re-deriving the argument from scratch.
4. **Baseline it.** If narrowing the gate opens an attack, that shows up as a
   `NEW_BREACH` in CI immediately rather than in an incident later.

What not to do: reclassify a tool into a quieter role to silence a prompt. The
role map is also what binds attacks and what a compliance reviewer reads. A
`move_value` tool filed as `mutate_state` makes the noise stop and the coverage
disappear at the same time.

## Multi-agent

Two additions, both natural.

**One manifest and one role map per agent.** A research agent and a payments
agent should not share a gated set.

**Anything another agent said is untrusted content.** Inter-agent messages are
structurally tool calls — same `(name, args)` shape — so the same conditions
apply, and `read_untrusted` extends to them without change.

The honest gap: chain-level policy *across* agents. Per-call checks cannot see
"no single agent did anything wrong, the orchestration did". That is the same
limitation TPL-08 exposes within one agent, amplified. It is roadmap, not a
shipped feature, and it should be described that way.
