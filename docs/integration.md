# Integration

DetGuard is a library you call, not a service that watches you. There is no
daemon, no agent-side sidecar, and no network call. It is a command and four
functions, which is the whole reason it can run inside a regulated network.

## The four hooks

| Hook | When | What it sees | The case it exists for |
|---|---|---|---|
| `before_input` | text enters the agent | user message, or retrieved document | overt injection; instructions hidden in a document |
| `before_tool` | after the agent decides, **before anything runs** | the whole batch of calls with concrete arguments | the destination came from the document, not the user |
| `after_tool` | a tool returned, before the value re-enters context | the return value | a secret in a result, echoed onward |
| `before_output` | before the user sees the answer | the final prose | the agent states the secret rather than sending it |

`before_tool` is the one that distinguishes this from a text filter. The
arguments are concrete by then, so the check is exact instead of probabilistic.

## Minimal loop

```python
from detguard import engine, policy
from detguard.events import ToolCall

policy_set = policy.load("guardrail/policy.yaml")

def handle(user_text: str) -> str:
    v = engine.before_input(user_text, policy_set)
    if not v.allow:
        return refuse(v)

    calls = [ToolCall(name=n, args=a) for n, a in my_agent.decide(v.text)]

    v = engine.before_tool(calls, policy_set, user_prompt=user_text)
    if v.requires_approval:
        return escalate_to_human(v)          # a human may still say yes
    if not v.allow:
        return refuse(v)                     # a hard stop

    for call in calls:
        call.result = execute(call)          # exactly once
        v = engine.after_tool(call, policy_set, user_prompt=user_text)
        if not v.allow:
            return refuse(v)
        call.result = v.text or call.result  # honour a redaction

    answer = my_agent.summarise(calls)
    v = engine.before_output(answer, policy_set, user_prompt=user_text, tool_calls=calls)
    return v.text if v.allow else refuse(v)
```

Four things about that snippet are load-bearing.

**`user_prompt` goes to every hook.** Several conditions cannot work without
the original request — `ungrounded_arg` above all, which is what catches a
destination the user never mentioned. Without it, that condition declines to
fire rather than guessing, and you lose a layer silently.

**`requires_approval` is checked before `allow`.** Both stop unattended
execution, but only one means a human can proceed. Collapsing them turns every
approval prompt into a reported breach.

**`call.result` is set once.** detguard never re-executes a call to find out
what it returned. For a read that would be a correctness bug; for anything that
moves money it is an incident.

**A redaction is applied, not just logged.** If the policy masked a value,
hand the masked version onward. Reporting a redaction and then passing the
original makes the entire decision trace fiction.

## Reading a Verdict

```python
v.allow              # False for both `block` and `require_hitl`
v.requires_approval  # True only for `require_hitl`
v.blocked_by         # the rule id, chosen by severity when several fire
v.severity           # that rule's severity
v.text               # possibly redacted
v.decisions          # every rule evaluated, fired or not — the audit trail
```

`decisions` includes rules that did *not* fire. That is deliberate: "which
layers looked at this and passed" is the evidence, and it is what the
dashboard's layer-attribution view is built from.

## Adapters

An adapter is only needed to run the **regression suite**. Enforcement needs
no adapter at all — that is just the four functions above.

```python
class BaseAdapter(ABC):
    def introspect(self) -> dict          # -> manifest dict
    def reset(self) -> None               # fresh state per attack
    def invoke(self, user_prompt, injected_context) -> AgentRun
    def get_state(self, path: str) -> Any # for success checks
```

`invoke`'s second argument is the untrusted carrier, or `None`:

```python
{"name": "ticket_body", "kind": "record", "injection_point": "body",
 "content": "...the payload...", "position": "end"}
```

Nothing in this contract assumes in-process execution, so a future MCP proxy
adapter can satisfy it by mapping a request to `before_tool` and a response to
`after_tool`.

### Hand-writing `detguard_adapter.py` (no framework)

When `GenericAdapter` doesn't fit — your agent needs bespoke reset/state
logic, or you want full control over dispatch — subclass `BaseAdapter`
directly:

```python
from detguard.adapters.base import AgentRun, BaseAdapter

class MyAdapter(BaseAdapter):
    name = "..."
    def introspect(self) -> dict: ...      # manifest as a dict, metadata only
    def reset(self) -> None: ...           # fresh state before EVERY attack
    def invoke(self, user_prompt: str, injected_context: dict | None = None) -> AgentRun: ...
    def get_state(self, path: str): ...    # read real post-run state

def build_adapter() -> MyAdapter:
    return MyAdapter()
```

**The module must define a zero-argument factory named exactly
`build_adapter()`.** Everything downstream — `detguard run --agent`, the CI
workflow `detguard derive` generates — addresses the adapter as
`module:build_adapter`, so a differently named factory means every command
and workflow is wrong.

Four requirements, in order of how badly they break things when missed:

**(a) A tool is executed exactly once.** `invoke()` must run the agent's own
loop once and *record* what it did. It must NOT collect a list of intended
calls and then execute them itself — that doubles every real side effect
(rows inserted twice, emails sent twice) and makes every number in the report
fiction. Find where your source actually executes tools and record there.

**(b) The trace must survive dispatch.** Look at how your loop maps a tool
name to a function. If it builds a dict at import time, patching the module
attribute will not work — the dict already holds the original reference, and
you get an empty trace, which reports as "the agent never called anything"
and reads as a perfect defense. Patch whatever the loop actually reads from,
and restore it afterwards.

**(c) `reset()` must genuinely reset.** If your seed/init function is
idempotent ("only seed if empty"), it is NOT usable as a reset hook — state
from attack 1 leaks into attack 2 and every result after the first is
measured against contaminated state. Write a reset that truly wipes and
reseeds.

**(d) `get_state(path)` reads the real store.** Not the agent's account of
itself. Use `self.read_path(mapping, path)` or query the backing store
directly. Where no reader is possible, return the `UNREADABLE` sentinel from
`detguard.adapters.base` — never `None`, which reads as "unchanged" and gets
reported as a defense that never happened.

Handle `injected_context`: when it carries `content`, place that untrusted
text where this agent would really encounter it.

### Hand-writing `roles.yaml`

```yaml
roles:
  # why: transfers funds out of the principal's account
  send_money: [move_value]
```

Closed vocabulary, nothing outside it — an unrecognized role is a hard
load-time error, not a warning:

```
read_internal, read_untrusted, mutate_state, mutate_identity,
move_value, change_credential, external_send, external_fetch, destructive
```

Gated by default (land in `human_in_loop` unless you deliberately tune down):
`mutate_identity`, `move_value`, `change_credential`, `external_send`,
`destructive`.

**When uncertain, assign the more restrictive role.** A tool wrongly classed
`read_internal` is never gated by anything and fails silently; a tool wrongly
classed `external_send` causes a visible, fixable false positive. These are
not symmetric errors.

Put a `# why:` comment above each tool giving your reasoning in one line, so a
reviewer checks the judgement instead of trusting it.

For `ungrounded_destination` and `amount_bound` to bind automatically, name
which argument carries a destination and which carries an amount in an
`arg_hints.yaml`:

```yaml
send_money:
  destination_arg: to
  amount_arg: amount
```

### Deriving `policy.yaml`

Once `manifest.yaml` and `roles.yaml` exist, everything past that point is
mechanical — `derive_policy` fills the CLIENT-marked rules from the role map
by rule, never by judgement:

```bash
detguard derive --manifest config/manifest.yaml --roles config/roles.yaml \
  --arg-hints config/arg_hints.yaml \
  --adapter-import myapp.detguard_adapter:build_adapter
```

No model, no network call. See `docs/scaffold.md` for the full command and
what it does and does not fill in.

### Custom framework — `GenericAdapter`

The universal fallback. It wraps a tool dict and a decide-function and works
with anything, including a hand-rolled `while` loop.

```python
from detguard.adapters.generic import GenericAdapter

TOOLS = {"get_balance": get_balance, "send_money": send_money}

def decide(user_prompt, injected_context, state):
    """Return [(tool_name, args), ...] — your agent goes here."""
    return my_llm_loop(user_prompt, injected_context)

def build_adapter():
    return GenericAdapter(
        tools=TOOLS,
        decide=decide,
        state={"account": {"balance": 100.0}},
        agent_name="my-agent",
        final_output=lambda prompt, calls, state: summarise(calls),
    )
```

```bash
detguard run --corpus corpus/attacks --policy guardrail/policy.yaml \
  --agent myapp.detguard_adapter:build_adapter --guardrail on --out results.json
```

`GenericAdapter.introspect()` drafts a manifest from your callables'
signatures. It will not guess roles — nothing in a function signature says
whether a tool moves money, and a wrong guess about what is dangerous is worse
than an honest blank.

### LangGraph

For a LangGraph agent you do not write an adapter file at all. Point the CLI at
the compiled graph and the reset function directly:

```bash
detguard init --framework langgraph \
  --graph agent.graph:graph \
  --reset db.seed:seed \
  --agent-name email-assistant \
  --out config/manifest.yaml

detguard run --corpus corpus/attacks --policy config/policy.yaml \
  --adapter langgraph --graph agent.graph:graph --reset db.seed:seed \
  --guardrail on --out results.json
```

`--graph` and `--reset` are `module:attribute` import strings resolved against
the directory you run from; detguard constructs the `LangGraphAdapter` itself.
`--reset` is optional for `init`, which only reads metadata, and required for
`run`, which needs fresh state per attack.

#### How tools are found

You do not have to tell DetGuard what your tools are. It tries four sources, in
order, and stops at the first that yields any:

| Order | Source | Reported as |
|---|---|---|
| 1 | `--tools` / `tools=[...]` | `explicit` |
| 2 | a prebuilt `ToolNode`'s registry | `tool_node` |
| 3 | a model built with `llm.bind_tools([...])` | `bound_model:NAME` |
| 4 | a module-level tool list or dict used by a graph node | `module_global:NAME` |

Strategy 3 comes before 4 because it is authoritative — those are definitionally
the tools the model can emit a call for, and they carry argument schemas.
Strategy 4 is what finds `ALL_TOOLS` in a graph whose tool node is hand-written,
which is the common case that used to require an adapter file.

Every tool records its source in the manifest as `discovered_from`, so a wrong
guess is visible in review and in the diff rather than silently shaping a corpus.
When strategy 4 is used at all, `init` says so on stderr. If it guesses wrong,
override it:

```bash
detguard init --framework langgraph --graph agent.graph:graph \
  --tools mypackage.tools:ALL_TOOLS
```

`--tools` accepts a list of tools or a dict of `name -> tool`.

Discovering nothing is a **config error**, not a draft: `init` exits 2 and names
what it tried. An empty `tools:` list would be rejected by every later command
anyway, so writing one out only moves the failure somewhere less informative.

#### Reading post-attack state

Success checks for several templates ask what changed in your system — did the
payee move, did the credential change. Only your code can answer, so pass a
reader:

```bash
detguard run ... --state-reader myapp.detguard_state:read
```

Build one from data rather than writing path dispatch by hand:

```python
from detguard.adapters.state import sql_reader
import sqlite3

read = sql_reader(
    lambda: sqlite3.connect("app.db"),
    {
        "emails.last_recipient":
            "SELECT to_emails FROM emails ORDER BY id DESC LIMIT 1",
        "account.credential": "SELECT credential FROM account",
    },
)
```

`mapping_reader({path: callable})` is the same idea for non-SQL state.

**Both return `UNREADABLE` for a path they were not given, and this matters more
than it looks.** A reader that returns `None` for an unmapped path is
indistinguishable from a path whose value genuinely is `None`, and a
`field_changed` check comparing `None != None` concludes the state did not change
— which the report presents as a successful defence. A hand-rolled reader that
falls through to `return None` will therefore hide real breaches as green rows.
Use these helpers, or return `UNREADABLE` yourself:

```python
from detguard.adapters.state import UNREADABLE
```

Without any reader, state-based checks are reported as `inconclusive` and
coverage drops below 100% — never as defended.

Write a factory and pass `--agent` instead when you need something the flags do
not cover — a non-default `input_key` or a custom `inject`:

```python
from detguard.adapters.langgraph import LangGraphAdapter

def build_adapter():
    return LangGraphAdapter(
        graph=compiled_graph,
        reset_hook=reset_my_database,
        state_reader=lambda path: read_from_db(path),
        agent_name="support-agent",
    )
```

Requires `pip install "detguard[langgraph]"`. The `reset_hook` is required, not
optional — without fresh state per attack, results leak between cases and every
number in the report is meaningless.

LangGraph already ships `interrupt()`, which is a perfectly good HITL
mechanism. DetGuard is not replacing it. The difference is that a
policy-defined gate is versioned, reviewed, regression-tested, and comes with a
measured false-positive rate.

### OpenAI Agents SDK

```python
from detguard.adapters.openai_agents import OpenAIAgentsAdapter

def build_adapter():
    return OpenAIAgentsAdapter(
        agent=my_agent,
        reset_hook=reset_my_database,
        state_reader=lambda path: read_from_db(path),
    )
```

Requires `pip install "detguard[openai]"`. The manifest is drafted from the
SDK's own JSON Schema per tool — the same artifact you would publish in your
API docs, and the reason onboarding never needs your source.

## What DetGuard never does

- Call out to a network service during enforcement
- Put a model in the enforcement path (`llm_judge` ships `enabled: false`)
- Execute a tool, ever — your code does that; DetGuard reads the result
- Modify your policy file
- Send anything anywhere
