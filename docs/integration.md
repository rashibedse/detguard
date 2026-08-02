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

## Three ways to install enforcement

Calling the four hooks in the right order, with the right arguments, is the part
a host application has to get right — and every way of getting it wrong is
silent. Pick the highest-level option your agent's shape allows.

| | Use when | Hooks you get |
|---|---|---|
| `guarded.run()` | you own the loop | all four |
| `guarded.guard()` | a framework owns the loop | `before_tool`, `after_tool` |
| the four hooks by hand | you need control the other two do not give | all four, your ordering |

### `guarded.run()` — you own the loop

```python
from detguard import guarded, policy

policy_set = policy.load("guardrail/policy.yaml")

result = guarded.run(
    user_text,
    policy_set,
    decide=my_planner,        # fn(prompt, calls_so_far, retrieved) -> [(name, args), ...]
    execute={"get_balance": get_balance, "send_money": send_money},
    summarise=lambda prompt, calls: compose_answer(calls),
    retrieved=fetched_document,
)

if result.refused:
    return refuse(result)
return result.output
```

`decide` is called repeatedly until it returns nothing, so an agent that reads a
document and *then* decides what to do with it works — which is what real agents
do, and what a single decide-then-execute batch cannot express.

`max_rounds` defaults to 8, and exhausting it **raises `RuntimeError`** rather
than returning what it had — an agent still asking for tools after 8 rounds is a
bug or a denial of service, not a turn to summarise. Note that the exception
discards the `TurnResult`, including the decision trace for calls that already
executed, so catch it if you need that record.

It never raises on a block: enforcement stopping a turn is an outcome, not an
error. Read it off the [`TurnResult`](#reading-a-turnresult).

`retrieved` is checked as retrieved content, which is the flag separating "the
user said this" from "a document said this" — and if a redaction fires on it,
`result.retrieved` holds the masked version the agent actually saw.

`execute` callables must be **synchronous**. See [Async tools](#async-tools).

### `guarded.guard()` — a framework owns the loop

A decorator on the tool rather than the orchestration, which is why the same one
works on LangChain, LangGraph and the Agents SDK — a tool is a plain callable in
all three. Put it **below** the framework's own decorator so it wraps the
function:

```python
from detguard import guarded

@tool                              # LangChain/LangGraph, or @function_tool
@guarded.guard(policy_set)
def send_money(destination: str, amount: float) -> str: ...
```

It raises rather than returning a verdict, because a framework's tool-calling
machinery has nowhere to put one:

```python
try:
    answer = agent.invoke(user_text)
except guarded.ApprovalRequired as stop:
    return escalate(stop.verdict)      # a human may still say yes
except guarded.Blocked as stop:
    return refuse(stop.verdict)        # a hard stop
```

Both subclass `guarded.GuardrailStop`, and they are separate types on purpose —
catching only the base class collapses an approval prompt into a refusal.

**Set the turn prompt, or lose a layer.** The decorator cannot see the original
request, so it reads one from a context variable:

```python
with guarded.turn(user_text):
    answer = agent.invoke(user_text)
```

`guarded.run()` does this for you. Under a framework it is yours to do, and
without it `ungrounded_arg` — the condition that catches an injected destination
— declines to fire rather than guessing. Nothing warns you.

**Three limits, stated because a silent gap is worse than a documented one.**

**It is sync-only** — see [Async tools](#async-tools) below, which applies to
`run()` equally.

**It sees one call, not the batch**, so `call_budget`, `repeated_call` and
anything reasoning over a whole decided batch cannot do their job through it.
Use `run()` or the framework's own batch hook when those matter.

**It carries `before_tool`/`after_tool` only** — the other two need
per-framework wiring.

### Async tools

**Neither `run()` nor `guard()` awaits, so an `async def` tool silently loses
`after_tool`.** The tool is called but not awaited, so `call.result` holds the
coroutine object rather than the value, and every result-inspecting condition
examines a coroutine and finds nothing in it. The call still runs, and its result
still reaches the agent — unchecked and unredacted.

```python
@guarded.guard(policy_set)
def read_note() -> str: ...        # after_tool fires; a leaked secret is blocked

@guarded.guard(policy_set)
async def read_note() -> str: ...  # after_tool sees a coroutine; the secret gets through
```

`guarded.run(execute={"read_note": read_note})` behaves the same way for the
same reason — this is a property of the module, not of the decorator.

`before_tool` is unaffected either way: arguments are concrete before the
coroutine is ever created, so the HITL gate and every argument-level rule still
hold. It is specifically `after_tool` — result inspection and redaction — that
goes quiet.

This matters because tools in all three frameworks above are commonly async.
Until it is fixed, **hand `guarded` a synchronous callable** and do the awaiting
inside it:

```python
@guarded.guard(policy_set)
def read_note() -> str:
    return asyncio.run(_read_note_async())   # after_tool sees a str again
```

### Reading a `TurnResult`

```python
result.allowed            # False if anything stopped the turn
result.refused            # not allowed
result.requires_approval  # a human may still clear it
result.output             # the final answer, post-redaction, "" if stopped
result.tool_calls         # every ToolCall, with .result set
result.retrieved          # the document as the agent saw it, post-redaction
result.blocked_at_hook    # which of the four
result.blocked_by         # the rule id
result.severity
result.decisions          # every rule evaluated, fired or not
result.to_dict()          # JSON-ready, for your own audit sink
```

## Calling the four hooks by hand

Everything below is what `guarded` does for you. Reach for it when neither shape
above fits — but the four mistakes it exists to prevent are all silent, so read
the notes after the snippet before choosing this path.

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

Five things about that snippet are load-bearing.

**Retrieved content gets its own `before_input`.** The snippet above only checks
the user's message. Any document the agent fetched needs a second call with
`is_retrieved=True` — that flag is what separates "the user said this" from "a
document said this", and skipping it removes the entire indirect-injection
defence. `guarded.run(retrieved=...)` does it for you.

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

As with LangGraph, you do not need an adapter file. Point the CLI at the
`agents.Agent` instance itself with `--agent-obj`:

```bash
detguard init --framework openai_agents \
  --agent-obj myapp.agent:support_agent \
  --out config/manifest.yaml

detguard run --corpus corpus/attacks --policy config/policy.yaml \
  --adapter openai_agents --agent-obj myapp.agent:support_agent \
  --reset db.seed:reset --guardrail on --run-dir runs/first
```

`--agent-obj` is a `module:attribute` import string and is deliberately distinct
from `--agent`, which names a zero-arg *factory*. `--reset` is optional for
`init`, which only reads metadata, and required for `run`, which needs fresh
state per attack.

`--state-reader myapp.detguard_state:read` works here too, exactly as it does
for LangGraph above — state-based success checks need it, and without one they
report as `inconclusive` rather than as defended.

Write a factory and pass `--agent` instead when you need something the flags do
not cover:

```python
from detguard.adapters.openai_agents import OpenAIAgentsAdapter

def build_adapter():
    return OpenAIAgentsAdapter(
        agent=my_agent,
        reset_hook=reset_my_database,
        state_reader=lambda path: read_from_db(path),
    )
```

Requires `pip install "detguard[openai]"`, which installs the `openai-agents`
SDK. The manifest is drafted from the SDK's own JSON Schema per tool — the same
artifact you would publish in your API docs, and the reason onboarding never
needs your source.

**This is the only adapter that *can* measure in `prevented` mode**, and it is
worth reading that as conditional. It attaches the runner's guard to each tool's
own `tool_input_guardrails`, and when that attaches, a block during a corpus run
stops the call before the tool body runs. `set_tool_guard` returns False — and
the run silently falls back to `detected` — when the agent has no tools, or when
the installed SDK predates `tool_input_guardrails`. Check the `enforcement`
field in `results.json` rather than assuming; that is what it is there for.

Every other adapter has no such seam and evaluates hooks after `invoke()`
returns — see the README's
[`prevented` vs `detected`](../README.md#prevented-vs-detected--read-this-before-the-defense-rate)
section, because the two must never be averaged into one defense rate.

## What DetGuard never does

- Call out to a network service during enforcement
- Put a model in the enforcement path (`llm_judge` ships `enabled: false`)
- Execute a tool, ever — your code does that; DetGuard reads the result
- Modify your policy file
- Send anything anywhere
