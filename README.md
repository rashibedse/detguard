# DetGuard

**Semgrep for AI agent tool calls.**

Policy-as-code enforcement for agent tool calls, plus an adversarial regression
suite that proves the policy still works after every change.

Most guardrail products are input/output text filters — a classifier checking a
model, fooled by the same techniques it catches. DetGuard sits at the
least-served point in the stack: **the tool call itself**, where the arguments
are concrete and the check can be deterministic.

Two things ship together, because neither is worth much alone.

**Enforcement** — a small library you call at four points in your agent loop.
Allow, block, redact, or require approval, decided by a versioned, reviewable
policy file. No LLM in the enforcement path.

**A regression suite** — role-parameterised attack templates that instantiate
against *your* tool manifest, a runner, a baseline, a CI gate and a dashboard.
It answers "is my agent still defended after this change?"

## The four placement points

```python
from detguard import engine, policy
from detguard.events import ToolCall

policy_set = policy.load("guardrail/policy.yaml")

v = engine.before_input(user_text, policy_set)
if not v.allow:
    return refuse(v)

calls = [ToolCall(name=n, args=a) for n, a in agent.decide(v.text)]

v = engine.before_tool(calls, policy_set, user_prompt=user_text)
if v.requires_approval:
    return escalate(v)          # a human may still say yes
if not v.allow:
    return refuse(v)            # a hard stop

for c in calls:
    c.result = execute(c)       # executed exactly once
    v = engine.after_tool(c, policy_set, user_prompt=user_text)
    c.result = v.text or c.result

v = engine.before_output(answer, policy_set, user_prompt=user_text)
```

No framework dependency, no network, no daemon. Adapters for LangGraph and the
OpenAI Agents SDK are thin wrappers over the same contract.

### Or let detguard own the ordering

Getting that sequence right is the client's job above, and every way of getting
it wrong is silent — a missed retrieved-content check, an unthreaded
`user_prompt`, a redaction reported but not applied, an approval collapsed into
a refusal. So `detguard.guarded` ships the ordering itself, in two shapes.

**You own the loop** — all four hooks, no sequencing to reproduce:

```python
from detguard import guarded

result = guarded.run(user_text, policy_set, decide=my_planner,
                     execute=MY_TOOLS, summarise=compose, retrieved=document)
return result.output if result.allowed else refuse(result)
```

**A framework owns the loop** — a decorator on the tool, so the same one works
on LangChain, LangGraph and the Agents SDK:

```python
@tool
@guarded.guard(policy_set)
def send_money(destination: str, amount: float) -> str: ...
```

It gives you `before_tool` and `after_tool` — the two that make this more than a
text filter — and raises `Blocked` or `ApprovalRequired`, which are separate
types so a pause a human could clear never reads as a hard refusal. Wrap the
turn in `guarded.turn(user_text)` so `ungrounded_arg` can still see the original
request. See [docs/integration.md](docs/integration.md) for both in full.

## Install

Alpha, and not on PyPI yet — install from source:

```bash
git clone https://github.com/rashibedse/detguard && cd detguard
pip install -e .                       # core: pyyaml only
pip install -e ".[dashboard]"          # + Streamlit dashboard
pip install -e ".[langgraph]"          # + LangGraph adapter
pip install -e ".[openai]"             # + OpenAI Agents SDK adapter
```

To pin it as a dependency of your own project, name the repo directly:

```
git+https://github.com/rashibedse/detguard.git@main
```

## What it looks like

Against the example agent that ships with the repo:

```
$ detguard run --corpus corpus/attacks --policy examples/banking_agent/policy.yaml \
    --agent examples.banking_agent.agent:FixtureAgent --guardrail off --run-dir runs/demo
  36 attacks · 35 breached · 0 blocked · defense rate 0.0%

$ detguard run ... --guardrail on --run-dir runs/demo
  36 attacks · 1 breached · 31 blocked · 3 held for approval · defense rate 86.1%
```

Read those two numbers together. **86.1%** is the defense rate: 31 hard blocks
out of 36. Three more attacks were held for a human, which takes the
*containment* rate to 94.4% — reported separately, never summed into the
headline, for the reason in the design commitments below. One attack still
succeeds, and the report names the one-line policy change that closes it. That
finding — a real gap in a real agent — is the deliverable. See
[docs/quickstart.md](docs/quickstart.md) to reproduce it in five minutes.

### `prevented` vs `detected` — read this before the defense rate

Every run records an `enforcement` mode, and `blocked` means something
different under each.

**`prevented`** — the adapter exposes a pre-execution seam, so `before_tool` is
consulted inside the agent loop immediately before each tool body runs. A block
stops the call: the transfer does not happen. `OpenAIAgentsAdapter` does this
via the SDK's own `tool_input_guardrails`.

**`detected`** — the adapter has no such seam, so the tool hooks are evaluated
after the agent's turn has already completed. The decision trace is accurate and
the policy logic is identical, but the call has run and the state has already
moved. A `blocked` row here means *"a live integration would have stopped
this"*, which is a claim about the policy, not a record of prevention.

Both are useful and only one is a guardrail. When you call the four hooks
yourself, as in the snippet above, you are always in the first mode — the
distinction exists because a corpus runner has to drive somebody else's agent
loop, and not every framework lets it in.

## What you give us

Not your codebase. Your **tool manifest** — the names and argument schemas of
the tools your agent can call, which every framework already generates and which
contains no business logic — plus a role classification you own and edit.

Attacks are templates bound to roles, so they aim at your surface
automatically. You do not write attacks, and we do not need to know what your
tools do internally. Everything runs in your CI, on your infrastructure.

On LangGraph or the OpenAI Agents SDK, `detguard init` drafts the manifest by
introspecting the framework's own tool registry, and you never write an adapter
at all — pass the graph or the agent object and DetGuard builds one in memory.

Anywhere else, three files are yours to write: `detguard_adapter.py`,
`manifest.yaml`, and `roles.yaml`. There is no model and no code generation
involved, deliberately — classifying what a tool is allowed to do, and finding
the one point in your loop where a call can be recorded without executing it
twice, are judgements about code nobody but you has read. `detguard derive`
then takes those three and derives `policy.yaml` plus a CI workflow from them
*by rule*, no network call and no API key:

```bash
detguard derive --manifest config/manifest.yaml --roles config/roles.yaml \
  --adapter-import myapp.detguard_adapter:build_adapter
```

See [docs/scaffold.md](docs/scaffold.md) for exactly which files are generated,
derived, and neither, and [docs/integration.md](docs/integration.md) for the
adapter contract with a worked example per framework.

Two dashboards, two different jobs. `streamlit run dashboard/setup.py` is a
config wizard — it turns manifest/roles/policy/CI into forms that validate
before they write; the hand-editing path below still works, this is the
shortcut. `streamlit run dashboard/app.py` is the results viewer — point it at
a directory of `results-*.json` and it renders the KPIs, coverage, and
per-attack trace shown above. Neither one executes a tool or invokes an agent.

## Design commitments

These are not defaults. They are the reasons the rest is trustworthy.

- **No LLM in the enforcement path.** `llm_judge` exists in the registry, ships
  `enabled: false`, and fails open when unavailable.
- **A tool is executed exactly once.** `ToolCall.result` is authoritative and is
  never recomputed.
- **A rule that fires changes what the consumer sees.** A `redact` action masks
  the text that actually continues downstream. Reporting a redaction and then
  forwarding the original would make the whole decision trace fiction, so
  results carry a `mitigated` outcome distinct from `blocked`.
- **Weaker outcomes are never summed into stronger ones.** `defense_rate`
  counts hard blocks only. A HITL pause means a human may still say yes, and it
  is reported as `containment_rate`; a redaction is reported as `mitigated`.
- **"Could not measure" is not "passed", and not "regressed" either.** An
  unmeasurable run exits `3`, distinct from a real regression's `1`, so a flaky
  provider cannot look like a security change. `--allow-unmeasured` downgrades
  it to a warning.
- **A success check never passes on an empty tool-call list.** An agent that did
  nothing did not fall for anything.
- **A skipped template is reported, never dropped.** "Not applicable to this
  agent, and here is why" is coverage information.
- **Core never imports an adapter or a framework.**
- **Same inputs, byte-identical corpus.** Otherwise a diff means nothing.
- **A blocked benign case fails the build.** An unmeasured false-positive rate
  ends with the guardrail switched off.

## Docs

| Doc | What it answers |
|---|---|
| [quickstart.md](docs/quickstart.md) | Nothing to a dashboard in five minutes |
| [scaffold.md](docs/scaffold.md) | What `derive` fills in, and what stays hand-written |
| [integration.md](docs/integration.md) | Where the four hooks go; all three adapters |
| [policy-reference.md](docs/policy-reference.md) | Every condition, param and action |
| [attack-corpus.md](docs/attack-corpus.md) | The 16 templates and the 8 mutations |
| [roles.md](docs/roles.md) | Classifying tools; tuning the gate down safely |
| [ci.md](docs/ci.md) | Baselines, known gaps, regression classes, exit codes |

## Honest status

Alpha. The engine, corpus, instantiator, runner, dashboard, baseline gate and
adapters are built and work. What is **not** built: proxy/sidecar mode, a hosted
decision API, an LLM-backed role classifier, a policy generator, and the benign
corpus content (the schema and loader exist; the cases are yours to write).

Chain-level policy *across* multiple agents is a known gap, not a feature.

## Licence

Apache-2.0.
