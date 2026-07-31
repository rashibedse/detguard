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

## Install

```bash
pip install detguard                 # core: pyyaml only
pip install "detguard[dashboard]"    # + Streamlit dashboard
pip install "detguard[langgraph]"    # + LangGraph adapter
pip install "detguard[openai]"       # + OpenAI Agents SDK adapter
```

## What it looks like

Against the example agent that ships with the repo:

```
$ detguard run --corpus corpus/attacks --policy examples/banking_agent/policy.yaml \
    --agent examples.banking_agent.agent:FixtureAgent --guardrail off --run-dir runs/demo
  36 attacks · 35 breached · 0 blocked · defense rate 0.0%

$ detguard run ... --guardrail on --run-dir runs/demo
  36 attacks · 1 breached · 30 blocked · 4 held for approval · defense rate 94.4%
```

One attack still succeeds, and the report names the one-line policy change that
closes it. That finding — a real gap in a real agent — is the deliverable. See
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

If your agent is not on a framework DetGuard already adapts, `detguard
scaffold` reads its source and writes the whole integration — adapter,
manifest, roles, policy, CI workflow — validating every file before it writes
any of them. The role classification and the adapter come from a model; the
policy and the workflow are *derived* by rule. Enforcement is untouched: it
still runs deterministic conditions over a file you reviewed and committed.
See [docs/scaffold.md](docs/scaffold.md).

`streamlit run dashboard/setup.py` turns the same artifacts into forms that
validate before they write — the hand-editing path below still works, these
are the shortcuts.

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
| [scaffold.md](docs/scaffold.md) | Generating an integration for a framework-free agent |
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
