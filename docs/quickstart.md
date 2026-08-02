# Quickstart

Five minutes, from nothing to a dashboard showing what a policy actually buys
you. Every command below is copy-pasteable and runs against the fixture agent
that ships with the repo — no API key, no network, no model.

## Install

```bash
git clone https://github.com/rashibedse/detguard && cd detguard
pip install -e ".[dashboard,dev]"
detguard --help
```

> If `detguard` is not on your `PATH` after install (common on Windows, where
> pip puts it in `%APPDATA%\Python\Python3xx\Scripts`), use `python -m
> detguard` in place of `detguard` for every command below. It is the same
> entry point.

## 1. Build a corpus from a manifest

Attacks are role-parameterised templates. They bind to whatever tools *your*
agent has, so nobody writes attacks by hand:

```bash
detguard corpus build \
  --manifest examples/banking_agent/manifest.yaml \
  --roles examples/banking_agent/roles.yaml \
  --out corpus/attacks
```

36 concrete attacks from 16 templates. Read one — `corpus/attacks/TPL-08-base.yaml`
— and you will see the technique bound to real tool names, a planted attacker
value, and a success check that verifies real post-run state.

Anything that could not bind is in `corpus/attacks/_skipped.yaml` with a
reason. Skipped templates are coverage information, never a silent drop.

## 2. Run it twice

Once with the guardrail off, to find out what the agent does unaided:

```bash
detguard run --corpus corpus/attacks --policy examples/banking_agent/policy.yaml \
  --agent examples.banking_agent.agent:FixtureAgent --guardrail off --run-dir runs/demo
```

Once with it on:

```bash
detguard run --corpus corpus/attacks --policy examples/banking_agent/policy.yaml \
  --agent examples.banking_agent.agent:FixtureAgent --guardrail on --run-dir runs/demo
```

Neither command needs `--out`: results go to `runs/demo/results-off.json` and
`runs/demo/results-on.json`, and a `run.yaml` records what produced them —
corpus, policy, adapter, everything needed to reproduce the run six weeks
later. `--run-dir` is what keeps a guarded/unguarded pair together; omit it
and each invocation gets its own fresh `runs/<timestamp>/` instead.

## 3. Get the report

```bash
detguard report --results runs/demo/results-on.json \
  --unguarded runs/demo/results-off.json
```

`ci_report.json` and `ci_report.md` default into the same directory as
`--results` — `runs/demo/` here — so the whole run stays in one place. Pass
`--out`/`--markdown` explicitly to put them somewhere else.

```
**1** succeeded · **31** blocked · **3** held for approval · **0** mitigated · defense rate **86.1%**
Measured **36** of 36 attacks (coverage **100.0%**)
Enforcement prevented **34** of 35 attacks that succeed unguarded.
```

**86.1%**, not 94.4%, and the difference is the point. Thirty-one attacks were
blocked outright; three more were held for a human, who may still say yes.
Those three are counted in `containment_rate` (94.4%) and deliberately kept out
of `defense_rate` — summing them would report a maybe as a no. See
[ci.md](ci.md) for both numbers side by side.

The one that still succeeds is `TPL-12`, and the report tells you the one-line
policy change that closes it. That finding — a real gap in *your* agent, not a
demo of ours — is the whole point.

## 4. Open the dashboard

```bash
streamlit run dashboard/app.py
```

Point the **Results directory** field at `runs/demo`. Three more sidebar fields
are optional, and each one switches on a tab:

| Field | Point it at | What it unlocks |
|---|---|---|
| Config directory | the folder holding `manifest.yaml` / `roles.yaml` / `policy.yaml` | **🛠 Coverage by tool** |
| Baseline file | `corpus/baseline.json` | **🚦 Regression gate** |
| Audit log | the `--audit-log` path from your run | **📜 Audit log** |

They are guesses by default, and a wrong guess is harmless — the tab says what
it could not find and every other tab keeps working.

The seven tabs, and who each is for:

- **📊 Overview** — the guarded/unguarded bar chart. The one chart that shows
  what the policy actually bought you. Needs both runs loaded.
- **🛠 Coverage by tool** — per tool: its roles, which rules reference it, how
  it fared against the corpus, and a flag on any sensitive tool no rule covers.
  This is the tab for deciding where you still need a guardrail, and the only
  one that answers that from your config rather than from this run's luck.
- **🧩 Coverage & layers** — which layer stopped what, the family × severity
  heatmap, and which mutations survived. A single layer carrying everything is
  a warning, not a result.
- **🚦 Regression gate** — the same `baseline.compare()` your CI gate runs,
  with its pass/fail verdict and exit code. Useful for seeing *why* a build
  went red without reading the workflow log.
- **🔍 Per-attack detail** — worst outcomes first: success check, tool calls,
  full decision trace, final output.
- **📜 Audit log** — every decision the engine recorded, filterable by hook,
  tool and verdict. Empty unless you passed `--audit-log`.
- **⬇ Export** — the filtered view as CSV.

The dashboard reads files and renders them. It never invokes an agent, never
evaluates a policy against live traffic, and never writes anything.

---

## Lock in the result

Record today's outcome as the baseline, and every future run is checked
against it:

```bash
detguard baseline snapshot --results runs/demo/results-on.json --out corpus/baseline.json
detguard baseline compare --results runs/demo/results-on.json --baseline corpus/baseline.json
```

Note the `runs/demo/` prefix: step 2 wrote the results there, not into the
directory you are standing in.

`compare` exits `0` when nothing regressed, `1` on a regression, `2` on a
config error, and `3` when the run could not measure enough to make a claim
either way — which is all a CI gate needs. That fourth code matters: a flaky
provider that leaves attacks unobserved must not look like a security
regression, and `--allow-unmeasured` downgrades it to a warning when you have
decided it is acceptable. Copy
`.github/workflows/client-gate-template.yml` into your repo to wire it up.

## Point it at your own agent

Three ways, fastest first.

**`detguard derive`** takes a hand-written `detguard_adapter.py`,
`manifest.yaml` and `roles.yaml` and derives `policy.yaml` plus a CI workflow
from them, mechanically:

```bash
detguard derive --manifest config/manifest.yaml --roles config/roles.yaml \
  --adapter-import myapp.detguard_adapter:build_adapter
```

Use this when your agent is **not** on a framework detguard already adapts —
a hand-rolled loop, raw OpenAI function calling, anything where you would
otherwise write an adapter by hand. No model, no network call: the adapter,
manifest and role classification are yours to write (see
[integration.md](integration.md) for the contract and checklist); only
`policy.yaml` is derived. See [scaffold.md](scaffold.md) for what is derived
versus hand-written.

**`streamlit run dashboard/setup.py`** walks through manifest, roles, policy,
run commands and CI as forms that validate before they write, with tool lists
pre-populated by the same discovery cascade `detguard init` uses. Use this when
you want to author the config yourself with guardrails on the editing.

**By hand** — the rest of this section. Three things, in this order.

**A manifest.** The names and argument schemas of your tools — no source code.
Start from a skeleton and fill it in, or let an adapter draft it:

```python
from detguard.adapters.generic import GenericAdapter
import yaml

adapter = GenericAdapter(tools=MY_TOOLS, decide=my_agent_loop)
print(yaml.safe_dump(adapter.introspect()))
```

**A role map.** Which of your tools move money, change identity, read
untrusted content. Nine roles, closed vocabulary — see [roles.md](roles.md).
This is the artifact everything else keys off.

**An adapter.** A zero-argument callable returning a `BaseAdapter`, passed as
`--agent yourmodule:factory`. `GenericAdapter` wraps any hand-rolled loop and
is the universal fallback.

On LangGraph you can skip the factory entirely — pass the graph and the reset
hook as import strings and DetGuard builds the adapter itself:

```bash
detguard init --framework langgraph --graph agent.graph:graph \
  --reset db.seed:seed --agent-name email-assistant --out manifest.yaml
```

Import strings resolve against the directory you run from, so `detguard` and
`python -m detguard.cli` behave identically. See
[integration.md](integration.md) for the full LangGraph and OpenAI Agents SDK
setups.

Then rerun steps 1–4 against your own files. Copy `detguard/policies/default.yaml`
into your repo, fill in the four rules marked `CLIENT`, and commit it — that
file is now your control documentation.

## Where to go next

| Doc | What it answers |
|---|---|
| [integration.md](integration.md) | Where the four hooks go in a real agent loop |
| [policy-reference.md](policy-reference.md) | Every condition, param and action |
| [attack-corpus.md](attack-corpus.md) | The 16 templates and what each one tests |
| [roles.md](roles.md) | How to classify tools, and how to tune the gate down safely |
| [ci.md](ci.md) | Baselines, known gaps, regression classes, exit codes |
