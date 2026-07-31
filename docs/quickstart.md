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
**1** succeeded · **30** blocked · **4** held for approval · defense rate **94.4%**
Enforcement prevented **34** of 35 attacks that succeed unguarded.
```

The one that still succeeds is `TPL-12`, and the report tells you the one-line
policy change that closes it. That finding — a real gap in *your* agent, not a
demo of ours — is the whole point.

## 4. Open the dashboard

```bash
streamlit run dashboard/app.py
```

Point the sidebar at the directory holding your `results-*.json`.

---

## Lock in the result

Record today's outcome as the baseline, and every future run is checked
against it:

```bash
detguard baseline snapshot --results results-on.json --out corpus/baseline.json
detguard baseline compare --results results-on.json --baseline corpus/baseline.json
```

`compare` exits `0` when nothing regressed, `1` on a regression, `2` on a
config error — which is all a CI gate needs. Copy
`.github/workflows/client-gate-template.yml` into your repo to wire it up.

## Point it at your own agent

Three ways, fastest first.

**`detguard scaffold`** reads your agent's source and writes the whole
integration — adapter, manifest, roles, policy, CI workflow:

```bash
export DETGUARD_API_KEY=...
detguard scaffold --source-dir . --entry agent:run_agent
```

Use this when your agent is **not** on a framework detguard already adapts —
a hand-rolled loop, raw OpenAI function calling, anything where you would
otherwise write an adapter by hand. See [scaffold.md](scaffold.md) for what is
generated versus derived, and why the output is a draft rather than an answer.

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
