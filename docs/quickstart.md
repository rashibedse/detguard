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
> detguard.cli` in place of `detguard` for every command below. It is the same
> entry point.

## 1. Build a corpus from a manifest

Attacks are role-parameterised templates. They bind to whatever tools *your*
agent has, so nobody writes attacks by hand:

```bash
detguard corpus build \
  --manifest tests/fixture_manifest.yaml \
  --roles tests/fixture_roles.yaml \
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
detguard run --corpus corpus/attacks --policy tests/fixture_policy.yaml \
  --agent tests.fixture_agent:FixtureAgent --guardrail off --out results-off.json
```

Once with it on:

```bash
detguard run --corpus corpus/attacks --policy tests/fixture_policy.yaml \
  --agent tests.fixture_agent:FixtureAgent --guardrail on --out results-on.json
```

## 3. Get the report

```bash
detguard report --results results-on.json --unguarded results-off.json \
  --out ci_report.json --markdown ci_report.md
```

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

Three things, in this order.

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
hook as import strings and detguard builds the adapter itself:

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
