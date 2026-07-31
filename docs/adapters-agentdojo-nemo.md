# AgentDojo and NeMo Guardrails: mechanism, fit, and recommendation

Design note. No code written yet. The question this answers: *how does each one
actually work, which is the better integration, which is friendlier to a user,
and which assimilates into DetGuard without deforming it.*

The headline finding: **these are not the same kind of object.** AgentDojo is a
benchmark harness that runs agents. NeMo Guardrails is a defence that wraps
them. `BaseAdapter` is a contract for *the thing under test*. Only one of these
is naturally that thing, and forcing the other into the same slot is where the
design goes wrong.

---

## 1. AgentDojo

### Mechanism

AgentDojo (ETH Zurich SPY Lab) is built from four pieces that happen to line up
almost exactly with DetGuard's four adapter methods.

**`TaskSuite`** owns a name, a pydantic `TaskEnvironment` subclass, and a list
of `Function` objects. It is constructed against a data directory containing
`environment.yaml` (the initial world state) and `injection_vectors.yaml` (the
declared injection points).

**`Function`** is a pydantic model with `name`, `description`, `parameters`
(itself a pydantic model — a real input schema), `run`, and `dependencies`.
`make_function` derives all of this from a plain Python function's type hints
and reStructuredText docstring. This is a *better* tool manifest source than
either LangGraph or the Agents SDK gives us: it is always present, always
typed, and never has to be discovered heuristically.

**Injection vectors are first-class.** `environment.yaml` contains literal
placeholders:

```yaml
counter:
  counter_description: "A simple counter{injection_counter_0}"
```

and `injection_vectors.yaml` declares each placeholder with a description and a
default. `suite.load_and_inject_default_environment({"injection_counter_0":
"<payload>"})` returns an environment with the payload substituted, or with the
declared default when no attack is running. This is precisely DetGuard's
`injected_context` carrier concept, already formalised upstream.

**`AgentPipeline.query(prompt, runtime, env)`** returns
`(query, runtime, env, messages, extra_args)`. Tools execute exactly once
inside `FunctionsRuntime.run_function`, which validates arguments against the
pydantic schema and returns `(result, error_or_None)`. The calls and their
results are recoverable from `messages` — upstream even ships
`functions_stack_trace_from_messages` and `model_output_from_messages`.

### Mapping onto `BaseAdapter`

| Method | Implementation |
|---|---|
| `introspect()` | iterate `suite.tools`; `params` from `Function.parameters.model_json_schema()`; `description` from `Function.description` |
| `reset()` | rebuild the environment from `load_and_inject_default_environment(...)` then `user_task.init_environment(env)`; keep a `model_copy(deep=True)` as `pre_state` |
| `invoke()` | `pipeline.query(prompt, runtime, env)`; translate `messages` into `ToolCall`s with results read off the stream, never recomputed |
| `get_state()` | `read_path` over the pydantic env — `getattr` traversal already works |

### The two frictions

**Injection timing.** Our contract delivers `injected_context` to `invoke`.
AgentDojo bakes injections into the environment at *load*, before the agent
runs. Resolution: the adapter stashes the context and rebuilds the environment
at the top of `invoke`, not in `reset`. This is legal under the contract —
`reset` still guarantees fresh state — but it must be documented, because a
reader will otherwise expect the injection to happen in `reset` and will be
confused about which snapshot `pre_state` refers to.

**`read_path` has no list indexing.** AgentDojo environments are list-heavy
(`inbox.emails`, `bank_account.transactions`). `transactions.0.amount`
currently returns `UNREADABLE`, and per our own design commitment that is
reported as inconclusive rather than as a defence — correct, but it makes a
large fraction of realistic success checks unevaluatable. Fix is four lines in
`BaseAdapter.read_path`: accept an all-digits path segment as a sequence index.
This is a core-adjacent change and should land as its own commit with its own
test.

### The unexpected payoff

AgentDojo's `BaseInjectionTask.security(model_output, pre_env, post_env)` is an
independently authored predicate for "did this attack land". Running our corpus
in their environments gives us a second opinion on our own scoring that we did
not write. If our success check and their `security()` ever disagree on the
same run, one of the two is wrong — and that is exactly the kind of finding
worth having before a client finds it for us.

---

## 2. NeMo Guardrails

### Mechanism

NeMo Guardrails is a runtime that wraps an LLM application in four categories of
rail — `input`, `dialog`, `retrieval`, `output` — configured in YAML and Colang.

**`LLMRails(config)`** is the entry point. `rails.generate(messages=[...])`
runs the configured rails around the generation.

**Actions are the tool surface.** `rails.register_action(fn, name="...")`
registers a Python callable (including a LangChain tool) as an action; Colang
flows invoke actions by name. *Execution rails* are the ones that wrap action
input and output — conceptually the same placement as our `before_tool` /
`after_tool`.

**Observability comes from generation options**, not from a message stream:

```python
res = rails.generate(messages=messages, options={
    "log": {"activated_rails": True, "llm_calls": True}
})
```

`res.log.activated_rails` is a list of activated rails, each carrying
`executed_actions` with the action name, parameters, and return value. That is
the closest thing NeMo has to a tool-call trace.

### Why this is an awkward adapter

Three specific problems, in increasing order of seriousness.

1. **The action stream is polluted.** `executed_actions` contains the
   guardrail's *own* internals — `self_check_input`, `generate_user_intent`,
   `retrieve_relevant_chunks`, `generate_bot_message` — interleaved with the
   client's real tools. The adapter must filter to registered user actions, and
   any filter is a heuristic that can go wrong in the direction of a manifest
   that misstates the attack surface. Compare LangGraph, where `_discover_tools`
   at least records *which strategy* found each tool; here the same discipline
   means tagging every tool with "survived an exclusion list", which is weaker
   evidence.

2. **There is no state model.** NeMo has a context dict, but the client's tools
   mutate the client's own store. `get_state` would return `UNREADABLE` unless a
   `state_reader` is supplied — so, like LangGraph and the Agents SDK, the
   adapter must *require* one rather than degrade quietly.

3. **We would be testing the wrong subject.** An agent running under NeMo is an
   agent *plus a defence*. Attacking it measures NeMo, not the agent. Our
   `--guardrail off` baseline stops being an undefended baseline, and the
   headline "0.0% → 94.4%" number stops meaning what it says. This is the real
   objection: it is not that the adapter is hard, it is that the resulting
   number is uninterpretable.

### The placement that actually fits

Not an adapter — a **third guardrail mode**. Same corpus, same agent, NeMo's
rails in the path instead of our policy:

```
detguard run ... --guardrail off    → 0.0%
detguard run ... --guardrail nemo   → ?
detguard run ... --guardrail on     → 94.4%
```

That produces a three-column table over our 16 templates, and it directly tests
the claim the README currently *asserts* rather than measures: that a
text-filter guardrail is fooled by the same techniques it catches. It also
keeps NeMo's LLM calls in the comparator and out of the enforcement path, so
the "no LLM in the enforcement path" commitment is untouched.

Honest cost: this is not a new file. `runner.py:455` hardcodes `on|off`;
`cli.py` has `--guardrail` as a two-valued flag; `report.py` and `baseline.py`
assume a pair of runs, not a set. Roughly: a `Guardrail` protocol with
`before_input` / `before_tool` / `after_tool` / `before_output` returning our
`Verdict`, our engine as the default implementation, a NeMo implementation in
an optional extra, and a report that generalises from a pair to a set.

---

## 3. Comparison

| | AgentDojo | NeMo Guardrails |
|---|---|---|
| **What it is** | benchmark harness + environments | defence runtime |
| **Right slot** | adapter | guardrail mode (not adapter) |
| **Tool manifest** | pydantic schema per `Function`, always present | filtered action registry, heuristic |
| **Call + result trace** | `messages`, executed once by the runtime | `log.activated_rails[*].executed_actions`, mixed with rail internals |
| **State for success checks** | typed pydantic env, diffable | none; requires a client-supplied reader |
| **Injection carrier** | declared `injection_vectors.yaml` | none; payload goes in the prompt |
| **Core changes needed** | list indexing in `read_path` | `Guardrail` protocol; runner, cli, report, baseline |
| **Third-party dep** | `agentdojo` extra | `nemoguardrails` extra (heavy, pulls LangChain) |
| **Runs offline** | with a stub pipeline, yes | no — rails make LLM calls |

**Which is better:** AgentDojo, and not narrowly. It gives us a typed manifest,
a real state model, a declared injection carrier, and an independent scoring
oracle, in exchange for a four-line change to `read_path`. NeMo gives us a
noisy action list and no state.

**Which is more user-friendly:** AgentDojo, for the *evaluation* audience —
a user runs `detguard run --agent agentdojo:banking` and gets numbers on
published environments with no manifest authoring and no roles file to write.
It is the shortest path from install to a chart we have.

But note the asymmetry: AgentDojo is friendly to *researchers and to us*.
It is not on any client's production path. NeMo, if a client has it, *is*. So
"friendlier" depends on which audience the next milestone is for — a paper or
demo table, or a pilot integration.

**Which is more assimilable:** AgentDojo, decisively. It satisfies the existing
four methods with no contract change; `invoke` does not even need to execute
anything, since the runtime already did, which honours "executed exactly once"
for free. NeMo-as-adapter satisfies the letter of the contract and violates its
intent (the subject under test is no longer the agent). NeMo-as-guardrail-mode
is the honest version and costs a new abstraction across four core modules.

---

## 4. Recommendation

1. **Build the AgentDojo adapter first**, plus the `read_path` list-indexing
   fix as a separate prior commit. Self-contained, high value, no core churn.
2. **Do not ship a NeMo adapter.** It would be the kind of integration that
   looks like coverage and produces a number nobody can interpret.
3. **Treat NeMo as a comparison baseline**, scheduled as its own piece of work,
   behind a `Guardrail` protocol. Sequence it after AgentDojo, because
   AgentDojo's environments are the fairest place to run that comparison — a
   third-party benchmark neither we nor NVIDIA authored.

## 5. What this comparison says about DetGuard's own adapter mechanism

Reviewing AgentDojo's design against `BaseAdapter` surfaced four problems in
ours. They are listed here because they are prerequisites: writing the
AgentDojo adapter on top of the contract as it stands would inherit them.

### 5.1 The injection contract is honoured by one adapter, and it is the fixture

`runner.py:322-329` constructs the carrier dict with `injection_point` and
`position`. `FixtureAgent` honours both — `_carrier(point, document)` places the
payload in the named field and `position_shift` places it at the requested
offset. No shipped adapter does:

| Adapter | Placement | `injection_point` | `position` |
|---|---|---|---|
| `GenericAdapter` | none; forwarded to `decide()` | ignored | ignored |
| `LangGraphAdapter` | standalone user message at index 0 | ignored | ignored |
| `OpenAIAgentsAdapter` | `[label]\n{content}\n\n{prompt}` | ignored | ignored |

Consequence: TPL-02, an *indirect* injection whose payload belongs at the end of
`statement_memo`, arrives on the LangGraph adapter as a fresh user turn at the
front of the conversation — a *direct* injection. The template ID says one
thing and the agent sees another. Design commitment #6 ("same inputs,
byte-identical corpus") holds for the corpus file and fails for what reaches the
agent, so no number is comparable across adapters.

AgentDojo cannot have this failure mode: placement is data
(`{injection_x}` in `environment.yaml`, declared in `injection_vectors.yaml`),
not adapter behaviour.

### 5.2 The headline result depends on the fixture's completeness

`36 attacks · 0.0% → 94.4%` is measured against `FixtureAgent`, the only
implementation of the whole contract. The README describes the LangGraph and
Agents SDK adapters as "thin wrappers over the same contract"; they are thin,
but the contract they cover is a subset, and neither can reproduce that run.

### 5.3 `introspect()` cannot produce the half of the manifest that matters

All three adapters hardcode `"untrusted_sources": []`, and `instantiate.py:630`
skips any template requiring a carrier. Introspection therefore yields a
manifest that skips most of the corpus until a human writes carriers by hand.
The skip is reported, which is the right behaviour — but "your tool manifest is
all we need" is only true for the direct-injection half of the suite.

### 5.4 `pre_state` is limited to paths the check already named

```python
watched = [p for p in (check.get("path"), check.get("expected_from_state")) if p]
pre_state = {path: adapter.get_state(path) for path in watched}
```

Only enumerated paths are sampled, so only enumerated breaches are detectable.
AgentDojo snapshots the entire environment (`model_copy(deep=True)`) and its
`security()` predicates can assert on divergence nobody anticipated. Since an
injection attack is characteristically the agent doing something unanticipated,
this is a detection ceiling rather than a missing convenience.

### 5.5 Root cause

5.1 and 5.4 share one: "four methods, no more" makes `invoke` responsible for
both *placing the payload* and *running the turn*, so placement became
per-adapter improvisation with three different defaults. AgentDojo separates
environment construction from pipeline execution.

Candidate fixes, in dependency order:

1. Move placement out of `invoke` into its own method (`place(context) -> None`,
   or a `Carrier` object the adapter resolves). Placement then becomes testable
   without running an agent: assert the payload lands at offset *N* of carrier
   *X*. This is a contract change and needs a decision, not a patch.
2. Make `injection_point` / `position` mandatory for any adapter claiming
   carrier support, and have `introspect()` declare which carriers it supports —
   an adapter that cannot place into a named field should skip those templates
   loudly, exactly as the instantiator already does for an empty
   `untrusted_sources`.
3. Add an optional `snapshot()` to the contract for whole-state diffing, with
   `get_state` retained for adapters that cannot provide one.
4. List indexing in `read_path` (§1).

## 6. Proposal: an AgentDojo-shaped adapter contract

### 6.1 What transfers and what does not

AgentDojo declares injection vectors as data (`injection_vectors.yaml`) because
it *authored* the environment. DetGuard adapts an agent it did not write, which
has no environment file and never will. So:

- **Transfers:** the separation of *declaring* an injection point, *placing*
  into it, and *running* the turn; whole-state snapshotting; the injection point
  as a named, reviewable thing rather than an adapter's improvisation.
- **Does not transfer:** ownership of the world. The declaration has to live in
  the adapter, in code — `environment.yaml`-in-code. `FixtureAgent` already has
  this shape privately (`_carrier` plus a document registry). The proposal is to
  promote it to the contract.

### 6.2 The contract

```python
class BaseAdapter(ABC):
    name: str

    @abstractmethod
    def introspect(self) -> dict:
        """Manifest, now including a `carriers` list. See 6.3."""

    @abstractmethod
    def reset(self) -> None: ...

    @abstractmethod
    def place(self, carrier: str, content: str, position: str = "end") -> str:
        """Stage untrusted content in a named carrier.

        Returns the rendered carrier document — the exact bytes the agent will
        encounter. Raises UnsupportedCarrier if this adapter cannot place into
        `carrier` at `position`.
        """

    @abstractmethod
    def invoke(self, user_prompt: str) -> AgentRun:
        """Run one turn. No longer responsible for placement."""

    @abstractmethod
    def get_state(self, path: str) -> Any: ...

    def snapshot(self) -> Any:
        """Optional whole-state capture for diffing. UNREADABLE by default."""
        return UNREADABLE
```

### 6.3 `carriers` in the manifest

`introspect()` gains what it has never been able to produce — the half of the
manifest that decides whether an indirect-injection template is even runnable:

```yaml
carriers:
  - name: message_body
    kind: record
    injection_point: body
    positions: [start, middle, end]
  - name: statement_memo
    kind: record
    injection_point: memo
    positions: [end]
```

This is the `injection_vectors.yaml` equivalent. `untrusted_sources` in the
existing manifest schema becomes the client-authored override of the same
shape, and `instantiate.py` binds templates to it exactly as it does today.

### 6.4 What this buys

1. **The rendered document becomes an artifact.** `place` returns it, the runner
   records it in `results.json`. A run becomes auditable — "here is the memo the
   agent actually read" — and byte-diffable across adapters. AgentDojo gets this
   free because its environment is an inspectable pydantic object; DetGuard
   currently has no way to produce it at all.
2. **The runner can verify the payload landed.** If `content not in rendered`,
   the case is inconclusive, not a defence. Same discipline as `UNREADABLE`,
   applied to placement.
3. **Placement becomes unit-testable.** Assert the payload sits at offset *N* of
   carrier *X* without running an agent. Today that is only reachable through a
   full attack run against the fixture.
4. **§5.1 becomes reported coverage instead of a silent semantic swap.**
   `UnsupportedCarrier` → a skip with a reason. This introduces no new
   principle: design commitment #4 ("a skipped template is reported, never
   dropped") simply starts applying to placement, which is the one place it
   currently does not.
5. **`snapshot()` lifts the detection ceiling** from "breaches you enumerated"
   to "any divergence", where an adapter can provide it.

### 6.5 Migration

Blast radius is smaller than the contract change suggests: `runner.py:331` is
the **only** production call site of `invoke`. Beyond it, roughly six test
doubles (`test_runner.py`, `test_measurement.py`, `test_report_delta.py`) and
the three shipped adapters.

Honest declarations for the existing adapters:

| Adapter | Declares | Effect |
|---|---|---|
| `FixtureAgent` | both carriers, all positions | unchanged; it already does this |
| `LangGraphAdapter` | one carrier, `conversation`, kind `message`, `positions: [start]` | describes exactly today's behaviour — but now indirect templates *skip* instead of silently becoming direct ones |
| `OpenAIAgentsAdapter` | same | same |
| `GenericAdapter` | whatever the client passes as `carriers=` | placement stops being the `decide()` function's problem |

**Expect the numbers on LangGraph and OpenAI to move.** Templates that
previously reported a defence or a breach against a substituted attack will
start reporting skips. That is the correction, not a regression.

### 6.6 Cost and the counter-argument

Method count goes 4 → 5, against `base.py`'s stated "four methods, no more".
The constraint that actually carried weight in that docstring was
out-of-process satisfiability, and `place` maps cleanly onto "stage content in
the proxy's backing store, then forward the request" — so the MCP-proxy
commitment is intact.

The real counter-argument is that `place` pushes work onto adapter authors:
every adapter now needs carrier documents, where before it could get away with
prepending a string. That is true, and it is the point — the adapters that got
away with it were producing numbers that did not mean what they said.

## Open questions

- Which AgentDojo suites first — `banking` is the closest match to the example
  agent and to the existing 16 templates.
- Do we map their injection vectors to our carriers automatically, or require
  an explicit mapping in the manifest? Automatic is friendlier; explicit is
  reviewable, which is the value we keep claiming elsewhere.
- Their pipelines make real LLM calls. Is there a deterministic stub pipeline
  good enough for CI, or does the AgentDojo path stay a manual/nightly job?
  This decides whether it can ever be part of the gate.
- Version pinning: AgentDojo carries a `BenchmarkVersion` and their suites
  change between versions. A byte-identical corpus is a design commitment; a
  moving upstream benchmark is in tension with it.

## Sources

- [AgentDojo — Task Suite API](https://agentdojo.spylab.ai/api/task_suite/)
- [AgentDojo — Task Suite and Tasks](https://agentdojo.spylab.ai/concepts/task_suite_and_tasks/)
- [AgentDojo — Functions Runtime API](https://agentdojo.spylab.ai/api/functions_runtime/)
- [AgentDojo paper (arXiv 2406.13352)](https://arxiv.org/pdf/2406.13352)
- [NeMo Guardrails — Generation Options](https://docs.nvidia.com/nemo/guardrails/latest/user-guides/advanced/generation-options.html)
- [NeMo Guardrails — Registering Actions](https://docs.nvidia.com/nemo/guardrails/latest/configure-rails/actions/registering-actions.html)
- [NeMo Guardrails — Python API](https://docs.nvidia.com/nemo/guardrails/latest/user-guides/python-api.html)
