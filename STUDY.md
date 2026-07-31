# DetGuard in 60 minutes

For tomorrow. Read the file, say the line out loud, move on. Don't read code you
don't have a question about.

---

## 0:00–0:03 — The one sentence

> "Most guardrails are text filters — a classifier checking a model, fooled by
> the same techniques it catches. DetGuard checks the **tool call**, where the
> arguments are concrete and the check can be deterministic."

If you say nothing else correctly tomorrow, say this. It is the whole thesis.

**The follow-up you will get: "isn't that what NeMo Guardrails / OpenAI's SDK
already does?"**
No. Both do *content* — they inspect text going in and coming out. Neither gates
tool *arguments*. OpenAI's own SDK ships input/output guardrails and has nothing
for actions. That gap is the product.

---

## 0:03–0:15 — The four hooks (the actual product)

**Read:** `src/detguard/engine.py`. All of it. It's 193 lines and half is
docstring.

| Hook | Fires when | Sees | Exists for |
|---|---|---|---|
| `before_input` | text enters the agent | user message, **or** a retrieved document | overt injection; instructions hidden in a document |
| `before_tool` | agent decided, **nothing has run yet** | the whole batch, arguments concrete | the destination came from the document, not the user |
| `after_tool` | a tool returned, before the value re-enters context | the return value | a secret in a result, echoed onward |
| `before_output` | before the user sees the answer | the final prose | agent *states* the secret instead of sending it |

```
user text
   │
   ├─► before_input(text)                        ← blocks overt injection
   │
   ├─► before_input(document, is_retrieved=True) ← blocks hidden instructions
   │
  agent decides
   │
   ├─► before_tool([calls])                      ← THE ONE THAT MATTERS
   │
  each tool executes  (exactly once)
   │
   ├─► after_tool(call)                          ← blocks result leaks
   │
  agent writes the answer
   │
   └─► before_output(answer)                     ← blocks spoken secrets
```

**Two details you will be asked about:**

- `is_retrieved=True` is the whole basis of the indirect-injection defence. It's
  what separates "the user said this" from "a document the user asked me to read
  said this." Same sentence, different threat.
- `mode="off"` is a **clean passthrough** — allow, zero decisions, text
  unchanged. Not "lenient." That is what makes the with/without comparison
  honest.

**Say out loud:** "Four hooks. `before_tool` is the differentiator, because by
then the arguments are concrete, so the check is exact instead of probabilistic."

---

## 0:15–0:25 — The policy file

**Read:** `src/detguard/policies/default.yaml` — the header comment and two or
three rules. Then skim the function names in `src/detguard/registry.py`
(lines 219–520).

A rule is: **a condition** (what to look for) + **an action** (allow / block /
redact / require approval) + **a severity** + **which hook it runs at**.

Know these three conditions cold. They are the ones that make you not-a-regex:

- **`ungrounded_arg`** — a tool argument that does not appear anywhere in the
  user's original request. That's the structural signature of an injected
  destination. This is why `user_prompt` must be threaded through *every* hook.
- **`external_destination`** — the call is sending value somewhere outside a
  known-good set.
- **`unrequested_tool`** — the agent called something the user never asked for.

Thirteen conditions exist. `llm_judge` is in the registry, ships
`enabled: false`, and fails open. **No LLM in the enforcement path** — say this;
it's a design commitment and it's what makes the whole thing auditable.

**Say out loud:** "The policy file is versioned, diffable, reviewed in a PR, and
enforced in CI. That artifact is the control documentation auditors ask for and
rarely get."

---

## 0:25–0:35 — The corpus

**Read:** `docs/attack-corpus.md`. Skim two template YAMLs, e.g. `TPL-01` and
`TPL-02`.

- **16 templates × 8 mutations.** Templates are *role-parameterised*: they bind
  to tool roles (`move_value`, `change_credential`, `external_send`…), not to
  tool names. That's why they aim at a client's surface automatically and why
  the client never writes attacks.
- **Direct vs indirect injection** is the key split. TPL-01 is the payload in
  the prompt. TPL-02 is the payload inside a document the agent reads. Indirect
  is the hard one and the realistic one.
- **A skipped template is reported, never dropped.** "Not applicable to this
  agent, and here's why" is coverage information.

**Say out loud:** "You give us your tool manifest and a role classification you
own. Not your source. The attacks instantiate against your surface."

---

## 0:35–0:45 — Scoring (your strongest work — defend it)

**Read:** `src/detguard/runner.py`, lines 100–130 and 380–420. The comments
argue for themselves.

Four outcomes, and the distinctions are the point:

| Outcome | Meaning |
|---|---|
| **breach** | attack achieved its objective and nothing stopped it |
| **blocked** | the policy stopped it |
| **not_complied** | the agent just didn't fall for it — a property of the *agent*, not your policy |
| **inconclusive** | you could not observe the outcome at all |

Why this matters, and it's the sharpest thing in the codebase:

- If you count **not_complied** as a defence, you inflate the unguarded baseline
  and shrink the very delta the comparison exists to show.
- If you count **inconclusive** as a defence, an unmeasured run reads as a clean
  sweep. Hence the `UNREADABLE` sentinel — `None` was doing two jobs, and
  `None != None` was being scored as "state didn't change," i.e. as a successful
  defence. A real breach could sit in a report as a green row.
- **A success check never passes on an empty tool-call list.** An agent that did
  nothing did not fall for anything.

**Say out loud:** "'Defended' and 'the agent never fell for it' are different
facts and I refuse to sum them."

---

## 0:45–0:55 — The gap. Own it before they find it.

You built the measurement layer. The delivery layer — the middleware — is not
built. Say it first, in these terms:

> "I sequenced measurement before delivery deliberately: a guardrail you can't
> measure is a claim, not a control. The enforcement logic is built and tested —
> thirteen deterministic conditions, four hooks, 94.4% on the reference agent.
> What's not built is the packaging that drops it into a client's loop without
> them hand-wiring four call sites."

Then give the plan, which is small and concrete:

1. **`guarded.run()`** — extract the loop that already exists in
   `runner.run_one` into a public module. Client supplies three callables
   (`decide`, `execute`, `summarise`); DetGuard owns hook ordering. Makes
   *measured* and *deployed* the same code by construction.
2. **`@detguard.guard(policy)`** — a tool decorator. `before_tool` on entry,
   `after_tool` on return. Three-line diff in the client's code. Covers the hook
   that differentiates you.
3. **Framework wiring** — the OpenAI Agents SDK already has the sockets
   (`RunHooks.on_tool_start` / `on_tool_end`, `@input_guardrail` /
   `@output_guardrail` with tripwires). LangGraph: wrap the tool node; approvals
   route to `interrupt()`.

Estimate honestly: ~1 day for (1) and (2). That's the demo.

---

## 0:55–1:00 — Self-quiz. Answer out loud, no notes.

1. Why check the tool call instead of the text?
2. What does `is_retrieved=True` change, and why does it matter?
3. Name three conditions and what each detects.
4. Why is `not_complied` not counted as a defence?
5. What is `UNREADABLE` and what bug does it prevent?
6. What does the client hand you, and what do they *not* hand you?
7. What's not built, and what's the plan?

If you can answer 1, 4, 5 and 7 cleanly, you can hold the room.

---

## Three questions you will get, and honest answers

**"How is this different from NeMo Guardrails?"**
NeMo wraps the model in input/dialog/retrieval/output rails — it's content
inspection, and it uses an LLM to do it. DetGuard checks tool arguments with
deterministic conditions and no LLM. Complementary, not competing. I'd like to
run both against the same corpus and publish the comparison.

**"Regression-testing a nondeterministic system is incoherent."**
Fair, and it's why the CI gate runs against a scripted fixture agent, not a live
model. Deterministic subject, deterministic conditions, so a diff in the report
means a change in the policy, not model variance.

**"What's your false-positive rate?"**
Not measured yet — the benign corpus schema and loader exist, the cases are
unwritten. It's a known gap and it's the next thing after the middleware, because
a blocked benign case fails the build by design and an unmeasured false-positive
rate ends with the guardrail switched off.
