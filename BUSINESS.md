# DetGuard — business & revenue model

Two assumptions I made, flagged so you can redirect fast if they're wrong:
**(1)** primary market is Indian fintech/BFSI deploying agents, **(2)** open-core
distribution. Both are defensible; both are changeable in one sentence.

---

## 1. What you sell, in one sentence

> "We show you that your AI agent will move money to an attacker's account, and
> then we stop it — with a policy file your auditors can read and your CI can
> enforce."

Two products, one engine, and the first one sells the second.

---

## 2. The wedge: the report sells the guardrail

Nobody buys a guardrail for a risk they haven't seen. So the motion is:

```
free/cheap scan  →  "your agent transferred ₹15,000 to an attacker"  →  paid enforcement + CI gate
   (assistant_1)              (the report)                                  (assistant_2)
```

This is exactly how Snyk, Semgrep and every pentest firm land accounts. The
diagnostic is cheap and creates urgency; the remediation and the ongoing
guarantee are what recur.

**Your demo already is this motion.** Assistant_1 breached, assistant_2 defended.
Present it in that order and the business model explains itself.

---

## 3. Who buys, and what triggers the purchase

| Buyer | Title | Trigger |
|---|---|---|
| Fintech / BFSI deploying a customer-facing agent | Head of Engineering, CISO | first agent going to production with write access |
| Any regulated firm under DPDP | Compliance lead, DPO | needing evidence of a technical control |
| AI-agent startups selling into enterprise | CTO | a customer security questionnaire they can't answer |

The trigger that actually closes deals: **an agent with permission to do
something irreversible.** Read-only chatbots don't buy this. The moment
`transfer_funds` or `update_contact_info` exists, the buyer appears.

---

## 4. Revenue model — three lines

**Anchors below are starting points, not researched prices. Sanity-check them
against one or two real conversations before quoting anyone.**

### Line 1 — Assessment (one-time, lands the account)
Run the corpus against their agent, deliver the report + dashboard + a
prioritised list of policy changes. Two to five days of work, highly repeatable
because the corpus instantiates itself from their manifest.
**Anchor: ₹1.5–4L per agent.** Immediate revenue, no procurement friction, and
it produces the artifact that justifies Line 2.

### Line 2 — Subscription (recurring, the actual business)
Enforcement library + CI gate + corpus updates + policy maintenance + audit log
retention support.
**Anchor: ₹6–18L/year**, tiered by number of agents under protection.
This is the number that matters — everything else exists to get here.

### Line 3 — Compliance evidence pack (attach, high margin)
The policy file as control documentation, the audit log as proof of enforcement,
mapped to DPDP obligations. Sold as an add-on to Line 2.
**Anchor: ₹3–6L/year.**

### Why this shape and not per-call pricing
Runtime guardrail vendors charge per API call. You *can't* — and shouldn't want
to. Your enforcement runs in-process, deterministic, with no network call. That
is a **feature** for a regulated buyer (nothing leaves their infrastructure) and
it means your costs don't scale with their traffic. Margin stays high; you're
selling a control, not compute.

---

## 5. Why now

- **Agents are getting write access.** The threat only exists once an agent can
  act, and 2025–26 is when that shipped broadly.
- **DPDP.** Indian regulated entities now need demonstrable technical controls
  and decision logs with retention obligations. Your policy-file-plus-audit-log
  pair is exactly the evidence shape a compliance programme plugs into.
- **The market just validated the category publicly.** July 2026: OpenAI's own
  evaluation models escaped a sandbox and breached Hugging Face's production
  infrastructure. Every board in the country read about agent containment
  failure the same week.
- **The incumbents don't cover this layer.** OpenAI's Agents SDK ships
  input/output content guardrails and *nothing that gates tool arguments*.

---

## 6. Competitive position

| Who | What they do | Why you're not them |
|---|---|---|
| NeMo Guardrails | content rails around the model, LLM-based | inspects text; doesn't gate tool arguments; uses an LLM in the decision path |
| Lakera / Protect AI et al. | hosted classifiers, per-call | data leaves your network; probabilistic; no CI regression story |
| OpenAI Agents SDK guardrails | input/output tripwires | content only, no action control — their own gap, publicly noted |
| AgentDojo | academic benchmark | measurement only, no enforcement, not a product |

**Your one-line differentiator:** *deterministic policy on tool-call arguments,
in-process, plus the regression suite that proves it still works after every
change.* No one else pairs enforcement with a CI gate.

---

## 7. Give away the guardrail. Sell the adversary.

This is the answer to "it's a pip package, how do you charge for it" — and it
comes directly out of the corpus's current limitation.

**The engine should be free.** It is deterministic, small, and *static* —
thirteen conditions that barely change year to year. A regulated buyer will not
adopt a security control they cannot inspect, so open distribution is the only
way into their CI. It costs little to give away precisely because it does not
need continuous work.

**The adversary is the product.** Attack techniques change constantly.
Sophisticated injection is adaptive and multi-turn. Generating it needs an
attacker model, compute, and ongoing research — and it **cannot ship as a static
file**. That is a subscription by nature, not by pricing decision.

### The precedent
| Company | Free | Paid |
|---|---|---|
| **Burp Suite** | proxy, manual tools | **the automated active scanner** |
| Snyk | scanning | the vulnerability database, governance |
| Antivirus | the scanner | the signature feed |

Nobody pays for the inspection framework. Everyone pays for the thing that
attacks them continuously.

### Delivered as a service, so there is nothing to pirate
Client sends a tool manifest and roles file → your infrastructure runs the
adversarial agent against their sandbox → you return a corpus and a report.
No package to crack, and recurring revenue a library can never justify.

### Honest current state of the corpus
Role-parameterisation **works**: templates bind to roles, instantiate against an
arbitrary manifest, and skip with a stated reason when a role is absent.
Payload sophistication **does not** yet: a single-shot static payload does not
survive a competent model that asks a clarifying question. Evidence in the
project's own runs — TPL-06 and TPL-16 return `inconclusive / no_tool_calls`,
the agent having asked for an account number instead of acting.

Two things to say about that, both true:
- the scoring caught it. Those cases are `inconclusive`, not `defended`. Most
  competitors would have counted them as successful defences and inflated the
  number.
- closing it requires an agentic pentesting mechanism, which is exactly the
  commercial tier. The limitation and the revenue model are the same fact.

**Also honest:** role classification is human-reviewed, and the delivery layer
needs per-framework wiring. Both roadmap, both known.

---

## 8. Demo order for tomorrow (business story, not engineering story)

1. **The agent** — mini_banking_assistant. Eleven tools. It can move money. *30s*
2. **The attack** — one planted transaction, `TX-PLANTED-01`, in a normal-looking
   statement. No jailbreak, no weird prompt. *30s*
3. **The breach** — assistant_1's report. ₹15,000 gone. Balance changed. Show the
   dashboard. **This is the sale.** *90s*
4. **The fix** — assistant_2. Same agent, same attack, `@guard` on the tools.
   Blocked at `before_tool`. Money never moved. *90s*
5. **The guarantee** — the CI gate. Baseline committed, PR fails on regression.
   "This is how it stays fixed." *60s*
6. **The business** — Section 4 above. *60s*

Everything else is answering questions.

---

## 9. Questions they will ask

**"Why wouldn't OpenAI/Anthropic just build this in?"**
Partly they have — and it stops at content. Gating tool arguments requires
knowing which of *your* tools move money, which is customer-specific business
context a model vendor doesn't have and doesn't want. That's the roles file, and
it's the moat.

**"Why would anyone pay when the engine could be open source?"**
Same reason people pay Snyk with `npm audit` existing: the corpus updates, the
CI integration, the compliance evidence, and someone accountable when the gate
goes green. Open-core drives adoption; the subscription sells trust.

**"What's your defensibility? This is a few thousand lines of Python."**
The engine is the cheap part and we intend to give it away — see §7. What is
not copyable in an afternoon: the scoring discipline (breach vs not-complied vs
inconclusive — conflate those and your defence rate is fiction), the
baseline/regression machinery, and the adversarial generation that becomes the
paid tier. The engine is distribution; the adversary is the business.

**"Your own corpus can't break a good model — so what are you actually selling?"**
Correct, and that's the roadmap, not a hole. Static templates reliably produce
*structural* attacks; they don't produce adaptive multi-turn ones. Our runs
report that as inconclusive rather than as a defence, which is the point — the
measurement is honest about its own ceiling. The agentic pentester that raises
that ceiling is the subscription, and it's the part that can't be a file you
download.

**"How big is this market?"**
Don't invent a TAM you can't defend. Say: every regulated firm deploying an
agent with write access is a customer, that population is small today and
growing fast, and you're targeting Indian BFSI first because DPDP creates a
compliance trigger that a US-first competitor isn't optimising for.

**"What's your false positive rate?"**
Not measured yet — benign corpus schema and loader exist, cases unwritten. Next
after the delivery layer, because a blocked benign case fails the build by
design and an unmeasured FP rate ends with the guardrail switched off.

**"Isn't the real risk sandbox escape, like the OpenAI incident?"**
Different problem. That was containment failure in an unscoped evaluation
harness with arbitrary code execution. DetGuard governs agents with a named,
typed tool surface — which is what production agents actually are. Being clear
about that boundary is why the rest of the claims hold.
