# Policy-as-Code Enforcement for Agent Tool Calls
### Static and Dynamic Anomaly Analysis of Guardrail Policies

---

## 1. Problem Statement

The field has moved from *models checking models* (LLM-as-judge, alignment-based
safety) to *deterministic policy-as-code* enforcement — rule-based, auditable,
reproducible checks on what an AI agent's tool calls are permitted to do. DetGuard is
an example of this shift: four canonical hooks (`before_input`, `before_tool`,
`after_tool`, `before_output`), a YAML policy file, no LLM anywhere in the
enforcement path.

That migration did not eliminate trust — it **relocated** it. The system no longer
trusts the model's judgment; it trusts the policy file's correctness. The policy is
now the single point of failure for the entire security posture.

**Nothing checks the policy file.** Unlike code, it has no compiler, no type checker,
no linter, no coverage tool. The enforcement engine evaluates whatever rules it is
given and returns a verdict — it has no way to know a rule is dead, unreachable, or
never actually contributes to a decision.

**The core failure is invisible by construction.** If a policy's measured defence
rate is 100%, that number cannot distinguish between *all eight layers working* and
*two layers working while six are decorative*. Both produce an identical dashboard.
Both pass CI. This was discovered empirically during this project: `human_in_loop`
— severity `critical`, guarding money movement, self-described in its own policy
comment as *"The gate"* — never once determined an outcome across the baseline
corpus. It was not broken. It was **shadowed** by an earlier hook that always halted
the pipeline first. No existing tool, test, or CI gate could distinguish "broken"
from "shadowed," and those two diagnoses demand opposite responses.

**When it matters most, the failure surfaces at the worst possible time.** A
shadowed rule is not harmless dead weight — it is load-bearing exactly when the
layer above it is evaded. In this project's own corpus, `whitespace_pad` and
`base64_wrap` obfuscation mutations slip past the top content-scanning layer, and
the "dead" deeper rules are what actually catch them. Defense-in-depth that has
never been tested is discovered to be theatre at the exact moment a novel attack
defeats the cheap top layer.

**Historical framing.** This is the same reckoning firewalls had. Deterministic
rule-based enforcement was the answer to "you can't just trust the network"; within
a decade, the rulesets themselves — not the enforcement engines — became the
problem (Al-Shaer's research programme exists because of this). The same reckoning
came for XACML access-control policies and for cloud IAM. Agent guardrails are at
the "we have a firewall" stage now. Nobody has had the "is the ruleset itself
coherent?" reckoning yet.

**Forward-looking urgency.** Policies are increasingly machine-generated.
AgentSpec's LLM-generated rules achieve 70.96% recall — meaning roughly three in
ten needed rules are silently missing from a generated policy, and nothing flags
which. If policies are generated automatically, they need to be verified
automatically. Today we do the first and not the second.

> **We made the guardrail auditable. We never audited it.**

---

## 2. Research Gap

Two literatures verify **policy artifacts as software objects**:

- **Firewall anomaly analysis** (Al-Shaer & Hamed) — taxonomy of shadowing,
  redundancy, correlation, generalization, over a single-pass, first-match-wins
  rule list.
- **Access-control policy verification** (Fisler's Margrave; Martin's Targen/Cirg)
  — semantic differencing and unreachable-rule detection for XACML.

The agent-guardrail literature (ClawGuard, AgentSpec, Progent, LlamaFirewall, NeMo
Guardrails, and others) evaluates **runtime detection accuracy** exclusively (attack
success rate, F1, verdict accuracy). As of 2026 a handful of papers extend static
analysis to *other* agent artifacts — Agentproof verifies workflow-graph topology,
λA lints composition configs, Agent Audit performs SAST on application code — but
**none analyse the guardrail policy ruleset itself.**

**The structural, non-derivative contribution:** firewall rulesets are one linear
list; XACML is a tree with combining algorithms. An agent guardrail policy is a
**staged pipeline** of four hooks where a block at an earlier stage means later
stages are *never evaluated at all*. This produces an anomaly class with no
analogue in either source literature: **cross-hook shadowing**. A second novel
class, **attribution-shadowing**, arises because DetGuard's evaluator does not
short-circuit within a hook — every rule bound to a hook is evaluated, but only one
is selected as the blocker by severity rank. A rule can fire without ever being
credited.

**Gap statement, one sentence:**
> *Static pre-deployment analysis has recently reached agent workflow graphs,
> composition configs, and application code — but not the guardrail policy
> ruleset, whose staged, non-short-circuiting evaluation model produces anomaly
> classes none of those artifacts can express.*

---

## 3. Research Questions

**RQ1 (Taxonomy).** What anomaly classes arise in staged, multi-hook policy
pipelines that have no analogue in single-pass rule sets or tree-structured
policies with combining algorithms?

**RQ2 (Detectability).** Can these anomalies be detected from the policy artifact
and its execution traces alone — without executing the agent — and which classes
require which pass (static vs. dynamic)?

**RQ3 (Prevalence and consequence).** In a deployed policy, how concentrated is
actual defensive attribution relative to the number of enabled rules, and does a
rule that appears redundant under normal traffic remain load-bearing under
adversarial evasion of the layers above it?

---

## 4. Proposed Solution

A **static + dynamic policy analyzer** — `detguard lint` — plus one new metric.
Purely additive: it never modifies `engine.py`, `policy.py`, or `runner.py`. It is
a lint, not a verifier — no soundness proof is claimed.

**One-line pitch:** *A pre-deployment check that tells you which rules in your
policy actually do anything — before an attacker finds out for you.*

### 4.1 Anomaly taxonomy (answers RQ1)

| Class | Detection | Definition | Status |
|---|---|---|---|
| Dead-by-logic | Static | Provably unreachable from the condition's own guard clause (e.g. empty `tools` list) | Ported (Targen/Cirg) |
| Inert-by-configuration | Static | `enabled: false` | New label, obvious concept |
| Redundant | Static | Same hook + condition + params as another rule | Ported (Al-Shaer) |
| **Cross-hook shadowed** | Dynamic | Rule's hook is never reached — an earlier hook always halts the pipeline first | **Novel** |
| Never-triggered | Dynamic | Hook reached, rule evaluated, condition never fires for this corpus | Ported concept |
| **Attribution-shadowed** | Dynamic | Fires, but never selected as the blocker (severity-ranked attribution) | **Novel** |
| Load-bearing | Dynamic | Determines at least one outcome | — |

### 4.2 `detguard lint` — two-pass analyzer (answers RQ2)

- **Static pass** — reads `policy.yaml` alone. Detects dead-by-logic and
  inert-by-configuration rules in milliseconds, no execution.
- **Dynamic pass** — reads existing decision traces already recorded in
  `results.json` by the corpus runner. No new agent execution, no LLM call.
  Classifies every enabled rule via three nested sets:
  $$A(r) \subseteq F(r) \subseteq E(r)$$
  ($E$ = evaluated, $F$ = fired, $A$ = attributed as blocker)

### 4.3 Defense Concentration Index — DCI (answers RQ3)

$$DCI = \sum_{r \,:\, |A(r)|>0} \left(\frac{|A(r)|}{\sum_{r'}|A(r')|}\right)^2 \qquad DCI \in \left[\tfrac{1}{k}, 1\right]$$

Reported with its inverse, **effective rule count** $N_\text{eff} = 1/DCI$.

Adapted from the Herfindahl-Hirschman Index (Rhoades, 1993), the standard
concentration measure from antitrust economics, following precedent for
concentration-as-security-risk reasoning (Geer et al., 2020, applying HHI-style
thinking to internet ecosystem vendor concentration).

**Worked example, from this project's own `bankingass_2` corpus run:** 8 rules
enabled; across 23 determined cases, `overt_injection` won attribution 11 times and
`retrieved_instruction` won 12 times; all other 6 enabled rules won zero.

$$DCI = \left(\frac{11}{23}\right)^2 + \left(\frac{12}{23}\right)^2 = 0.50 \qquad N_\text{eff} = \frac{1}{0.50} = 2$$

A policy with 8 enabled rules behaves, in practice, like a 2-rule policy — 4× the
theoretical minimum DCI of 0.125 for 8 evenly-sharing rules.

**Known limitation, stated explicitly:** HHI lacks the "value-validity" property
(Kvålseth, 2021) — used here for interpretability and established convention; a
corrected index is named as future refinement.

---

## 5. System Architecture

`detguard lint` is a **read-only side-car**, not a modification to the enforcement
path. It sits outside DetGuard's existing pipeline and consumes two artifacts the
pipeline already produces:

```
Policy author → policy.yaml → DetGuard core (unchanged: 4-hook pipeline,
                                              engine.py + policy.py)
                                    ↓
                              Corpus run (runner.py) → results.json
                                    ↑                        ↑
                                    │                        │
                         static pass│              dynamic pass│
                    (policy.yaml alone,        (existing traces,
                     no execution)              no re-run)
                                    └──────────┬─────────────┘
                                          detguard lint
                                          (THIS WORK)
                                               ↓
                                     Findings + DCI
                                               ↓
                                     back to Policy author
                                  (closes a loop that does not
                                        exist today)
```

The critical architectural fact: the dynamic pass requires **no new execution** —
`results.json` traces are already produced by every existing corpus run.

---

## 6. Methodology

### 6.1 Design
Artifact-centric case study with fully offline analysis. Every measurement is
derived from `policy.yaml` and `results.json` — no model invocation, no network, no
agent re-execution. Deterministic and exactly reproducible by construction.

### 6.2 Formal model
A policy $P$ is a finite set of rules $r = \langle \text{id}, h, c, \theta, a, s, e \rangle$.
Hooks form a strict total order $h_1 \prec h_2 \prec h_3 \prec h_4$. Three evaluation
semantics, stated precisely because the taxonomy derives from them:

- **(S1)** Within a hook, evaluation is exhaustive — no short-circuit on first match.
- **(S2)** Attribution is severity-ranked — one blocker selected when multiple rules fire.
- **(S3)** Across hooks, a block halts the pipeline — downstream hooks never evaluated.

S1+S2 → attribution-shadowing. S3 → cross-hook shadowing.

### 6.3 Detection procedures
Static pass: iterate rules, test `enabled` flag and guard-clause satisfiability,
pairwise-compare for redundancy. Dynamic pass: single linear scan over
`results.json`'s decision traces, incrementing $E$, $F$, $A$ counts per rule,
classifying by the nested-set emptiness tests.

### 6.4 Validation strategy
- **(a) Cross-pass consistency** — any rule flagged dead-by-logic statically must
  appear as never-triggered or cross-hook-shadowed dynamically; a violation
  indicates one analysis is wrong. Free internal-validity check.
- **(b) Class instantiation** — every taxonomy class must be witnessed by at least
  one real rule in the study subjects; report which were and weren't observed.
- **(c) Counterfactual attribution** — because evaluation is exhaustive within a
  hook (S1), the trace records every rule that fired, not just the winner. This
  permits recomputing the blocker with a rule removed from the candidate set,
  **without re-running anything**. Exact within a hook; explicitly undefined
  across hooks (stated limitation, not glossed over).
- **(d) Natural experiment already in the corpus** — `whitespace_pad` and
  `base64_wrap` variants are observed (not simulated) cases where a rule inert
  under the base corpus becomes attributed once the top layer is evaded.

### 6.5 Study subjects
Two deployed policies (`bankingass`, `bankingass_2`) with their existing guarded
and unguarded corpus runs.

### 6.6 Threats to validity
- **External** — two policies is a case study, not a prevalence study; cross-org
  prevalence named as future work.
- **Construct** — corpus-relative inertness ≠ global deadness; reported as
  separate classes deliberately.
- **Internal** — manual guard-clause inspection may misclassify; mitigated by
  cross-pass consistency check.
- **Instrument** — DCI's known value-validity limitation (Kvålseth, 2021).

---

## 7. Key Performance Indicators (maximum 3)

1. **Defense Concentration Index** — $DCI$, $N_\text{eff}$. Measures the policy.
2. **Anomaly Class Distribution** — rule counts per class. Diagnoses the policy.
3. **Analysis Overhead** — wall-clock time, LLM calls, API cost. Target:
   sub-second, zero, zero. Establishes deployability as a pre-commit / CI check.

---

## 8. Software and Hardware Setup

**Analysis (this contribution):** Python 3.13, PyYAML, pytest 8.x (364-test
regression suite). No external dependencies, no network access required to run
`detguard lint`.

**Platform under study:** DetGuard (editable source install), `openai-agents` SDK,
SQLite, Streamlit + pandas + altair (results dashboard).

**Corpus generation (prerequisite only, not part of the analysis itself):** Groq
API (`llama-3.1-8b-instant`, `openai/gpt-oss-20b`), GitHub Actions CI.

**Hardware:** ASUS Vivobook, Windows 11 Home Single Language. No GPU required.

**Key finding worth stating on its own:** the analysis method requires no GPU, no
API key, and no network. LLM access was needed only once, to generate the corpus
traces already on disk; every measurement in this work is computed offline and is
exactly reproducible.

---

## 9. Full Literature List

### 9.1 Firewall policy anomaly analysis (source literature — ported)
- Al-Shaer, E. & Hamed, H. (2003). *Firewall Policy Advisor for anomaly discovery
  and rule editing.* IFIP/IEEE IM. 240 citations.
- Al-Shaer, E. & Hamed, H. (2005). *Conflict classification and analysis of
  distributed firewall policies.* IEEE JSAC. 330 citations.
- Hu, H. et al. (2012). *Detecting and Resolving Firewall Policy Anomalies.* IEEE
  TDSC. 184 citations.
- Kingsley, J. et al. (2019). *Firewall Rule Anomaly Detection and Resolution
  using Particle Swarm Optimization.* IJCA.
- Bringhenti, D. et al. (2023, 2025). *An Optimized Approach for Assisted Firewall
  Anomaly Resolution* (IEEE Access); *Automated Firewall Configuration in Virtual
  Networks* (IEEE TDSC, 429 citations); *Atomizing Firewall Policies for Anomaly
  Analysis and Resolution* (IEEE TDSC).

### 9.2 Access-control policy verification (source literature — ported)
- Fisler, K. et al. (2005). *Verification and change-impact analysis of
  access-control policies (Margrave).* ICSE. 499 citations.
- Martin, E. (2006). *Automated test generation for access control policies
  (Targen/Cirg).* 77 citations.
- Arshad, H. et al. (2022). *Process Algebra Can Save Lives: Static Analysis of
  XACML Access Control Policies Using mCRL2.*
- Sissodiya, A. et al. (2025). *Formal Verification for Preventing Misconfigured
  Access Policies in Kubernetes Clusters.* IEEE Access.

### 9.3 Agent guardrail enforcement (runtime — the crowded space, not competed with)
- Zhao, W. et al. (2026). *ClawGuard: A Runtime Security Framework for
  Tool-Augmented LLM Agents Against Indirect Prompt Injection.* 14 citations.
- Wang, H. et al. (2025). *AgentSpec: Customizable Runtime Enforcement for Safe
  and Reliable LLM Agents.* 137 citations.
- Shi, T. et al. (2025). *Progent: Securing AI Agents with Privilege Control.* 82
  citations.
- Chennabasappa, S. et al. (2025). *LlamaFirewall: An open source guardrail
  system for building secure AI agents.* 102 citations.
- Rebedea, T. et al. (2023). *NeMo Guardrails: A Toolkit for Controllable and Safe
  LLM Applications.* 435 citations.
- Sigdel, A. et al. (2026). *Guardrails as Infrastructure: Policy-First Control
  for Tool-Orchestrated Workflows.*
- Yang, C. (2026). *AgentTrust: Runtime Safety Evaluation and Interception for AI
  Agent Tool Use.*
- Xiang, Z. et al. (2024). *GuardAgent: Safeguard LLM Agents via Knowledge-Enabled
  Reasoning.* 89–107 citations.

### 9.4 Static analysis of agent artifacts (2026 — closest prior art, distinguished by artifact)
- Xavier, M. et al. (2026). *Agentproof: Static Verification of Agent Workflow
  Graphs.* Verifies workflow-graph topology (dead-end nodes, unreachable exits);
  55% of a benchmark violates a human-gate policy — cited as convergent evidence
  with this project's `human_in_loop` finding.
- Liu, Q. (2026). *λA: A Typed Lambda Calculus for LLM Agent Composition.* Derives
  a lint from operational semantics for composition configs; 94.1% of 835
  real-world configs structurally incomplete.
- Zhang, H. et al. (2026). *Agent Audit: A Security Analysis System for LLM Agent
  Applications.* SAST over agent code — dataflow, credentials, MCP privilege risk.
- Dang, H. (2026). *Enforcing Benign Trajectories: A Behavioral Firewall for
  Structured-Workflow AI Agents.* Runtime trajectory conformance (pDFA over
  tool-call sequences) — distinguished explicitly: behavioral conformance, not
  policy-artifact analysis.

### 9.5 Obfuscation / evasion (grounds the empirical mutation findings)
- Boucher, N. et al. (2021). *Bad Characters: Imperceptible NLP Attacks.* IEEE
  S&P. 143 citations. — canonical homoglyph/zero-width attack reference.
- Hackett, W. et al. (2025). *Bypassing LLM Guardrails: An Empirical Analysis of
  Evasion Attacks against Prompt Injection and Jailbreak Detection Systems.* Up to
  100% evasion of Azure Prompt Shield / Meta Prompt Guard via character injection.
- Zhan, Q. et al. (2025). *Adaptive Attacks Break Defenses Against Indirect Prompt
  Injection Attacks on LLM Agents.* All 8 tested defenses bypassed, >50% ASR each
  — motivates the "non-adaptive adversary" limitation stated in this work.

### 9.6 Field-level evaluation critique (motivates why this gap matters)
- Kehkashan, T. et al. (2026). *From benchmarks to deployment: a comprehensive
  review of agentic AI evaluation.* 0 of 15 major agent benchmarks integrate
  safety/security into scoring; 0 of 15 include cost-efficiency metrics.
- Meimandi, K. et al. (2025). *The Measurement Imbalance in Agentic AI Evaluation
  Undermines Industry Productivity Claims.* Systematic review of 84 papers,
  2023–2025: technical metrics dominate 83% of evaluations, safety only 53%.
- Ye, B. et al. (2026). *Claw-Eval: Towards Trustworthy Evaluation of Autonomous
  Agents.* Trajectory-opaque evaluation misses 44% of safety violations.

### 9.7 Concentration metric — origin and precedent
- Rhoades, S. (1993). *The Herfindahl-Hirschman Index.* Federal Reserve Bulletin.
  737 citations. — canonical citable definition and DOJ/Fed usage.
- Geer, D. et al. (2020). *On market concentration and cybersecurity risk.*
  Journal of Cyber Policy. 45 citations. — precedent for concentration as a
  security risk indicator, not only an economic one.
- Kvålseth, T. (2021). *A Cautionary Note About the Herfindahl-Hirschman Index of
  Market (Industry) Concentration.* Contemporary Economics. — stated limitation
  (lacks value-validity property).

### 9.8 Not pursued, and why (avoid raising in Q&A unprompted)
- **Least-privilege / permission minimisation** — most crowded adjacent area:
  Progent (SMT-backed, evaluated on AgentDojo *and* ASB), MiniScope (22
  citations), AgenTRIM, MCP-Secure, AIRGuard, Prismata. Entering here means
  competing with SMT-backed systems on standard benchmarks.

---

## 10. Named Future Work

- **Semantic policy diffing** — Margrave-style behavioural change-impact analysis
  between two policy versions, replacing DetGuard's current SHA-256
  `policy_hash`-only drift detection.
- **Cross-org anomaly prevalence** — the case-study limitation's direct fix;
  requires policies from independently-authored deployments.
- **Multi-agent policy composition** — when a parent agent spawns a sub-agent, is
  the sub-agent's policy inherited, intersected, or replaced? Al-Shaer's 2005
  *interfirewall* anomaly work is the un-ported analogue; contemporary work
  (*When Child Inherits*, *Safe Bilevel Delegation*, both 2026) addresses memory
  inheritance and delegation theory but not policy composition specifically.
- **Sound verification** — Margrave / SMT-backed formal verification as the rigor
  tier above a lint, with a soundness proof this work does not attempt.
