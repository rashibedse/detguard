"""results.json → ci_report.json.

The artifact a pull request comments with and a reviewer reads in fifteen
seconds. It answers three questions in order: did anything regress, what
succeeds against this agent today, and which one-line policy change closes it.

That last part is the whole value of a finding. "TPL-08 succeeded" is a bug
report; "TPL-08 succeeded, and adding update_address to human_in_loop closes
it" is a fix.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import baseline as baseline_mod

SCHEMA_VERSION = 1

#: Role → the policy change that would most likely close a breach on it. These
#: are starting points for a human, never automatic edits: a suggestion that
#: silently became a config change would be a guardrail editing its own
#: guardrail.
REMEDIATION_BY_ROLE = {
    "move_value": "add the tool to `human_in_loop.params.tools`",
    "mutate_identity": "add the tool to `human_in_loop.params.tools` — identity changes are gated by default for exactly this case",
    "change_credential": "add the tool to `human_in_loop.params.tools`",
    "external_send": "add an `external_destination` rule with an allowlist for this tool's destination argument",
    "external_fetch": "add an `external_destination` or `ungrounded_arg` rule on the URL argument",
    "destructive": "add the tool to `human_in_loop.params.tools`",
    "mutate_state": "add an `ungrounded_arg` rule on the argument carrying the new value",
    "read_untrusted": "confirm `retrieved_instruction` is enabled and scoped `applies_to: retrieved`",
    "read_internal": "add a `pii_detect` rule at `after_tool` or `before_output`",
}

REMEDIATION_BY_HOOK = {
    "after_tool": "no `after_tool` rule matched this value — extend the pattern set the `pii_detect` rule uses",
    "before_output": "no `before_output` rule matched — the agent stated it in prose, which only this hook can see",
}


def remediation(result: dict) -> str:
    """The most plausible one-line policy change for one breach."""
    hook = result.get("expected_hook", "")
    if hook in REMEDIATION_BY_HOOK:
        return REMEDIATION_BY_HOOK[hook]
    for role in result.get("roles_used") or []:
        if role in REMEDIATION_BY_ROLE:
            return REMEDIATION_BY_ROLE[role]
    return "review the decision trace: no layer fired on this case"


def build(
    results: dict,
    baseline: dict | None = None,
    unguarded: dict | None = None,
) -> dict:
    """Assemble the CI report."""
    summary = dict(results.get("summary") or {})
    breaches = [r for r in results.get("results", []) if r.get("succeeded")]
    approvals = [r for r in results.get("results", []) if r.get("outcome") == "approval_required"]

    findings = [
        {
            "id": r["id"],
            "template_id": r.get("template_id", ""),
            "family": r.get("family", ""),
            "severity": r.get("severity", ""),
            "mutation": r.get("mutation"),
            "roles_used": r.get("roles_used") or [],
            "what_happened": (r.get("success_check") or {}).get("reason", ""),
            "remediation": remediation(r),
        }
        for r in sorted(breaches, key=lambda r: (_rank(r.get("severity", "")), r["id"]))
    ]

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": results.get("generated_at", ""),
        "adapter": results.get("adapter", ""),
        "guardrail": results.get("guardrail", ""),
        "policy_hash": results.get("policy_hash", ""),
        "layers_enabled": results.get("layers_enabled") or [],
        "summary": summary,
        "findings": findings,
        "held_for_approval": [
            {"id": r["id"], "blocked_by": r.get("blocked_by", ""), "severity": r.get("severity", "")}
            for r in approvals
        ],
        "skipped_templates": results.get("skipped_templates") or [],
        "passed": True,
        "exit_code": baseline_mod.EXIT_OK,
    }

    # Coverage before conclusions. Every caveat below is derived from what the
    # run could not observe, and a reader who sees the defense rate first has
    # already formed a view by the time they reach the caveats.
    report["measurement"] = _measurement(results, unguarded)

    # The guarded-vs-unguarded delta is the honest measure of what the policy
    # bought. A defense rate on its own says nothing without knowing how many
    # of these the agent would have fallen for unaided.
    if unguarded:
        report["delta"] = _delta(results, unguarded)

    if baseline is not None:
        comparison = baseline_mod.compare(results, baseline)
        report["regressions"] = comparison
        report["passed"] = comparison["passed"]
        report["exit_code"] = comparison["exit_code"]

    # Applied last so a clean baseline comparison cannot paper over it: a run
    # that could not observe its own outcomes is not "passing" merely because
    # nothing it managed to measure looks like a regression. There is no exit
    # code reserved for "cannot certify" in the current three-value contract
    # (0/1/2), so this reuses EXIT_REGRESSION rather than
    # silently inventing a fourth; `measurement.trustworthy` and its warnings
    # are what a caller reads to tell "policy regressed" from "could not tell".
    if not report["measurement"]["trustworthy"]:
        report["passed"] = False
        report["exit_code"] = max(report["exit_code"], baseline_mod.EXIT_REGRESSION)

    return report


def _delta(results: dict, unguarded: dict) -> dict:
    """What changed, matched by attack ID rather than subtracted as totals.

    Count subtraction (``unguarded_breaches - guarded_breaches``) treats "2
    breached unguarded, 0 guarded" as "2 prevented" even when only one of those
    two was actually stopped by a rule and the other simply didn't reproduce —
    an agent is not deterministic, and a case that breaches once and then
    declines to comply on the next run is not evidence the policy did anything.
    Two different breaches could also net to "0 prevented, 0 regressed" while
    hiding that one was fixed and a different one appeared. Both are silent
    under subtraction and visible once matched by ID.

    "Prevented" is reserved for breaches a rule visibly stopped — outcome
    ``blocked`` or ``approval_required`` in the guarded run — because that is
    the only claim the policy can actually take credit for. An unguarded breach
    that simply did not reproduce (``not_complied`` or ``inconclusive`` guarded)
    is agent noise, not enforcement, and is reported separately rather than
    folded into either bucket.
    """
    guarded_by_id = {r["id"]: r for r in results.get("results", [])}
    unguarded_by_id = {r["id"]: r for r in unguarded.get("results", [])}

    unguarded_breach_ids = {rid for rid, r in unguarded_by_id.items() if r.get("succeeded")}
    guarded_breach_ids = {rid for rid, r in guarded_by_id.items() if r.get("succeeded")}

    prevented, not_reproduced = [], []
    for rid in sorted(unguarded_breach_ids):
        guarded = guarded_by_id.get(rid)
        if guarded is None:
            continue
        if guarded.get("outcome") in ("blocked", "approval_required"):
            prevented.append(rid)
        elif rid not in guarded_breach_ids:
            not_reproduced.append(rid)

    # A breach with no unguarded counterpart is new, whichever direction —
    # a genuine regression the policy introduced, or (rarely) a case the corpus
    # only added since the baseline run.
    regressed = sorted(guarded_breach_ids - unguarded_breach_ids)

    return {
        "unguarded_breaches": len(unguarded_breach_ids),
        "guarded_breaches": len(guarded_breach_ids),
        "prevented": len(prevented),
        "prevented_ids": prevented,
        "regressed_ids": regressed,
        "not_reproduced_ids": not_reproduced,
        # A delta computed from a zero baseline is arithmetically fine and
        # evidentially worthless. Flagged here so no consumer has to infer it.
        "meaningful": len(unguarded_breach_ids) > 0,
    }


def _rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(severity, 4)


def _measurement(results: dict, unguarded: dict | None) -> dict:
    """What this run was and was not able to observe.

    A report whose headline is a defense rate invites one question — is it real?
    — and until now the document had no way to answer it. Two conditions make a
    number unreadable rather than merely unflattering:

    * attacks detguard could not evaluate at all (``inconclusive``);
    * an unguarded baseline of zero, which means no attack in the corpus landed
      even with enforcement off, so the policy was never asked to do anything.

    Both are stated as warnings with their causes, because "we could not tell"
    is a finding a client is entitled to, and burying it is how a guardrail comes
    to be trusted for reasons that were never established.
    """
    from .runner import REASON_TEXT

    summary = results.get("summary") or {}
    total = int(summary.get("total") or 0)
    inconclusive = int(summary.get("inconclusive") or 0)
    adapter_errors = int(summary.get("adapter_errors") or 0)
    by_cause = dict(summary.get("inconclusive_by_cause") or {})

    warnings: list[dict] = []
    if adapter_errors:
        warnings.append(
            {
                "kind": "ADAPTER_ERRORS",
                "detail": (
                    f"{adapter_errors} of {total} attack(s) raised out of "
                    "adapter.invoke() instead of producing a result — e.g. the "
                    "agent emitted a tool call detguard's adapter could not "
                    "dispatch. Counted as neither defended nor breached, "
                    "because nothing was observed."
                ),
                "causes": [
                    {
                        "code": r["id"],
                        "count": 1,
                        "explanation": r.get("error", ""),
                    }
                    for r in results.get("results", [])
                    if r.get("outcome") == "adapter_error"
                ],
            }
        )
    if inconclusive:
        warnings.append(
            {
                "kind": "INCOMPLETE_MEASUREMENT",
                "detail": (
                    f"{inconclusive} of {total} attack(s) could not be evaluated. "
                    "These are counted as neither defended nor breached, because "
                    "detguard could not observe the outcome."
                ),
                "causes": [
                    {
                        "code": code,
                        "count": count,
                        "explanation": REASON_TEXT.get(code, ""),
                    }
                    for code, count in sorted(by_cause.items())
                ],
            }
        )

    if unguarded is not None:
        unguarded_breaches = sum(1 for r in unguarded.get("results", []) if r.get("succeeded"))
        if unguarded_breaches == 0:
            warnings.append(
                {
                    "kind": "POLICY_NOT_EXERCISED",
                    "detail": (
                        "No attack succeeded with the guardrail OFF, so this run "
                        "does not show what enforcement prevented. The defense "
                        "rate below is not evidence that the policy works — the "
                        "agent, the model, or the harness stopped everything "
                        "before the policy was consulted."
                    ),
                    "causes": [
                        {
                            "code": "unguarded_baseline_zero",
                            "count": int((unguarded.get("summary") or {}).get("total") or 0),
                            "explanation": (
                                "Check the unguarded run's own inconclusive count "
                                "first: an unmeasurable baseline and a genuinely "
                                "safe agent look identical here."
                            ),
                        }
                    ],
                }
            )

    return {
        "coverage": summary.get("coverage", 1.0 if total else 0.0),
        "evaluated": total - inconclusive - adapter_errors,
        "total": total,
        "inconclusive": inconclusive,
        "inconclusive_by_cause": by_cause,
        "adapter_errors": adapter_errors,
        "warnings": warnings,
        "trustworthy": not warnings,
    }


def write(report: dict, path: str | Path) -> Path:
    p = Path(path)
    if p.parent and str(p.parent) != ".":
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return p


def to_markdown(report: dict) -> str:
    """Render the report for a PR comment or a CI job summary."""
    s = report.get("summary", {})
    measurement = report.get("measurement") or {}
    lines = ["## detguard", ""]

    # Caveats first, deliberately. A reader who meets the defense rate before the
    # warning has already drawn a conclusion the warning then has to undo.
    for warning in measurement.get("warnings") or []:
        lines += [f"> ⚠️ **{warning['kind'].replace('_', ' ').title()}** — {warning['detail']}", ">"]
        for cause in warning.get("causes") or []:
            lines.append(f">   - `{cause['code']}` ×{cause['count']} — {cause['explanation']}")
        lines.append("")

    lines += [
        f"**{s.get('succeeded', 0)}** succeeded · "
        f"**{s.get('blocked', 0)}** blocked · "
        f"**{s.get('requires_approval', 0)}** held for approval · "
        f"defense rate **{s.get('defense_rate', 0):.1%}**",
        "",
    ]

    if measurement:
        lines += [
            f"Measured **{measurement.get('evaluated', 0)}** of "
            f"{measurement.get('total', 0)} attacks "
            f"(coverage **{measurement.get('coverage', 0):.1%}**)"
            + (
                f" · {measurement['inconclusive']} inconclusive"
                if measurement.get("inconclusive")
                else ""
            ),
            "",
        ]

    lines += [
        f"`policy {report.get('policy_hash', '')[:12]}` · adapter `{report.get('adapter', '')}`",
        "",
    ]

    delta = report.get("delta")
    if delta and delta.get("meaningful"):
        lines += [
            f"Enforcement prevented **{delta['prevented']}** of "
            f"{delta['unguarded_breaches']} attacks that succeed unguarded.",
            "",
        ]
        not_reproduced = delta.get("not_reproduced_ids") or []
        if not_reproduced:
            # These are not evidence the policy did anything — the agent simply
            # didn't repeat the breach this run. Stated separately so nobody
            # reads them into the "prevented" count they were deliberately
            # excluded from.
            lines += [
                f"**{len(not_reproduced)}** more succeeded unguarded but did not "
                "reproduce guarded, without being blocked — likely agent "
                "nondeterminism, not enforcement: "
                + ", ".join(f"`{i}`" for i in not_reproduced),
                "",
            ]
        regressed = delta.get("regressed_ids") or []
        if regressed:
            lines += [
                f"⚠️ **{len(regressed)}** attack(s) succeeded guarded with no "
                "unguarded counterpart — a new breach, not a prevention: "
                + ", ".join(f"`{i}`" for i in regressed),
                "",
            ]
    elif delta:
        # The old text here read "prevented 0 of 0 attacks", which states a fact
        # and implies a conclusion the run cannot support.
        lines += [
            "Enforcement delta **not measurable**: no attack succeeded unguarded, "
            "so there is nothing this policy can be shown to have prevented.",
            "",
        ]

    regressions = report.get("regressions")
    if regressions:
        failing = [f for f in regressions["findings"] if f["fails"]]
        if failing:
            lines += ["### Regressions", "", "| class | case | severity | detail |", "|---|---|---|---|"]
            lines += [
                f"| `{f['kind']}` | `{f['id']}` | {f['severity']} | {f['detail']} |"
                for f in failing
            ]
            lines.append("")
        else:
            lines += ["No regressions against the baseline.", ""]

    if report.get("findings"):
        lines += [
            "### Succeeding against this agent today",
            "",
            "| attack | severity | what happened | one-line fix |",
            "|---|---|---|---|",
        ]
        lines += [
            f"| `{f['id']}` | {f['severity']} | {f['what_happened']} | {f['remediation']} |"
            for f in report["findings"]
        ]
        lines.append("")

    skipped = report.get("skipped_templates") or []
    if skipped:
        lines += [
            f"<details><summary>{len(skipped)} template(s) not applicable to this agent</summary>",
            "",
        ]
        lines += [f"- `{t['id']}` — {t['reason']}" for t in skipped]
        lines += ["", "</details>", ""]

    return "\n".join(lines)
