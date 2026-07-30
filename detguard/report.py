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

    # The guarded-vs-unguarded delta is the honest measure of what the policy
    # bought. A defense rate on its own says nothing without knowing how many
    # of these the agent would have fallen for unaided.
    if unguarded:
        unguarded_breaches = sum(1 for r in unguarded.get("results", []) if r.get("succeeded"))
        report["delta"] = {
            "unguarded_breaches": unguarded_breaches,
            "guarded_breaches": len(breaches),
            "prevented": max(0, unguarded_breaches - len(breaches)),
        }

    if baseline is not None:
        comparison = baseline_mod.compare(results, baseline)
        report["regressions"] = comparison
        report["passed"] = comparison["passed"]
        report["exit_code"] = comparison["exit_code"]

    return report


def _rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(severity, 4)


def write(report: dict, path: str | Path) -> Path:
    p = Path(path)
    if p.parent and str(p.parent) != ".":
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return p


def to_markdown(report: dict) -> str:
    """Render the report for a PR comment or a CI job summary."""
    s = report.get("summary", {})
    lines = [
        "## detguard",
        "",
        f"**{s.get('succeeded', 0)}** succeeded · "
        f"**{s.get('blocked', 0)}** blocked · "
        f"**{s.get('requires_approval', 0)}** held for approval · "
        f"defense rate **{s.get('defense_rate', 0):.1%}**",
        "",
        f"`policy {report.get('policy_hash', '')[:12]}` · adapter `{report.get('adapter', '')}`",
        "",
    ]

    delta = report.get("delta")
    if delta:
        lines += [
            f"Enforcement prevented **{delta['prevented']}** of "
            f"{delta['unguarded_breaches']} attacks that succeed unguarded.",
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
