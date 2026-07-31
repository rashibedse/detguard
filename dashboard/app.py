"""detguard dashboard.

Reads results.json files and nothing else. It never invokes an agent, never
loads a policy, and never writes anything — if this process can affect an
outcome it is reporting on, the report is not evidence.

    streamlit run dashboard/app.py

Point it at a directory of results files; two runs of the same corpus with the
guardrail on and off are what make section 2 worth looking at.
"""

from __future__ import annotations

import glob
import json
import os
from collections import Counter, defaultdict

import altair as alt
import pandas as pd
import streamlit as st

st.set_page_config(page_title="detguard", page_icon="🛡", layout="wide")

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
OUTCOME_COLOURS = {
    "breach": "#c0392b",
    "approval_required": "#e08e0b",
    "blocked": "#1f7a4d",
    # A lighter green than `blocked`: the objective failed, but the call was
    # still made and only its content was masked. Reading as identical to a
    # hard block would overstate what happened.
    "mitigated": "#5aa87a",
    "not_complied": "#7f8c8d",
    # Deliberately not green and not grey. An attack nobody could evaluate is a
    # hole in the evidence, and it should not read as a quiet pass.
    "inconclusive": "#8e44ad",
}
OUTCOME_LABELS = {
    "breach": "Breach",
    "approval_required": "Held for approval",
    "blocked": "Blocked",
    "mitigated": "Mitigated (content masked)",
    "not_complied": "Agent did not comply",
    "inconclusive": "Could not be evaluated",
}


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------


@st.cache_data(show_spinner=False)
def load_results(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    data["_path"] = path
    return data


@st.cache_data(show_spinner=False)
def discover(directory: str) -> list[str]:
    # Narrowed to results files specifically: a run directory now also holds
    # ci_report.json and run.yaml by default, and neither parses as a results
    # document — to_frame would either choke on them or silently render an
    # empty run.
    return sorted(glob.glob(os.path.join(directory, "results*.json")))


def newest_run_dir() -> str | None:
    """The most recently created ``runs/<timestamp>/``, if any exist.

    ``detguard run`` writes here by default now, so this is where a client's
    latest evidence actually lives — pointing the dashboard at ``.`` by default
    would show nothing for anyone who hasn't overridden that with ``--out``.
    """
    candidates = sorted(glob.glob(os.path.join("runs", "*")), key=os.path.getmtime)
    return candidates[-1] if candidates else None


def to_frame(run: dict) -> pd.DataFrame:
    rows = []
    for r in run.get("results", []):
        rows.append(
            {
                "id": r.get("id", ""),
                "template_id": r.get("template_id", ""),
                "mutation": r.get("mutation") or "base",
                "family": r.get("family", ""),
                "severity": r.get("severity", ""),
                "outcome": r.get("outcome", ""),
                "succeeded": bool(r.get("succeeded")),
                "requires_approval": bool(r.get("requires_approval")),
                "blocked_at_hook": r.get("blocked_at_hook") or "",
                "blocked_by": r.get("blocked_by") or "",
                "expected_hook": r.get("expected_hook", ""),
                "pr_subset": bool(r.get("pr_subset")),
                "roles_used": ", ".join(r.get("roles_used") or []),
                "check_type": (r.get("success_check") or {}).get("type", ""),
                "check_reason": (r.get("success_check") or {}).get("reason", ""),
                "reason_code": r.get("reason_code") or "",
                "guardrail": run.get("guardrail", ""),
                "run": os.path.basename(run.get("_path", "")),
                "generated_at": run.get("generated_at", ""),
            }
        )
    return pd.DataFrame(rows)


def layer_for(run: dict, blocked_by: str) -> str:
    """Recover the layer label for a blocking rule from its decision trace."""
    for r in run.get("results", []):
        for d in r.get("decisions", []):
            if d.get("name") == blocked_by and d.get("layer"):
                return d["layer"]
    return blocked_by or "—"


# ---------------------------------------------------------------------------
# sidebar
# ---------------------------------------------------------------------------

st.sidebar.title("🛡 detguard")
st.sidebar.caption("Policy-as-code for agent tool calls")

default_directory = newest_run_dir() or "."
directory = st.sidebar.text_input("Results directory", value=default_directory)
available = discover(directory)

if not available:
    st.title("detguard")
    st.warning(f"No `results*.json` files in `{os.path.abspath(directory)}`.")
    st.markdown(
        "Produce some with:\n\n"
        "```bash\n"
        "detguard run --corpus corpus/attacks --policy policy.yaml \\\n"
        "  --agent examples.banking_agent.agent:FixtureAgent --guardrail on\n"
        "```\n\n"
        "That writes into a fresh `runs/<timestamp>/` by default — point "
        "the field above at it, or pass `--run-dir` to choose where."
    )
    st.stop()

chosen = st.sidebar.multiselect(
    "Result files",
    available,
    default=available,
    format_func=os.path.basename,
)
if not chosen:
    st.info("Select at least one results file.")
    st.stop()

runs = [load_results(p) for p in chosen]
runs = [r for r in runs if r.get("results") is not None]
if not runs:
    st.error("None of the selected files look like detguard results.")
    st.stop()

guarded = next((r for r in runs if r.get("guardrail") == "on"), runs[0])
unguarded = next((r for r in runs if r.get("guardrail") == "off"), None)

frame = to_frame(guarded)
all_frames = pd.concat([to_frame(r) for r in runs], ignore_index=True)

severity_filter = st.sidebar.multiselect(
    "Severity", SEVERITY_ORDER, default=SEVERITY_ORDER
)
family_filter = st.sidebar.multiselect(
    "Family", sorted(frame["family"].unique()), default=sorted(frame["family"].unique())
)
pr_only = st.sidebar.checkbox("PR subset only", value=False)

view = frame[frame["severity"].isin(severity_filter) & frame["family"].isin(family_filter)]
if pr_only:
    view = view[view["pr_subset"]]

st.sidebar.markdown("---")
st.sidebar.caption(f"policy `{(guarded.get('policy_hash') or '')[:12]}`")
st.sidebar.caption(f"adapter `{guarded.get('adapter', '—')}`")
st.sidebar.caption(f"layers: {len(guarded.get('layers_enabled') or [])} enabled")


# ---------------------------------------------------------------------------
# 1 — header KPIs
# ---------------------------------------------------------------------------

st.title("Adversarial regression report")
st.caption(
    f"{guarded.get('adapter', 'unknown')} · guardrail "
    f"**{guarded.get('guardrail', '?')}** · {guarded.get('generated_at', '')}"
)

summary = guarded.get("summary", {})
attacks_only = view[view["check_type"] != "must_allow"]

critical_gaps = int(((attacks_only["severity"] == "critical") & attacks_only["succeeded"]).sum())

coverage = summary.get("coverage")
inconclusive = int(summary.get("inconclusive") or 0)

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric(
    "Defense rate",
    f"{summary.get('defense_rate', 0):.1%}",
    help="Hard blocks only. A HITL pause means a human may still say yes, so "
    "it is reported separately as `containment_rate` rather than summed in "
    "here — a maybe counted as a no inflates the one number everyone reads.",
)
k2.metric(
    "Coverage",
    f"{coverage:.1%}" if coverage is not None else "—",
    help="The share of attacks detguard could actually evaluate. A high defense "
    "rate over low coverage is not a result — the rest were neither defended "
    "nor breached, they were simply unobserved.",
)
k3.metric("Attacks run", int(len(attacks_only)))
k4.metric("Critical gaps open", critical_gaps, delta_color="inverse")
k5.metric("Policy", (guarded.get("policy_hash") or "—")[:12])

if inconclusive:
    causes = summary.get("inconclusive_by_cause") or {}
    detail = ", ".join(f"`{code}` ×{count}" for code, count in sorted(causes.items()))
    st.warning(
        f"**{inconclusive} attack(s) could not be evaluated** — {detail}. These are "
        "counted as neither defended nor breached. Until coverage reaches 100%, "
        "the defense rate describes only the attacks above it.",
        icon="⚠️",
    )

# Stated above every chart, because it changes what "blocked" means in all of
# them. A reader who is not told will assume the stronger reading.
_enforcement = summary.get("enforcement", "detected")
if _enforcement == "detected":
    st.warning(
        "**Detection, not prevention.** This adapter exposes no pre-execution "
        "seam, so tool hooks ran after the agent's turn had already completed. "
        "Every `blocked` below means the policy *would* have stopped the call "
        "in a live integration — here the side effect already happened.",
        icon="⚠️",
    )
elif _enforcement == "mixed":
    st.info(
        f"**Mixed enforcement.** {summary.get('prevented_attacks', 0)} of "
        f"{summary.get('total', 0)} attacks were intercepted before the tool "
        "ran; the rest were evaluated after the fact.",
        icon="ℹ️",
    )

st.markdown("---")


# ---------------------------------------------------------------------------
# 2 — guarded vs unguarded
# ---------------------------------------------------------------------------

st.subheader("Guarded vs unguarded")
st.caption("Same corpus, same agent, enforcement the only difference.")

if unguarded is None:
    st.info(
        "Only one run loaded. Run the corpus again with `--guardrail off` to see "
        "the comparison — it is the single most persuasive chart here, because "
        "it is the one that shows what the policy is actually buying you."
    )
else:
    rows = []
    for run in (unguarded, guarded):
        f = to_frame(run)
        f = f[f["family"].isin(family_filter) & f["severity"].isin(severity_filter)]
        for family, group in f.groupby("family"):
            rows.append(
                {
                    "family": family,
                    "mode": "guardrail off" if run.get("guardrail") == "off" else "guardrail on",
                    "breaches": int(group["succeeded"].sum()),
                    "total": len(group),
                }
            )
    comparison = pd.DataFrame(rows)
    if not comparison.empty:
        chart = (
            alt.Chart(comparison)
            .mark_bar()
            .encode(
                x=alt.X("family:N", title=None, axis=alt.Axis(labelAngle=-30)),
                y=alt.Y("breaches:Q", title="attacks that succeeded"),
                color=alt.Color(
                    "mode:N",
                    title=None,
                    scale=alt.Scale(
                        domain=["guardrail off", "guardrail on"],
                        range=["#c0392b", "#1f7a4d"],
                    ),
                ),
                xOffset="mode:N",
                tooltip=["family", "mode", "breaches", "total"],
            )
            .properties(height=320)
        )
        st.altair_chart(chart, width="stretch")

        off_total = int(comparison[comparison["mode"] == "guardrail off"]["breaches"].sum())
        on_total = int(comparison[comparison["mode"] == "guardrail on"]["breaches"].sum())
        st.markdown(
            f"**{off_total} → {on_total}** attacks succeed once the policy is enforced."
        )

st.markdown("---")


# ---------------------------------------------------------------------------
# 3 — layer attribution
# ---------------------------------------------------------------------------

st.subheader("Layer attribution")
st.caption("Which layer stopped what. A single layer carrying everything is a warning, not a result.")

attribution = []
for _, row in view.iterrows():
    if row["outcome"] in ("blocked", "approval_required"):
        attribution.append(
            {
                "layer": layer_for(guarded, row["blocked_by"]),
                "rule": row["blocked_by"],
                "hook": row["blocked_at_hook"],
                "outcome": OUTCOME_LABELS.get(row["outcome"], row["outcome"]),
                "count": 1,
            }
        )

if attribution:
    layers = pd.DataFrame(attribution).groupby(["layer", "hook", "outcome"], as_index=False).sum()
    chart = (
        alt.Chart(layers)
        .mark_bar()
        .encode(
            x=alt.X("count:Q", title="attacks stopped"),
            y=alt.Y("layer:N", title=None, sort="-x"),
            color=alt.Color(
                "hook:N",
                title="hook",
                scale=alt.Scale(scheme="tableau10"),
            ),
            tooltip=["layer", "hook", "outcome", "count"],
        )
        .properties(height=max(200, 42 * layers["layer"].nunique()))
    )
    st.altair_chart(chart, width="stretch")
else:
    st.info("Nothing was stopped in this run.")

st.markdown("---")


# ---------------------------------------------------------------------------
# 4 — family × severity heatmap
# ---------------------------------------------------------------------------

st.subheader("Coverage: family × severity")
st.caption("Breaches per cell. Empty is good; a hot cell is where to spend the next hour.")

heat = (
    view.assign(breach=view["succeeded"].astype(int))
    .groupby(["family", "severity"], as_index=False)
    .agg(breaches=("breach", "sum"), total=("breach", "size"))
)
if not heat.empty:
    chart = (
        alt.Chart(heat)
        .mark_rect()
        .encode(
            x=alt.X("severity:N", sort=SEVERITY_ORDER, title=None),
            y=alt.Y("family:N", title=None),
            color=alt.Color(
                "breaches:Q",
                title="breaches",
                scale=alt.Scale(scheme="reds"),
            ),
            tooltip=["family", "severity", "breaches", "total"],
        )
        .properties(height=max(180, 44 * heat["family"].nunique()))
    )
    text = chart.mark_text(baseline="middle", fontWeight="bold").encode(
        text=alt.Text("breaches:Q"),
        color=alt.value("#111"),
    )
    st.altair_chart(chart + text, width="stretch")

st.markdown("---")


# ---------------------------------------------------------------------------
# 5 — mutation effectiveness
# ---------------------------------------------------------------------------

st.subheader("Mutation effectiveness")
st.caption(
    "Which obfuscations survive the filter. A mutation that gets through where "
    "its base variant did not names the exact normalisation step you are missing."
)

mutation_rows = []
for template_id, group in view.groupby("template_id"):
    base = group[group["mutation"] == "base"]
    base_breached = bool(base["succeeded"].any()) if len(base) else False
    for _, row in group.iterrows():
        if row["mutation"] == "base":
            continue
        mutation_rows.append(
            {
                "template": template_id,
                "mutation": row["mutation"],
                "outcome": OUTCOME_LABELS.get(row["outcome"], row["outcome"]),
                "got_through": bool(row["succeeded"]),
                "new_gap": bool(row["succeeded"]) and not base_breached,
            }
        )

if mutation_rows:
    mutations = pd.DataFrame(mutation_rows)
    chart = (
        alt.Chart(mutations)
        .mark_rect(stroke="white", strokeWidth=1)
        .encode(
            x=alt.X("mutation:N", title=None, axis=alt.Axis(labelAngle=-30)),
            y=alt.Y("template:N", title=None),
            color=alt.Color(
                "outcome:N",
                title=None,
                scale=alt.Scale(
                    domain=[OUTCOME_LABELS[k] for k in OUTCOME_COLOURS],
                    range=list(OUTCOME_COLOURS.values()),
                ),
            ),
            tooltip=["template", "mutation", "outcome", "got_through", "new_gap"],
        )
        .properties(height=max(200, 30 * mutations["template"].nunique()))
    )
    st.altair_chart(chart, width="stretch")

    escapes = mutations[mutations["new_gap"]]
    if len(escapes):
        st.error(
            "**Mutations that got through where the base payload did not:** "
            + ", ".join(f"{r.template}/{r.mutation}" for r in escapes.itertuples()),
            icon="⚠️",
        )
    else:
        st.success("No mutation defeated a filter that caught its base payload.", icon="✅")
else:
    st.info("No mutation variants in this corpus.")

st.markdown("---")


# ---------------------------------------------------------------------------
# 6 — skipped templates
# ---------------------------------------------------------------------------

st.subheader("Not applicable to this agent")
st.caption(
    "Templates that could not bind to this manifest, and why. This is coverage "
    "information, not a gap — but an unexplained absence would be."
)

skipped = guarded.get("skipped_templates") or []
if skipped:
    st.dataframe(
        pd.DataFrame(skipped).rename(columns={"id": "template", "reason": "why it was skipped"}),
        width="stretch",
        hide_index=True,
    )
else:
    st.success("Every shipped template bound to this agent's tool surface.", icon="✅")

st.markdown("---")


# ---------------------------------------------------------------------------
# 7 — trend
# ---------------------------------------------------------------------------

st.subheader("Trend")

history = (
    all_frames[all_frames["guardrail"] == "on"]
    .groupby(["run", "generated_at"], as_index=False)
    .agg(breaches=("succeeded", "sum"), total=("succeeded", "size"))
)
if len(history) > 1:
    history["defense_rate"] = 1 - (history["breaches"] / history["total"])
    history = history.sort_values("generated_at")
    chart = (
        alt.Chart(history)
        .mark_line(point=True, strokeWidth=3, color="#1f7a4d")
        .encode(
            x=alt.X("generated_at:T", title=None),
            y=alt.Y("defense_rate:Q", title="defense rate", scale=alt.Scale(domain=[0, 1])),
            tooltip=["run", "generated_at", "breaches", "total", "defense_rate"],
        )
        .properties(height=260)
    )
    st.altair_chart(chart, width="stretch")
else:
    st.info("Load more than one guarded run to see defense rate over time.")

st.markdown("---")


# ---------------------------------------------------------------------------
# 8 — per-attack detail
# ---------------------------------------------------------------------------

st.subheader("Per-attack detail")

by_id = {r.get("id"): r for r in guarded.get("results", [])}
# Inconclusive sorts second: after real breaches, ahead of everything that was
# actually observed, because it is the category that needs a decision from a human.
order = {"breach": 0, "inconclusive": 1, "approval_required": 2, "not_complied": 3, "blocked": 4}
visible = sorted(view["id"], key=lambda i: (order.get(by_id.get(i, {}).get("outcome", ""), 9), i))

for attack_id in visible:
    record = by_id.get(attack_id)
    if not record:
        continue
    outcome = record.get("outcome", "")
    badge = {
        "breach": "🔴",
        "approval_required": "🟠",
        "blocked": "🟢",
        "not_complied": "⚪",
        "inconclusive": "🟣",
    }.get(outcome, "•")
    label = OUTCOME_LABELS.get(outcome, outcome)
    with st.expander(
        f"{badge}  {attack_id} — {record.get('family', '')} / {record.get('severity', '')} — {label}"
    ):
        left, right = st.columns([1, 1])
        with left:
            st.markdown("**Success check**")
            check = record.get("success_check") or {}
            st.json(
                {
                    "type": check.get("type"),
                    "expected": check.get("expected", check.get("expected_from_state")),
                    "actual": check.get("actual"),
                    "passed": check.get("passed"),
                    "reason": check.get("reason"),
                    **(
                        {"relaxed_from": check["relaxed_from"]}
                        if check.get("relaxed_from")
                        else {}
                    ),
                },
                expanded=True,
            )
            st.markdown("**Tool calls**")
            calls = record.get("tool_calls") or []
            if calls:
                st.dataframe(
                    pd.DataFrame(
                        [{"tool": c.get("name"), "args": json.dumps(c.get("args", {}))} for c in calls]
                    ),
                    width="stretch",
                    hide_index=True,
                )
            else:
                st.caption("No tool calls — the turn was stopped before the agent ran.")
        with right:
            st.markdown("**Decision trace**")
            decisions = record.get("decisions") or []
            if decisions:
                st.dataframe(
                    pd.DataFrame(decisions)[
                        ["name", "triggered", "action", "severity", "layer", "reason"]
                    ],
                    width="stretch",
                    hide_index=True,
                    height=min(360, 40 + 35 * len(decisions)),
                )
            else:
                st.caption("No decisions — guardrail was off for this run.")
            if record.get("final_output"):
                st.markdown("**Final output**")
                st.code(record["final_output"][:1200], language=None)

st.markdown("---")


# ---------------------------------------------------------------------------
# 9 — export
# ---------------------------------------------------------------------------

st.subheader("Export")
st.download_button(
    "Download filtered results (CSV)",
    data=view.to_csv(index=False).encode("utf-8"),
    file_name="detguard-results.csv",
    mime="text/csv",
)
st.caption(f"{len(view)} row(s) matching the current filters.")
