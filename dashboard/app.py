"""detguard dashboard.

Reads results files, and optionally the manifest/roles/policy that produced
them, and nothing else. It never invokes an agent and never writes anything —
if this process can affect an outcome it is reporting on, the report is not
evidence. Loading a policy here is a deliberate, narrow exception to that rule:
the "Coverage by tool" tab has to read `policy.yaml`'s rule params to say which
tool a rule covers, same as `detguard report` already does when it names a
one-line fix — evaluation of that policy against live traffic still happens
nowhere but `engine.py`.

    streamlit run dashboard/app.py

Point it at a directory of results files; two runs of the same corpus with the
guardrail on and off are what make section 2 worth looking at. Point "Config
directory" at the folder holding `manifest.yaml`/`roles.yaml`/`policy.yaml` to
unlock the "Coverage by tool" tab — every other tab works without it.
"""

from __future__ import annotations

import glob
import json
import os

import altair as alt
import pandas as pd
import streamlit as st

from detguard import baseline as baseline_mod
from detguard import manifest as manifest_mod
from detguard import policy as policy_mod
from detguard import roles as roles_mod

st.set_page_config(page_title="detguard", page_icon="🛡", layout="wide")

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
#: One severity → one colour, reused everywhere severity appears as a plain
#: table column, so "critical" means the same shade in the decision trace as
#: it does in the audit log rather than each table inventing its own scale.
SEVERITY_COLOURS = {
    "critical": "#4a1f1f",
    "high": "#4a331f",
    "medium": "#3a3410",
    "low": "#22303a",
}


def _severity_row_style(row: pd.Series) -> list[str]:
    colour = SEVERITY_COLOURS.get(str(row.get("severity", "")).lower(), "")
    style = f"background-color: {colour}" if colour else ""
    return [style for _ in row]
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
def load_results(path: str) -> dict | None:
    """Parse one results file, or ``None`` on anything unreadable.

    A malformed or truncated file (a demo interrupted mid-write, a hand-edited
    JSON with a typo) must not take the whole page down — the caller filters
    ``None`` out and reports which files it skipped, rather than the app
    throwing before a single tab renders.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
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
# coverage-by-tool: manifest + roles + policy, optionally loaded alongside
# the results files. Best-effort — any of the three missing or invalid just
# narrows what the tab can show, it never breaks the rest of the page.
# ---------------------------------------------------------------------------

#: Rule params that name the tool(s) a rule applies to, by condition shape.
#: A single "tool" key present-but-empty means "any tool" (the registry's own
#: fail-safe default for ungrounded_arg/numeric_bound/tool_arg_matches/
#: external_destination) — that is different from the key being absent
#: entirely, which means the condition is not tool-scoped at all (content
#: scans, call_budget, repeated_call) and says nothing about per-tool coverage.
_TOOL_LIST_PARAMS = ("tools", "mutating_tools")


def _find_config_dir(results_dir: str) -> str:
    """Best-effort guess at where manifest/roles/policy.yaml live.

    Results land in ``runs/<timestamp>/``; config conventionally lives in
    ``config/`` next to it. Tried in order, first directory holding at least
    a manifest wins — falls back to ``config`` so the sidebar field always has
    a sensible starting value even when nothing is found yet.
    """
    abs_results = os.path.abspath(results_dir)
    parent = os.path.dirname(abs_results)
    grandparent = os.path.dirname(parent)
    candidates = [
        os.path.join(abs_results, "config"),
        os.path.join(parent, "config"),
        # Covers the common `runs/<timestamp>/` nesting one level deeper than
        # `parent` accounts for — the project root is two hops up from there.
        os.path.join(grandparent, "config"),
        "config",
        ".",
    ]
    for c in candidates:
        if os.path.isfile(os.path.join(c, "manifest.yaml")):
            return c
    return "config"


@st.cache_data(show_spinner=False)
def load_coverage_sources(config_dir: str):
    """``(Manifest | None, RoleMap | None, PolicySet | None)``.

    Each loads independently — a broken `policy.yaml` should not also hide a
    perfectly good `manifest.yaml`. Errors are swallowed here because this tab
    degrades by design; `detguard run`/`detguard derive` are where a bad
    config file is supposed to be a loud, fatal error, not a Streamlit page.
    """
    manifest = role_map = policy = None
    manifest_path = os.path.join(config_dir, "manifest.yaml")
    roles_path = os.path.join(config_dir, "roles.yaml")
    policy_path = os.path.join(config_dir, "policy.yaml")

    if os.path.isfile(manifest_path):
        try:
            manifest = manifest_mod.load_manifest(manifest_path)
        except manifest_mod.ManifestError:
            manifest = None
    if os.path.isfile(roles_path):
        try:
            role_map = manifest_mod.load_roles(roles_path, manifest=manifest)
        except manifest_mod.ManifestError:
            role_map = None
    if os.path.isfile(policy_path):
        try:
            policy = policy_mod.load(policy_path)
        except policy_mod.PolicyError:
            policy = None
    return manifest, role_map, policy


def _find_baseline_path(results_dir: str, config_dir: str) -> str:
    """Best-effort guess at ``baseline.json``'s location.

    Convention (``docs/ci.md``) is ``corpus/baseline.json``, a sibling of
    ``config/`` rather than of the results directory — tried alongside a
    couple of looser fallbacks so the sidebar field starts somewhere sane.
    """
    project_root = os.path.dirname(os.path.abspath(config_dir))
    candidates = [
        os.path.join(results_dir, "baseline.json"),
        os.path.join(project_root, "corpus", "baseline.json"),
        os.path.join("corpus", "baseline.json"),
        "baseline.json",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return candidates[1]


@st.cache_data(show_spinner=False)
def load_baseline_source(path: str):
    """The parsed baseline, or ``None`` if it doesn't exist or won't parse."""
    if not path or not os.path.isfile(path):
        return None
    try:
        return baseline_mod.load(path)
    except baseline_mod.BaselineError:
        return None


def _find_audit_log_path(results_dir: str) -> str:
    """Best-effort guess at ``audit.jsonl``'s location — same directory as
    the results file is the common case (``--audit-log runs/<ts>/audit.jsonl``)."""
    candidates = [
        os.path.join(results_dir, "audit.jsonl"),
        "audit.jsonl",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return candidates[0]


@st.cache_data(show_spinner=False)
def load_audit_log(path: str) -> pd.DataFrame | None:
    """Parse a JSONL audit log into a DataFrame, or ``None`` if it's absent.

    One malformed line does not sink the rest — this is a log a client may
    have hand-inspected or truncated mid-write, not a file detguard itself
    guarantees is always well-formed.
    """
    if not path or not os.path.isfile(path):
        return None
    rows = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def _rule_tool_scope(rule, all_tool_names: list[str]) -> set[str]:
    """Which tool names this rule's params reference.

    Empty set means "not tool-scoped at all" (a content scan, a call budget)
    — that is deliberately not the same as covering zero tools, and the
    caller must not read it that way.
    """
    params = rule.params or {}
    for key in _TOOL_LIST_PARAMS:
        if params.get(key):
            return {str(x) for x in params[key]}
    if "tool" in params:
        value = params.get("tool")
        return {str(value)} if value else set(all_tool_names)
    return set()


def _tool_attack_stats(guarded_run: dict, tool_name: str) -> tuple[int, int, int]:
    """(attacks targeting this tool, blocked, breached) for one tool.

    "Targeting" means the tool was actually called, or would have been had a
    ``before_tool`` guard not intercepted it first (``prevented_calls`` —
    without counting those too, a fully-prevented tool would misread as never
    attacked at all).
    """
    targeted = blocked = breached = 0
    for r in guarded_run.get("results", []):
        names = {c.get("name") for c in (r.get("tool_calls") or [])}
        names |= {c.get("name") for c in (r.get("prevented_calls") or [])}
        if tool_name not in names:
            continue
        targeted += 1
        if r.get("outcome") in ("blocked", "approval_required"):
            blocked += 1
        elif r.get("succeeded"):
            breached += 1
    return targeted, blocked, breached


def build_tool_coverage(
    guarded_run: dict, manifest, role_map, policy
) -> pd.DataFrame:
    """One row per tool: role(s), covering rule(s), attack outcomes, gap flag.

    Falls back to tools observed in the results file when no manifest is
    loaded, so the tab is never just empty — it just can't show roles/rules
    for tools it never saw exercised.
    """
    if manifest is not None:
        tool_names = manifest.tool_names
    else:
        seen: set[str] = set()
        for r in guarded_run.get("results", []):
            seen |= {c.get("name") for c in (r.get("tool_calls") or [])}
            seen |= {c.get("name") for c in (r.get("prevented_calls") or [])}
        tool_names = sorted(n for n in seen if n)

    enabled_rules = [r for r in (policy.rules if policy is not None else []) if r.enabled]

    rows = []
    for name in tool_names:
        tool_roles = roles_mod.roles_of(role_map.roles, name) if role_map is not None else []
        covering = sorted(
            r.id for r in enabled_rules if name in _rule_tool_scope(r, tool_names)
        )
        is_sensitive = any(role in roles_mod.GATED_BY_DEFAULT for role in tool_roles)
        targeted, blocked, breached = _tool_attack_stats(guarded_run, name)
        rows.append(
            {
                "tool": name,
                "role(s)": ", ".join(tool_roles) or "—",
                "rule(s) covering it": ", ".join(covering) or "—",
                "attacks targeting it": targeted,
                "blocked": blocked,
                "breached": breached,
                "⚠ gap": is_sensitive and not covering,
            }
        )
    return pd.DataFrame(rows)


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

loaded = [(p, load_results(p)) for p in chosen]
unreadable = [p for p, r in loaded if r is None]
if unreadable:
    st.sidebar.warning(
        f"Could not parse {len(unreadable)} file(s): "
        + ", ".join(os.path.basename(p) for p in unreadable),
        icon="⚠️",
    )
runs = [r for _, r in loaded if r is not None and r.get("results") is not None]
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
config_dir = st.sidebar.text_input(
    "Config directory (manifest/roles/policy.yaml)",
    value=_find_config_dir(directory),
    help="Optional. Unlocks the 'Coverage by tool' tab — everything else "
    "on this page works without it.",
)
manifest, role_map, policy = load_coverage_sources(config_dir)

baseline_path = st.sidebar.text_input(
    "Baseline file",
    value=_find_baseline_path(directory, config_dir),
    help="Optional. Unlocks the 'Regression gate' tab.",
)
baseline_data = load_baseline_source(baseline_path)

audit_path = st.sidebar.text_input(
    "Audit log (JSONL)",
    value=_find_audit_log_path(directory),
    help="Optional. Unlocks the 'Audit log' tab — off by default in policy.yaml, "
    "so this is often empty unless `--audit-log` was passed to `detguard run`.",
)
audit_df = load_audit_log(audit_path)

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

k1, k2, k3, k4, k5, k6 = st.columns(6)
k1.metric(
    "Defense rate",
    f"{summary.get('defense_rate', 0):.1%}",
    help="Hard blocks only. A HITL pause means a human may still say yes, so "
    "it is reported separately as `containment_rate` rather than summed in "
    "here — a maybe counted as a no inflates the one number everyone reads.",
)
k2.metric(
    "Containment rate",
    f"{summary.get('containment_rate', 0):.1%}" if "containment_rate" in summary else "—",
    help="Hard blocks *plus* HITL pauses — everything that stopped unattended "
    "execution, whether or not a human still needs to say yes. Always ≥ "
    "defense rate; the gap between the two is exactly how many attacks are "
    "sitting in a human's queue rather than closed outright.",
)
k3.metric(
    "Coverage",
    f"{coverage:.1%}" if coverage is not None else "—",
    help="The share of attacks detguard could actually evaluate. A high defense "
    "rate over low coverage is not a result — the rest were neither defended "
    "nor breached, they were simply unobserved.",
)
k4.metric("Attacks run", int(len(attacks_only)))
k5.metric("Critical gaps open", critical_gaps, delta_color="inverse")
k6.metric("Policy", (guarded.get("policy_hash") or "—")[:12])

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

(
    tab_overview,
    tab_tool_coverage,
    tab_coverage,
    tab_regression,
    tab_detail,
    tab_audit,
    tab_export,
) = st.tabs(
    [
        "📊 Overview",
        "🛠 Coverage by tool",
        "🧩 Coverage & layers",
        "🚦 Regression gate",
        "🔍 Per-attack detail",
        "📜 Audit log",
        "⬇ Export",
    ]
)


# ---------------------------------------------------------------------------
# Tab 1 — overview: guarded vs unguarded, trend
# ---------------------------------------------------------------------------

with tab_overview:
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


# ---------------------------------------------------------------------------
# Tab — coverage by tool: for the person deciding where they still need a
# guardrail. Per tool: its role(s), which rules cover it, how it performed
# against the corpus, and whether a sensitive tool has zero coverage at all.
# ---------------------------------------------------------------------------

with tab_tool_coverage:
    st.subheader("Coverage by tool")
    st.caption(
        "What a rule actually protects, and what it doesn't yet. A sensitive "
        "tool with no rule referencing it is a gap whether or not this "
        "corpus happened to find it."
    )

    if manifest is None:
        st.info(
            f"No `manifest.yaml` found at `{os.path.abspath(config_dir)}`. Showing "
            "tools observed in this run only — point 'Config directory' in the "
            "sidebar at the folder holding manifest.yaml/roles.yaml/policy.yaml "
            "for role and rule coverage too."
        )
    elif role_map is None:
        st.info(f"No `roles.yaml` found at `{os.path.abspath(config_dir)}` — showing tools without role classification.")
    if manifest is not None and policy is None:
        st.info(f"No `policy.yaml` found at `{os.path.abspath(config_dir)}` — rule coverage can't be shown.")

    coverage_df = build_tool_coverage(guarded, manifest, role_map, policy)
    if coverage_df.empty:
        st.warning("No tools to show — no manifest loaded and no tool calls in this run.")
    else:
        gaps = coverage_df[coverage_df["⚠ gap"]]
        if role_map is not None and policy is not None:
            if len(gaps):
                st.error(
                    f"**{len(gaps)} sensitive tool(s) with no rule covering them:** "
                    + ", ".join(gaps["tool"]),
                    icon="⚠️",
                )
            else:
                st.success("Every sensitive-role tool has at least one rule covering it.", icon="✅")

        st.dataframe(
            coverage_df.style.apply(
                lambda row: ["background-color: #4a1f1f" if row["⚠ gap"] else "" for _ in row],
                axis=1,
            )
            if len(coverage_df)
            else coverage_df,
            width="stretch",
            hide_index=True,
        )
        st.caption(
            "A tool with `attacks targeting it = 0` is either not sensitive enough "
            "to be a template target, or the corpus doesn't yet exercise it — "
            "check `docs/attack-corpus.md` before reading that row as safe."
        )


# ---------------------------------------------------------------------------
# Tab 2 — coverage & layers: layer attribution, heatmap, mutations, skipped
# ---------------------------------------------------------------------------

with tab_coverage:
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


# ---------------------------------------------------------------------------
# Tab — regression gate: same classification `detguard baseline compare` uses
# to fail a build, made clickable instead of a markdown table in a PR comment.
# ---------------------------------------------------------------------------

with tab_regression:
    st.subheader("Regression gate")
    st.caption(
        "What changed since the baseline — the exact classification the CI "
        "gate runs to decide whether to fail a build."
    )

    if baseline_data is None:
        st.info(
            f"No baseline found at `{os.path.abspath(baseline_path)}`. Create one with "
            "`detguard baseline snapshot --results <results.json> --out "
            f"{baseline_path}`, or point the field above at an existing one."
        )
    else:
        comparison = baseline_mod.compare(guarded, baseline_data)
        if comparison["passed"]:
            st.success(f"**Gate passes** — exit code {comparison['exit_code']}.", icon="✅")
        else:
            st.error(f"**Gate fails** — exit code {comparison['exit_code']}.", icon="🛑")

        counts = comparison.get("counts") or {}
        if counts:
            st.dataframe(
                pd.DataFrame(
                    [{"regression class": k, "count": v} for k, v in counts.items()]
                ),
                width="stretch",
                hide_index=True,
            )

        findings = comparison.get("findings") or []
        if findings:
            findings_df = pd.DataFrame(findings).sort_values(
                ["fails", "kind"], ascending=[False, True]
            )

            def _row_colour(row):
                if row["fails"]:
                    style = "background-color: #4a1f1f"
                elif row["kind"] == "FIXED":
                    style = "background-color: #1f3a26"
                else:
                    style = ""
                return [style for _ in row]

            st.dataframe(
                findings_df.style.apply(_row_colour, axis=1),
                width="stretch",
                hide_index=True,
            )
        else:
            st.success("No differences from the baseline.", icon="✅")


# ---------------------------------------------------------------------------
# Tab 3 — per-attack detail
# ---------------------------------------------------------------------------

with tab_detail:
    by_id = {r.get("id"): r for r in guarded.get("results", [])}
    # Inconclusive sorts second: after real breaches, ahead of everything that was
    # actually observed, because it is the category that needs a decision from a human.
    order = {"breach": 0, "inconclusive": 1, "approval_required": 2, "not_complied": 3, "blocked": 4}
    visible = sorted(view["id"], key=lambda i: (order.get(by_id.get(i, {}).get("outcome", ""), 9), i))

    st.caption(f"{len(visible)} attack(s) matching the current filters, worst outcomes first.")

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
                    decisions_df = pd.DataFrame(decisions)[
                        ["name", "triggered", "action", "severity", "layer", "reason"]
                    ]
                    st.dataframe(
                        decisions_df.style.apply(_severity_row_style, axis=1),
                        width="stretch",
                        hide_index=True,
                        height=min(360, 40 + 35 * len(decisions)),
                    )
                else:
                    st.caption("No decisions — guardrail was off for this run.")
                if record.get("final_output"):
                    st.markdown("**Final output**")
                    st.code(record["final_output"][:1200], language=None)


# ---------------------------------------------------------------------------
# Tab — audit log: audit.py writes structured JSONL with no viewer of its
# own; this is that viewer.
# ---------------------------------------------------------------------------

with tab_audit:
    st.subheader("Audit log")
    st.caption(
        "Every decision the engine recorded, one row per rule evaluated. "
        "Off by default — populated only when `audit.enabled` in policy.yaml "
        "or `--audit-log` was used for this run."
    )

    if audit_df is None:
        st.info(
            f"No audit log found at `{os.path.abspath(audit_path)}`. Enable it with "
            "`detguard run --audit-log path/to/audit.jsonl ...`, or point the field "
            "above at an existing one."
        )
    elif audit_df.empty:
        st.warning(f"`{audit_path}` exists but has no readable rows.")
    else:
        cols = st.columns(4)
        hook_filter = cols[0].multiselect(
            "Hook", sorted(audit_df["hook"].dropna().unique()) if "hook" in audit_df else []
        )
        tool_filter = cols[1].multiselect(
            "Tool", sorted(audit_df["tool"].dropna().unique()) if "tool" in audit_df else []
        )
        verdict_filter = cols[2].multiselect(
            "Verdict", sorted(audit_df["verdict"].dropna().unique()) if "verdict" in audit_df else []
        )
        triggered_only = cols[3].checkbox("Triggered rules only", value=False)

        audit_view = audit_df
        if hook_filter:
            audit_view = audit_view[audit_view["hook"].isin(hook_filter)]
        if tool_filter:
            audit_view = audit_view[audit_view["tool"].isin(tool_filter)]
        if verdict_filter:
            audit_view = audit_view[audit_view["verdict"].isin(verdict_filter)]
        if triggered_only and "triggered" in audit_view:
            audit_view = audit_view[audit_view["triggered"].astype(bool)]

        display_cols = [
            c
            for c in (
                "timestamp",
                "case",
                "hook",
                "tool",
                "policy",
                "layer",
                "triggered",
                "action",
                "severity",
                "verdict",
                "reason",
            )
            if c in audit_view.columns
        ]
        st.caption(f"{len(audit_view)} of {len(audit_df)} log line(s) shown.")
        audit_display = (
            audit_view[display_cols].sort_values("timestamp", ascending=False)
            if "timestamp" in display_cols
            else audit_view[display_cols]
        )
        st.dataframe(
            audit_display.style.apply(_severity_row_style, axis=1)
            if "severity" in display_cols
            else audit_display,
            width="stretch",
            hide_index=True,
        )


# ---------------------------------------------------------------------------
# Tab 4 — export
# ---------------------------------------------------------------------------

with tab_export:
    st.subheader("Export")
    st.download_button(
        "Download filtered results (CSV)",
        data=view.to_csv(index=False).encode("utf-8"),
        file_name="detguard-results.csv",
        mime="text/csv",
    )
    st.caption(f"{len(view)} row(s) matching the current filters.")
