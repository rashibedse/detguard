"""detguard config-authoring app.

Writes ``manifest.yaml``, ``roles.yaml``, ``policy.yaml`` and (optionally) a
CI workflow file. Separate from ``dashboard/app.py`` on purpose: that app's
own contract is that it never writes anything, because a report is not
evidence if the process producing it can also affect the outcome. This app is
the opposite — its only job is writing config, correctly, before you ever run
an attack.

    streamlit run dashboard/setup.py

Every form round-trips through the same validators the CLI uses
(``manifest.parse_manifest``, ``manifest.parse_roles``, ``policy.loads``)
before anything is written, so this app cannot produce a file the CLI would
later reject. It never executes a tool, never invokes an agent — introspection
reads metadata only, and ``run``/``report`` are commands you copy into a
terminal or into CI, not buttons here.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import streamlit as st
import yaml

import detguard
from detguard.manifest import (
    FRAMEWORKS,
    SOURCE_KINDS,
    ManifestError,
    parse_manifest,
    parse_roles,
)
from detguard.policy import PolicyError, loads as load_policy
from detguard.roles import GATED_BY_DEFAULT, ROLES, gated_tools
from detguard.scaffold import AdapterConfig, RunConfig, build_commands, generate_workflow

st.set_page_config(page_title="detguard setup", page_icon="🛠", layout="wide")

DEFAULT_POLICY_PATH = Path(detguard.__file__).resolve().parent / "policies" / "default.yaml"

# The five rules default.yaml ships CLIENT-marked and inert. Setup only ever
# edits these `params` blocks — everything else in the policy (pattern_sets,
# the deterministic content-scan/PII rules, audit) is shipped correct and is
# not something a form should be able to drift from the reviewed default.
CLIENT_RULES = (
    "human_in_loop",
    "unrequested_mutation",
    "ungrounded_destination",
    "external_destination_allowlist",
    "amount_bound",
)


# ---------------------------------------------------------------------------
# session state
# ---------------------------------------------------------------------------


def _init_state() -> None:
    ss = st.session_state
    ss.setdefault("config_dir", "guardrail")
    ss.setdefault("agent", "my-agent")
    ss.setdefault("framework", "generic")
    ss.setdefault("principal", "the account holder")
    ss.setdefault("tools", [])  # list of {name, description, params_json}
    ss.setdefault("untrusted_sources", [])  # list of {name, kind, injection_point}
    ss.setdefault("state_paths", {})  # role -> path
    ss.setdefault("roles_map", {})  # tool -> [role, ...]
    ss.setdefault("unclassified", [])
    ss.setdefault("policy_doc", None)  # full parsed policy.yaml, dict form
    ss.setdefault("run_cfg", {
        "policy": "guardrail/policy.yaml",
        "corpus": "corpus/attacks",
        "run_dir": "runs/demo",
        "adapter_kind": "generic",
        "agent_ref": "myapp.detguard_adapter:build_adapter",
        "graph": "",
        "reset": "",
        "tools_ref": "",
        "state_reader": "",
    })
    ss.setdefault("include_nightly", True)


_init_state()


def _manifest_dict() -> dict:
    tools = []
    for t in st.session_state.tools:
        try:
            params = json.loads(t.get("params_json") or "{}")
        except json.JSONDecodeError:
            params = {}
        tools.append({"name": t["name"], "description": t.get("description", ""), "params": params})
    return {
        "agent": st.session_state.agent,
        "framework": st.session_state.framework,
        "principal": st.session_state.principal,
        "tools": tools,
        "untrusted_sources": [dict(s) for s in st.session_state.untrusted_sources],
        "state_paths": dict(st.session_state.state_paths),
    }


def _roles_dict() -> dict:
    return {
        "agent": st.session_state.agent,
        "roles": {tool: list(assigned) for tool, assigned in st.session_state.roles_map.items()},
        "unclassified": list(st.session_state.unclassified),
    }


def _validated_manifest():
    return parse_manifest(_manifest_dict())


def _write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False)


st.sidebar.title("🛠 detguard setup")
st.sidebar.caption("Config authoring — validates before it writes, never runs an attack")
st.session_state.config_dir = st.sidebar.text_input(
    "Config directory", value=st.session_state.config_dir,
    help="Where manifest.yaml / roles.yaml / policy.yaml are written and read from",
)
config_dir = Path(st.session_state.config_dir)

if st.sidebar.button("Load existing config from this directory"):
    loaded_any = False
    manifest_path = config_dir / "manifest.yaml"
    roles_path = config_dir / "roles.yaml"
    policy_path = config_dir / "policy.yaml"
    if manifest_path.is_file():
        try:
            raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
            m = parse_manifest(raw, source_path=str(manifest_path))
            st.session_state.agent = m.agent
            st.session_state.framework = m.framework
            st.session_state.principal = m.principal
            st.session_state.tools = [
                {"name": t.name, "description": t.description, "params_json": json.dumps(t.params)}
                for t in m.tools
            ]
            st.session_state.untrusted_sources = [s.to_dict() for s in m.untrusted_sources]
            st.session_state.state_paths = dict(m.state_paths)
            loaded_any = True
        except ManifestError as exc:
            st.sidebar.error(f"manifest.yaml: {exc}")
    if roles_path.is_file():
        try:
            raw = yaml.safe_load(roles_path.read_text(encoding="utf-8"))
            r = parse_roles(raw, source_path=str(roles_path))
            st.session_state.roles_map = dict(r.roles)
            st.session_state.unclassified = list(r.unclassified)
            loaded_any = True
        except ManifestError as exc:
            st.sidebar.error(f"roles.yaml: {exc}")
    if policy_path.is_file():
        try:
            raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
            load_policy(raw, source_path=str(policy_path))  # validate only
            st.session_state.policy_doc = raw
            loaded_any = True
        except PolicyError as exc:
            st.sidebar.error(f"policy.yaml: {exc}")
    if loaded_any:
        st.sidebar.success("Loaded.")
    else:
        st.sidebar.info("Nothing found there yet — starting fresh.")

st.title("detguard setup")
tab_manifest, tab_roles, tab_policy, tab_run, tab_ci = st.tabs(
    ["Manifest", "Roles", "Policy", "Run", "CI"]
)


# ---------------------------------------------------------------------------
# Manifest tab
# ---------------------------------------------------------------------------

with tab_manifest:
    st.caption(
        "The entire integration contract: your tool names and argument schemas. "
        "No source code, no data, no credentials."
    )

    c1, c2, c3 = st.columns(3)
    st.session_state.agent = c1.text_input("Agent name", value=st.session_state.agent)
    st.session_state.framework = c2.selectbox(
        "Framework", FRAMEWORKS, index=FRAMEWORKS.index(st.session_state.framework)
    )
    st.session_state.principal = c3.text_input("Principal", value=st.session_state.principal)

    st.markdown("#### Discover tools")
    st.caption(
        "Pre-populate the tool list by introspecting a live adapter — metadata "
        "only, nothing is invoked. Same discovery cascade `detguard init` uses."
    )
    disc_col1, disc_col2 = st.columns(2)
    with disc_col1:
        graph_spec = st.text_input("LangGraph graph (module:graph)", key="disc_graph")
    with disc_col2:
        agent_spec = st.text_input("Adapter factory (module:factory)", key="disc_agent")

    if st.button("Run discovery"):
        if graph_spec and agent_spec:
            st.error("Pass either a graph or a factory, not both.")
        elif not graph_spec and not agent_spec:
            st.error("Enter a graph or a factory import string first.")
        else:
            try:
                import sys

                cwd = os.getcwd()
                if cwd not in sys.path:
                    sys.path.insert(0, cwd)
                if graph_spec:
                    from detguard.cli import _resolve_import

                    graph = _resolve_import(graph_spec, "graph")
                    from detguard.adapters.langgraph import LangGraphAdapter

                    adapter = LangGraphAdapter(graph=graph, reset_hook=None)
                    st.session_state.framework = "langgraph"
                else:
                    from detguard.cli import _resolve_import

                    factory = _resolve_import(agent_spec, "factory")
                    adapter = factory()
                introspected = adapter.introspect()
                st.session_state.tools = [
                    {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "params_json": json.dumps(t.get("params", {})),
                        "discovered_from": t.get("discovered_from", ""),
                    }
                    for t in introspected.get("tools", [])
                ]
                if not st.session_state.tools:
                    st.warning("Discovery found no tools. Add them by hand below.")
                else:
                    st.success(f"Discovered {len(st.session_state.tools)} tool(s).")
            except Exception as exc:  # noqa: BLE001 - surface whatever import/introspect raised
                st.error(f"Discovery failed: {exc}")

    st.markdown("#### Tools")
    for i, tool in enumerate(st.session_state.tools):
        with st.expander(
            f"{tool.get('name') or f'tool #{i + 1}'}"
            + (f"  ·  from {tool['discovered_from']}" if tool.get("discovered_from") else ""),
            expanded=not tool.get("name"),
        ):
            tool["name"] = st.text_input("Name", value=tool.get("name", ""), key=f"tool_name_{i}")
            tool["description"] = st.text_input(
                "Description", value=tool.get("description", ""), key=f"tool_desc_{i}"
            )
            tool["params_json"] = st.text_area(
                "Params (JSON)", value=tool.get("params_json", "{}"), key=f"tool_params_{i}", height=80
            )
            if st.button("Remove tool", key=f"tool_remove_{i}"):
                st.session_state.tools.pop(i)
                st.rerun()
    if st.button("Add tool"):
        st.session_state.tools.append({"name": "", "description": "", "params_json": "{}"})
        st.rerun()

    st.markdown("#### Untrusted sources")
    st.caption(
        "Carriers an attacker could author into — ticket bodies, fetched files, "
        "retrieved documents. Indirect-injection templates skip without at least one."
    )
    for i, src in enumerate(st.session_state.untrusted_sources):
        cols = st.columns([3, 2, 3, 1])
        src["name"] = cols[0].text_input("Name", value=src.get("name", ""), key=f"src_name_{i}")
        src["kind"] = cols[1].selectbox(
            "Kind", SOURCE_KINDS, index=SOURCE_KINDS.index(src.get("kind", "record")), key=f"src_kind_{i}"
        )
        src["injection_point"] = cols[2].text_input(
            "Injection point", value=src.get("injection_point", ""), key=f"src_inj_{i}"
        )
        if cols[3].button("✕", key=f"src_remove_{i}"):
            st.session_state.untrusted_sources.pop(i)
            st.rerun()
    if st.button("Add untrusted source"):
        st.session_state.untrusted_sources.append({"name": "", "kind": "record", "injection_point": ""})
        st.rerun()

    st.markdown("#### State paths")
    st.caption(
        "Where a role's effect lands in your state, so success checks verify real "
        "post-run state rather than trusting the agent's own account of itself."
    )
    for role in ROLES:
        st.session_state.state_paths[role] = st.text_input(
            role, value=st.session_state.state_paths.get(role, ""), key=f"state_path_{role}"
        ) or st.session_state.state_paths.get(role, "")
    # Drop roles left blank so an empty string never round-trips into the file.
    st.session_state.state_paths = {
        r: p for r, p in st.session_state.state_paths.items() if p
    }

    st.markdown("---")
    try:
        _validated_manifest()
        st.success("Manifest is valid.")
        if st.button("Write manifest.yaml", type="primary"):
            _write_yaml(config_dir / "manifest.yaml", _manifest_dict())
            st.success(f"Wrote {config_dir / 'manifest.yaml'}")
    except ManifestError as exc:
        st.error(f"Not valid yet: {exc}")


# ---------------------------------------------------------------------------
# Roles tab
# ---------------------------------------------------------------------------

with tab_roles:
    st.caption(
        "Nine roles, closed vocabulary. This is the artifact everything else "
        "keys off — attack templates, the policy defaults, the gate."
    )

    tool_names = sorted({t["name"] for t in st.session_state.tools if t.get("name")})
    if not tool_names:
        st.info("Add tools in the Manifest tab first.")
    for name in tool_names:
        current = st.session_state.roles_map.get(name, [])
        chosen = st.multiselect(
            name, ROLES, default=[r for r in current if r in ROLES], key=f"roles_{name}",
            help="Gated by default: " + ", ".join(GATED_BY_DEFAULT),
        )
        st.session_state.roles_map[name] = chosen

    # Tools removed from the manifest since the last edit should not linger.
    st.session_state.roles_map = {
        name: roles for name, roles in st.session_state.roles_map.items() if name in tool_names
    }

    unclassified = [n for n in tool_names if not st.session_state.roles_map.get(n)]
    if unclassified:
        st.warning(
            "Unclassified — attacks cannot bind to these and no rule will gate "
            "them: " + ", ".join(unclassified)
        )
    st.session_state.unclassified = unclassified

    st.markdown("---")
    try:
        manifest = _validated_manifest()
        role_map = parse_roles(_roles_dict(), manifest=manifest)
        st.success("Role map is valid.")
        gated = gated_tools(st.session_state.roles_map)
        if gated:
            st.caption("Gated by default (feeds the Policy tab's `human_in_loop` suggestion): " + ", ".join(gated))
        if st.button("Write roles.yaml", type="primary"):
            _write_yaml(config_dir / "roles.yaml", _roles_dict())
            st.success(f"Wrote {config_dir / 'roles.yaml'}")
    except ManifestError as exc:
        st.error(f"Not valid yet: {exc}")


# ---------------------------------------------------------------------------
# Policy tab
# ---------------------------------------------------------------------------

with tab_policy:
    st.caption(
        "The five rules default.yaml ships CLIENT-marked and inert. Everything "
        "else — pattern_sets, the deterministic scans, audit — is the reviewed "
        "default and is not edited here."
    )

    if st.session_state.policy_doc is None:
        base = yaml.safe_load(DEFAULT_POLICY_PATH.read_text(encoding="utf-8"))
        st.session_state.policy_doc = base
        st.info(f"Starting from the shipped default: {DEFAULT_POLICY_PATH}")

    doc = st.session_state.policy_doc
    rules_by_id = {r["id"]: r for r in doc.get("rules", [])}
    gated = gated_tools(st.session_state.roles_map)

    if "human_in_loop" in rules_by_id:
        st.markdown("##### `human_in_loop` — the gate")
        params = rules_by_id["human_in_loop"].setdefault("params", {})
        current = params.get("tools") or []
        if gated and st.button("Suggest from roles.yaml (gated-by-default tools)"):
            current = gated
        params["tools"] = st.multiselect(
            "Tools requiring human approval",
            sorted(set(current) | set(gated)),
            default=current,
            key="policy_hitl_tools",
        )

    if "unrequested_mutation" in rules_by_id:
        st.markdown("##### `unrequested_mutation`")
        params = rules_by_id["unrequested_mutation"].setdefault("params", {})
        all_tools = sorted({t["name"] for t in st.session_state.tools if t.get("name")})
        params["mutating_tools"] = st.multiselect(
            "Tools that change state", all_tools, default=params.get("mutating_tools") or [],
            key="policy_um_mutating",
        )
        params["allowed_tools"] = st.multiselect(
            "Tools a view-only request licenses", all_tools, default=params.get("allowed_tools") or [],
            key="policy_um_allowed",
        )

    if "ungrounded_destination" in rules_by_id:
        st.markdown("##### `ungrounded_destination`")
        params = rules_by_id["ungrounded_destination"].setdefault("params", {})
        c1, c2 = st.columns(2)
        params["tool"] = c1.text_input(
            "Tool ('' = any)", value=params.get("tool", ""), key="policy_gd_tool"
        )
        params["arg"] = c2.text_input(
            "Destination argument", value=params.get("arg", ""), key="policy_gd_arg"
        )

    if "external_destination_allowlist" in rules_by_id:
        st.markdown("##### `external_destination_allowlist`")
        params = rules_by_id["external_destination_allowlist"].setdefault("params", {})
        c1, c2 = st.columns(2)
        params["tool"] = c1.text_input(
            "External send/fetch tool", value=params.get("tool", ""), key="policy_ea_tool"
        )
        params["arg"] = c2.text_input(
            "Destination argument", value=params.get("arg", ""), key="policy_ea_arg"
        )
        allowlist_text = st.text_area(
            "Allowlist (one per line — empty blocks every external destination)",
            value="\n".join(params.get("allowlist") or []),
            key="policy_ea_allowlist",
        )
        params["allowlist"] = [line.strip() for line in allowlist_text.splitlines() if line.strip()]

    if "amount_bound" in rules_by_id:
        st.markdown("##### `amount_bound` (ships disabled)")
        rule = rules_by_id["amount_bound"]
        params = rule.setdefault("params", {})
        c1, c2, c3 = st.columns(3)
        params["tool"] = c1.text_input(
            "move_value tool", value=params.get("tool", ""), key="policy_ab_tool"
        )
        params["arg"] = c2.text_input(
            "Amount argument", value=params.get("arg", ""), key="policy_ab_arg"
        )
        params["min"] = c3.number_input(
            "Minimum requiring approval", value=float(params.get("min", 0)), key="policy_ab_min"
        )
        rule["enabled"] = st.checkbox(
            "Enable (only once you have a number you believe)",
            value=rule.get("enabled", False), key="policy_ab_enabled",
        )

    st.markdown("---")
    try:
        load_policy(doc, source_path="<setup.py>")
        st.success("Policy is valid.")
        if st.button("Write policy.yaml", type="primary"):
            _write_yaml(config_dir / "policy.yaml", doc)
            st.success(f"Wrote {config_dir / 'policy.yaml'}")
    except PolicyError as exc:
        st.error(f"Not valid yet: {exc}")


# ---------------------------------------------------------------------------
# Run tab
# ---------------------------------------------------------------------------

with tab_run:
    st.caption(
        "Assembles the commands quickstart.md walks through, filled in from "
        "your config above. Nothing on this page executes anything — copy a "
        "command into a terminal, or use the CI tab to run it in your pipeline."
    )

    rc = st.session_state.run_cfg
    c1, c2, c3 = st.columns(3)
    rc["policy"] = c1.text_input("Policy path", value=rc["policy"])
    rc["corpus"] = c2.text_input("Corpus dir", value=rc["corpus"])
    rc["run_dir"] = c3.text_input("Run dir", value=rc["run_dir"])

    rc["adapter_kind"] = st.selectbox(
        "Adapter", ["generic", "langgraph", "openai_agents"],
        index=["generic", "langgraph", "openai_agents"].index(rc["adapter_kind"]),
    )
    if rc["adapter_kind"] == "langgraph":
        c1, c2 = st.columns(2)
        rc["graph"] = c1.text_input("Graph (module:graph)", value=rc["graph"])
        rc["reset"] = c2.text_input("Reset hook (module:function)", value=rc["reset"])
        c3, c4 = st.columns(2)
        rc["tools_ref"] = c3.text_input(
            "Tools override (module:LIST, optional)", value=rc["tools_ref"]
        )
        rc["state_reader"] = c4.text_input(
            "State reader (module:function, optional)", value=rc["state_reader"]
        )
        rc["agent_ref"] = st.text_input(
            "…or a factory instead (module:factory, leave graph blank to use this)",
            value=rc["agent_ref"],
        )
    else:
        rc["agent_ref"] = st.text_input("Adapter factory (module:factory)", value=rc["agent_ref"])

    manifest_path = str(config_dir / "manifest.yaml")
    roles_path = str(config_dir / "roles.yaml")

    adapter_cfg = AdapterConfig(
        kind=rc["adapter_kind"],
        agent=rc["agent_ref"],
        graph=rc["graph"] if rc["adapter_kind"] == "langgraph" else "",
        reset=rc["reset"] if rc["adapter_kind"] == "langgraph" else "",
        tools=rc["tools_ref"] if rc["adapter_kind"] == "langgraph" else "",
        state_reader=rc["state_reader"] if rc["adapter_kind"] == "langgraph" else "",
    )
    run_config = RunConfig(
        manifest=manifest_path, roles=roles_path, policy=rc["policy"],
        corpus=rc["corpus"], run_dir=rc["run_dir"], adapter=adapter_cfg,
    )

    problems = adapter_cfg.problems()
    if problems:
        st.warning("Not runnable yet: " + "; ".join(problems))
    else:
        st.markdown("#### Commands")
        for label, cmd in build_commands(run_config).items():
            st.code(cmd, language="bash")


# ---------------------------------------------------------------------------
# CI tab
# ---------------------------------------------------------------------------

with tab_ci:
    st.caption(
        "Generates `.github/workflows/detguard-gate.yml` from the same config "
        "as the Run tab — the file you would otherwise hand-edit from "
        "`.github/workflows/client-gate-template.yml`."
    )

    st.session_state.include_nightly = st.checkbox(
        "Include a non-blocking nightly job (full corpus, llm_judge enabled)",
        value=st.session_state.include_nightly,
    )

    rc = st.session_state.run_cfg
    adapter_cfg = AdapterConfig(
        kind=rc["adapter_kind"],
        agent=rc["agent_ref"],
        graph=rc["graph"] if rc["adapter_kind"] == "langgraph" else "",
        reset=rc["reset"] if rc["adapter_kind"] == "langgraph" else "",
        tools=rc["tools_ref"] if rc["adapter_kind"] == "langgraph" else "",
        state_reader=rc["state_reader"] if rc["adapter_kind"] == "langgraph" else "",
    )
    run_config = RunConfig(
        manifest=str(config_dir / "manifest.yaml"),
        roles=str(config_dir / "roles.yaml"),
        policy=rc["policy"], corpus=rc["corpus"], run_dir=rc["run_dir"], adapter=adapter_cfg,
    )

    problems = adapter_cfg.problems()
    if problems:
        st.warning("Fill in the Run tab's adapter fields first: " + "; ".join(problems))
    else:
        try:
            workflow_text = generate_workflow(run_config, include_nightly=st.session_state.include_nightly)
            st.code(workflow_text, language="yaml")
            out_path = Path(".github/workflows/detguard-gate.yml")
            if st.button("Write .github/workflows/detguard-gate.yml", type="primary"):
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(workflow_text, encoding="utf-8")
                st.success(f"Wrote {out_path}")
        except ValueError as exc:
            st.error(str(exc))
