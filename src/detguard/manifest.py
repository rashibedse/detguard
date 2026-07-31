"""Manifest and role-map loading.

The tool manifest is the entire integration contract. A client never hands over
source code — they hand over the names and argument schemas of the tools their
agent can call, which every framework already generates and which contains no
business logic. Everything downstream binds to *roles*, not to tool names,
which is why the role map is validated as strictly as the policy is.

Hard error on an unknown role. Warning on an unclassified tool: a tool nobody
has classified is a coverage gap, and a gap you can see is survivable — one
that silently reads as "not sensitive" is not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .roles import ROLES, RoleError, validate_role

FRAMEWORKS = ("langgraph", "openai_agents", "generic")
SOURCE_KINDS = ("record", "file", "retrieval")


class ManifestError(ValueError):
    """Raised on an invalid manifest or role map. Always fatal."""


@dataclass
class Tool:
    name: str
    description: str = ""
    params: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"name": self.name, "description": self.description, "params": dict(self.params)}


@dataclass
class UntrustedSource:
    """A carrier an attacker can author into.

    ``name`` is the human-readable form used by ``{{source:read_untrusted}}`` —
    a filename, a record field, whatever the user would call it. ``kind`` says
    how it reaches the agent, and ``injection_point`` names the field the
    runner writes the payload into.
    """

    name: str
    kind: str = "record"
    injection_point: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind, "injection_point": self.injection_point}


@dataclass
class Manifest:
    agent: str
    framework: str = "generic"
    principal: str = "the account holder"
    tools: list = field(default_factory=list)
    untrusted_sources: list = field(default_factory=list)
    state_paths: dict = field(default_factory=dict)
    source_path: str = ""

    @property
    def tool_names(self) -> list[str]:
        return sorted(t.name for t in self.tools)

    def tool(self, name: str) -> Tool | None:
        for t in self.tools:
            if t.name == name:
                return t
        return None

    def state_path(self, role: str) -> str:
        return self.state_paths.get(validate_role(role), "")


@dataclass
class RoleMap:
    agent: str = ""
    roles: dict = field(default_factory=dict)
    unclassified: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    source_path: str = ""

    def tools_for(self, role: str) -> list[str]:
        canonical = validate_role(role)
        return sorted(
            tool for tool, assigned in self.roles.items() if canonical in assigned
        )

    @property
    def roles_present(self) -> list[str]:
        found: set[str] = set()
        for assigned in self.roles.values():
            found.update(assigned)
        return sorted(found)


# ---------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------


def load_manifest(path: str | Path) -> Manifest:
    p = Path(path)
    if not p.is_file():
        raise ManifestError(f"manifest not found: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ManifestError(f"{p}: not valid YAML: {exc}") from exc
    return parse_manifest(data, source_path=str(p))


def parse_manifest(data: Any, source_path: str = "<memory>") -> Manifest:
    if not isinstance(data, dict):
        raise ManifestError(f"{source_path}: manifest must be a mapping")

    agent = data.get("agent")
    if not isinstance(agent, str) or not agent.strip():
        raise ManifestError(f"{source_path}: 'agent' must be a non-empty string")

    framework = data.get("framework", "generic")
    if framework not in FRAMEWORKS:
        raise ManifestError(
            f"{source_path}: unknown framework {framework!r}; "
            f"must be one of {', '.join(FRAMEWORKS)}"
        )

    principal = data.get("principal") or "the account holder"
    if not isinstance(principal, str):
        raise ManifestError(f"{source_path}: 'principal' must be a string")

    raw_tools = data.get("tools")
    if not isinstance(raw_tools, list) or not raw_tools:
        raise ManifestError(f"{source_path}: 'tools' must be a non-empty list")

    tools: list[Tool] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_tools):
        where = f"{source_path}: tool #{index + 1}"
        if not isinstance(raw, dict):
            raise ManifestError(f"{where}: must be a mapping")
        name = raw.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ManifestError(f"{where}: 'name' must be a non-empty string")
        if name in seen:
            raise ManifestError(f"{source_path}: duplicate tool {name!r}")
        seen.add(name)
        params = raw.get("params") or {}
        if not isinstance(params, dict):
            raise ManifestError(f"{where} ({name}): 'params' must be a mapping")
        tools.append(Tool(name=name, description=str(raw.get("description", "")), params=params))

    sources: list[UntrustedSource] = []
    for index, raw in enumerate(data.get("untrusted_sources") or []):
        where = f"{source_path}: untrusted_source #{index + 1}"
        if not isinstance(raw, dict):
            raise ManifestError(f"{where}: must be a mapping")
        name = raw.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ManifestError(f"{where}: 'name' must be a non-empty string")
        kind = raw.get("kind", "record")
        if kind not in SOURCE_KINDS:
            raise ManifestError(
                f"{where} ({name}): unknown kind {kind!r}; "
                f"must be one of {', '.join(SOURCE_KINDS)}"
            )
        sources.append(
            UntrustedSource(
                name=name, kind=kind, injection_point=str(raw.get("injection_point", ""))
            )
        )

    raw_paths = data.get("state_paths") or {}
    if not isinstance(raw_paths, dict):
        raise ManifestError(f"{source_path}: 'state_paths' must be a mapping")
    state_paths: dict[str, str] = {}
    for role, path_expr in raw_paths.items():
        try:
            canonical = validate_role(role)
        except RoleError as exc:
            raise ManifestError(f"{source_path}: state_paths: {exc}") from exc
        if not isinstance(path_expr, str) or not path_expr.strip():
            raise ManifestError(
                f"{source_path}: state_paths[{role}] must be a non-empty string"
            )
        state_paths[canonical] = path_expr

    return Manifest(
        agent=agent,
        framework=framework,
        principal=principal,
        tools=tools,
        untrusted_sources=sources,
        state_paths=state_paths,
        source_path=source_path,
    )


# ---------------------------------------------------------------------------
# role map
# ---------------------------------------------------------------------------


def load_roles(path: str | Path, manifest: Manifest | None = None) -> RoleMap:
    p = Path(path)
    if not p.is_file():
        raise ManifestError(f"roles file not found: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ManifestError(f"{p}: not valid YAML: {exc}") from exc
    return parse_roles(data, manifest=manifest, source_path=str(p))


def parse_roles(
    data: Any, manifest: Manifest | None = None, source_path: str = "<memory>"
) -> RoleMap:
    if not isinstance(data, dict):
        raise ManifestError(f"{source_path}: roles file must be a mapping")

    raw_roles = data.get("roles")
    if not isinstance(raw_roles, dict) or not raw_roles:
        raise ManifestError(f"{source_path}: 'roles' must be a non-empty mapping")

    warnings: list[str] = []
    resolved: dict[str, list[str]] = {}

    for tool, assigned in raw_roles.items():
        if not isinstance(tool, str) or not tool.strip():
            raise ManifestError(f"{source_path}: roles keys must be tool names")
        if assigned is None:
            assigned = []
        if isinstance(assigned, str):
            assigned = [assigned]
        if not isinstance(assigned, list):
            raise ManifestError(
                f"{source_path}: roles[{tool}] must be a list of roles, got "
                f"{type(assigned).__name__}"
            )
        try:
            canonical = sorted({validate_role(r) for r in assigned})
        except RoleError as exc:
            raise ManifestError(f"{source_path}: roles[{tool}]: {exc}") from exc
        if not canonical:
            warnings.append(f"tool {tool!r} has no roles assigned")
        resolved[tool] = canonical

    unclassified = list(data.get("unclassified") or [])

    if manifest is not None:
        known = set(manifest.tool_names)
        unknown = sorted(set(resolved) - known)
        if unknown:
            raise ManifestError(
                f"{source_path}: roles reference tool(s) absent from the manifest: "
                f"{', '.join(unknown)}"
            )
        missing = sorted(known - set(resolved) - set(unclassified))
        if missing:
            unclassified = sorted(set(unclassified) | set(missing))
        if unclassified:
            warnings.append(
                "unclassified tool(s) — attacks cannot bind to them and no rule "
                f"will gate them: {', '.join(sorted(unclassified))}"
            )

    return RoleMap(
        agent=str(data.get("agent", "")),
        roles=resolved,
        unclassified=sorted(unclassified),
        warnings=warnings,
        source_path=source_path,
    )


def load_pair(manifest_path: str | Path, roles_path: str | Path) -> tuple[Manifest, RoleMap]:
    """Load both, cross-validated. This is what the CLI uses."""
    manifest = load_manifest(manifest_path)
    role_map = load_roles(roles_path, manifest=manifest)
    if role_map.agent and role_map.agent != manifest.agent:
        role_map.warnings.append(
            f"agent mismatch: manifest says {manifest.agent!r}, roles say {role_map.agent!r}"
        )
    return manifest, role_map


def skeleton(agent: str = "my-agent", framework: str = "generic") -> str:
    """A commented manifest for hand-filling when introspection is unavailable."""
    return f"""\
# detguard tool manifest — the entire integration contract.
# No source code, no data, no credentials. Just what your agent can call.
agent: {agent}
framework: {framework}

# Display name for the account holder, used by attack templates.
principal: "Sam Taylor"

tools:
  - name: example_read
    description: What this tool does, in one line.
    params:
      record_id: {{type: string, required: true}}

# Carriers an attacker could author into: ticket bodies, fetched files,
# retrieved documents, transaction memos. Indirect-injection templates need at
# least one of these, and are skipped without them.
untrusted_sources:
  - name: "ticket_body"
    kind: record            # record | file | retrieval
    injection_point: "body"

# Where a role's effect lands in your state, so success checks can verify real
# post-run state rather than trusting the agent's own account of itself.
state_paths:
  mutate_identity: "customer.address"

# Roles live in roles.yaml. Valid roles:
# {', '.join(ROLES)}
"""
