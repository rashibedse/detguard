"""Deterministic derivation of policy.yaml from a hand-written manifest + roles.

Every agent that is not built on a framework detguard already adapts needs the
same three artifacts: an adapter, a manifest, and a role map. There is no
reading-comprehension shortcut for those — classifying a tool's role and
finding the one place in *someone else's* agent loop where a call can be
recorded without executing it twice both require a human who has actually read
the source. See ``docs/integration.md`` for how to hand-write them.

What *is* mechanical, once a manifest and role map exist, is turning them into
a filled-in policy: :func:`derive_policy` fills the CLIENT-marked rules from
the role map by rule, not by judgement. Nothing here needs a model and nothing
here is allowed to want one — detguard's claim is that **no LLM sits in the
enforcement path**, at authoring time or otherwise.

Two things keep a derived policy honest:

* everything round-trips through the real validators (``manifest.py``,
  ``policy.py``) before it is written, so an invalid file is never produced;
* :func:`unfilled` names every rule param a human still has to supply, because
  a rule that loads without erroring and a rule that actually fires are not
  the same thing.
"""

from __future__ import annotations

import datetime as _dt
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path

from .roles import GATED_BY_DEFAULT, tools_with_role

#: Roles whose tools change something. Used to fill ``unrequested_mutation``.
MUTATING_ROLES = (
    "mutate_state",
    "mutate_identity",
    "move_value",
    "change_credential",
    "destructive",
)

#: Roles that only ever read. A tool carrying nothing else is safe to license
#: for a view-only request.
READ_ONLY_ROLES = ("read_internal", "read_untrusted")


class AuthoringError(RuntimeError):
    """Derivation failed. Never downgraded to a partial write."""


# ---------------------------------------------------------------------------
# deterministic: policy from roles
# ---------------------------------------------------------------------------


def read_only_tools(roles_map: dict) -> list[str]:
    """Tools whose every role is a read. Sorted."""
    found = []
    for tool, assigned in (roles_map or {}).items():
        canonical = {str(r).strip().lower() for r in (assigned or [])}
        if canonical and canonical <= set(READ_ONLY_ROLES):
            found.append(tool)
    return sorted(found)


def mutating_tools(roles_map: dict) -> list[str]:
    """Tools carrying any role that changes state. Sorted."""
    found: set[str] = set()
    for role in MUTATING_ROLES:
        found.update(tools_with_role(roles_map or {}, role))
    return sorted(found)


def _sole(candidates: list[str]) -> str:
    """The single candidate, or '' when the choice is not forced.

    Two ``move_value`` tools and no way to pick between them is not something to
    guess at: a rule bound to the wrong tool is a rule that never fires, and it
    reads identically to one that is working.
    """
    return candidates[0] if len(candidates) == 1 else ""


def derive_policy(
    roles_map: dict,
    arg_hints: dict | None = None,
    base: dict | None = None,
) -> dict:
    """Fill the CLIENT-marked rules from a role map.

    Mechanical wherever the answer follows from the roles, and left empty
    wherever it does not. ``arg_hints`` supplies the parts that genuinely
    cannot be derived — which argument on a tool carries the destination, and
    which carries the amount — in the shape::

        {"send_email": {"destination_arg": "to"},
         "transfer":   {"amount_arg": "amount"}}

    Two things are deliberately *not* filled, ever:

    * ``external_destination_allowlist.allowlist`` stays empty, because an
      empty allowlist blocks every external destination and a list somebody
      forgot to fill in must not read as "everywhere is fine";
    * ``amount_bound.min`` keeps its default and the rule stays disabled — a
      ceiling that does not match the business is worse than no ceiling, and
      no model knows what that number is.
    """
    import yaml

    if base is None:
        default_path = Path(__file__).resolve().parent / "policies" / "default.yaml"
        base = yaml.safe_load(default_path.read_text(encoding="utf-8"))

    policy = deepcopy(base)
    hints = arg_hints or {}
    rules = {r.get("id"): r for r in policy.get("rules", []) if isinstance(r, dict)}

    gated = sorted({t for role in GATED_BY_DEFAULT for t in tools_with_role(roles_map, role)})

    # 1. human_in_loop — every gated tool, no judgement involved.
    if "human_in_loop" in rules:
        rules["human_in_loop"].setdefault("params", {})["tools"] = gated

    # 2. unrequested_mutation — mutators vs what a view-only request licenses.
    if "unrequested_mutation" in rules:
        params = rules["unrequested_mutation"].setdefault("params", {})
        params["mutating_tools"] = mutating_tools(roles_map)
        params["allowed_tools"] = read_only_tools(roles_map)

    # 3. ungrounded_destination — tool stays '' (meaning any), which is the
    #    broader and therefore safer binding. Only the arg name is a guess.
    if "ungrounded_destination" in rules:
        params = rules["ungrounded_destination"].setdefault("params", {})
        params["tool"] = ""
        params["arg"] = _first_hint(hints, gated, "destination_arg")

    # 4. external_destination_allowlist — bound to the egress tool when there
    #    is exactly one. The allowlist itself stays empty on purpose.
    if "external_destination_allowlist" in rules:
        params = rules["external_destination_allowlist"].setdefault("params", {})
        egress = sorted(
            set(tools_with_role(roles_map, "external_send"))
            | set(tools_with_role(roles_map, "external_fetch"))
        )
        tool = _sole(egress)
        params["tool"] = tool
        params["arg"] = hints.get(tool, {}).get("destination_arg", "") if tool else ""
        params.setdefault("allowlist", [])

    # 5. amount_bound — bound to the move_value tool, still disabled.
    if "amount_bound" in rules:
        params = rules["amount_bound"].setdefault("params", {})
        tool = _sole(tools_with_role(roles_map, "move_value"))
        params["tool"] = tool
        params["arg"] = hints.get(tool, {}).get("amount_arg", "") if tool else ""
        params.setdefault("min", 0)
        rules["amount_bound"]["enabled"] = False

    return policy


def _first_hint(hints: dict, candidates: list[str], key: str) -> str:
    for tool in candidates:
        value = hints.get(tool, {}).get(key)
        if value:
            return str(value)
    return ""


#: Params where empty is a deliberate, meaningful value rather than a gap.
#:
#: ``tool: ''`` means *any tool* — ``_calls_for_tool`` matches everything, so an
#: empty binding is the broader and stricter one. ``allowlist: []`` means
#: nothing is pre-approved, so every external destination fires. Reporting
#: either as "you forgot this" would push a reviewer to narrow a rule that is
#: currently at its safest setting.
EMPTY_IS_DELIBERATE = frozenset({"tool", "allowlist"})


def unfilled(policy: dict) -> list[str]:
    """Params a human still has to supply, as ``rule.param`` strings.

    The point of naming these is that an unfilled rule is *inert* — it loads
    fine and never fires. Somebody has to know which parts of their gate are
    not yet switched on, and "it validated" does not tell them.
    """
    gaps: list[str] = []
    for rule in policy.get("rules", []):
        if not isinstance(rule, dict):
            continue
        # A rule that ships disabled is not an unfilled gap — switching it on is
        # a deliberate act with its own decision behind it. Listing `llm_judge`
        # here would put "no LLM in the enforcement path" on a to-do list.
        if not rule.get("enabled", True):
            continue
        rule_id = rule.get("id", "?")
        params = rule.get("params") or {}
        for name, value in params.items():
            if value in ("", [], None) and name not in EMPTY_IS_DELIBERATE:
                gaps.append(f"{rule_id}.{name}")
    if not (policy_rule(policy, "amount_bound") or {}).get("enabled", False):
        gaps.append("amount_bound.min (rule ships disabled)")
    return gaps


def policy_rule(policy: dict, rule_id: str) -> dict | None:
    for rule in policy.get("rules", []):
        if isinstance(rule, dict) and rule.get("id") == rule_id:
            return rule
    return None


# ---------------------------------------------------------------------------
# writing
# ---------------------------------------------------------------------------


def write_policy(bundle: Bundle, policy_path: str | Path, overwrite: bool = False) -> Path:
    """Write the derived policy.yaml. Refuses to write a bundle with problems.

    Only ``policy.yaml`` is written here. ``manifest.yaml`` and ``roles.yaml``
    are hand-written by the client and already live wherever they put them —
    this function derives one file from the other two, it does not copy them.
    """
    import yaml

    if not bundle.ok:
        raise AuthoringError(
            "refusing to write a policy derived from a bundle that failed "
            "validation:\n  " + "\n  ".join(bundle.problems)
        )

    path = Path(policy_path)
    if path.exists() and not overwrite:
        raise AuthoringError(f"{path} already exists (pass --overwrite to replace it)")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(header() + yaml.safe_dump(bundle.policy, sort_keys=False), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


@dataclass
class Bundle:
    """A manifest + role map, plus what deriving a policy from them found."""

    manifest: dict = field(default_factory=dict)
    roles: dict = field(default_factory=dict)
    arg_hints: dict = field(default_factory=dict)
    policy: dict = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def build_bundle(manifest_text: str, roles_text: str, arg_hints_text: str = "") -> Bundle:
    """Validate a hand-written manifest + role map and derive a policy from them.

    Nothing is written by this function. A file that does not survive the real
    validators is a problem recorded on the bundle, not a file on disk — the
    same guarantee ``dashboard/setup.py`` makes, for the same reason.
    """
    import yaml

    from .manifest import ManifestError, parse_manifest, parse_roles
    from .policy import PolicyError, loads as load_policy

    bundle = Bundle()

    manifest_obj = None
    try:
        bundle.manifest = yaml.safe_load(manifest_text) or {}
        manifest_obj = parse_manifest(bundle.manifest, source_path="<manifest.yaml>")
    except (yaml.YAMLError, ManifestError) as exc:
        bundle.problems.append(f"manifest.yaml: {exc}")

    try:
        bundle.roles = yaml.safe_load(roles_text) or {}
        parse_roles(bundle.roles, manifest=manifest_obj, source_path="<roles.yaml>")
    except (yaml.YAMLError, ManifestError) as exc:
        bundle.problems.append(f"roles.yaml: {exc}")

    try:
        bundle.arg_hints = yaml.safe_load(arg_hints_text) or {}
        if not isinstance(bundle.arg_hints, dict):
            bundle.arg_hints = {}
    except yaml.YAMLError:
        bundle.arg_hints = {}

    # The policy is derived, never hand-written — see module docstring.
    roles_map = (bundle.roles or {}).get("roles") or {}
    try:
        bundle.policy = derive_policy(roles_map, arg_hints=bundle.arg_hints)
        load_policy(bundle.policy, source_path="<derived>")
    except (PolicyError, ValueError) as exc:
        bundle.problems.append(f"derived policy.yaml: {exc}")

    return bundle


# ---------------------------------------------------------------------------
# provenance
# ---------------------------------------------------------------------------


def header(comment: str = "#") -> str:
    """The banner policy.yaml carries, so a reviewer never mistakes derived
    output for something hand-edited and diffs the wrong file."""
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    return (
        f"{comment} DERIVED by `detguard derive` on {stamp} from roles.yaml.\n"
        f"{comment} Mechanical, not hand-authored — edit roles.yaml / arg_hints\n"
        f"{comment} and re-run rather than hand-editing this file. Run\n"
        f"{comment} `detguard.authoring.unfilled` (or re-run the CLI) to see which\n"
        f"{comment} rule params still need a human to fill them in.\n"
    )
