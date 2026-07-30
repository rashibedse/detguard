"""The role vocabulary.

Tool *names* mean nothing to a generic engine — ``refund_order`` is just a
string. Roles are what the attack templates, the policy defaults and the
compliance mapping all key off, which is why the vocabulary is closed: a role
outside this list is a hard load-time error, not a warning.
"""

from __future__ import annotations

ROLES = (
    "read_internal",      # reads trusted internal state
    "read_untrusted",     # pulls in attacker-authorable content
    "mutate_state",       # changes non-critical state
    "mutate_identity",    # changes who/where the principal is
    "move_value",         # money, goods, entitlements
    "change_credential",  # auth material
    "external_send",      # data leaves the perimeter
    "external_fetch",     # retrieves from an attacker-influencable address
    "destructive",        # irreversible
)

#: Roles that land in the human-in-the-loop set by default. A client tunes
#: *down* from here — a deliberate, logged decision — rather than tuning up
#: from nothing.
GATED_BY_DEFAULT = (
    "mutate_identity",
    "move_value",
    "change_credential",
    "external_send",
    "destructive",
)

#: Token usable in a template's ``requires_roles`` to mean "any one of the
#: gated roles this agent happens to have".
ANY_GATED = "any_gated"


class RoleError(ValueError):
    """Raised on a role outside the closed vocabulary."""


def validate_role(role: str) -> str:
    """Return the canonical role name, or raise.

    Accepts any casing so templates may write ``{{tool:MOVE_VALUE}}``.
    """
    if not isinstance(role, str):
        raise RoleError(f"role must be a string, got {type(role).__name__}")
    canonical = role.strip().lower()
    if canonical not in ROLES:
        raise RoleError(
            f"unknown role {role!r}; must be one of: {', '.join(ROLES)}"
        )
    return canonical


def is_gated(role: str) -> bool:
    """True if this role is human-gated by default."""
    return validate_role(role) in GATED_BY_DEFAULT


def tools_with_role(roles_map: dict, role: str) -> list[str]:
    """Every tool in ``roles_map`` carrying ``role``, sorted for determinism.

    ``roles_map`` is ``{tool_name: [role, ...]}`` — the ``roles:`` block of a
    roles.yaml.
    """
    canonical = validate_role(role)
    matches = [
        tool
        for tool, assigned in roles_map.items()
        if canonical in {str(r).strip().lower() for r in (assigned or [])}
    ]
    return sorted(matches)


def gated_tools(roles_map: dict) -> list[str]:
    """Every tool carrying at least one gated-by-default role, sorted."""
    found: set[str] = set()
    for role in GATED_BY_DEFAULT:
        found.update(tools_with_role(roles_map, role))
    return sorted(found)


def roles_of(roles_map: dict, tool: str) -> list[str]:
    """The canonical roles assigned to one tool, sorted."""
    return sorted(validate_role(r) for r in (roles_map.get(tool) or []))
