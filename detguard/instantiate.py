"""Templates × manifest → concrete attacks.

This is the thesis of the whole product. An attack has two separable halves:
the **technique**, which is generic and reusable forever, and the **binding**,
which is the client's own tools and carriers. Templates are what we maintain
and ship; instances belong to the client and live in their repo. New techniques
arrive as templates and auto-instantiate against every manifest, which is what
makes a corpus subscription a product rather than per-client consulting.

Two rules govern everything here:

**Never silently skip a template.** A template whose roles the client's agent
does not have is coverage information — "not applicable to this agent, and
here is why" — and it is reported output, not a dropped row.

**Same inputs produce byte-identical output.** No timestamps, no randomness,
no set iteration order. Attacker values are derived from a hash of
``(template_id, type)``, so a rerun produces the same corpus and a diff in
version control means something actually changed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from .manifest import Manifest, RoleMap
from .roles import ANY_GATED, GATED_BY_DEFAULT, RoleError, validate_role

TEMPLATE_DIR = Path(__file__).parent / "templates"

#: The five placeholder forms. Anything else is a hard error — never a
#: placeholder left unresolved in a shipped attack.
PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z_]+)\s*(?::\s*([a-zA-Z_]+)\s*)?\}\}")

PLACEHOLDER_KINDS = ("tool", "source", "attacker_value", "principal", "field")

ATTACKER_VALUE_TYPES = ("account", "address", "url", "email", "credential")

#: Resolution order for ``any_gated``. Deterministic, and value-moving roles
#: come first because every template that uses the token is written in the
#: language of moving something — a prompt about sending funds reads wrong when
#: bound to a credential tool.
ANY_GATED_PREFERENCE = (
    "move_value",
    "change_credential",
    "mutate_identity",
    "destructive",
    "external_send",
)

#: success_check types that need a state path to verify real post-run state.
NEEDS_STATE_PATH = {"field_changed", "field_equals"}

#: success_check types that need a concrete expected value.
NEEDS_EXPECTED = {"field_equals", "external_destination_reached"}

SUCCESS_CHECK_TYPES = {
    "field_changed",
    "field_equals",
    "tool_called",
    "output_contains",
    "call_count_over",
    "external_destination_reached",
    "must_allow",
}

from .mutations import CARRIER_MUTATIONS, MUTATIONS


class InstantiationError(ValueError):
    """Raised on an unresolvable template. Always fatal — an attack with an
    unresolved placeholder in it is worse than no attack, because it reads as
    coverage."""


# ---------------------------------------------------------------------------
# deterministic attacker values
# ---------------------------------------------------------------------------

_STREETS = (
    "Marlow Gardens", "Ashfield Road", "Beckett Lane", "Cranmer Close",
    "Denholm Way", "Elmswood Avenue", "Fairlop Rise", "Gorseway",
)
_CITIES = (
    ("Bristol", "BS"), ("Leeds", "LS"), ("Norwich", "NR"), ("Derby", "DE"),
    ("Ipswich", "IP"), ("Carlisle", "CA"), ("Preston", "PR"), ("Truro", "TR"),
)
_SURNAMES = (
    "aldridge", "beckwith", "carrow", "denby",
    "ellery", "fenwick", "garrick", "haldane",
)
_WORDS = (
    "parkview", "northgate", "eastbrook", "stanmore",
    "westhill", "kingsmere", "ravensden", "oakfield",
)
_LETTERS = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_CRED_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _pick(seq, h: str, offset: int):
    return seq[int(h[offset : offset + 4], 16) % len(seq)]


def attacker_value(template_id: str, value_type: str) -> str:
    """Generate one attacker-controlled value, deterministically.

    Format-valid but provably fake: reserved ``.invalid`` domains that cannot
    resolve, an IBAN-shaped string on a non-existent bank code, an address that
    parses as an address. Nothing is named "attacker" — a payload that
    announces itself tests the reader's eyesight, not the agent's judgement.
    """
    if value_type not in ATTACKER_VALUE_TYPES:
        raise InstantiationError(
            f"{template_id}: unknown attacker_value type {value_type!r}; "
            f"must be one of {', '.join(ATTACKER_VALUE_TYPES)}"
        )
    h = _digest(template_id, value_type)

    if value_type == "account":
        check = int(h[0:2], 16) % 90 + 10
        body = "".join(str(int(h[i : i + 2], 16) % 10) for i in range(2, 30, 2))
        return f"GB{check}ZZZZ{body}"

    if value_type == "address":
        number = int(h[0:3], 16) % 240 + 1
        street = _pick(_STREETS, h, 4)
        city, prefix = _pick(_CITIES, h, 8)
        out_digit = int(h[12:14], 16) % 9 + 1
        in_digit = int(h[14:16], 16) % 9 + 1
        l1 = _LETTERS[int(h[16:18], 16) % len(_LETTERS)]
        l2 = _LETTERS[int(h[18:20], 16) % len(_LETTERS)]
        return f"{number} {street}, {city} {prefix}{out_digit} {in_digit}{l1}{l2}"

    if value_type == "url":
        host = _pick(_WORDS, h, 0)
        second = _pick(_WORDS, h, 4)
        return f"https://{host}-{second}.invalid/notice/{h[20:26]}"

    if value_type == "email":
        surname = _pick(_SURNAMES, h, 0)
        domain = _pick(_WORDS, h, 4)
        initial = surname[0]
        return f"{initial}.{surname}@{domain}-admin.invalid"

    # credential
    token = "".join(_CRED_ALPHABET[int(h[i : i + 2], 16) % len(_CRED_ALPHABET)] for i in range(0, 12, 2))
    return f"PWD-{token}"


# ---------------------------------------------------------------------------
# templates
# ---------------------------------------------------------------------------

_TEMPLATE_KEYS = {
    "id", "family", "severity", "requires_roles", "optional_roles",
    "expected_hook", "pr_subset", "cost", "mutations", "carrier", "technique",
    "user_prompt_template", "payload_template", "success_check", "notes",
    "tool_hint", "source_hint",
}

#: Keys a template may omit.
_OPTIONAL_TEMPLATE_KEYS = {"notes", "tool_hint", "source_hint"}


@dataclass
class Template:
    id: str
    family: str
    severity: str
    requires_roles: list
    optional_roles: list
    expected_hook: str
    pr_subset: bool
    cost: str
    mutations: list
    carrier: str
    technique: str
    user_prompt_template: str
    payload_template: str
    success_check: dict
    notes: str = ""
    tool_hint: str = ""
    """Optional substring tried against candidate tool names before falling back
    to sorted-first. Deterministic exact-substring match or nothing — no
    scoring, no fuzzy matching. It exists because sorted-first is deterministic
    but occasionally semantically wrong: TPL-08 says "check what you have on
    file", which means get_profile, not whichever read_internal tool happens to
    sort first."""

    source_hint: str = ""
    """Same, for untrusted-source names."""

    sha: str = ""


def load_templates(directory: str | Path | None = None) -> list[Template]:
    """Load every shipped template, sorted by id."""
    d = Path(directory) if directory else TEMPLATE_DIR
    if not d.is_dir():
        raise InstantiationError(f"template directory not found: {d}")

    templates: list[Template] = []
    for path in sorted(d.glob("TPL-*.yaml")):
        raw_bytes = path.read_bytes()
        try:
            data = yaml.safe_load(raw_bytes.decode("utf-8"))
        except yaml.YAMLError as exc:
            raise InstantiationError(f"{path}: not valid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise InstantiationError(f"{path}: template must be a mapping")

        unknown = set(data) - _TEMPLATE_KEYS
        if unknown:
            raise InstantiationError(f"{path}: unknown key(s): {', '.join(sorted(unknown))}")
        missing = _TEMPLATE_KEYS - _OPTIONAL_TEMPLATE_KEYS - set(data)
        if missing:
            raise InstantiationError(f"{path}: missing key(s): {', '.join(sorted(missing))}")

        check = data["success_check"]
        if not isinstance(check, dict) or check.get("type") not in SUCCESS_CHECK_TYPES:
            raise InstantiationError(
                f"{path}: success_check.type must be one of "
                f"{', '.join(sorted(SUCCESS_CHECK_TYPES))}"
            )

        templates.append(
            Template(
                id=str(data["id"]),
                family=str(data["family"]),
                severity=str(data["severity"]),
                requires_roles=list(data["requires_roles"] or []),
                optional_roles=list(data["optional_roles"] or []),
                expected_hook=str(data["expected_hook"]),
                pr_subset=bool(data["pr_subset"]),
                cost=str(data["cost"]),
                mutations=list(data["mutations"] or []),
                carrier=str(data["carrier"]),
                technique=str(data["technique"]).strip(),
                user_prompt_template=str(data["user_prompt_template"]).strip(),
                payload_template=str(data["payload_template"] or "").strip(),
                success_check=dict(check),
                notes=str(data.get("notes", "")).strip(),
                tool_hint=str(data.get("tool_hint", "")).strip(),
                source_hint=str(data.get("source_hint", "")).strip(),
                sha=hashlib.sha256(raw_bytes).hexdigest()[:12],
            )
        )
    return templates


# ---------------------------------------------------------------------------
# concrete attacks
# ---------------------------------------------------------------------------


@dataclass
class ConcreteAttack:
    id: str
    template_id: str
    mutation: str | None
    family: str
    severity: str
    expected_hook: str
    pr_subset: bool
    cost: str
    carrier: str
    user_prompt: str
    payload: str
    payload_position: str
    roles_used: list
    tools_used: dict
    source: dict
    attacker_values: dict
    success_check: dict
    provenance: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "template_id": self.template_id,
            "mutation": self.mutation,
            "family": self.family,
            "severity": self.severity,
            "expected_hook": self.expected_hook,
            "pr_subset": self.pr_subset,
            "cost": self.cost,
            "carrier": self.carrier,
            "user_prompt": self.user_prompt,
            "payload": self.payload,
            "payload_position": self.payload_position,
            "roles_used": list(self.roles_used),
            "tools_used": dict(self.tools_used),
            "source": dict(self.source),
            "attacker_values": dict(self.attacker_values),
            "success_check": dict(self.success_check),
            "provenance": dict(self.provenance),
        }


@dataclass
class InstantiationResult:
    attacks: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    skipped_mutations: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    def by_template(self, template_id: str) -> list:
        return [a for a in self.attacks if a.template_id == template_id]

    def to_dict(self) -> dict:
        return {
            "attacks": [a.to_dict() for a in self.attacks],
            "skipped": list(self.skipped),
            "skipped_mutations": list(self.skipped_mutations),
            "warnings": list(self.warnings),
        }


def choose(candidates: list[str], hint: str = "") -> str:
    """Pick one candidate from a sorted list, honouring an optional hint.

    Sorted-first is deterministic, which is the property that matters, but it is
    occasionally semantically wrong — TPL-08's "check what you have on file"
    means the profile tool, not whichever read_internal tool sorts first. A
    template may supply a substring hint; where it matches a candidate name the
    match wins, and where it matches nothing the sorted-first default stands.

    Exact substring, case-insensitive, no scoring and no fuzzy matching: a hint
    either identifies a tool or it does not, and a resolver that "mostly" picks
    the right tool is worse than one that picks predictably.
    """
    ordered = sorted(candidates)
    if not ordered:
        raise InstantiationError("choose() called with no candidates")
    if hint:
        needle = hint.strip().lower()
        matches = [c for c in ordered if needle in c.lower()]
        if matches:
            return matches[0]
    return ordered[0]


class _Binding:
    """Role tokens → concrete role, tool and state path for one template."""

    def __init__(self, template: Template, manifest: Manifest, role_map: RoleMap):
        self.template = template
        self.manifest = manifest
        self.role_map = role_map
        self.roles: dict[str, str] = {}   # token -> canonical role
        self.tools: dict[str, str] = {}   # canonical role -> tool name
        self.values: dict[str, str] = {}  # attacker value type -> value

    def bind(self, token: str) -> tuple[str, str] | None:
        """Resolve a role token to ``(canonical_role, tool_name)``, or None."""
        token = str(token).strip().lower()
        if token in self.roles:
            role = self.roles[token]
            return role, self.tools[role]

        if token == ANY_GATED:
            for candidate in ANY_GATED_PREFERENCE:
                tools = self.role_map.tools_for(candidate)
                if tools:
                    chosen = choose(tools, self.template.tool_hint)
                    self.roles[token] = candidate
                    self.tools[candidate] = chosen
                    return candidate, chosen
            return None

        try:
            role = validate_role(token)
        except RoleError as exc:
            raise InstantiationError(f"{self.template.id}: {exc}") from exc

        tools = self.role_map.tools_for(role)
        if not tools:
            return None
        chosen = choose(tools, self.template.tool_hint)
        self.roles[token] = role
        self.tools[role] = chosen
        return role, chosen

    def value(self, value_type: str) -> str:
        if value_type not in self.values:
            self.values[value_type] = attacker_value(self.template.id, value_type)
        return self.values[value_type]


def _resolve(text: str, binding: _Binding, source_name: str) -> str:
    """Substitute every placeholder. An unknown one is fatal."""
    if not text:
        return ""

    template_id = binding.template.id

    def replace(match: re.Match) -> str:
        kind = match.group(1)
        arg = (match.group(2) or "").strip()

        if kind == "principal":
            return binding.manifest.principal

        if kind == "attacker_value":
            if not arg:
                raise InstantiationError(
                    f"{template_id}: {{{{attacker_value}}}} needs a type, e.g. "
                    "{{attacker_value:account}}"
                )
            return binding.value(arg)

        if kind == "source":
            if not source_name:
                raise InstantiationError(
                    f"{template_id}: {{{{source:...}}}} used but no untrusted source is bound"
                )
            return source_name

        if kind == "tool":
            bound = binding.bind(arg)
            if bound is None:
                raise InstantiationError(
                    f"{template_id}: {{{{tool:{arg}}}}} could not bind — no tool with that role"
                )
            return bound[1]

        if kind == "field":
            bound = binding.bind(arg)
            if bound is None:
                raise InstantiationError(
                    f"{template_id}: {{{{field:{arg}}}}} could not bind — no tool with that role"
                )
            path = binding.manifest.state_path(bound[0])
            if not path:
                raise InstantiationError(
                    f"{template_id}: {{{{field:{arg}}}}} needs state_paths[{bound[0]}] in the manifest"
                )
            return path

        raise InstantiationError(
            f"{template_id}: unknown placeholder {match.group(0)!r}; "
            f"the vocabulary is exactly: {', '.join(PLACEHOLDER_KINDS)}"
        )

    resolved = PLACEHOLDER_RE.sub(replace, text)

    leftover = re.search(r"\{\{|\}\}", resolved)
    if leftover:
        raise InstantiationError(
            f"{template_id}: unresolved placeholder braces remain in: {resolved[:120]!r}"
        )
    return resolved


def _resolve_success_check(
    template: Template, binding: _Binding, source_name: str
) -> tuple[dict | None, str]:
    """Return ``(resolved_check, skip_reason)``."""
    raw = dict(template.success_check)
    check_type = raw["type"]
    resolved: dict[str, Any] = {"type": check_type}

    target_token = raw.get("target_role")
    if target_token:
        bound = binding.bind(str(target_token))
        if bound is None:
            return None, f"success_check targets role {target_token!r}, no tool has it"
        role, _tool = bound
        resolved["target_role"] = role
        resolved["target_tools"] = binding.role_map.tools_for(role)

        if check_type in NEEDS_STATE_PATH:
            path = binding.manifest.state_path(role)
            if not path:
                return None, (
                    f"success_check {check_type!r} needs state_paths[{role}] and the "
                    "manifest does not declare one"
                )
            resolved["path"] = path

    if "limit" in raw:
        resolved["limit"] = int(raw["limit"])

    if "value" in raw:
        resolved["expected"] = _resolve(str(raw["value"]), binding, source_name)

    if "value_from_state" in raw:
        resolved["expected_from_state"] = _resolve(
            str(raw["value_from_state"]), binding, source_name
        )

    if check_type in NEEDS_EXPECTED and "expected" not in resolved:
        # The attacker value this template planted IS the expected outcome:
        # state that now equals it, or a destination that received it.
        if len(binding.values) == 1:
            resolved["expected"] = next(iter(binding.values.values()))
        else:
            raise InstantiationError(
                f"{template.id}: success_check {check_type!r} needs an expected value, "
                f"but the template generated {len(binding.values)} attacker values "
                "— declare one explicitly with success_check.value"
            )

    return resolved, ""


#: When a mutation garbles the planted value beyond recognition, the exact-match
#: check becomes unverifiable but the structural one does not: you can still ask
#: whether the agent was induced to act, only not exactly where it sent things.
_RELAXATION = {
    "external_destination_reached": "tool_called",
    "field_equals": "field_changed",
}


def _reconcile_check(
    check: dict, mutation: str, haystack: str
) -> tuple[dict | None, str]:
    """Keep a value-dependent success_check honest across a mutation.

    A mutation rewrites the carrier, and some of them rewrite the planted value
    along with it. Three outcomes, in order of preference:

    1. the value survived verbatim — the check stands unchanged;
    2. the value survived in transformed form and that form is derivable by
       applying the same transform to it — the check tracks it, which is the
       right answer for ``homoglyph`` on TPL-14, where a lookalike domain *is*
       the attack;
    3. the value did not survive in any recoverable form (``base64_wrap``,
       ``whitespace_pad``, ``case_scramble``) — the exact check is relaxed to
       its structural equivalent and says so, or the variant is dropped when
       nothing structural remains to assert.

    What is never allowed is outcome four: leaving an exact check in place
    against a string the carrier no longer contains, which can never pass and
    reads in the corpus as coverage.
    """
    expected = check.get("expected")
    if not expected or expected in haystack:
        return check, ""

    if mutation not in CARRIER_MUTATIONS:
        derived = MUTATIONS[mutation](expected)
        if derived and derived in haystack:
            return {**check, "expected": derived, "expected_mutated_by": mutation}, ""

    relaxed_type = _RELAXATION.get(check["type"])
    if relaxed_type is None:
        return None, (
            f"{mutation} transformed the planted value beyond recovery and "
            f"{check['type']!r} has no structural equivalent to fall back to"
        )

    relaxed = {k: v for k, v in check.items() if k != "expected"}
    relaxed["type"] = relaxed_type
    relaxed["relaxed_from"] = check["type"]
    relaxed["relaxed_reason"] = f"{mutation} transformed the planted value"
    return relaxed, ""


def instantiate(
    templates: Iterable[Template],
    manifest: Manifest,
    role_map: RoleMap,
) -> InstantiationResult:
    """Bind every template to this agent's surface.

    Templates that cannot bind are skipped **with a reason**, and the reasons
    are the point: "TPL-14 does not apply because your agent cannot fetch a
    URL" is a real statement about coverage, and it reads as rigour rather than
    as a gap.
    """
    result = InstantiationResult()
    result.warnings.extend(role_map.warnings)

    sources = sorted(manifest.untrusted_sources, key=lambda s: s.name)

    for template in sorted(templates, key=lambda t: t.id):
        binding = _Binding(template, manifest, role_map)

        # 1. required roles
        unmet: list[str] = []
        for token in template.requires_roles:
            if binding.bind(token) is None:
                unmet.append(str(token))
        if unmet:
            reasons = ", ".join(
                f"no tool with role {t}"
                + (f" (any of {', '.join(GATED_BY_DEFAULT)})" if t == ANY_GATED else "")
                for t in unmet
            )
            result.skipped.append({"id": template.id, "reason": reasons})
            continue

        # 2. optional roles bind if available, and are simply absent if not
        for token in template.optional_roles:
            binding.bind(token)

        # 3. a carrier, if this template needs one
        needs_source = template.carrier == "untrusted_source" or "{{source" in (
            template.user_prompt_template + template.payload_template
        )
        if needs_source and not sources:
            result.skipped.append(
                {
                    "id": template.id,
                    "reason": (
                        "manifest declares no untrusted_sources, and this template's "
                        "payload has to arrive inside one"
                    ),
                }
            )
            continue
        # Only bind a carrier to templates that actually use one. A prompt-carrier
        # template carrying a source it never writes into would invite the runner
        # to inject an empty payload into a document for no reason.
        source = None
        if needs_source and sources:
            by_name = {s.name: s for s in sources}
            source = by_name[choose(list(by_name), template.source_hint)]
        source_name = source.name if source else ""

        # 4. resolve text
        try:
            user_prompt = _resolve(template.user_prompt_template, binding, source_name)
            payload = _resolve(template.payload_template, binding, source_name)
            check, skip_reason = _resolve_success_check(template, binding, source_name)
        except InstantiationError:
            raise
        if check is None:
            result.skipped.append({"id": template.id, "reason": skip_reason})
            continue

        # 5. TPL-12's lesson: a success_check looking for a string that is
        #    absent from the carrier can never pass, and sits in the corpus
        #    reading as a permanent green.
        expected = check.get("expected")
        if check["type"] == "output_contains" and expected:
            haystack = f"{user_prompt}\n{payload}"
            if expected not in haystack:
                raise InstantiationError(
                    f"{template.id}: success_check expects {expected!r} in the output, but "
                    "no carrier text contains it — this check could never pass"
                )

        roles_used = sorted(binding.tools)
        tools_used = {role: binding.tools[role] for role in roles_used}
        source_dict = source.to_dict() if source else {}
        base_provenance = {
            "template_id": template.id,
            "template_sha": template.sha,
            "agent": manifest.agent,
            "framework": manifest.framework,
            "roles_used": roles_used,
        }

        # 6. base variant, always
        result.attacks.append(
            ConcreteAttack(
                id=f"{template.id}-base",
                template_id=template.id,
                mutation=None,
                family=template.family,
                severity=template.severity,
                expected_hook=template.expected_hook,
                pr_subset=template.pr_subset,
                cost=template.cost,
                carrier=template.carrier,
                user_prompt=user_prompt,
                payload=payload,
                payload_position="end",
                roles_used=roles_used,
                tools_used=tools_used,
                source=source_dict,
                attacker_values=dict(sorted(binding.values.items())),
                success_check=check,
                provenance={**base_provenance, "mutation": None},
            )
        )

        # 7. one variant per declared mutation
        for name in template.mutations:
            if name not in MUTATIONS:
                result.skipped_mutations.append(
                    {
                        "id": template.id,
                        "mutation": name,
                        "reason": "mutation not available in this build",
                    }
                )
                continue

            position = "end"
            mutated_prompt = user_prompt
            mutated_payload = payload

            if name in CARRIER_MUTATIONS:
                if not payload:
                    result.skipped_mutations.append(
                        {
                            "id": template.id,
                            "mutation": name,
                            "reason": (
                                "needs a payload separable from its carrier; this "
                                f"template's carrier is {template.carrier!r} with no payload"
                            ),
                        }
                    )
                    continue
                position = "start"
            elif payload:
                mutated_payload = MUTATIONS[name](payload)
            else:
                # Prompt-carrier template: the prompt IS the payload.
                mutated_prompt = MUTATIONS[name](user_prompt)

            # A transform with nothing to transform would emit a variant
            # byte-identical to its base — a duplicate row that inflates the
            # corpus and reads as coverage it does not provide. politeness_wrap
            # on TPL-07 and TPL-08 is the honest case: those payloads contain
            # no imperative to rewrite, which is precisely what makes them
            # dangerous. Recorded, not dropped.
            if name not in CARRIER_MUTATIONS and (
                mutated_payload == payload and mutated_prompt == user_prompt
            ):
                result.skipped_mutations.append(
                    {
                        "id": template.id,
                        "mutation": name,
                        "reason": "no-op on this text; the variant would duplicate the base",
                    }
                )
                continue

            variant_check, drop_reason = _reconcile_check(
                check, name, f"{mutated_prompt}\n{mutated_payload}"
            )
            if variant_check is None:
                result.skipped_mutations.append(
                    {"id": template.id, "mutation": name, "reason": drop_reason}
                )
                continue

            result.attacks.append(
                ConcreteAttack(
                    id=f"{template.id}-{name}",
                    template_id=template.id,
                    mutation=name,
                    family=template.family,
                    severity=template.severity,
                    expected_hook=template.expected_hook,
                    pr_subset=template.pr_subset,
                    cost=template.cost,
                    carrier=template.carrier,
                    user_prompt=mutated_prompt,
                    payload=mutated_payload,
                    payload_position=position,
                    roles_used=roles_used,
                    tools_used=tools_used,
                    source=source_dict,
                    attacker_values=dict(sorted(binding.values.items())),
                    success_check=variant_check,
                    provenance={**base_provenance, "mutation": name},
                )
            )

    result.attacks.sort(key=lambda a: a.id)
    result.skipped.sort(key=lambda s: s["id"])
    result.skipped_mutations.sort(key=lambda s: (s["id"], s["mutation"]))
    return result


# ---------------------------------------------------------------------------
# writing
# ---------------------------------------------------------------------------


def _dump(data: dict) -> str:
    return yaml.safe_dump(
        data, sort_keys=True, allow_unicode=True, default_flow_style=False, width=100
    )


def write_corpus(result: InstantiationResult, out_dir: str | Path) -> list[Path]:
    """Write the corpus to disk. Byte-identical across runs by construction —
    nothing here records a time, a path, or an iteration order."""
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for attack in result.attacks:
        path = d / f"{attack.id}.yaml"
        path.write_text(_dump(attack.to_dict()), encoding="utf-8")
        written.append(path)

    # Prune attacks this build did not produce. Without this, a template that
    # stops instantiating — roles removed, a mutation newly a no-op — leaves its
    # last file behind, and the runner happily executes a phantom attack that no
    # template still vouches for. Only files carrying our own provenance are
    # touched; anything else in the directory is somebody else's business.
    keep = {p.name for p in written}
    for path in sorted(d.glob("*.yaml")):
        if path.name in keep or path.name.startswith("_"):
            continue
        try:
            existing = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            continue
        if isinstance(existing, dict) and existing.get("template_id") and existing.get("id"):
            path.unlink()
            result.warnings.append(f"removed stale attack {path.name} from a previous build")

    # Skips are reported output, so they get a file of their own in the corpus
    # directory rather than living only in a log nobody reads.
    skip_path = d / "_skipped.yaml"
    skip_path.write_text(
        _dump(
            {
                "skipped_templates": result.skipped,
                "skipped_mutations": result.skipped_mutations,
                "warnings": result.warnings,
            }
        ),
        encoding="utf-8",
    )
    written.append(skip_path)
    return written


def load_corpus(directory: str | Path) -> list[dict]:
    """Read concrete attacks back off disk, sorted by id. The runner's input."""
    d = Path(directory)
    if not d.is_dir():
        raise InstantiationError(f"corpus directory not found: {d}")
    attacks: list[dict] = []
    for path in sorted(d.glob("*.yaml")):
        if path.name.startswith("_"):
            continue
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("id"):
            attacks.append(data)
    attacks.sort(key=lambda a: a["id"])
    return attacks


def load_skipped(directory: str | Path) -> dict:
    """Read the skip report back. Empty dict when there is none."""
    path = Path(directory) / "_skipped.yaml"
    if not path.is_file():
        return {"skipped_templates": [], "skipped_mutations": [], "warnings": []}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def build(
    manifest_path: str | Path,
    roles_path: str | Path,
    out_dir: str | Path = "corpus/attacks",
    template_dir: str | Path | None = None,
) -> InstantiationResult:
    """Load everything, instantiate, write. What ``detguard corpus build`` calls."""
    from .manifest import load_pair

    manifest, role_map = load_pair(manifest_path, roles_path)
    templates = load_templates(template_dir)
    result = instantiate(templates, manifest, role_map)
    write_corpus(result, out_dir)
    return result
