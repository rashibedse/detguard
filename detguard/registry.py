"""The condition registry — every check detguard can perform.

Contract, without exception::

    fn(ctx: GuardContext, params: dict) -> tuple[bool, str]

``True`` means *the condition fired* (something the policy cares about was
found), not "allow". What to do about it is the rule's ``action``, which is
policy's business, not the condition's.

Only conditions named in :data:`TRANSFORMING` may touch the context, and only
by setting ``ctx.redacted_text``. Everything else is pure.

Every condition here is deterministic. ``llm_judge`` is the sole exception in
principle, and it ships disabled and fails **open** — an unavailable judge must
never silently become a block, because a security tool that fails closed on
infrastructure trouble gets switched off within a week.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from .events import GuardContext

# ---------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------

#: Invisible codepoints an attacker inserts to break naive keyword matching.
#: Zero-width space/non-joiner/joiner, LTR and RTL marks, BOM, word joiner.
INVISIBLE_CHARS = (
    "​",  # ZERO WIDTH SPACE
    "‌",  # ZERO WIDTH NON-JOINER
    "‍",  # ZERO WIDTH JOINER
    "‎",  # LEFT-TO-RIGHT MARK
    "‏",  # RIGHT-TO-LEFT MARK
    "﻿",  # ZERO WIDTH NO-BREAK SPACE / BOM
    "⁠",  # WORD JOINER
)

_INVISIBLE_TABLE = {ord(c): None for c in INVISIBLE_CHARS}

#: Cyrillic (and friends) lookalikes mapped back to their Latin originals, so
#: that a homoglyph-mutated payload still matches a plain-Latin pattern.
_HOMOGLYPH_FOLD = {
    "а": "a",  # а
    "е": "e",  # е
    "о": "o",  # о
    "р": "p",  # р
    "с": "c",  # с
    "х": "x",  # х
    "ѕ": "s",  # ѕ
    "і": "i",  # і
    "ј": "j",  # ј
    "һ": "h",  # һ
    "ԁ": "d",  # ԁ
}

_HOMOGLYPH_TABLE = {ord(k): v for k, v in _HOMOGLYPH_FOLD.items()}


def normalize(text: str) -> str:
    """Strip invisible codepoints and fold homoglyphs back to Latin.

    Applied before every regex match. This is what stops the ``zero_width`` and
    ``homoglyph`` mutations from trivially defeating the cheap layer — and the
    fact that some mutations *still* get through after this is the interesting
    result the dashboard reports.
    """
    if not text:
        return ""
    return str(text).translate(_INVISIBLE_TABLE).translate(_HOMOGLYPH_TABLE)


def _norm_ws(text: str) -> str:
    """Normalise whitespace too — defeats ``whitespace_pad``."""
    return re.sub(r"\s+", " ", normalize(text).replace(" ", " ")).strip()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _patterns(ctx: GuardContext, params: dict) -> tuple[str, list[str]]:
    name = params.get("pattern_set", "")
    return name, list(ctx.pattern_sets.get(name, []) or [])


def _calls_for_tool(ctx: GuardContext, tool: str) -> list:
    """Calls matching ``tool``. An empty/absent tool param means *any* tool."""
    calls = ctx.tool_calls or []
    if not tool:
        return list(calls)
    return [c for c in calls if getattr(c, "name", None) == tool]


def _arg(call: Any, arg: str) -> Any:
    args = getattr(call, "args", None) or {}
    return args.get(arg)


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _result_text(ctx: GuardContext) -> str:
    """The text an ``after_tool`` condition inspects.

    ``ctx.text`` wins when set; otherwise the tool result is stringified. Dicts
    and lists are flattened so a secret nested in a return value is still seen.
    """
    if ctx.text:
        return ctx.text
    return _stringify(ctx.tool_result)


# ---------------------------------------------------------------------------
# conditions
# ---------------------------------------------------------------------------


def content_scan(ctx: GuardContext, params: dict) -> tuple[bool, str]:
    """Regex match against the hook's text, after normalisation. First match wins.

    ``applies_to`` narrows the rule to one trust class of text:

    * ``any`` (default) — scan whatever this hook is holding
    * ``retrieved`` — only content that came from an untrusted source
    * ``user`` — only text the user actually typed

    This matters for the instruction-shaped patterns that catch indirect
    injection. "the outstanding item should be settled to X" is an attack
    inside a fetched document and an ordinary sentence in a user's own request,
    and a rule that cannot tell those apart is a false-positive generator.
    """
    name, patterns = _patterns(ctx, params)
    applies_to = str(params.get("applies_to", "any")).lower()

    if applies_to == "retrieved" and not ctx.is_retrieved:
        return False, "content_scan: skipped (applies_to=retrieved, is_retrieved=False)"
    if applies_to == "user" and ctx.is_retrieved:
        return False, "content_scan: skipped (applies_to=user, is_retrieved=True)"

    haystack = _norm_ws(ctx.text or "")
    if not haystack:
        return False, "content_scan: no text to scan"
    for pattern in patterns:
        match = re.search(pattern, haystack, re.IGNORECASE)
        if match:
            excerpt = match.group(0)[:80]
            return True, f"content_scan[{name}]: matched {pattern!r} on {excerpt!r}"
    return False, f"content_scan[{name}]: no match over {len(patterns)} pattern(s)"


def pii_detect(ctx: GuardContext, params: dict) -> tuple[bool, str]:
    """Detect sensitive values. Detect only — never mutates."""
    name, patterns = _patterns(ctx, params)
    haystack = _norm_ws(_result_text(ctx))
    if not haystack:
        return False, "pii_detect: no text to scan"
    hits: list[str] = []
    for pattern in patterns:
        for match in re.finditer(pattern, haystack, re.IGNORECASE):
            hits.append(match.group(0))
    if hits:
        return True, f"pii_detect[{name}]: {len(hits)} match(es), first={hits[0][:40]!r}"
    return False, f"pii_detect[{name}]: no match over {len(patterns)} pattern(s)"


def pii_redact(ctx: GuardContext, params: dict) -> tuple[bool, str]:
    """Mask sensitive values and continue.

    ``applies_to: retrieved`` means "only redact content that came from an
    untrusted source". It MUST no-op when ``ctx.is_retrieved`` is False,
    otherwise the agent's own trusted internal state gets shredded on the way
    to the user.
    """
    name, patterns = _patterns(ctx, params)
    applies_to = str(params.get("applies_to", "any")).lower()

    if applies_to == "retrieved" and not ctx.is_retrieved:
        return False, "pii_redact: skipped (applies_to=retrieved, is_retrieved=False)"

    source = _result_text(ctx)
    if not source:
        return False, "pii_redact: no text to redact"

    mask = str(params.get("mask", "[REDACTED]"))
    redacted = source
    count = 0
    for pattern in patterns:
        redacted, n = re.subn(pattern, mask, redacted, flags=re.IGNORECASE)
        count += n

    if count:
        ctx.redacted_text = redacted
        return True, f"pii_redact[{name}]: masked {count} value(s)"
    return False, f"pii_redact[{name}]: nothing to mask"


def sensitive_tool_call(ctx: GuardContext, params: dict) -> tuple[bool, str]:
    """Fire if any decided call names a tool in the sensitive set.

    This is the human-in-the-loop gate. The set is client-owned, generated from
    their role classification — every tool classed ``move_value``,
    ``change_credential``, ``mutate_identity``, ``external_send`` or
    ``destructive`` lands here by default.
    """
    sensitive = {str(t) for t in (params.get("tools") or [])}
    if not sensitive:
        return False, "sensitive_tool_call: empty tool set"
    hit = [c.name for c in (ctx.tool_calls or []) if getattr(c, "name", None) in sensitive]
    if hit:
        return True, f"sensitive_tool_call: {', '.join(sorted(set(hit)))}"
    return False, "sensitive_tool_call: no sensitive tool in this batch"


def tool_arg_matches(ctx: GuardContext, params: dict) -> tuple[bool, str]:
    """Regex on one argument value of one tool."""
    tool = str(params.get("tool", ""))
    arg = str(params.get("arg", ""))
    pattern = str(params.get("pattern", ""))
    if not pattern:
        return False, "tool_arg_matches: no pattern configured"

    for call in _calls_for_tool(ctx, tool):
        value = _norm_ws(_stringify(_arg(call, arg)))
        if value and re.search(pattern, value, re.IGNORECASE):
            return True, f"tool_arg_matches: {call.name}.{arg}={value[:60]!r} ~ {pattern!r}"
    return False, f"tool_arg_matches: no {tool or 'any'}.{arg} matched {pattern!r}"


def numeric_bound(ctx: GuardContext, params: dict) -> tuple[bool, str]:
    """Fire when a numeric argument falls outside ``[min, max]``.

    Either bound may be omitted. A non-numeric value fires too — an amount that
    cannot be parsed is not a value you should be moving.
    """
    tool = str(params.get("tool", ""))
    arg = str(params.get("arg", ""))
    low = params.get("min")
    high = params.get("max")

    for call in _calls_for_tool(ctx, tool):
        raw = _arg(call, arg)
        if raw is None:
            continue
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return True, f"numeric_bound: {call.name}.{arg}={raw!r} is not numeric"
        if low is not None and value < float(low):
            return True, f"numeric_bound: {call.name}.{arg}={value} below min {low}"
        if high is not None and value > float(high):
            return True, f"numeric_bound: {call.name}.{arg}={value} above max {high}"
    return False, f"numeric_bound: {tool or 'any'}.{arg} within bounds"


def call_budget(ctx: GuardContext, params: dict) -> tuple[bool, str]:
    """Total call-count cap for one turn."""
    try:
        limit = int(params.get("max_calls", 0))
    except (TypeError, ValueError):
        return False, "call_budget: max_calls is not an integer"
    total = len(ctx.tool_calls or [])
    if limit and total > limit:
        return True, f"call_budget: {total} calls exceeds max_calls={limit}"
    return False, f"call_budget: {total} calls within max_calls={limit}"


def repeated_call(ctx: GuardContext, params: dict) -> tuple[bool, str]:
    """Same tool (optionally with same args) repeated past a threshold.

    Fires at N+1, not at N: ``max_repeats: 3`` permits three and objects to the
    fourth. This is the structuring check — one action split into N
    sub-threshold actions to duck a review limit.
    """
    try:
        limit = int(params.get("max_repeats", 0))
    except (TypeError, ValueError):
        return False, "repeated_call: max_repeats is not an integer"
    if limit <= 0:
        return False, "repeated_call: no threshold configured"

    match_args = bool(params.get("match_args", True))
    counts: dict[tuple, int] = {}
    for call in ctx.tool_calls or []:
        if match_args:
            key = (call.name, tuple(sorted((k, _stringify(v)) for k, v in (call.args or {}).items())))
        else:
            key = (call.name, ())
        counts[key] = counts.get(key, 0) + 1

    for (name, _), count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0][0])):
        if count > limit:
            scope = "same args" if match_args else "any args"
            return True, f"repeated_call: {name} called {count}x ({scope}), max_repeats={limit}"
    return False, f"repeated_call: nothing repeated more than {limit}x"


def ungrounded_arg(ctx: GuardContext, params: dict) -> tuple[bool, str]:
    """Fire when an argument value appears nowhere in the user's own request.

    This is the destination-substitution check: the user asked to settle an
    invoice, the agent is about to send money to an account the user never
    mentioned. That account came from somewhere else — usually the untrusted
    document.

    Without a user prompt there is nothing to ground against, so it returns
    False early with a recorded reason. Returning True there would flag every
    call in any context that failed to plumb the prompt through, which is how a
    guardrail earns a reputation for noise.
    """
    tool = str(params.get("tool", ""))
    arg = str(params.get("arg", ""))

    if not (ctx.user_prompt or "").strip():
        return False, "ungrounded_arg: no user_prompt available; cannot ground"

    prompt = _norm_ws(ctx.user_prompt).lower()
    min_len = int(params.get("min_length", 4))

    for call in _calls_for_tool(ctx, tool):
        value = _norm_ws(_stringify(_arg(call, arg)))
        if not value or len(value) < min_len:
            continue
        if value.lower() not in prompt:
            return True, (
                f"ungrounded_arg: {call.name}.{arg}={value[:60]!r} "
                "does not appear in the user's request"
            )
    return False, f"ungrounded_arg: {tool or 'any'}.{arg} grounded in the user's request"


def unrequested_tool(ctx: GuardContext, params: dict) -> tuple[bool, str]:
    """A mutating call the user's request did not licence.

    Overreach, not attack: the user asked to *view* and the agent also
    *modified*. This is the shape most real incidents take.
    """
    mutating = {str(t) for t in (params.get("mutating_tools") or [])}
    allowed = {str(t) for t in (params.get("allowed_tools") or [])}
    if not mutating:
        return False, "unrequested_tool: empty mutating_tools set"

    offenders = sorted(
        {
            c.name
            for c in (ctx.tool_calls or [])
            if getattr(c, "name", None) in mutating and c.name not in allowed
        }
    )
    if offenders:
        return True, f"unrequested_tool: {', '.join(offenders)} not in allowed set"
    return False, "unrequested_tool: no unlicensed mutation"


def external_destination(ctx: GuardContext, params: dict) -> tuple[bool, str]:
    """Fire when data leaves for a destination outside the allowlist.

    An absent or empty allowlist means *nothing* is pre-approved, so any
    external destination fires. That is the safe default: an allowlist someone
    forgot to fill in must not read as "everywhere is fine".
    """
    tool = str(params.get("tool", ""))
    arg = str(params.get("arg", ""))
    allowlist = {str(a).strip().lower() for a in (params.get("allowlist") or [])}

    for call in _calls_for_tool(ctx, tool):
        raw = _norm_ws(_stringify(_arg(call, arg)))
        if not raw:
            continue
        value = raw.lower()
        if value in allowlist:
            continue
        # Substring form so an allowlisted domain covers addresses on it.
        if any(entry and entry in value for entry in allowlist):
            continue
        return True, f"external_destination: {call.name}.{arg}={raw[:60]!r} not allowlisted"
    return False, f"external_destination: {tool or 'any'}.{arg} allowlisted or absent"


#: Optional, caller-supplied judge. Signature ``fn(ctx, params) -> (bool, str)``.
#: Nothing in detguard sets this. It exists so that enabling ``llm_judge`` is an
#: explicit act by the host application, never a default.
JUDGE_BACKEND: Callable[[GuardContext, dict], tuple[bool, str]] | None = None


def llm_judge(ctx: GuardContext, params: dict) -> tuple[bool, str]:
    """Model-based check. Ships disabled; **fails open** when unavailable.

    No LLM sits in the enforcement path in v1. With no backend configured this
    records why it could not run and returns False. It never blocks on its own
    absence, and it never imports a provider SDK into core.
    """
    if JUDGE_BACKEND is None:
        model = params.get("model", "unset")
        return False, f"llm_judge: unavailable (no backend configured, model={model}) — failed open"
    try:
        return JUDGE_BACKEND(ctx, params)
    except Exception as exc:  # pragma: no cover - depends on host backend
        return False, f"llm_judge: backend error ({exc.__class__.__name__}) — failed open"


# ---------------------------------------------------------------------------
# module constants
# ---------------------------------------------------------------------------

CONDITIONS: dict[str, Callable[[GuardContext, dict], tuple[bool, str]]] = {
    "content_scan": content_scan,
    "pii_detect": pii_detect,
    "pii_redact": pii_redact,
    "sensitive_tool_call": sensitive_tool_call,
    "tool_arg_matches": tool_arg_matches,
    "numeric_bound": numeric_bound,
    "call_budget": call_budget,
    "repeated_call": repeated_call,
    "ungrounded_arg": ungrounded_arg,
    "unrequested_tool": unrequested_tool,
    "external_destination": external_destination,
    "llm_judge": llm_judge,
}

#: Conditions permitted to mutate the context (via ``ctx.redacted_text``).
TRANSFORMING = {"pii_redact"}

#: Conditions that require a ``pattern_set`` param naming a set the policy defines.
REQUIRES_PATTERN_SET = {"content_scan", "pii_detect", "pii_redact"}

#: ``notify`` is here for compliance/breach-notification wiring. In v1 it writes
#: to the audit log and does not block.
ACTIONS = {"block", "redact", "require_hitl", "warn", "limit", "notify"}

#: Actions that stop unattended execution. ``require_hitl`` is here because
#: nothing proceeds without a human — but the Verdict still distinguishes it
#: from a hard block via ``requires_approval``.
BLOCKING_ACTIONS = {"block", "require_hitl"}

#: Conditions that ship disabled and must be turned on deliberately, e.g. via
#: ``detguard run --enable-layer llm_judge``.
DISABLED_BY_DEFAULT = {"llm_judge"}
