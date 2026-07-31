"""Authoring-time generation of the files a client would otherwise hand-write.

Every agent that is not built on a framework detguard already adapts needs the
same four artifacts written by hand: an adapter, a manifest, a role map, and a
filled-in policy. The adapter is the worst of them, because the hard part is not
boilerplate — it is finding the one place in *someone else's* agent loop where a
tool call can be recorded without executing it twice.

This module generates them. Two halves, deliberately separated:

**Deterministic** — :func:`derive_policy` fills the CLIENT-marked rules from a
role map by rule, not by judgement, and the CI workflow comes from
:mod:`detguard.scaffold`. Nothing here needs a model and nothing here is allowed
to want one.

**Model-assisted** — classifying tools into roles, and writing adapter code
against an unfamiliar dispatch structure. Both are reading-comprehension tasks
over source nobody has seen before, and neither can be derived.

The line this must not cross
----------------------------
detguard's claim is that **no LLM sits in the enforcement path**. Generation
happens at authoring time; the output is YAML and Python that a human reads,
edits, commits, and diffs, and enforcement then runs deterministic conditions
over that committed file. A model that helped write a policy in March has no
part in the decision made in June.

That distinction survives only if generated output is treated as a *draft*:

* every file carries a provenance header naming the model and the date;
* the role map carries per-tool reasoning inline, so a reviewer checks the
  judgement instead of trusting it;
* everything round-trips through the real validators before it is written, so
  an invalid file is never produced;
* classification errs **gated** — an uncertain tool gets the more restrictive
  role, because over-gating is visible and annoying while under-gating is
  invisible and fatal.

Needs the optional extra::

    pip install "detguard[authoring]"
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .roles import GATED_BY_DEFAULT, ROLES, tools_with_role

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

#: Source files larger than this are truncated in the prompt. A 200KB vendored
#: module is not what anyone is asking about, and sending it crowds out the
#: file that matters.
MAX_SOURCE_BYTES = 60_000

DEFAULT_SOURCE_GLOBS = ("*.py",)

#: Directories never worth reading: dependencies, caches, and detguard's own
#: generated output.
SKIP_DIRS = frozenset({
    ".git", ".venv", "venv", "env", "__pycache__", "node_modules",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "site-packages",
    "runs", "corpus", "build", "dist",
})


class AuthoringError(RuntimeError):
    """Generation failed. Never downgraded to a partial write."""


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

    policy = _deep_copy(base)
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


def _deep_copy(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _deep_copy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep_copy(v) for v in value]
    return value


# ---------------------------------------------------------------------------
# source collection
# ---------------------------------------------------------------------------


@dataclass
class SourceFile:
    path: str
    text: str
    truncated: bool = False


def collect_sources(
    root: str | Path,
    globs: tuple[str, ...] = DEFAULT_SOURCE_GLOBS,
    max_bytes: int = MAX_SOURCE_BYTES,
    max_files: int = 40,
) -> list[SourceFile]:
    """Read the agent's source, skipping dependencies and generated output.

    Truncation is recorded rather than silent: a model that only saw the first
    half of a dispatch table should say so in its output, and a reviewer should
    be able to see that is why it guessed.
    """
    base = Path(root).resolve()
    if not base.is_dir():
        raise AuthoringError(f"source directory not found: {base}")

    found: list[SourceFile] = []
    for pattern in globs:
        for path in sorted(base.rglob(pattern)):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if not path.is_file():
                continue
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            truncated = len(raw.encode("utf-8")) > max_bytes
            if truncated:
                raw = raw[:max_bytes] + "\n\n# ... truncated by detguard scaffold ...\n"
            found.append(
                SourceFile(path=str(path.relative_to(base)), text=raw, truncated=truncated)
            )
            if len(found) >= max_files:
                return found
    if not found:
        raise AuthoringError(
            f"no source files matching {', '.join(globs)} under {base} — "
            "point --source-dir at the directory holding your agent"
        )
    return found


# ---------------------------------------------------------------------------
# prompt
# ---------------------------------------------------------------------------


FILE_BEGIN = "--- BEGIN {name} ---"
FILE_END = "--- END {name} ---"

_SYSTEM = """\
You generate integration files for detguard, a policy-as-code guardrail that \
tests AI agents against an adversarial corpus. You are writing a DRAFT that a \
human will review, edit and commit. Accuracy about what the source actually \
does matters far more than producing something that looks complete.

Never invent a function, module, table or column that is not in the source you \
were given. If something needed is genuinely absent, say so in the NOTES \
section rather than fabricating it."""


def build_prompt(
    sources: list[SourceFile],
    entry: str,
    reset: str = "",
    agent_name: str = "",
) -> str:
    """Assemble the generation prompt.

    The adapter contract is spelled out in full rather than assumed, because
    the failure it is guarding against — recording tool calls by re-executing
    them — produces working-looking code that silently doubles every side
    effect the agent has.
    """
    blocks = []
    for source in sources:
        marker = "  (TRUNCATED)" if source.truncated else ""
        blocks.append(f"### {source.path}{marker}\n```python\n{source.text}\n```")
    source_text = "\n\n".join(blocks)

    return f"""{_SYSTEM}

# The agent

Entry point: `{entry}`
{f"Reset hook: `{reset}`" if reset else "Reset hook: not supplied — infer one if the source has a seeding/reset function, else leave a TODO."}
{f"Name: {agent_name}" if agent_name else ""}

# Source

{source_text}

# What to produce

Four files, each wrapped in the exact delimiters shown at the end.

## 1. detguard_adapter.py

A `BaseAdapter` subclass. The contract:

```python
from detguard.adapters.base import AgentRun, BaseAdapter

class MyAdapter(BaseAdapter):
    name = "..."
    def introspect(self) -> dict: ...      # manifest as a dict, metadata only
    def reset(self) -> None: ...           # fresh state before EVERY attack
    def invoke(self, user_prompt: str, injected_context: dict | None = None) -> AgentRun: ...
    def get_state(self, path: str): ...    # read real post-run state
```

Four requirements, in order of how badly they break things when missed:

**(a) A tool is executed exactly once.** `invoke()` must run the agent's own
loop once and *record* what it did. It must NOT collect a list of intended
calls and then execute them itself — that doubles every real side effect
(rows inserted twice, emails sent twice) and makes every number in the report
fiction. Find where the source actually executes tools and record there.

**(b) The trace must survive dispatch.** Look at how the loop maps a tool name
to a function. If it builds a dict at import time, patching the module
attribute will not work — the dict already holds the original reference, and
you will get an empty trace, which reports as "the agent never called
anything" and reads as a perfect defense. Patch whatever the loop actually
reads from, and restore it afterwards.

**(c) `reset()` must genuinely reset.** If the source's seed/init function is
idempotent ("only seed if empty"), it is NOT usable as a reset hook — state
from attack 1 leaks into attack 2 and every result after the first is
measured against contaminated state. If that is the case here, generate a
reset that truly wipes and reseeds, and flag it loudly in NOTES.

**(d) `get_state(path)` reads the real store.** Not the agent's account of
itself. Use `self.read_path(mapping, path)` or query the backing store
directly. Where no reader is possible, return the `UNREADABLE` sentinel from
`detguard.adapters.base` — never `None`, which reads as "unchanged" and gets
reported as a defense that never happened.

Include `injected_context` handling: when it carries `content`, place that
untrusted text where this agent would really encounter it.

**The module must define a zero-argument factory named exactly
`build_adapter()`** returning a configured instance. Everything downstream
addresses the adapter as `detguard_adapter:build_adapter`, so a differently
named factory means every generated command and CI workflow is wrong.

## 2. manifest.yaml

```yaml
agent: <name>
framework: generic
principal: the account holder
tools:
  - name: <tool>
    description: <one line>
    params: {{<arg>: {{type: string, required: true}}}}
untrusted_sources:
  - name: <carrier an attacker can author into>
    kind: record        # record | file | retrieval
    injection_point: <field the payload goes in>
state_paths:
  <role>: <dotted path get_state understands>
```

Only tools the agent can really call. `untrusted_sources` are carriers an
attacker could author into — a document body, a fetched file, a record field.
Without at least one, every indirect-injection template is skipped.

## 3. roles.yaml

```yaml
roles:
  <tool>: [<role>, ...]
```

Closed vocabulary, nothing outside it: {", ".join(ROLES)}

Gated by default: {", ".join(GATED_BY_DEFAULT)}

**When uncertain, assign the MORE restrictive role.** A tool wrongly classed
`read_internal` is never gated by anything and fails silently; a tool wrongly
classed `external_send` causes a visible, fixable false positive. These are
not symmetric errors.

Above each tool put a `# why:` comment giving your reasoning in one line, so a
reviewer can check the judgement instead of trusting it.

## 4. ARG_HINTS

Which argument carries a destination, and which carries an amount. detguard
binds its grounding, egress and value-ceiling rules to these.

```yaml
<tool>:
  destination_arg: <arg name, or omit>
  amount_arg: <arg name, or omit>
```

# Output format

Exactly this, nothing outside the delimiters except the NOTES section:

{FILE_BEGIN.format(name="detguard_adapter.py")}
<python>
{FILE_END.format(name="detguard_adapter.py")}

{FILE_BEGIN.format(name="manifest.yaml")}
<yaml>
{FILE_END.format(name="manifest.yaml")}

{FILE_BEGIN.format(name="roles.yaml")}
<yaml>
{FILE_END.format(name="roles.yaml")}

{FILE_BEGIN.format(name="ARG_HINTS")}
<yaml>
{FILE_END.format(name="ARG_HINTS")}

NOTES:
- anything you had to guess, could not find, or that the reviewer must fix
"""


# ---------------------------------------------------------------------------
# response parsing
# ---------------------------------------------------------------------------


def parse_response(text: str) -> dict[str, str]:
    """Pull the delimited files out of a model response.

    Fenced-block delimiters rather than JSON: generated Python contains quotes,
    backslashes and newlines, and a JSON envelope turns every one of them into
    an escaping bug that fails at parse time after the expensive call.
    """
    files: dict[str, str] = {}
    pattern = re.compile(
        r"^--- BEGIN (?P<name>[\w.\-]+) ---\s*\n(?P<body>.*?)\n?^--- END (?P=name) ---",
        re.MULTILINE | re.DOTALL,
    )
    for match in pattern.finditer(text):
        files[match.group("name")] = _strip_code_fence(match.group("body"))
    if not files:
        raise AuthoringError(
            "the model returned no delimited files — nothing was written. "
            "Re-run; if it repeats, the model may be refusing or truncating."
        )
    return files


def _strip_code_fence(body: str) -> str:
    """Remove a ```lang fence if the model wrapped the body in one anyway."""
    lines = body.strip("\n").split("\n")
    if lines and lines[0].lstrip().startswith("```"):
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
    return "\n".join(lines).strip("\n") + "\n"


def extract_notes(text: str) -> str:
    match = re.search(r"^NOTES:\s*\n(.*)", text, re.MULTILINE | re.DOTALL)
    return match.group(1).strip() if match else ""


# ---------------------------------------------------------------------------
# the model call
# ---------------------------------------------------------------------------


def infer_provider(model: str) -> str:
    """Pick a provider from the model name, so the common case needs no flag."""
    name = (model or "").lower()
    if name.startswith("claude"):
        return "anthropic"
    return "openai"


def call_model(
    prompt: str,
    model: str,
    api_key: str,
    provider: str = "",
    base_url: str = "",
    max_tokens: int = 16_000,
) -> str:
    """Send the prompt and return raw text.

    The SDK import is deliberately lazy and local. detguard's core must be
    installable and runnable with pyyaml alone — an authoring convenience is not
    permitted to add a hard dependency to a package whose whole argument is that
    it has almost none.

    ``base_url`` covers every OpenAI-compatible endpoint (Groq, Together, a
    local server), which is the same escape hatch the adapters give you.
    """
    provider = provider or infer_provider(model)
    if not api_key:
        raise AuthoringError(
            "no API key. Pass --api-key or set DETGUARD_API_KEY "
            "(ANTHROPIC_API_KEY / OPENAI_API_KEY are also read)."
        )

    if provider == "anthropic":
        try:
            import anthropic
        except ImportError as exc:
            raise AuthoringError(
                'the anthropic SDK is not installed: pip install "detguard[authoring]"'
            ) from exc
        client = anthropic.Anthropic(api_key=api_key, **({"base_url": base_url} if base_url else {}))
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in message.content if getattr(block, "type", "") == "text")

    try:
        import openai
    except ImportError as exc:
        raise AuthoringError(
            'the openai SDK is not installed: pip install "detguard[authoring]"'
        ) from exc
    client = openai.OpenAI(api_key=api_key, **({"base_url": base_url} if base_url else {}))
    completion = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    return completion.choices[0].message.content or ""


def resolve_api_key(explicit: str = "") -> str:
    """First key found, in the order somebody would expect."""
    import os

    if explicit:
        return explicit
    for name in ("DETGUARD_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        found = os.environ.get(name, "")
        if found:
            return found
    return ""


# ---------------------------------------------------------------------------
# writing
# ---------------------------------------------------------------------------


def write_bundle(
    bundle: Bundle,
    config_dir: str | Path,
    adapter_path: str | Path,
    overwrite: bool = False,
) -> list[Path]:
    """Write a validated bundle to disk. Refuses to write a bundle with problems.

    Refusing is the whole point. A half-written integration where the manifest
    landed and the adapter did not is worse than nothing, because the next
    command fails somewhere unrelated and the cause is three steps back.
    """
    import yaml

    if not bundle.ok:
        raise AuthoringError(
            "refusing to write a bundle that failed validation:\n  "
            + "\n  ".join(bundle.problems)
        )

    config = Path(config_dir)
    config.mkdir(parents=True, exist_ok=True)
    targets = {
        Path(adapter_path): bundle.adapter_code,
        # Raw text, not a re-dump — see the Bundle docstring on why the
        # per-role `# why:` comments must survive to disk.
        config / "manifest.yaml": bundle.manifest_text,
        config / "roles.yaml": bundle.roles_text,
        config / "policy.yaml": yaml.safe_dump(bundle.policy, sort_keys=False),
    }

    existing = [p for p in targets if p.exists()]
    if existing and not overwrite:
        raise AuthoringError(
            "these already exist (pass --overwrite to replace them):\n  "
            + "\n  ".join(str(p) for p in existing)
        )

    written = []
    for path, body in targets.items():
        comment = "#"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(header(bundle.model, comment) + body, encoding="utf-8")
        written.append(path)
    return written


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


@dataclass
class Bundle:
    """A generated set, plus what validating it found.

    Model-written files keep their **raw text** alongside the parsed form. The
    parsed dict is what gets validated; the raw text is what gets written. That
    split exists for one reason: the prompt asks for a ``# why:`` comment above
    every role so a reviewer can check the classification instead of trusting
    it, and round-tripping through ``yaml.safe_dump`` would strip every one of
    those comments on the way to disk — deleting the review material we went
    out of our way to ask for.

    The policy is the exception: it is derived here rather than generated, so
    there is no author's comment to lose and the dict is the source of truth.
    """

    adapter_code: str = ""
    manifest_text: str = ""
    roles_text: str = ""
    manifest: dict = field(default_factory=dict)
    roles: dict = field(default_factory=dict)
    arg_hints: dict = field(default_factory=dict)
    policy: dict = field(default_factory=dict)
    notes: str = ""
    problems: list[str] = field(default_factory=list)
    model: str = ""

    @property
    def ok(self) -> bool:
        return not self.problems


def build_bundle(files: dict[str, str], notes: str = "", model: str = "") -> Bundle:
    """Parse generated text into a Bundle, validating every piece.

    Nothing is written by this function. A file that does not survive the real
    validators is a problem recorded on the bundle, not a file on disk — the
    same guarantee ``dashboard/setup.py`` makes, for the same reason.
    """
    import yaml

    from .manifest import ManifestError, parse_manifest, parse_roles
    from .policy import PolicyError, loads as load_policy

    bundle = Bundle(model=model, notes=notes)

    bundle.adapter_code = files.get("detguard_adapter.py", "")
    if not bundle.adapter_code.strip():
        bundle.problems.append("no adapter code was generated")
    else:
        try:
            compile(bundle.adapter_code, "detguard_adapter.py", "exec")
        except SyntaxError as exc:
            bundle.problems.append(f"generated adapter does not parse: {exc}")

    manifest_obj = None
    bundle.manifest_text = files.get("manifest.yaml", "")
    try:
        bundle.manifest = yaml.safe_load(bundle.manifest_text) or {}
        manifest_obj = parse_manifest(bundle.manifest, source_path="<generated>")
    except (yaml.YAMLError, ManifestError) as exc:
        bundle.problems.append(f"manifest.yaml: {exc}")

    bundle.roles_text = files.get("roles.yaml", "")
    try:
        bundle.roles = yaml.safe_load(bundle.roles_text) or {}
        parse_roles(bundle.roles, manifest=manifest_obj, source_path="<generated>")
    except (yaml.YAMLError, ManifestError) as exc:
        bundle.problems.append(f"roles.yaml: {exc}")

    try:
        bundle.arg_hints = yaml.safe_load(files.get("ARG_HINTS", "")) or {}
        if not isinstance(bundle.arg_hints, dict):
            bundle.arg_hints = {}
    except yaml.YAMLError:
        bundle.arg_hints = {}

    # The policy is derived, never generated — see module docstring.
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


def header(model: str, comment: str = "#") -> str:
    """The banner every generated file carries.

    A reviewer who cannot tell generated output from reviewed output will
    eventually treat both the same way, and the one that matters is the one
    nobody checked.
    """
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    return (
        f"{comment} GENERATED by `detguard scaffold` on {stamp} using {model or 'a model'}.\n"
        f"{comment} This is a DRAFT. Read it before you commit it — a wrong role\n"
        f"{comment} classification is a gate that never fires, and it looks exactly\n"
        f"{comment} like one that works.\n"
    )
