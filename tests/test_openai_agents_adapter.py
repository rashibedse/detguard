"""``OpenAIAgentsAdapter``'s interception seam, against the real SDK.

Every other test touching this class (``test_cli.py``) replaces it with a stub
to test CLI flag wiring, so the seam that turns a detected block into a
prevented one — ``set_tool_guard``, its ``tool_input_guardrails`` wiring, the
argument-decoding it depends on — had zero coverage anywhere in the suite.
It was verified once, by hand, against a live agent; this is what makes that
verification repeatable.

No model call anywhere here. ``set_tool_guard`` and the guardrail callback it
installs are synchronous and pure — they never invoke the LLM — so this stays
as offline and deterministic as the rest of the suite. Running a full turn
through ``Runner.run_sync`` needs a real or mocked model and is out of scope
for a unit test; ``runner.py``'s own tests already cover the scoring semantics
using a fake adapter, and this session's manual verification (control vs.
guarded, against the live Groq-backed banking agent) is the end-to-end proof
that the two compose correctly.
"""

from __future__ import annotations

import pytest

pytest.importorskip("agents")

from agents import Agent, function_tool  # noqa: E402

from detguard.adapters.openai_agents import OpenAIAgentsAdapter, _decode_args  # noqa: E402


@function_tool
def transfer_funds(to: str, amount: float) -> str:
    """Move money. Docstring required by the SDK's schema generation."""
    return f"sent {amount} to {to}"


@function_tool
def get_balance(account: str) -> str:
    """Read a balance. Docstring required by the SDK's schema generation."""
    return "100.00"


def build_agent() -> Agent:
    return Agent(name="test-agent", instructions="test", tools=[transfer_funds, get_balance])


def build_adapter() -> OpenAIAgentsAdapter:
    return OpenAIAgentsAdapter(agent=build_agent(), reset_hook=lambda: None)


# ---------------------------------------------------------------------------
# attachment
# ---------------------------------------------------------------------------


def test_set_tool_guard_attaches_to_every_tool_and_reports_intercepting():
    adapter = build_adapter()
    assert adapter.intercepts is False  # honest before installation

    installed = adapter.set_tool_guard(lambda name, args: (True, ""))

    assert installed is True
    assert adapter.intercepts is True
    for tool in adapter.agent.tools:
        names = [g.name for g in (tool.tool_input_guardrails or [])]
        assert "detguard_tool_guard" in names


def test_set_tool_guard_on_an_agent_with_no_tools_reports_it_did_not_take():
    agent = Agent(name="toolless", instructions="test", tools=[])
    adapter = OpenAIAgentsAdapter(agent=agent, reset_hook=lambda: None)

    installed = adapter.set_tool_guard(lambda name, args: (True, ""))

    assert installed is False
    assert adapter.intercepts is False


def test_reattaching_replaces_rather_than_stacks():
    """A second `set_tool_guard` (e.g. a second attack's reset) must not pile
    up duplicate guardrails on the same tool — each attack gets exactly one
    check per call, not one per attack that has ever run."""
    adapter = build_adapter()
    adapter.set_tool_guard(lambda name, args: (True, ""))
    adapter.set_tool_guard(lambda name, args: (True, ""))

    for tool in adapter.agent.tools:
        names = [g.name for g in (tool.tool_input_guardrails or [])]
        assert names.count("detguard_tool_guard") == 1


def test_set_tool_guard_none_detaches_and_reports_not_intercepting():
    adapter = build_adapter()
    adapter.set_tool_guard(lambda name, args: (True, ""))

    result = adapter.set_tool_guard(None)

    assert result is False
    assert adapter.intercepts is False
    for tool in adapter.agent.tools:
        names = [g.name for g in (tool.tool_input_guardrails or [])]
        assert "detguard_tool_guard" not in names


def test_set_tool_guard_preserves_a_pre_existing_unrelated_guardrail():
    """Attaching ours must not silently discard a guardrail the host already
    put on the tool — only the previous *detguard* guardrail is replaced."""
    from agents import ToolGuardrailFunctionOutput, ToolInputGuardrail

    def _host_guard(data):
        return ToolGuardrailFunctionOutput.allow()

    agent = build_agent()
    host_guardrail = ToolInputGuardrail(guardrail_function=_host_guard, name="host_owned")
    for tool in agent.tools:
        tool.tool_input_guardrails = [host_guardrail]

    adapter = OpenAIAgentsAdapter(agent=agent, reset_hook=lambda: None)
    adapter.set_tool_guard(lambda name, args: (True, ""))

    for tool in agent.tools:
        names = {g.name for g in (tool.tool_input_guardrails or [])}
        assert names == {"host_owned", "detguard_tool_guard"}


# ---------------------------------------------------------------------------
# the guardrail's own decision
# ---------------------------------------------------------------------------


class _StubToolContext:
    def __init__(self, tool_name: str, tool_arguments):
        self.tool_name = tool_name
        self.tool_arguments = tool_arguments


class _StubGuardrailData:
    def __init__(self, tool_name: str, tool_arguments):
        self.context = _StubToolContext(tool_name, tool_arguments)


def _installed_screen(adapter: OpenAIAgentsAdapter):
    """The internal callback the SDK will actually invoke, recovered the same
    way the SDK reaches it — off the tool's own guardrail list, not off a
    private adapter attribute."""
    tool = adapter.agent.tools[0]
    (guardrail,) = [g for g in tool.tool_input_guardrails if g.name == "detguard_tool_guard"]
    return guardrail.guardrail_function


def _reject_message(outcome) -> str | None:
    """The SDK nests the refusal text in `outcome.behavior`, not a top-level
    attribute — checked once here so a future SDK version only needs updating
    in one place."""
    behavior = getattr(outcome, "behavior", None) or {}
    if getattr(behavior, "get", None):
        return behavior.get("message")
    return getattr(behavior, "message", None)


def test_an_allowed_call_produces_an_allow_output():
    adapter = build_adapter()
    adapter.set_tool_guard(lambda name, args: (True, ""))
    screen = _installed_screen(adapter)

    outcome = screen(_StubGuardrailData("transfer_funds", '{"to": "X", "amount": 100}'))

    assert getattr(outcome, "behavior", {}).get("type") == "allow"
    assert not adapter.take_denials()


def test_a_denied_call_rejects_with_the_guard_reason_and_is_recorded():
    seen = []

    def guard(name, args):
        seen.append((name, args))
        return False, "blocked by policy rule 'no_unrequested_transfer'"

    adapter = build_adapter()
    adapter.set_tool_guard(guard)
    screen = _installed_screen(adapter)

    outcome = screen(
        _StubGuardrailData("transfer_funds", '{"to": "attacker", "amount": 9999}')
    )

    assert getattr(outcome, "behavior", {}).get("type") == "reject_content"
    assert _reject_message(outcome) == "blocked by policy rule 'no_unrequested_transfer'"
    assert seen == [("transfer_funds", {"to": "attacker", "amount": 9999})]

    denied = adapter.take_denials()
    assert denied == [
        {
            "name": "transfer_funds",
            "args": {"to": "attacker", "amount": 9999},
            "reason": "blocked by policy rule 'no_unrequested_transfer'",
        }
    ]
    # Drained, not merely read — the next attack must not inherit this one's denials.
    assert adapter.take_denials() == []


def test_a_guard_that_raises_fails_closed_not_open():
    """A broken guard denying-by-default is the only safe failure mode for a
    security check — the alternative is a bug in policy code silently
    granting every call it was supposed to be gating."""

    def guard(name, args):
        raise RuntimeError("boom")

    adapter = build_adapter()
    adapter.set_tool_guard(guard)
    screen = _installed_screen(adapter)

    outcome = screen(_StubGuardrailData("transfer_funds", "{}"))

    message = _reject_message(outcome)
    assert message
    assert "RuntimeError" in message


# ---------------------------------------------------------------------------
# argument decoding
# ---------------------------------------------------------------------------


def test_decode_args_parses_the_sdks_json_string_form():
    assert _decode_args('{"to": "X", "amount": 100}') == {"to": "X", "amount": 100}


def test_decode_args_passes_through_a_dict_unchanged():
    assert _decode_args({"to": "X"}) == {"to": "X"}


def test_decode_args_handles_missing_or_malformed_input_without_raising():
    assert _decode_args(None) == {}
    assert _decode_args("") == {}
    assert _decode_args("not json") == {"_raw": "not json"}
