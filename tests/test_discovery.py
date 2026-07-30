"""Tool discovery: an adapter that needs an adapter is not an adapter.

`LangGraphAdapter` claims to wrap a compiled graph. It used to look for tools in
exactly one place — a prebuilt ``ToolNode``'s registry — and return nothing for
any graph that runs its tools from a node of its own. "Nothing" then reached the
user as an empty manifest plus an implicit instruction to hand-write a factory
module, which is the one thing the adapter exists to avoid.

Every graph shape below is one a real project produces, and each must introspect
with **no ``tools=`` argument**. The shapes are built in their own module
namespaces via ``exec``, because the thing under test is precisely whether the
tools can be recovered from the module a node function was defined in — and if
they were defined in *this* module, every test would pass for the wrong reason.
"""

from __future__ import annotations

from typing import Annotated, TypedDict

import pytest

pytest.importorskip("langgraph")

from langgraph.graph import END, StateGraph  # noqa: E402
from langgraph.graph.message import add_messages  # noqa: E402

from detguard.adapters.langgraph import (  # noqa: E402
    DISCOVERY_STRATEGIES,
    LangGraphAdapter,
    _is_tool,
)


class State(TypedDict):
    messages: Annotated[list, add_messages]


TOOLS_SOURCE = '''
from langchain_core.tools import tool

@tool
def send_email(to: str, body: str) -> str:
    """Send an email."""
    return "sent"

@tool
def read_inbox() -> str:
    """Read the inbox."""
    return "empty"

ALL_TOOLS = [send_email, read_inbox]
TOOLS_BY_NAME = {t.name: t for t in ALL_TOOLS}
'''

EXPECTED = ["read_inbox", "send_email"]


def module(source: str, with_tools: bool = True) -> dict:
    """Execute source in a fresh namespace, standing in for a project module."""
    namespace: dict = {}
    exec((TOOLS_SOURCE if with_tools else "") + source, namespace)
    return namespace


def graph_of(*nodes) -> object:
    builder = StateGraph(State)
    for name, node in nodes:
        builder.add_node(name, node)
    builder.set_entry_point(nodes[0][0])
    builder.add_edge(nodes[0][0], END)
    return builder.compile()


def names(manifest: dict) -> list[str]:
    return [t["name"] for t in manifest["tools"]]


def sources(manifest: dict) -> set[str]:
    return {t["discovered_from"] for t in manifest["tools"]}


# ---------------------------------------------------------------------------
# the four shapes
# ---------------------------------------------------------------------------


def test_prebuilt_tool_node():
    from langgraph.prebuilt import ToolNode

    ns = module("def call_model(state):\n    return {'messages': []}")
    g = graph_of(("model", ns["call_model"]), ("tools", ToolNode(ns["ALL_TOOLS"])))

    manifest = LangGraphAdapter(graph=g).introspect()

    assert names(manifest) == EXPECTED
    assert sources(manifest) == {"tool_node"}


def test_custom_tool_node_with_a_module_level_list():
    """The shape that forced a hand-written adapter file.

    A graph whose tool node is an ordinary function, with the tool list a module
    global. Nothing about this is exotic and it must not require configuration.
    """
    ns = module(
        "def run_tools(state):\n"
        "    for t in ALL_TOOLS:\n"
        "        pass\n"
        "    return {'messages': []}"
    )
    g = graph_of(("run_tools", ns["run_tools"]))

    manifest = LangGraphAdapter(graph=g).introspect()

    assert names(manifest) == EXPECTED
    assert sources(manifest) == {"module_global:ALL_TOOLS"}


def test_custom_tool_node_with_a_name_keyed_dict():
    ns = module(
        "def run_tools(state):\n"
        "    for name, t in TOOLS_BY_NAME.items():\n"
        "        pass\n"
        "    return {'messages': []}"
    )
    g = graph_of(("run_tools", ns["run_tools"]))

    assert names(LangGraphAdapter(graph=g).introspect()) == EXPECTED


def test_tools_known_only_to_a_bound_model():
    """``llm.bind_tools([...])`` — authoritative, and carries argument schemas."""
    ns = module(
        "from langchain_core.utils.function_calling import convert_to_openai_tool\n"
        "from langchain_core.language_models.fake_chat_models import "
        "FakeMessagesListChatModel\n"
        "from langchain_core.messages import AIMessage\n"
        "_llm = FakeMessagesListChatModel(responses=[AIMessage(content='hi')])\n"
        "MODEL = _llm.bind(tools=[convert_to_openai_tool(t) for t in ALL_TOOLS])\n"
        "def call_model(state):\n"
        "    return {'messages': []}"
    )
    g = graph_of(("model", ns["call_model"]))

    manifest = LangGraphAdapter(graph=g).introspect()

    assert names(manifest) == EXPECTED
    assert sources(manifest) == {"bound_model:MODEL"}
    params = {t["name"]: t["params"] for t in manifest["tools"]}
    assert set(params["send_email"]) == {"to", "body"}, "schemas must survive"


def test_explicit_tools_always_win():
    ns = module("def run_tools(state):\n    return {'messages': []}")
    g = graph_of(("run_tools", ns["run_tools"]))

    manifest = LangGraphAdapter(graph=g, tools=ns["ALL_TOOLS"]).introspect()

    assert names(manifest) == EXPECTED
    assert sources(manifest) == {"explicit"}


def test_every_shape_agrees():
    """The point of the cascade: one tool surface, however it was written."""
    from langgraph.prebuilt import ToolNode

    ns = module("def n(state):\n    return {'messages': []}")
    shapes = [
        graph_of(("n", ns["n"]), ("tools", ToolNode(ns["ALL_TOOLS"]))),
        graph_of(("n", module("def run_tools(state):\n    return {'messages': ALL_TOOLS}")["run_tools"])),
    ]
    assert {tuple(names(LangGraphAdapter(graph=g).introspect())) for g in shapes} == {
        tuple(EXPECTED)
    }


# ---------------------------------------------------------------------------
# not guessing
# ---------------------------------------------------------------------------


def test_a_graph_with_no_tools_discovers_nothing():
    ns = module("def lonely(state):\n    return {'messages': []}", with_tools=False)
    assert LangGraphAdapter(graph=graph_of(("n", ns["lonely"]))).introspect()["tools"] == []


def test_unrelated_globals_are_not_mistaken_for_tools():
    """A name and a description are not enough to be a tool."""
    ns = module(
        "CONFIG = ['a', 'b', 'c']\n"
        "LIMITS = {'x': 1, 'y': 2}\n"
        "class Thing:\n"
        "    name = 'thing'\n"
        "    description = 'not a tool'\n"
        "DECOYS = [Thing()]\n"
        "def lonely(state):\n"
        "    return {'messages': [CONFIG, LIMITS, DECOYS]}",
        with_tools=False,
    )
    assert LangGraphAdapter(graph=graph_of(("n", ns["lonely"]))).introspect()["tools"] == []


def test_tools_are_not_reported_twice():
    """Sibling nodes share one ``__globals__``; without dedupe every tool doubles."""
    ns = module(
        "def a(state):\n    return {'messages': ALL_TOOLS}\n"
        "def b(state):\n    return {'messages': ALL_TOOLS}"
    )
    manifest = LangGraphAdapter(graph=graph_of(("a", ns["a"]), ("b", ns["b"]))).introspect()
    assert names(manifest) == EXPECTED


def test_is_tool_does_not_screen_on_callability():
    """A ``@tool`` is a Runnable with no ``__call__``.

    Requiring ``callable()`` rejected every real tool — the bug that made the
    globals strategy silently find nothing on the first attempt.
    """
    from langchain_core.tools import tool

    @tool
    def sample(x: str) -> str:
        """Doc."""
        return x

    assert not callable(sample), "assumption behind this test changed"
    assert _is_tool(sample)


def test_discovery_strategies_are_documented_for_the_error_message():
    assert len(DISCOVERY_STRATEGIES) >= 4
    assert any("bind_tools" in s for s in DISCOVERY_STRATEGIES)


# ---------------------------------------------------------------------------
# state readers
# ---------------------------------------------------------------------------


def test_adapter_without_a_state_reader_says_it_cannot_read():
    from detguard.events import UNREADABLE

    ns = module("def n(state):\n    return {'messages': ALL_TOOLS}")
    adapter = LangGraphAdapter(graph=graph_of(("n", ns["n"])))
    assert adapter.get_state("emails.last_recipient") is UNREADABLE


def test_mapping_reader_distinguishes_unmapped_from_empty():
    from detguard.adapters.state import UNREADABLE, mapping_reader

    read = mapping_reader({"emails.last_recipient": lambda: None})

    # Mapped but empty: a real answer.
    assert read("emails.last_recipient") is None
    # Never mapped: not an answer at all.
    assert read("payees.last_added") is UNREADABLE


def test_sql_reader_reads_one_value_per_path():
    import sqlite3

    from detguard.adapters.state import UNREADABLE, sql_reader

    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE emails (id INTEGER PRIMARY KEY, to_emails TEXT)")
    connection.execute("INSERT INTO emails (to_emails) VALUES ('[\"a@x.com\"]')")
    connection.commit()

    read = sql_reader(
        lambda: connection,
        {"emails.last_recipient": "SELECT to_emails FROM emails ORDER BY id DESC LIMIT 1"},
    )

    assert read("emails.last_recipient") == "a@x.com", "JSON array unwrapped"
    assert read("calendar.last_title") is UNREADABLE


def test_sql_reader_empty_table_is_none_not_unreadable():
    """No rows is an answer; no query is not."""
    import sqlite3

    from detguard.adapters.state import sql_reader

    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE emails (id INTEGER PRIMARY KEY, to_emails TEXT)")
    connection.commit()

    read = sql_reader(lambda: connection, {"emails.last_recipient": "SELECT to_emails FROM emails"})
    assert read("emails.last_recipient") is None
