"""LangGraph adapter.

Thin by design. LangGraph already has the two things detguard needs — a tool
registry it can introspect and a message stream that records every call and
every result — so this adapter reads those and translates. It adds no
behaviour of its own.

``langgraph`` and ``langchain-core`` are optional. The import is guarded so
that ``pip install detguard`` with no extras still works; the error only
arrives if you actually try to use this adapter.

    pip install "detguard[langgraph]"

Note on placement: LangGraph ships ``interrupt()``, which is a perfectly good
HITL mechanism. detguard is not competing with it — the difference is that a
policy-defined gate is versioned, reviewed, regression-tested in CI, and comes
with a measured false-positive rate. "We have HITL" is not differentiating;
"we can tell you what our HITL costs in friction" is.
"""

from __future__ import annotations

from typing import Any, Callable

from .base import AgentRun, BaseAdapter

_IMPORT_HINT = (
    "LangGraph support needs the optional extra: pip install \"detguard[langgraph]\""
)


def _require_langgraph():
    try:
        import langgraph  # noqa: F401
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError(_IMPORT_HINT) from exc


class LangGraphAdapter(BaseAdapter):
    """Wrap a compiled LangGraph graph.

    Parameters
    ----------
    graph
        A compiled graph, i.e. the result of ``builder.compile()``.
    tools
        The tool objects, when they cannot be recovered from the graph. Any
        ``@tool``-decorated callable or ``BaseTool`` works.
    reset_hook
        Called before every attack to restore fresh state. Without one, results
        leak between cases and the whole run is worthless — so this adapter
        says so loudly rather than quietly reusing dirty state.
    state_reader
        ``fn(path) -> value``, for success checks. Defaults to reading the
        graph's own state via ``get_state`` when a thread config is supplied.
    inject
        ``fn(inputs, injected_context) -> inputs``. Places untrusted content
        where this graph expects to find it — a document key, a retrieved
        chunk, a tool's canned return. Defaults to appending a human message.
    """

    name = "langgraph"

    def __init__(
        self,
        graph: Any,
        tools: list | None = None,
        reset_hook: Callable[[], None] | None = None,
        state_reader: Callable[[str], Any] | None = None,
        inject: Callable[[dict, dict | None], dict] | None = None,
        agent_name: str = "langgraph-agent",
        input_key: str = "messages",
        config: dict | None = None,
        principal: str = "the account holder",
    ):
        _require_langgraph()
        self.graph = graph
        self._tools = list(tools or [])
        self.reset_hook = reset_hook
        self.state_reader = state_reader
        self.inject = inject
        self.agent_name = agent_name
        self.input_key = input_key
        self.config = dict(config or {})
        self.principal = principal

    # -- discovery ---------------------------------------------------------

    def _discover_tools(self) -> list:
        """Find the tools, from the constructor or by walking the graph's nodes.

        LangGraph does not expose a single canonical registry, so this looks in
        the places a ToolNode actually keeps them and gives up honestly rather
        than guessing.
        """
        if self._tools:
            return self._tools

        found: list = []
        nodes = getattr(getattr(self.graph, "builder", None), "nodes", None) or {}
        for node in nodes.values():
            runnable = getattr(node, "runnable", node)
            registry = getattr(runnable, "tools_by_name", None)
            if isinstance(registry, dict):
                found.extend(registry.values())
                continue
            tools = getattr(runnable, "tools", None)
            if isinstance(tools, (list, tuple)):
                found.extend(tools)

        self._tools = found
        return found

    def introspect(self) -> dict:
        tools = []
        for tool in self._discover_tools():
            tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "")
            if not tool_name:
                continue
            tools.append(
                {
                    "name": tool_name,
                    "description": (getattr(tool, "description", "") or "").strip(),
                    "params": _schema_params(tool),
                }
            )
        tools.sort(key=lambda t: t["name"])

        return {
            "agent": self.agent_name,
            "framework": "langgraph",
            "principal": self.principal,
            "tools": tools,
            # Neither of these is inferable from a graph. Roles depend on what a
            # tool means to the business, and carriers depend on where untrusted
            # content enters — both are the client's to state, and a guess here
            # would be a guess about what is dangerous.
            "untrusted_sources": [],
            "state_paths": {},
        }

    # -- contract ----------------------------------------------------------

    def reset(self) -> None:
        if self.reset_hook is None:
            raise RuntimeError(
                "LangGraphAdapter needs a reset_hook: without fresh state per attack, "
                "results leak between cases and the run cannot be trusted."
            )
        self.reset_hook()

    def get_state(self, path: str) -> Any:
        if self.state_reader is not None:
            return self.state_reader(path)
        if self.config:
            snapshot = self.graph.get_state(self.config)
            return self.read_path(getattr(snapshot, "values", {}) or {}, path)
        return None

    def invoke(self, user_prompt: str, injected_context: dict | None = None) -> AgentRun:
        inputs: dict = {self.input_key: [{"role": "user", "content": user_prompt}]}

        if self.inject is not None:
            inputs = self.inject(inputs, injected_context)
        elif injected_context and injected_context.get("content"):
            # Default placement: the untrusted document arrives as its own
            # message, which is how most graphs receive retrieved content.
            inputs[self.input_key].insert(
                0,
                {
                    "role": "user",
                    "content": (
                        f"[{injected_context.get('name', 'document')}]\n"
                        f"{injected_context['content']}"
                    ),
                },
            )

        final = self.graph.invoke(inputs, config=self.config or None)
        messages = (final or {}).get(self.input_key, []) or []
        return AgentRun(
            tool_calls=_calls_from_messages(messages, self.make_call),
            final_output=_final_text(messages),
            metadata={"framework": "langgraph"},
        )


# ---------------------------------------------------------------------------
# message translation
# ---------------------------------------------------------------------------


def _schema_params(tool: Any) -> dict:
    """Read an argument schema off a LangChain tool, pydantic v1 or v2."""
    schema = getattr(tool, "args_schema", None)
    if schema is None:
        return {}
    try:
        fields = getattr(schema, "model_fields", None)
        if fields is not None:  # pydantic v2
            return {
                key: {
                    "type": _annotation_name(field.annotation),
                    "required": field.is_required(),
                }
                for key, field in fields.items()
            }
        fields = getattr(schema, "__fields__", None) or {}  # pydantic v1
        return {
            key: {"type": _annotation_name(getattr(field, "outer_type_", None)),
                  "required": bool(getattr(field, "required", False))}
            for key, field in fields.items()
        }
    except Exception:  # pragma: no cover - schema shapes vary widely
        return {}


def _annotation_name(annotation: Any) -> str:
    mapping = {str: "string", int: "number", float: "number", bool: "boolean",
               dict: "object", list: "array"}
    if annotation in mapping:
        return mapping[annotation]
    return getattr(annotation, "__name__", "any")


def _calls_from_messages(messages: list, make_call: Callable) -> list:
    """Pair each requested tool call with the ToolMessage carrying its result.

    The result is read off the stream, never recomputed. A tool ran once inside
    the graph; re-running it here to find out what it returned would be both a
    correctness bug and, for anything that moves money, an incident.
    """
    requested: list[tuple[str, str, dict]] = []
    results: dict[str, Any] = {}

    for message in messages:
        for call in getattr(message, "tool_calls", None) or []:
            if isinstance(call, dict):
                requested.append(
                    (str(call.get("id", "")), str(call.get("name", "")), dict(call.get("args") or {}))
                )
            else:
                requested.append(
                    (
                        str(getattr(call, "id", "")),
                        str(getattr(call, "name", "")),
                        dict(getattr(call, "args", {}) or {}),
                    )
                )

        call_id = getattr(message, "tool_call_id", None)
        if call_id:
            results[str(call_id)] = getattr(message, "content", None)

    return [make_call(name, args, results.get(call_id)) for call_id, name, args in requested]


def _final_text(messages: list) -> str:
    for message in reversed(messages):
        if getattr(message, "tool_call_id", None):
            continue
        if getattr(message, "tool_calls", None):
            continue
        content = getattr(message, "content", None)
        if isinstance(content, str) and content.strip():
            return content
        if isinstance(content, list):  # content blocks
            parts = [b.get("text", "") for b in content if isinstance(b, dict)]
            if any(parts):
                return "".join(parts)
    return ""
