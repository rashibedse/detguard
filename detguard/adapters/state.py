"""State readers — how a success check finds out what actually happened.

An attack's success check asks a question about the world *after* the agent ran:
did the payee change, did money leave, is the credential still what it was. Only
the client's own system can answer that, so detguard needs a ``fn(path) -> value``
from them.

What it must never do is guess. A reader that returns ``None`` for a path it does
not handle is indistinguishable from a path whose value genuinely is ``None``,
and the runner reads that as "the attack did not achieve its objective" — i.e. as
a successful defence. That single ambiguity can turn a real breach into a green
row, so every reader here returns :data:`~detguard.adapters.base.UNREADABLE` for
a path it was not given, and the runner reports those separately from defences.

These helpers exist so that nobody has to hand-write path dispatch:

    from detguard.adapters.state import sql_reader

    state_reader = sql_reader(
        lambda: sqlite3.connect("app.db"),
        {
            "emails.last_recipient":
                "SELECT to_emails FROM emails ORDER BY id DESC LIMIT 1",
            "calendar_events.last_title":
                "SELECT title FROM calendar_events ORDER BY id DESC LIMIT 1",
        },
    )
"""

from __future__ import annotations

import json
from typing import Any, Callable, Mapping

from .base import UNREADABLE

__all__ = ["mapping_reader", "sql_reader", "UNREADABLE"]


def mapping_reader(paths: Mapping[str, Callable[[], Any]]) -> Callable[[str], Any]:
    """Build a reader from ``{path: zero-arg callable}``.

    An unmapped path yields ``UNREADABLE`` rather than ``None``, which is the
    whole point: "I was never told how to read this" and "this is empty" are
    different findings and must not collapse into one.
    """
    resolved = dict(paths)

    def read(path: str) -> Any:
        getter = resolved.get(path)
        if getter is None:
            return UNREADABLE
        return getter()

    read.detguard_paths = tuple(resolved)  # type: ignore[attr-defined]
    return read


def sql_reader(
    connect: Callable[[], Any],
    queries: Mapping[str, str],
    *,
    json_first_element: bool = True,
) -> Callable[[str], Any]:
    """Build a reader from ``{path: SQL}``, one query per path.

    Each query should select a single column from a single row; the first column
    of the first row is the value. A query returning no rows yields ``None`` —
    that is a real answer ("nothing has been sent yet"), not a failure to read,
    and the distinction is preserved deliberately.

    Parameters
    ----------
    connect
        Zero-arg callable returning a DB-API connection. Called per read, so a
        reset that swaps the database underneath is picked up rather than cached.
    queries
        ``{"emails.last_recipient": "SELECT to_emails FROM ..."}``.
    json_first_element
        Columns holding a JSON array — a recipients list, say — are unwrapped to
        their first element, because the check compares against one destination.
        Set ``False`` to get the raw stored value.
    """
    resolved = dict(queries)

    def read(path: str) -> Any:
        sql = resolved.get(path)
        if sql is None:
            return UNREADABLE

        connection = connect()
        try:
            cursor = connection.execute(sql)
            row = cursor.fetchone()
        finally:
            close = getattr(connection, "close", None)
            if callable(close):
                close()

        if row is None:
            return None
        value = row[0] if not isinstance(row, Mapping) else next(iter(row.values()))
        return _unwrap_json(value) if json_first_element else value

    read.detguard_paths = tuple(resolved)  # type: ignore[attr-defined]
    return read


def _unwrap_json(value: Any) -> Any:
    """A JSON array column -> its first element; anything else unchanged."""
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text.startswith("["):
        return value
    try:
        parsed = json.loads(text)
    except ValueError:
        return value
    if isinstance(parsed, list):
        return parsed[0] if parsed else None
    return value
