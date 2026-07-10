"""Shared helpers for the tabular renderers (CSV and Markdown).

These are intentionally tiny, dependency-free, and pure so both the CSV and
Markdown renderers derive their column order and cell text the same way.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["stringify", "union_header"]


def union_header(rows: list[dict[str, Any]]) -> list[str]:
    """Return a stable column order from the union of every row's keys.

    Keys are ordered by first appearance: the first row's keys come first (in
    insertion order), followed by any new keys contributed by later rows. This
    keeps output deterministic and header-stable even when rows are ragged
    (different keys / missing keys).

    Args:
        rows: The view-model rows.

    Returns:
        The ordered list of column names (empty if ``rows`` is empty).
    """
    header: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                header.append(key)
    return header


def stringify(value: Any) -> str:
    """Coerce an arbitrary cell value to a stable string.

    Scalars are rendered directly; ``None`` becomes an empty string; nested
    values (``dict``/``list``/``tuple``/``set`` or any other object) are
    serialised to compact, key-sorted JSON so the output is deterministic and
    round-trippable. Anything that resists JSON encoding falls back to ``str``.

    Args:
        value: The raw cell value.

    Returns:
        A string representation suitable for CSV/Markdown output.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, (int, float)):
        return str(value)
    try:
        return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)
