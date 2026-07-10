"""Markdown renderer — turns view-model rows into a GitHub-flavored table.

Pure function, no I/O and no network: ``render_markdown(rows, *, title=None)``.
The output is a GitHub-Flavored Markdown (GFM) table that pastes cleanly into
issues, pull requests, wikis and bug-bounty reports.

Input shape
-----------
Same as the CSV renderer — a ``list`` of flat ``dict`` "view models"::

    render_markdown(
        [{"cve_id": "CVE-2021-44228", "severity": "CRITICAL"}],
        title="Findings",
    )

The header is the stable union of all row keys (first-appearance order). Cell
values are stringified (nested values become compact JSON); the pipe character
``|`` is escaped as ``\\|`` and newlines are replaced with ``<br>`` so a value
can never break the table structure.
"""

from __future__ import annotations

from typing import Any

from pocmap.utils.renderers._common import stringify, union_header

__all__ = ["render_markdown"]


def _escape_cell(value: Any) -> str:
    """Stringify ``value`` and make it safe inside a GFM table cell."""
    text = stringify(value)
    # Normalise line endings, then neutralise the two characters that would
    # otherwise break a Markdown table row: the pipe and the newline.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("|", "\\|").replace("\n", "<br>")
    return text


def render_markdown(rows: list[dict[str, Any]], *, title: str | None = None) -> str:
    """Render ``rows`` as a GitHub-flavored Markdown table.

    Args:
        rows: A list of flat dict view models. Keys become columns (union of
            all rows, first-appearance order); values are stringified and
            escaped for table safety.
        title: Optional heading rendered as a level-1 ``# title`` above the
            table.

    Returns:
        The Markdown text (trailing newline included). If ``rows`` is empty,
        only the optional title is returned.
    """
    header = union_header(rows)
    lines: list[str] = []
    if title:
        lines.append(f"# {title}")

    if not header:
        # Only the (optional) title — no table, and hence no separating blank line.
        return (lines[0] + "\n") if lines else ""

    if lines:
        lines.append("")  # blank line between the title and the table

    lines.append("| " + " | ".join(_escape_cell(column) for column in header) + " |")
    lines.append("| " + " | ".join("---" for _ in header) + " |")
    for row in rows:
        lines.append(
            "| " + " | ".join(_escape_cell(row.get(column)) for column in header) + " |"
        )
    return "\n".join(lines) + "\n"
