"""CSV renderer — turns a list of view-model rows into a CSV string.

Pure function, no I/O and no network: ``render_csv(rows) -> str``. Built on the
stdlib :mod:`csv` module so quoting of embedded commas, quotes and newlines
(CR / LF / CRLF) is handled correctly and consumers can parse the result with
:class:`csv.DictReader`.

Input shape
-----------
``rows`` is a ``list`` of flat ``dict`` "view models" — for example the rows a
command has already flattened for display::

    [
        {"cve_id": "CVE-2021-44228", "severity": "CRITICAL", "epss": 97.53},
        {"cve_id": "CVE-2023-38408", "severity": "CRITICAL", "epss": 31.24},
    ]

The header is the stable union of all row keys (first-appearance order), so
ragged rows (missing keys) still produce a rectangular table with empty cells.
Nested values (dict/list/…) are stringified to compact JSON. String cells that
begin with a spreadsheet formula character (``= + - @`` / tab / CR) are prefixed
with a single quote to defuse CSV formula injection (CWE-1236) when the file is
opened in Excel / Sheets.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from pocmap.utils.renderers._common import stringify, union_header

__all__ = ["render_csv"]

# Leading characters that make Excel / Google Sheets / LibreOffice treat a cell
# as a formula. pocmap emits externally-sourced text (CVE descriptions, GitHub
# repo names/titles) to CSV that security analysts open in a spreadsheet, so a
# cell such as ``=HYPERLINK("http://evil","click")`` or ``=cmd|'/c calc'!A1``
# would execute — CSV / formula injection (CWE-1236). We neutralize it with the
# OWASP-recommended fix: prefix a single quote so the spreadsheet treats the
# cell as literal text.
_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: Any) -> str:
    """Stringify ``value`` and neutralize spreadsheet formula injection.

    Only values that ORIGINATED as strings can carry an injected formula, so a
    genuine number rendered by :func:`stringify` (e.g. a negative delta ``-5``)
    is never prefixed and stays numerically intact.
    """
    text = stringify(value)
    if isinstance(value, str) and text and text[0] in _FORMULA_LEADERS:
        return "'" + text
    return text


def render_csv(rows: list[dict[str, Any]]) -> str:
    """Render ``rows`` as a CSV document.

    Args:
        rows: A list of flat dict view models. Keys become columns (union of
            all rows, first-appearance order); values are stringified, with
            nested values encoded as compact JSON and ``None`` as an empty cell.

    Returns:
        The CSV text, with the standard ``\\r\\n`` (CRLF) line terminator. An
        empty string is returned when ``rows`` is empty (no columns to emit).
    """
    header = union_header(rows)
    if not header:
        return ""

    buffer = io.StringIO()
    writer = csv.writer(buffer)  # default excel dialect => CRLF line terminator
    writer.writerow(header)  # column names are internal field ids, not user data
    for row in rows:
        writer.writerow([_csv_safe(row.get(column)) for column in header])
    return buffer.getvalue()
