"""Output-format abstraction for the PocMap CLI.

This is the single, central rendering seam that every current and future
export feature (JSON now; CSV / Markdown / SARIF later) builds on, so that
output behaviour is defined once instead of drifting per command.

Contract
--------
Each command produces a plain *view model* and hands it to :func:`render`
together with the selected :class:`OutputFormat`:

* **JSON** — the view model MUST be a JSON-serialisable ``dict``/``list`` of
  primitives (build it with e.g. ``model.model_dump(mode="json")``). It is
  emitted to stdout as ``json.dumps(data, indent=2, default=str)`` and nothing
  else, so the stream stays machine-parseable and pipe-friendly.
* **TABLE** — the command keeps its own Rich rendering. It passes an already
  built Rich renderable (a :class:`rich.table.Table`, ``str``, ``Group`` ...)
  and :func:`render` simply prints it via the supplied console. Commands with
  multi-section table output may continue to print directly and not call
  :func:`render` at all for the table path — the two styles interoperate.

Only ``table`` and ``json`` are implemented today; ``csv``/``md``/``sarif`` are
reserved names added by later roadmap items. Selecting an unimplemented format
raises a clear :class:`ValueError` rather than silently producing nothing.

Example::

    from pocmap.utils.output import OutputFormat, render
    render({"id": "CVE-2021-44228"}, OutputFormat.JSON, console=console)
"""

from __future__ import annotations

import json
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rich.console import Console

__all__ = ["OutputFormat", "render"]


class OutputFormat(str, Enum):
    """Selectable CLI output formats.

    ``str``-backed so Typer renders the choices (``table``/``json``) directly
    and the value round-trips cleanly through ``--format``.

    Reserved for later roadmap items (do not enable until a renderer exists):
    ``csv``, ``md``, ``sarif``.
    """

    TABLE = "table"
    JSON = "json"


def render(data: Any, fmt: OutputFormat, *, console: Console) -> None:
    """Render ``data`` to ``console`` in the requested ``fmt``.

    Args:
        data: The view model. For :attr:`OutputFormat.JSON` a
            JSON-serialisable ``dict``/``list``; for :attr:`OutputFormat.TABLE`
            a Rich renderable (or ``None`` to render nothing).
        fmt: The target output format.
        console: The Rich console to write to (keyword-only). JSON is written
            verbatim (no wrapping/markup) so the output stays valid JSON.

    Raises:
        ValueError: If ``fmt`` is a reserved but not-yet-implemented format.
    """
    if fmt is OutputFormat.JSON:
        payload = json.dumps(data, indent=2, default=str)
        # soft_wrap + no markup/highlight => the JSON is emitted byte-for-byte
        # (no line wrapping at the console width, no ANSI, no ``[...]`` parsing).
        console.print(payload, soft_wrap=True, markup=False, highlight=False)
        return

    if fmt is OutputFormat.TABLE:
        if data is not None:
            console.print(data)
        return

    raise ValueError(f"Unsupported output format: {fmt!r}")
