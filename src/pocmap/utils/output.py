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

``table`` and ``json`` keep their long-standing behaviour; ``csv``, ``md`` and
``sarif`` dispatch to the pure renderers in :mod:`pocmap.utils.renderers`:

* **CSV** / **MARKDOWN** — the view model is a ``list[dict]`` (one row per
  exploit / lab / report / cpe / cve). :func:`render` hands it to
  :func:`~pocmap.utils.renderers.render_csv` /
  :func:`~pocmap.utils.renderers.render_markdown` and writes the result
  verbatim.
* **SARIF** — the view model is a ``list`` of CVE-shaped dicts (``id``,
  ``description``, ``cvss`` with ``base_score``/``severity``, ``epss``,
  ``kev_status``, ``exploit_count``, ``cwes``). :func:`render` calls
  :func:`~pocmap.utils.renderers.render_sarif`, injecting the pocmap package
  version as ``tool.driver.version``. Only the CVE-list commands can produce
  this shape; other commands reject ``sarif`` at the CLI layer with a clear
  ``INVALID_INPUT`` error before calling :func:`render`.

The raw-text formats (CSV / Markdown / SARIF) are written straight to
``console.file`` so the bytes the renderer produced — notably CSV's ``\\r\\n``
line terminators — survive unaltered (Rich's ``console.print`` would normalise
them). Selecting a genuinely unknown format still raises :class:`ValueError`.

Example::

    from pocmap.utils.output import OutputFormat, render
    render({"id": "CVE-2021-44228"}, OutputFormat.JSON, console=console)
    render([{"id": "CVE-2021-44228"}], OutputFormat.SARIF, console=console)
"""

from __future__ import annotations

import json
from enum import Enum
from typing import TYPE_CHECKING, Any

from pocmap.utils.renderers import render_csv, render_markdown, render_sarif

if TYPE_CHECKING:
    from rich.console import Console

__all__ = ["OutputFormat", "render"]


class OutputFormat(str, Enum):
    """Selectable CLI output formats.

    ``str``-backed so Typer renders the choices directly and each value
    round-trips cleanly through ``--format``:

    * ``table`` — the command's own Rich rendering (default).
    * ``json`` — a structured, JSON-serialisable view model.
    * ``csv`` / ``md`` — a ``list[dict]`` of rows (spreadsheet / Markdown table).
    * ``sarif`` — SARIF 2.1.0 for CI code-scanning (CVE-list commands only).
    """

    TABLE = "table"
    JSON = "json"
    CSV = "csv"
    MARKDOWN = "md"
    SARIF = "sarif"


def _write_raw(text: str, console: Console) -> None:
    """Write ``text`` to the console's underlying file byte-for-byte.

    Bypasses Rich rendering (no markup, no highlight, no newline normalisation)
    so CSV ``\\r\\n`` terminators and pre-formatted output survive intact. A
    trailing newline is appended when missing purely for terminal tidiness.
    """
    if text and not text.endswith("\n"):
        text += "\n"
    console.file.write(text)


def render(
    data: Any,
    fmt: OutputFormat,
    *,
    console: Console,
    title: str | None = None,
) -> None:
    """Render ``data`` to ``console`` in the requested ``fmt``.

    Args:
        data: The view model. For :attr:`OutputFormat.JSON` a
            JSON-serialisable ``dict``/``list``; for :attr:`OutputFormat.TABLE`
            a Rich renderable (or ``None`` to render nothing); for
            :attr:`OutputFormat.CSV`/:attr:`OutputFormat.MARKDOWN` a
            ``list[dict]`` of rows; for :attr:`OutputFormat.SARIF` a ``list`` of
            CVE-shaped dicts.
        fmt: The target output format.
        console: The Rich console to write to (keyword-only). Text formats are
            written verbatim so the output stays machine-parseable.
        title: Optional heading passed through to the Markdown renderer
            (ignored by every other format).

    Raises:
        ValueError: If ``fmt`` is not a recognised format.
    """
    if fmt is OutputFormat.JSON:
        payload = json.dumps(data, indent=2, default=str)
        # soft_wrap + no markup/highlight => the JSON is emitted byte-for-byte
        # (no line wrapping at the console width, no ANSI, no ``[...]`` parsing).
        console.print(payload, soft_wrap=True, markup=False, highlight=False)
        return

    if fmt is OutputFormat.CSV:
        _write_raw(render_csv(data), console)
        return

    if fmt is OutputFormat.MARKDOWN:
        _write_raw(render_markdown(data, title=title), console)
        return

    if fmt is OutputFormat.SARIF:
        # Imported lazily to keep the version string authoritative without a
        # module-load-time dependency on the top-level package.
        from pocmap import __version__

        _write_raw(render_sarif(data, tool_version=__version__), console)
        return

    if fmt is OutputFormat.TABLE:
        if data is not None:
            console.print(data)
        return

    raise ValueError(f"Unsupported output format: {fmt!r}")
