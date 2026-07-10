"""Command-line interface for PocMap.

Built with Typer and Rich for a modern, interactive experience.
Supports CVE lookup, exploit discovery, lab search, report generation,
and bulk processing from files.

Usage::

    pocmap CVE-2021-44228
    pocmap --description CVE-2021-44228
    pocmap --file cves.txt --output ./reports
    pocmap --labs CVE-2021-44228
    pocmap --bugbounty CVE-2021-44228
    pocmap --cpes CVE-2021-44228
    pocmap --cpe2cve "cpe:2.3:o:microsoft:windows_10:1607"
"""

from __future__ import annotations

import importlib.util
import logging
import re
import sys
from collections.abc import Callable, Iterable, Mapping
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Annotated, Any

import click
import typer
from rich import print as rprint
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
)
from rich.table import Table

from pocmap import __version__
from pocmap.bugbounty.automation import _post_webhook, _url_domain
from pocmap.config import (
    GITHUB_API_BASE,
    NVD_API_BASE,
    enable_offline,
    github_token_looks_valid,
    nvd_api_key_looks_valid,
    settings,
)
from pocmap.models import CVEInfo, export_schemas
from pocmap.services.bb_service import BugBountyService
from pocmap.services.cve_service import CVEService
from pocmap.services.exploit_service import ExploitService
from pocmap.services.lab_service import LabService
from pocmap.services.product_service import ProductDiscoveryService
from pocmap.services.recent_service import RecentService
from pocmap.services.report_service import ReportService
from pocmap.services.snapshot import (
    ChangeReason,
    SnapshotDiff,
    SnapshotRecord,
    diff_snapshots,
    load_snapshot,
    make_query_key,
    save_snapshot,
)
from pocmap.utils.cache import HTTPCache
from pocmap.utils.exit_codes import ExitCode
from pocmap.utils.formatters import (
    format_bb_table,
    format_cve_table,
    format_exploit_table,
    format_recent_cves_table,
)
from pocmap.utils.http import (
    HTTPClient,
    HTTPError,
    NotFoundError,
    OfflineError,
    ValidationError,
)
from pocmap.utils.output import OutputFormat, render
from pocmap.utils.paths import safe_path as _safe_path

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

console = Console()
# Separate stderr console for notes that must not pollute a machine-readable
# stdout stream (e.g. the ``bulk --fail-on`` gate message under ``--format json``).
err_console = Console(stderr=True)
app = typer.Typer(
    name="pocmap",
    help="A modern, AI-friendly tool to find PoCs related to CVE IDs",
    no_args_is_help=True,
    # Shell completion (--install-completion / --show-completion) is table
    # stakes for a CLI people live in; Typer generates bash/zsh/fish/PowerShell
    # scripts for free.
    add_completion=True,
)


def _banner() -> None:
    """Print the application banner."""
    rprint(
        rf"""
   _______    ___________   ____  ____  ______
  / ____/ |  / / ____/__ \ / __ \/ __ \/ ____/
 / /    | | / / __/  __/ // /_/ / / / / /
/ /___  | |/ / /___ / __// ____/ /_/ / /___
\____/  |___/_____//____/_/    \____/\____/
                                    AI-Enhanced Edition v{__version__}
"""
    )


@dataclass
class CLIState:
    """Global CLI state threaded through the Typer callback via ``ctx.obj``.

    Attributes:
        output_format: The selected output format (``table`` by default).
        quiet: Whether to suppress the banner and decorative output.
        offline: Whether the process is in offline (cache-only) mode.
    """

    output_format: OutputFormat = OutputFormat.TABLE
    quiet: bool = False
    offline: bool = False


def _state(ctx: typer.Context) -> CLIState:
    """Return the :class:`CLIState` stored on the context (or a default)."""
    obj = ctx.obj
    if isinstance(obj, CLIState):
        return obj
    return CLIState()


def _emit_json_error(exc: Exception, *, category: str) -> None:
    """Emit a compact JSON error object to stdout (json output mode)."""
    render(
        {
            "error": str(exc),
            "error_type": type(exc).__name__,
            "category": category,
        },
        OutputFormat.JSON,
        console=console,
    )


def _resolve_output(
    ctx: typer.Context,
    output_format: OutputFormat | None,
    quiet: bool,
) -> tuple[OutputFormat, bool]:
    """Merge a command-local ``--format``/``--quiet`` with the global callback.

    A locally-passed ``--format``/``--quiet`` overrides the global (callback)
    value recorded on ``ctx.obj``; otherwise the global value wins. Mirrors the
    ``lookup`` reference wiring.
    """
    state = _state(ctx)
    fmt = output_format if output_format is not None else state.output_format
    is_quiet = quiet or state.quiet
    return fmt, is_quiet


def _reject_sarif(fmt: OutputFormat) -> None:
    """Reject ``--format sarif`` on commands whose data is not a CVE list.

    SARIF results are keyed on CVE ids, so only the CVE-list commands
    (``latest``/``discover``) can produce a well-formed log. Every other command
    fails fast with a clear :attr:`ExitCode.INVALID_INPUT` instead of emitting a
    misleading or empty SARIF document.
    """
    if fmt is OutputFormat.SARIF:
        rprint(
            "[red3]Error: SARIF output is only available for the CVE-list "
            "commands (latest, discover)[/red3]"
        )
        raise typer.Exit(ExitCode.INVALID_INPUT)


def _emit_cli_error(exc: Exception, *, fmt: OutputFormat, category: str) -> None:
    """Emit an error as JSON (json mode) or a red console line (every other mode)."""
    if fmt is OutputFormat.JSON:
        _emit_json_error(exc, category=category)
    else:
        rprint(f"[red3]Error: {exc}[/red3]")


# The one, consistent message shown when ``--offline`` hits a cold cache. An
# offline cache-miss must read as its own thing (UPSTREAM_ERROR, exit 5), never
# as "not found" (3) or "no results" (2) — a source that is merely unreachable
# offline is not the same as one that genuinely has nothing.
_OFFLINE_HINT = (
    "Offline: no cached data for this query. Run online once to populate the "
    "cache, or drop --offline."
)


def _offline_exit(exc: Exception, *, fmt: OutputFormat) -> typer.Exit:
    """Report an :class:`OfflineError` cleanly and return the exit to raise.

    JSON mode emits the categorized error object (``category == "offline"``);
    every other mode prints the human-readable :data:`_OFFLINE_HINT`. Either way
    the command exits :attr:`ExitCode.UPSTREAM_ERROR` (5) with no traceback,
    mirroring how ``lookup`` already surfaces offline.
    """
    if fmt is OutputFormat.JSON:
        _emit_json_error(exc, category="offline")
    else:
        rprint(f"[red3]{_OFFLINE_HINT}[/red3]")
    return typer.Exit(ExitCode.UPSTREAM_ERROR)


def _cve_sarif_dict(cve: CVEInfo, *, exploit_count: int | None) -> dict[str, object]:
    """Map a :class:`CVEInfo` to the CVE-shaped dict the SARIF renderer expects."""
    cvss = cve.cvss
    cvss_block: dict[str, object] | None = (
        {"base_score": cvss.base_score, "severity": cvss.severity.value}
        if cvss is not None
        else None
    )
    return {
        "id": cve.id,
        "description": cve.description,
        "cvss": cvss_block,
        "epss": cve.epss,
        "kev_status": cve.kev_status,
        "exploit_count": exploit_count,
        "cwes": cve.cwes,
    }


def _discover_cve_row(cve: CVEInfo, *, tier: str) -> dict[str, object]:
    """Flatten a discovered :class:`CVEInfo` into a CSV/Markdown row (+ tier)."""
    cvss = cve.cvss
    return {
        "cve_id": cve.id,
        "tier": tier,
        "severity": cvss.severity.value if cvss is not None else "UNKNOWN",
        "base_score": cvss.base_score if cvss is not None else None,
        "epss": cve.epss,
        "kev_status": cve.kev_status,
        "vendor": cve.vendor,
        "product": cve.product,
        "publication_date": cve.publication_date,
        "description": cve.description,
    }


# ---------------------------------------------------------------------------
# bulk CI-gate helpers (stdin, per-CVE rows, --fail-on policy grammar)
# ---------------------------------------------------------------------------

# ``--fail-on epss>=N`` — a float threshold on the 0-100 EPSS scale. Whitespace
# around the operator is tolerated (e.g. ``epss >= 50``).
_FAIL_ON_EPSS_RE = re.compile(r"^epss\s*>=\s*(?P<value>\d+(?:\.\d+)?)$", re.IGNORECASE)

# Severity ranking so ``--fail-on high`` means "HIGH *or worse*" (the intuitive
# CI gate: fail the build if anything is at least this severe).
_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _read_cve_ids_from_stdin() -> list[str]:
    """Read CVE ids from stdin (one per line), mirroring the file parser.

    Blank lines and ``#`` comment lines are skipped, matching
    :meth:`ReportService.generate_bulk_report_from_file` so ``pocmap bulk -``
    behaves identically to ``pocmap bulk <file>``.
    """
    return [
        line.strip()
        for line in sys.stdin.read().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _bulk_cve_row(cve_id: str, entry: Any) -> dict[str, object]:
    """Flatten a bulk :class:`ReportEntry` into a summary row (CSV/MD/JSON)."""
    cve = entry.cve_info
    cvss = cve.cvss
    return {
        "cve_id": cve_id,
        "severity": cvss.severity.value if cvss is not None else "UNKNOWN",
        "base_score": cvss.base_score if cvss is not None else None,
        "epss": cve.epss,
        "kev_status": cve.kev_status,
        "exploit_count": len(entry.exploits),
        "vendor": cve.vendor,
        "product": cve.product,
        "description": cve.description,
    }


class FailOnError(ValueError):
    """Raised when a ``--fail-on`` expression is not understood."""


def _parse_fail_on(spec: str) -> Callable[[CVEInfo], bool]:
    """Compile a ``--fail-on`` expression into a per-CVE predicate.

    Grammar (case-insensitive):

    * ``critical`` — CVSS severity is CRITICAL.
    * ``high`` — CVSS severity is HIGH *or worse* (HIGH/CRITICAL).
    * ``kev`` — the CVE is in the CISA KEV catalog.
    * ``epss>=N`` — EPSS score is >= ``N`` on the 0-100 scale (e.g. ``epss>=50``).

    Returns a predicate that is ``True`` for a CVE that trips the gate.

    Raises:
        FailOnError: If *spec* is not one of the supported forms.
    """
    token = spec.strip().lower()

    if token == "kev":
        return lambda cve: bool(cve.kev_status)

    if token in ("critical", "high"):
        floor = _SEVERITY_ORDER["CRITICAL" if token == "critical" else "HIGH"]

        def _severity_pred(cve: CVEInfo) -> bool:
            if cve.cvss is None:
                return False
            return _SEVERITY_ORDER.get(cve.cvss.severity.value, 0) >= floor

        return _severity_pred

    match = _FAIL_ON_EPSS_RE.match(token)
    if match:
        threshold = float(match.group("value"))
        return lambda cve: cve.epss is not None and cve.epss >= threshold

    raise FailOnError(
        f"Unrecognized --fail-on '{spec}'. Use: critical, high, kev, or epss>=N."
    )


def _fail_on_hits(report: Any, predicate: Callable[[CVEInfo], bool]) -> list[str]:
    """Return the ids of report entries whose CVE trips *predicate* (sorted)."""
    return sorted(
        cve_id
        for cve_id, entry in report.entries.items()
        if predicate(entry.cve_info)
    )


# ---------------------------------------------------------------------------
# WATCH-DIFF rendering helpers (latest / discover --diff)
# ---------------------------------------------------------------------------


def _snapshot_record_row(
    record: SnapshotRecord, *, change: str, reasons: str = ""
) -> dict[str, object]:
    """Flatten a :class:`SnapshotRecord` into a diff row (CSV / Markdown)."""
    return {
        "change": change,
        "cve_id": record.cve_id,
        "reasons": reasons,
        "severity": record.severity or "UNKNOWN",
        "base_score": record.base_score,
        "epss": record.epss,
        "kev_status": record.kev_status,
        "has_poc": record.has_poc,
    }


def _record_to_sarif_dict(record: SnapshotRecord) -> dict[str, object]:
    """Map a :class:`SnapshotRecord` to the CVE-shaped dict the SARIF renderer wants."""
    return {
        "id": record.cve_id,
        "description": "",
        "cvss": {"base_score": record.base_score, "severity": record.severity or "UNKNOWN"},
        "epss": record.epss,
        "kev_status": record.kev_status,
        "exploit_count": None,
        "cwes": [],
    }


def _diff_rows(diff: SnapshotDiff) -> list[dict[str, object]]:
    """Flatten a diff into CSV/Markdown rows: added, then changed, then removed."""
    rows = [_snapshot_record_row(r, change="added") for r in diff.added]
    rows.extend(
        _snapshot_record_row(
            c.current, change="changed", reasons=", ".join(r.value for r in c.reasons)
        )
        for c in diff.changed
    )
    rows.extend(_snapshot_record_row(r, change="removed") for r in diff.removed)
    return rows


def _render_diff(diff: SnapshotDiff, fmt: OutputFormat, *, label: str) -> None:
    """Render a snapshot ``diff`` in the requested ``fmt`` (respects --format).

    ``table`` gets a grouped added/removed/changed view with reasons; ``json``
    the full ``diff.to_dict()`` envelope; ``csv``/``md`` a flat row per delta;
    ``sarif`` a log of the added + changed CVEs (the actionable set).
    """
    if fmt is OutputFormat.JSON:
        render(diff.to_dict(), fmt, console=console)
        return
    if fmt is OutputFormat.SARIF:
        actionable = [_record_to_sarif_dict(r) for r in diff.added]
        actionable.extend(_record_to_sarif_dict(c.current) for c in diff.changed)
        render(actionable, fmt, console=console)
        return
    if fmt in (OutputFormat.CSV, OutputFormat.MARKDOWN):
        render(_diff_rows(diff), fmt, console=console, title=f"{label} — changes since last run")
        return

    # Default: a clear Rich table.
    rprint(f"\n[bold]{label} — changes since last run[/bold]")
    if diff.is_empty:
        rprint(f"[dim]No changes ({diff.unchanged} unchanged).[/dim]")
        return
    table = Table(show_lines=False, header_style="bold")
    table.add_column("Change", justify="center")
    table.add_column("CVE")
    table.add_column("Severity")
    table.add_column("EPSS", justify="right")
    table.add_column("KEV", justify="center")
    table.add_column("Reasons", overflow="fold")
    for rec in diff.added:
        table.add_row(
            "[green1]added[/green1]", rec.cve_id, rec.severity or "-",
            _fmt_epss(rec.epss), "yes" if rec.kev_status else "no", "",
        )
    for change in diff.changed:
        cur = change.current
        table.add_row(
            "[yellow]changed[/yellow]", cur.cve_id, cur.severity or "-",
            _fmt_epss(cur.epss), "yes" if cur.kev_status else "no",
            ", ".join(r.value for r in change.reasons),
        )
    for rec in diff.removed:
        table.add_row(
            "[red3]removed[/red3]", rec.cve_id, rec.severity or "-",
            _fmt_epss(rec.epss), "yes" if rec.kev_status else "no", "",
        )
    console.print(table)
    rprint(f"\n[dim]Summary: {diff.summary()}[/dim]")


def _fmt_epss(value: float | None) -> str:
    """Format an EPSS score for a table cell (or ``-`` when unknown)."""
    return f"{value:.1f}" if value is not None else "-"


def _compute_diff(
    command: str, params: object, models: object
) -> SnapshotDiff:
    """Diff a query's *current* result set against its previous snapshot.

    Implements the WATCH-DIFF flow using only the snapshot engine's public API:
    load the prior snapshot for this query key, persist *models* as the new
    baseline, reload it as normalized records, and diff the two. Capturing the
    previous snapshot *before* the save is what makes the reload equal the
    current set. Pure local computation — no network.

    Args:
        command: The originating command (``"latest"`` / ``"discover"``).
        params: The query params that identify this result set (any mapping).
        models: The current result set (models the snapshot store understands).
    """
    key = make_query_key(command, params if isinstance(params, Mapping) else {})
    previous = load_snapshot(key)
    persisted: Iterable[Any] = models if isinstance(models, Iterable) else []
    save_snapshot(key, persisted)
    current = load_snapshot(key) or []
    return diff_snapshots(previous, current)


# ---------------------------------------------------------------------------
# NOTIFY — post a compact webhook summary of notable CVEs (latest / discover)
# ---------------------------------------------------------------------------

# Canonical, token-free NVD detail page put in each webhook item's ``url``.
_NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/"

# Cap the inline CVE list carried in a webhook payload; ``count`` still reflects
# the true total. Keeps a busy day from posting a giant blob to Slack/Discord.
_NOTIFY_MAX_ITEMS = 20

# Among the *changed* CVEs in a --diff delta, only these movements are worth
# pushing to a responder: newly-exploited (KEV gained) or a severity escalation.
# (Every *added* CVE is notable regardless.)
_NOTABLE_DIFF_REASONS = frozenset(
    {ChangeReason.KEV_GAINED, ChangeReason.SEVERITY_ESCALATED}
)


def _notify_item_from_cve(cve: CVEInfo) -> dict[str, object]:
    """Compact webhook item (id, severity, epss, kev, url) from a CVEInfo."""
    cvss = cve.cvss
    return {
        "id": cve.id,
        "severity": cvss.severity.value if cvss is not None else "UNKNOWN",
        "epss": cve.epss,
        "kev": bool(cve.kev_status),
        "url": f"{_NVD_DETAIL_URL}{cve.id}",
    }


def _notify_item_from_record(record: SnapshotRecord) -> dict[str, object]:
    """Compact webhook item from a snapshot record (the --diff delta path)."""
    return {
        "id": record.cve_id,
        "severity": record.severity or "UNKNOWN",
        "epss": record.epss,
        "kev": bool(record.kev_status),
        "url": f"{_NVD_DETAIL_URL}{record.cve_id}",
    }


def _notable_cve_items(cves: Iterable[CVEInfo]) -> list[dict[str, object]]:
    """Select the critical/high-or-KEV CVEs from a result set as webhook items."""
    items: list[dict[str, object]] = []
    for cve in cves:
        severity = cve.cvss.severity.value if cve.cvss is not None else None
        if severity in ("CRITICAL", "HIGH") or cve.kev_status:
            items.append(_notify_item_from_cve(cve))
    return items


def _notable_diff_items(diff: SnapshotDiff) -> list[dict[str, object]]:
    """Select the added + KEV-gained/severity-escalated CVEs from a --diff delta."""
    records = list(diff.added)
    records.extend(
        change.current
        for change in diff.changed
        if any(reason in _NOTABLE_DIFF_REASONS for reason in change.reasons)
    )
    return [_notify_item_from_record(record) for record in records]


def _notify_text(label: str, items: list[dict[str, object]]) -> str:
    """A short, human-readable summary line (renders nicely in Slack/Discord)."""
    head = ", ".join(str(item["id"]) for item in items[:5])
    more = "" if len(items) <= 5 else f", +{len(items) - 5} more"
    return f"{len(items)} notable CVE(s) — {label}: {head}{more}"


def _build_notify_payload(
    *,
    source: str,
    label: str,
    query: dict[str, object],
    items: list[dict[str, object]],
) -> dict[str, object]:
    """Assemble the compact JSON webhook payload for *items*.

    Shape: ``title``, ``text`` (human line), ``source`` (``latest``/``discover``),
    ``generated_at``, the ``query`` that produced it, ``count`` (true total),
    ``kev_count``, and a capped ``cves`` list of ``{id, severity, epss, kev,
    url}``. Carries no secrets — the only URLs are public NVD detail links.
    """
    total = len(items)
    return {
        "title": f"PocMap: {total} notable CVE(s) — {label}",
        "text": _notify_text(label, items),
        "source": source,
        "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "query": query,
        "count": total,
        "kev_count": sum(1 for item in items if item.get("kev")),
        "cves": items[:_NOTIFY_MAX_ITEMS],
    }


def _run_notify(
    notify: str | None,
    *,
    source: str,
    label: str,
    query: dict[str, object],
    items: list[dict[str, object]],
    is_quiet: bool,
) -> None:
    """POST a compact CVE summary to *notify* via the SSRF-guarded webhook sender.

    A no-op when ``--notify`` is absent. With **zero** notable CVEs the POST is
    skipped (documented behaviour) rather than pinging the webhook with an empty
    summary. Otherwise the payload is sent through
    :func:`pocmap.bugbounty.automation._post_webhook` — the single guarded choke
    point (``is_safe_url`` + ``HTTPClient.post_json`` →
    ``resolves_to_internal_ip`` + no-redirect) — so an internal/unsafe webhook is
    rejected by the guard and never actually reached.

    Only the target **domain** is ever printed (via :func:`_url_domain`); a token
    embedded in the webhook URL never lands in a log line. A guard rejection
    (``ValueError``), transport/internal-IP failure (``HTTPError``) or offline
    cache-miss (``OfflineError``) prints a clean stderr error and exits
    :attr:`ExitCode.UPSTREAM_ERROR` (5). Every confirmation goes to **stderr** so
    a machine-readable stdout stream stays byte-for-byte unchanged.
    """
    if not notify:
        return
    domain = _url_domain(notify)
    if not items:
        if not is_quiet:
            err_console.print(
                f"[dim]Notify: no notable CVEs for {label}; skipping {domain}.[/dim]"
            )
        return
    payload = _build_notify_payload(source=source, label=label, query=query, items=items)
    try:
        _post_webhook(notify, payload)
    except (ValueError, OfflineError, HTTPError) as exc:
        # Domain-only: never echo the full URL (it may embed a webhook token).
        err_console.print(
            f"[red3]Notify failed: could not POST to {domain} "
            f"({type(exc).__name__})[/red3]"
        )
        raise typer.Exit(ExitCode.UPSTREAM_ERROR) from exc
    if not is_quiet:
        err_console.print(
            f"[green1]Notified {domain} ({payload['count']} CVE(s))[/green1]"
        )


def _lookup_json(cve: str, *, language: str | None, limit: int) -> None:
    """JSON view-model path for ``lookup`` — no banner, no spinners, JSON only.

    Wires exit codes: invalid CVE id -> INVALID_INPUT (4); not-found ->
    NOT_FOUND (3); success -> 0.
    """
    with CVEService() as service, ExploitService() as exploit_svc, LabService() as lab_svc:
        try:
            cve_info = service.get_cve_info(cve)
        except ValidationError as exc:
            _emit_json_error(exc, category="invalid_input")
            raise typer.Exit(ExitCode.INVALID_INPUT) from exc
        except NotFoundError as exc:
            _emit_json_error(exc, category="not_found")
            raise typer.Exit(ExitCode.NOT_FOUND) from exc
        except OfflineError as exc:
            _emit_json_error(exc, category="offline")
            raise typer.Exit(ExitCode.UPSTREAM_ERROR) from exc

        github_pocs = exploit_svc.find_github_pocs(cve)
        if language:
            github_pocs = exploit_svc.filter_by_language(github_pocs, language)
        db_exploits = exploit_svc.find_db_exploits(cve)
        labs = lab_svc.find_labs(cve)

    view = {
        "cve": cve_info.model_dump(mode="json"),
        "github_pocs": [ex.model_dump(mode="json") for ex in github_pocs[:limit]],
        "db_exploits": [ex.model_dump(mode="json") for ex in db_exploits],
        "labs": [lab.model_dump(mode="json") for lab in labs],
    }
    render(view, OutputFormat.JSON, console=console)


@app.command()
def lookup(
    ctx: typer.Context,
    cve: Annotated[str, typer.Argument(help="CVE ID (e.g., CVE-2021-44228)")],
    description: Annotated[bool, typer.Option("--description", "-d", help="Show CVE description")] = False,
    language: Annotated[str | None, typer.Option("--language", "-l", help="Filter PoCs by programming language")] = None,
    limit: Annotated[int, typer.Option("--limit", help="Maximum number of PoCs to display", min=1)] = 10,
    no_banner: Annotated[bool, typer.Option("--no-banner", help="Suppress banner")] = False,
    output_format: Annotated[
        OutputFormat | None,
        typer.Option("--format", "-f", help="Output format: table (default) or json"),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress banner and decorative output"),
    ] = False,
) -> None:
    """Look up a single CVE and display its information along with discovered PoCs."""
    state = _state(ctx)
    # A locally-passed --format/--quiet overrides the global (callback) value;
    # otherwise fall back to whatever the global callback recorded on ctx.obj.
    fmt = output_format if output_format is not None else state.output_format
    is_quiet = quiet or state.quiet

    # JSON output: machine-readable view model to stdout, no banner/spinners.
    if fmt is OutputFormat.JSON:
        _lookup_json(cve, language=language, limit=limit)
        return

    if not no_banner and not is_quiet:
        _banner()

    with CVEService() as service, ExploitService() as exploit_svc, LabService() as lab_svc:
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                progress.add_task("[bright_blue]Fetching CVE info...[/bright_blue]", total=None)
                cve_info = service.get_cve_info(cve)
        except ValidationError as exc:
            rprint(f"[red3]Error: {exc}[/red3]")
            raise typer.Exit(ExitCode.INVALID_INPUT) from exc
        except NotFoundError as exc:
            rprint(f"[red3]Error: {exc}[/red3]")
            raise typer.Exit(ExitCode.NOT_FOUND) from exc
        except OfflineError as exc:
            rprint(f"[red3]Offline: {exc}[/red3]")
            raise typer.Exit(ExitCode.UPSTREAM_ERROR) from exc

        # Display CVE info
        rprint(format_cve_table(cve_info))

        # Display description if requested
        if description:
            desc = service.get_description(cve)
            if desc:
                rprint(f"\n[bold]Description[/bold]\n{'-' * 40}\n{desc}")
            else:
                rprint("\n[red3]No description found[/red3]")

            # Ransomware usage (only for KEV)
            if cve_info.kev_status and cve_info.ransomware_usage:
                usage = (
                    f"[red3]{cve_info.ransomware_usage}[/red3]"
                    if cve_info.ransomware_usage == "Known"
                    else cve_info.ransomware_usage
                )
                rprint(f"\n[bold]Ransomware Usage[/bold]\n{'-' * 40}\n{usage}")

            # References
            if cve_info.references:
                rprint(f"\n[bold]References[/bold]\n{'-' * 40}")
                ref_table = Table(show_lines=True, header_style="bold")
                ref_table.add_column("Source", justify="center")
                ref_table.add_column("URL", overflow="fold")
                for src, url in cve_info.references.items():
                    ref_table.add_row(src, url)
                rprint(ref_table)
            raise typer.Exit(0)

        # Search GitHub PoCs
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task("[bright_blue]Searching GitHub PoCs...[/bright_blue]", total=None)
            github_pocs = exploit_svc.find_github_pocs(cve)

        if github_pocs:
            if language:
                github_pocs = exploit_svc.filter_by_language(github_pocs, language)
                if not github_pocs:
                    rprint(f"\n[red3]No PoCs found in {language}[/red3]")
                    raise typer.Exit(0)

            rprint(f"\n[bold]GitHub PoCs ({len(github_pocs)} found)[/bold]")
            shown = github_pocs[:limit]
            rprint(format_exploit_table(shown))
        else:
            rprint("\n[red3]No GitHub PoCs found[/red3]")

        # Search DB exploits
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task("[bright_blue]Searching exploit databases...[/bright_blue]", total=None)
            db_exploits = exploit_svc.find_db_exploits(cve)

        if db_exploits:
            rprint("\n[bold]Exploits from Other Sources[/bold]")
            for ex in db_exploits:
                if ex.source.value == "metasploit" and ex.command:
                    _rank = ex.rank.value if ex.rank is not None else "unknown"
                    rprint(f"\n[magenta3]Metasploit:[/magenta3] {ex.command} (Rank: {_rank})")
                elif ex.source.value == "exploitdb" and ex.command:
                    rprint(f"\n[magenta3]ExploitDB:[/magenta3] {ex.command}")
                elif ex.source.value == "nuclei" and ex.command:
                    rprint(f"\n[magenta3]Nuclei:[/magenta3] {ex.command}")
                else:
                    rprint(f"\n[magenta3]{ex.source.value}:[/magenta3] {ex.url}")
        else:
            rprint("\n[red3]No exploits found in DB sources[/red3]")

        # Search labs
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task("[bright_blue]Searching labs...[/bright_blue]", total=None)
            labs = lab_svc.find_labs(cve)

        if labs:
            rprint(f"\n[bold]Lab Environments ({len(labs)} found)[/bold]")
            for lab in labs:
                if lab.platform.value == "vulhub" and lab.setup_instructions:
                    rprint(f"\n[bold]{lab.platform.value}[/bold]: {lab.url}")
                    rprint(lab.setup_instructions)
                else:
                    rprint(f"\n[bold]{lab.platform.value}[/bold]: {lab.name} -> {lab.url}")
        else:
            rprint("\n[red3]No lab environments found[/red3]")


@app.command()
def bulk(
    ctx: typer.Context,
    file: Annotated[
        Path,
        typer.Argument(help="File with CVE IDs (one per line), or '-' to read from stdin"),
    ],
    output: Annotated[Path, typer.Option("--output", "-o", help="Output directory for reports")] = Path("."),
    threads: Annotated[int, typer.Option("--threads", "-t", help="Number of concurrent workers", min=1)] = 10,
    output_format: Annotated[
        OutputFormat | None,
        typer.Option("--format", "-f", help="Stdout summary format: table (default), json, csv, sarif"),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Exit 6 (POLICY_FAIL) if any CVE matches: critical, high, kev, or epss>=N (e.g. epss>=50)",
        ),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress decorative output"),
    ] = False,
) -> None:
    """Process multiple CVEs from a file (or stdin) as a composable CI gate.

    Reads CVE IDs from a file, or from **stdin** when ``file`` is ``-`` (so
    ``... | pocmap bulk -`` works in a pipeline). The default (``table``) format
    preserves the historical behaviour — it writes a JSON **and** an HTML report
    to ``--output`` and prints confirmations. The machine formats (``json`` /
    ``csv`` / ``sarif``) instead emit a clean summary of every CVE to stdout and
    write no files, so the stream stays parseable in automation.

    ``--fail-on`` turns pocmap into a build gate: if **any** included CVE matches
    the condition (``critical``, ``high``, ``kev``, or ``epss>=N``) the command
    exits ``6`` (:attr:`ExitCode.POLICY_FAIL`); otherwise ``0``. A malformed
    ``--fail-on`` exits ``4`` (:attr:`ExitCode.INVALID_INPUT`).
    """
    fmt, is_quiet = _resolve_output(ctx, output_format, quiet)

    # Validate the --fail-on grammar up front so a typo fails fast (exit 4)
    # before any (potentially slow) report generation.
    predicate: Callable[[CVEInfo], bool] | None = None
    if fail_on is not None:
        try:
            predicate = _parse_fail_on(fail_on)
        except FailOnError as exc:
            _emit_cli_error(exc, fmt=fmt, category="invalid_input")
            raise typer.Exit(ExitCode.INVALID_INPUT) from exc

    from_stdin = str(file) == "-"

    with ReportService() as report_svc:
        try:
            if from_stdin:
                report = report_svc.generate_bulk_report(_read_cve_ids_from_stdin())
            else:
                if not file.exists():
                    rprint(f"[red3]File not found: {file}[/red3]")
                    raise typer.Exit(ExitCode.INVALID_INPUT)
                report = report_svc.generate_bulk_report_from_file(file)
        except typer.Exit:
            raise
        except OfflineError as exc:
            raise _offline_exit(exc, fmt=fmt) from exc
        except Exception as exc:
            _emit_cli_error(exc, fmt=fmt, category="unknown")
            raise typer.Exit(ExitCode.ERROR) from exc

        if not report.entries:
            if fmt is OutputFormat.TABLE:
                rprint("[red3]No valid CVE entries found in the report[/red3]")
                raise typer.Exit(ExitCode.ERROR)
            # Machine formats: still emit a well-formed empty document.
            if fmt is OutputFormat.JSON:
                render({"total": 0, "cves": []}, fmt, console=console)
            else:
                render([], fmt, console=console)
            raise typer.Exit(ExitCode.NO_RESULTS)

        # --fail-on evaluation (shared by every output format). A match is a
        # distinct POLICY_FAIL (6), not a generic ERROR (1), so CI can tell a
        # tripped gate apart from an operational failure. No match -> OK (0).
        hits = _fail_on_hits(report, predicate) if predicate is not None else []
        gate_code = ExitCode.POLICY_FAIL if hits else ExitCode.OK

        if fmt is OutputFormat.TABLE:
            _bulk_table_output(report_svc, report, output, is_quiet=is_quiet)
        else:
            _bulk_machine_output(report, fmt)

        if hits:
            # Keep the gate note off stdout in machine modes so the stream stays
            # parseable; CI reads the (nonzero) exit code regardless.
            err_console.print(
                f"[red3]--fail-on '{fail_on}' matched {len(hits)} CVE(s): "
                f"{', '.join(hits)}[/red3]"
            )
        raise typer.Exit(gate_code)


def _bulk_table_output(
    report_svc: ReportService,
    report: Any,
    output: Path,
    *,
    is_quiet: bool,
) -> None:
    """Historical ``bulk`` behaviour: write JSON + HTML reports and confirm."""
    try:
        _safe_path(str(output))
    except ValueError as exc:
        rprint(f"[red3]Unsafe output path: {exc}[/red3]")
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc

    output.mkdir(parents=True, exist_ok=True)
    json_path = report_svc.save_json_report(report, output)
    rprint(f"[green1]JSON report saved: {json_path}[/green1]")
    html_path = report_svc.save_html_report(report, output)
    rprint(f"[green1]HTML report saved: {html_path}[/green1]")
    if not is_quiet:
        rprint(f"\n[bold]Processed {len(report.entries)} CVE(s)[/bold]")


def _bulk_machine_output(report: Any, fmt: OutputFormat) -> None:
    """Emit a clean stdout summary of a bulk report (json / csv / sarif)."""
    rows = [_bulk_cve_row(cve_id, entry) for cve_id, entry in report.entries.items()]
    if fmt is OutputFormat.SARIF:
        sarif_cves = [
            _cve_sarif_dict(entry.cve_info, exploit_count=len(entry.exploits))
            for entry in report.entries.values()
        ]
        render(sarif_cves, fmt, console=console)
        return
    if fmt is OutputFormat.JSON:
        report_data = {
            "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            "total": len(rows),
            "cves": rows,
        }
        render(report_data, fmt, console=console)
        return
    # csv / md
    render(rows, fmt, console=console, title="Bulk CVE Report")


@app.command()
def labs(
    ctx: typer.Context,
    cve: Annotated[str, typer.Argument(help="CVE ID to search labs for")],
    output_format: Annotated[
        OutputFormat | None,
        typer.Option("--format", "-f", help="Output format: table (default), json, csv, md"),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress decorative output"),
    ] = False,
) -> None:
    """Search for CTF labs and vulnerable environments related to a CVE."""
    fmt, is_quiet = _resolve_output(ctx, output_format, quiet)
    _reject_sarif(fmt)

    with LabService() as service:
        try:
            CVEService.validate_cve_id(cve)
        except ValidationError as exc:
            _emit_cli_error(exc, fmt=fmt, category="invalid_input")
            raise typer.Exit(ExitCode.INVALID_INPUT) from exc

        try:
            results = service.find_labs(cve)
        except OfflineError as exc:
            raise _offline_exit(exc, fmt=fmt) from exc

    if not results:
        if fmt is OutputFormat.TABLE:
            rprint(f"[red3]No labs found for {cve}[/red3]")
        else:
            render({"cve": cve, "labs": []} if fmt is OutputFormat.JSON else [], fmt, console=console)
        raise typer.Exit(ExitCode.NO_RESULTS)

    if fmt is not OutputFormat.TABLE:
        rows = [lab.model_dump(mode="json") for lab in results]
        view = {"cve": cve, "labs": rows} if fmt is OutputFormat.JSON else rows
        render(view, fmt, console=console, title=f"Lab Environments for {cve}")
        return

    if not is_quiet:
        rprint(f"\n[bold]Lab Environments for {cve}[/bold]")
    for lab in results:
        if lab.platform.value == "vulhub" and lab.setup_instructions:
            rprint(f"\n[bright_cyan]{lab.platform.value}[/bright_cyan]")
            rprint(lab.setup_instructions)
        else:
            rprint(f"[bright_cyan]{lab.platform.value}[/bright_cyan]: {lab.name} -> {lab.url}")


@app.command()
def bugbounty(
    ctx: typer.Context,
    cve: Annotated[str, typer.Argument(help="CVE ID to search bug bounty reports for")],
    output_format: Annotated[
        OutputFormat | None,
        typer.Option("--format", "-f", help="Output format: table (default), json, csv, md"),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress decorative output"),
    ] = False,
) -> None:
    """Search for bug bounty reports related to a CVE."""
    fmt, is_quiet = _resolve_output(ctx, output_format, quiet)
    _reject_sarif(fmt)

    with BugBountyService() as service:
        try:
            CVEService.validate_cve_id(cve)
        except ValidationError as exc:
            _emit_cli_error(exc, fmt=fmt, category="invalid_input")
            raise typer.Exit(ExitCode.INVALID_INPUT) from exc

        try:
            results = service.find_reports(cve)
        except OfflineError as exc:
            raise _offline_exit(exc, fmt=fmt) from exc

    if not results:
        if fmt is OutputFormat.TABLE:
            rprint(f"[red3]No bug bounty reports found for {cve}[/red3]")
        else:
            render(
                {"cve": cve, "reports": []} if fmt is OutputFormat.JSON else [],
                fmt,
                console=console,
            )
        raise typer.Exit(ExitCode.NO_RESULTS)

    if fmt is not OutputFormat.TABLE:
        rows = [r.model_dump(mode="json") for r in results]
        view = {"cve": cve, "reports": rows} if fmt is OutputFormat.JSON else rows
        render(view, fmt, console=console, title=f"Bug Bounty Reports for {cve}")
        return

    if not is_quiet:
        rprint(f"\n[bold]Bug Bounty Reports for {cve}[/bold]")
    rprint(format_bb_table(results))


@app.command()
def cpes(
    ctx: typer.Context,
    cve: Annotated[str, typer.Argument(help="CVE ID to retrieve CPEs for")],
    output_format: Annotated[
        OutputFormat | None,
        typer.Option("--format", "-f", help="Output format: table (default), json, csv, md"),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress decorative output"),
    ] = False,
) -> None:
    """Retrieve CPE identifiers related to a CVE."""
    fmt, is_quiet = _resolve_output(ctx, output_format, quiet)
    _reject_sarif(fmt)

    with CVEService() as service:
        try:
            CVEService.validate_cve_id(cve)
        except ValidationError as exc:
            _emit_cli_error(exc, fmt=fmt, category="invalid_input")
            raise typer.Exit(ExitCode.INVALID_INPUT) from exc

        try:
            cpe_list = service.get_cpes(cve)
        except OfflineError as exc:
            raise _offline_exit(exc, fmt=fmt) from exc

    if not cpe_list:
        if fmt is OutputFormat.TABLE:
            rprint(f"[red3]No CPEs found for {cve}[/red3]")
        else:
            render(
                {"cve": cve, "cpes": []} if fmt is OutputFormat.JSON else [],
                fmt,
                console=console,
            )
        raise typer.Exit(ExitCode.NO_RESULTS)

    if fmt is not OutputFormat.TABLE:
        rows = [cpe.model_dump(mode="json") for cpe in cpe_list]
        view = {"cve": cve, "cpes": rows} if fmt is OutputFormat.JSON else rows
        render(view, fmt, console=console, title=f"Affected CPEs for {cve}")
        return

    if not is_quiet:
        rprint("\n[bold]Known Affected Software Configurations (CPE 2.3)[/bold]")
    table = Table(show_lines=True, header_style="bold")
    table.add_column("Namespace")
    table.add_column("Version")
    table.add_column("Type")
    table.add_column("Vendor")
    table.add_column("Product")
    table.add_column("Version")

    for cpe in cpe_list:
        parts = cpe.cpe_string.split(":")
        if len(parts) >= 6:
            table.add_row(
                f"[bright_blue]{parts[0]}[/bright_blue]",
                f"[bright_cyan]{parts[1]}[/bright_cyan]",
                f"[dark_orange]{parts[2]}[/dark_orange]",
                f"[spring_green2]{parts[3]}[/spring_green2]",
                f"[bright_yellow]{parts[4]}[/bright_yellow]",
                f"[bright_red]{parts[5]}[/bright_red]",
            )
        else:
            table.add_row(cpe.cpe_string, "", "", "", "", "")

    rprint(table)


@app.command()
def cpe2cve(
    ctx: typer.Context,
    cpe: Annotated[str, typer.Argument(help="CPE 2.3 string (e.g., cpe:2.3:o:microsoft:windows_10:1607)")],
    save: Annotated[Path | None, typer.Option("--save", "-s", help="Save results to file")] = None,
    output_format: Annotated[
        OutputFormat | None,
        typer.Option("--format", "-f", help="Output format: table (default), json, csv, md"),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress decorative output"),
    ] = False,
) -> None:
    """Retrieve CVE IDs related to a CPE identifier."""
    fmt, is_quiet = _resolve_output(ctx, output_format, quiet)
    # SARIF needs full CVE records; cpe2cve only yields bare CVE ids.
    _reject_sarif(fmt)

    with CVEService() as service:
        try:
            cve_ids = service.cpe_to_cves(cpe)
        except ValidationError as exc:
            _emit_cli_error(exc, fmt=fmt, category="invalid_input")
            raise typer.Exit(ExitCode.INVALID_INPUT) from exc
        except OfflineError as exc:
            raise _offline_exit(exc, fmt=fmt) from exc

    if not cve_ids:
        if fmt is OutputFormat.TABLE:
            rprint(f"[red3]No CVE IDs found for CPE: {cpe}[/red3]")
        else:
            render(
                {"cpe": cpe, "cve_ids": []} if fmt is OutputFormat.JSON else [],
                fmt,
                console=console,
            )
        raise typer.Exit(ExitCode.NO_RESULTS)

    result = "\n".join(cve_ids)

    # --save always writes the raw newline-joined id list (unchanged contract);
    # --format governs only what is rendered to stdout.
    if save:
        save.write_text(result, encoding="utf-8")

    if fmt is not OutputFormat.TABLE:
        rows = [{"cve_id": cid} for cid in cve_ids]
        view = {"cpe": cpe, "cve_ids": cve_ids} if fmt is OutputFormat.JSON else rows
        render(view, fmt, console=console, title=f"Affected CVE IDs for {cpe}")
        return

    if save:
        rprint(f"[green1]Results saved to {save}[/green1]")
    else:
        rprint("\n[bold]List of Affected CVE IDs[/bold]")
        rprint(result)


@app.command()
def readme(
    ctx: typer.Context,
    repo: Annotated[str, typer.Argument(help="GitHub repository URL")],
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Print the README directly, without paging"),
    ] = False,
) -> None:
    """Display a GitHub repository's README file."""
    if not repo.startswith("https://github.com/"):
        rprint("[red3]Please provide a valid GitHub repository URL[/red3]")
        raise typer.Exit(1)

    is_quiet = quiet or _state(ctx).quiet

    with ExploitService() as exploit_svc:
        content = exploit_svc.get_readme(repo)

    if not content:
        rprint("[red3]README.md not found[/red3]")
        return

    # Portable paging: click.echo_via_pager (Typer bundles click) works on every
    # platform, Windows included, and degrades gracefully — when stdout is not a
    # TTY (pipes, CI, tests) it falls back to a plain write instead of spawning a
    # pager. --quiet takes that plain path directly so scripted output stays clean.
    if is_quiet:
        click.echo(content)
    else:
        click.echo_via_pager(content)


@app.command()
def schemas(
    output: Annotated[Path, typer.Option("--output", "-o", help="Output directory for schemas")] = Path("./schemas"),
) -> None:
    """Export JSON schemas for all data models (useful for AI agent integration)."""
    paths = export_schemas(output)
    rprint(f"[green1]Exported {len(paths)} schemas to {output}:[/green1]")
    for p in paths:
        rprint(f"  - {p.name}")


@app.command()
def latest(
    ctx: typer.Context,
    since: Annotated[str | None, typer.Option("--since", help="Relative time: 1h, 24h, 7d, 30d")] = None,
    from_date: Annotated[str | None, typer.Option("--from", help="Start date YYYY-MM-DD")] = None,
    to_date: Annotated[str | None, typer.Option("--to", help="End date YYYY-MM-DD")] = None,
    only_with_poc: Annotated[bool, typer.Option("--only-with-poc", help="Only CVEs with known PoCs")] = False,
    kev_only: Annotated[bool, typer.Option("--kev-only", help="Only CISA KEV entries")] = False,
    min_epss: Annotated[float | None, typer.Option("--min-epss", help="Minimum EPSS score (0-100)", min=0.0, max=100.0)] = None,
    severity: Annotated[str | None, typer.Option("--severity", help="Comma-separated severities: critical,high,medium,low")] = None,
    sort: Annotated[str, typer.Option("--sort", help="Sort by: cve_date, severity, epss")] = "cve_date",
    limit: Annotated[int, typer.Option("--limit", help="Max results", min=1, max=100)] = 50,
    output: Annotated[str | None, typer.Option("--output", "-o", help="Save JSON report to file")] = None,
    diff: Annotated[
        bool,
        typer.Option(
            "--diff",
            "--since-last",
            help="Show only what changed since the last identical run (added/removed/changed)",
        ),
    ] = False,
    notify: Annotated[
        str | None,
        typer.Option(
            "--notify",
            help="POST a summary of notable CVEs to a webhook URL (Slack/Discord/generic); "
            "with --diff, only the delta is sent",
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat | None,
        typer.Option("--format", "-f", help="Output format: table (default), json, csv, md, sarif"),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress decorative output"),
    ] = False,
) -> None:
    """Find recently published CVEs with exploit intelligence."""
    fmt, is_quiet = _resolve_output(ctx, output_format, quiet)

    # Parse date arguments
    parsed_from: date | None = None
    parsed_to: date | None = None

    if from_date:
        try:
            parsed_from = date.fromisoformat(from_date)
        except ValueError as exc:
            rprint(f"[red3]Invalid --from date: {from_date}. Use YYYY-MM-DD format.[/red3]")
            raise typer.Exit(ExitCode.INVALID_INPUT) from exc

    if to_date:
        try:
            parsed_to = date.fromisoformat(to_date)
        except ValueError as exc:
            rprint(f"[red3]Invalid --to date: {to_date}. Use YYYY-MM-DD format.[/red3]")
            raise typer.Exit(ExitCode.INVALID_INPUT) from exc

    # Parse severity
    severity_list: list[str] | None = None
    if severity:
        severity_list = [s.strip() for s in severity.split(",") if s.strip()]

    # Validate sort
    if sort not in ("cve_date", "severity", "epss"):
        rprint(f"[red3]Invalid --sort: {sort}. Use: cve_date, severity, or epss[/red3]")
        raise typer.Exit(ExitCode.INVALID_INPUT)

    # The transient spinner writes to stdout, so suppress it in machine-readable
    # / quiet modes to keep those streams clean (JSON/CSV/SARIF stay parseable).
    show_progress = fmt is OutputFormat.TABLE and not is_quiet
    progress_cm: Progress | nullcontext[None] = (
        Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        )
        if show_progress
        else nullcontext()
    )
    with RecentService() as service:
        try:
            with progress_cm as progress:
                if progress is not None:
                    progress.add_task("[bright_blue]Fetching recent CVEs from NVD...[/bright_blue]", total=None)
                results = service.find_recent_cves(
                    since=since,
                    from_date=parsed_from,
                    to_date=parsed_to,
                    severity=severity_list,
                    kev_only=kev_only,
                    min_epss=min_epss,
                    only_with_poc=only_with_poc,
                    sort=sort,
                    limit=limit,
                )
        except ValueError as exc:
            rprint(f"[red3]Error: {exc}[/red3]")
            raise typer.Exit(ExitCode.INVALID_INPUT) from exc
        except OfflineError as exc:
            raise _offline_exit(exc, fmt=fmt) from exc
        except Exception as exc:
            rprint(f"[red3]Error fetching recent CVEs: {exc}[/red3]")
            raise typer.Exit(ExitCode.UPSTREAM_ERROR) from exc

    # An empty result set is only a dead end for a normal run. Under ``--diff`` an
    # empty *current* against a non-empty baseline is a real delta (everything was
    # removed), so fall through and let the diff engine report it.
    if not results and not diff:
        if fmt is OutputFormat.TABLE:
            rprint("[yellow]No CVEs found matching the specified criteria.[/yellow]")
        elif fmt is OutputFormat.JSON:
            render({"total": 0, "cves": []}, fmt, console=console)
        else:  # csv / md / sarif -> a well-formed empty document
            render([], fmt, console=console)
        # Zero results is zero notable CVEs: --notify is a documented skip (a
        # short stderr note when not quiet), never an empty webhook ping.
        _run_notify(
            notify, source="latest", label="Recent CVEs", query={}, items=[], is_quiet=is_quiet
        )
        raise typer.Exit(ExitCode.NO_RESULTS)

    # Build the structured view model once (shared by JSON stdout + --output file).
    cve_rows: list[dict[str, object]] = [
        {
            "cve_id": r.cve_info.id,
            "description": r.cve_info.description,
            "severity": r.cve_info.cvss.severity.value if r.cve_info.cvss else "UNKNOWN",
            "base_score": r.cve_info.cvss.base_score if r.cve_info.cvss else None,
            "epss": r.cve_info.epss,
            "kev_status": r.cve_info.kev_status,
            "vendor": r.cve_info.vendor,
            "product": r.cve_info.product,
            "publication_date": r.cve_info.publication_date,
            "has_poc": r.has_poc,
            "poc_sources": [s.value for s in r.poc_sources],
        }
        for r in results
    ]
    query_meta: dict[str, object] = {
        "since": since,
        "from_date": str(parsed_from) if parsed_from else None,
        "to_date": str(parsed_to) if parsed_to else None,
        "severity": severity_list,
        "kev_only": kev_only,
        "min_epss": min_epss,
        "only_with_poc": only_with_poc,
        "sort": sort,
        "limit": limit,
    }
    report_data: dict[str, object] = {
        "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "query": query_meta,
        "total": len(results),
        "cves": cve_rows,
    }

    def _write_report_file() -> None:
        """Persist ``report_data`` to ``--output`` (unchanged JSON contract)."""
        if not output:
            return
        import json as _json
        try:
            _safe_path(output)
        except ValueError as exc:
            rprint(f"[red3]Unsafe output path: {exc}[/red3]")
            raise typer.Exit(ExitCode.INVALID_INPUT) from exc
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(_json.dumps(report_data, indent=2, default=str), encoding="utf-8")
        # Keep the confirmation out of machine-readable streams.
        if fmt is OutputFormat.TABLE and not is_quiet:
            rprint(f"\n[green1]Report saved to {out_path}[/green1]")

    # --diff: render only the delta vs. the previous identical run, then persist
    # the current result set as the new baseline. Respects --format.
    if diff:
        delta = _compute_diff("latest", query_meta, results)
        _render_diff(delta, fmt, label="Recent CVEs")
        _write_report_file()
        # Notify on the delta only: added + KEV-gained/severity-escalated.
        _run_notify(
            notify,
            source="latest",
            label="Recent CVEs",
            query=query_meta,
            items=_notable_diff_items(delta),
            is_quiet=is_quiet,
        )
        raise typer.Exit(ExitCode.OK)

    # STDOUT rendering by format (the default table path is byte-for-byte as before).
    if fmt is OutputFormat.TABLE:
        rprint(f"\n[bold]Found {len(results)} recent CVE(s)[/bold]")
        rprint(format_recent_cves_table(results))

        # Summary
        poc_count = sum(1 for r in results if r.has_poc)
        kev_count = sum(1 for r in results if r.cve_info.kev_status)
        critical_high = sum(
            1 for r in results
            if r.cve_info.cvss and r.cve_info.cvss.severity.value in ("CRITICAL", "HIGH")
        )
        rprint(
            f"\n[dim]Summary: {poc_count} with PoC | {kev_count} in KEV | "
            f"{critical_high} Critical/High[/dim]"
        )
    elif fmt is OutputFormat.SARIF:
        sarif_cves = [
            _cve_sarif_dict(r.cve_info, exploit_count=len(r.poc_sources)) for r in results
        ]
        render(sarif_cves, fmt, console=console)
    elif fmt is OutputFormat.JSON:
        render(report_data, fmt, console=console)
    else:  # csv / md
        render(cve_rows, fmt, console=console, title="Recent CVEs")

    # Save to file if requested (unchanged JSON content; --format governs stdout).
    _write_report_file()

    # Notify (side effect; stdout above is untouched): critical/high + KEV CVEs.
    _run_notify(
        notify,
        source="latest",
        label="Recent CVEs",
        query=query_meta,
        items=_notable_cve_items(r.cve_info for r in results),
        is_quiet=is_quiet,
    )


@app.command()
def discover(
    ctx: typer.Context,
    product: Annotated[str, typer.Argument(help="Product name (e.g., 'Apache Struts', 'Log4j')")],
    version: Annotated[str | None, typer.Option("--version", "-v", help="Version: 2.x, 2.14.1, etc.")] = None,
    vendor: Annotated[str | None, typer.Option("--vendor", help="Vendor name (e.g., 'Apache')")] = None,
    limit: Annotated[int, typer.Option("--limit", help="Max CVEs to analyze", min=1, max=100)] = 50,
    output: Annotated[str | None, typer.Option("--output", "-o", help="Save JSON report to file")] = None,
    diff: Annotated[
        bool,
        typer.Option(
            "--diff",
            "--since-last",
            help="Show only what changed since the last identical run (added/removed/changed)",
        ),
    ] = False,
    notify: Annotated[
        str | None,
        typer.Option(
            "--notify",
            help="POST a summary of notable CVEs to a webhook URL (Slack/Discord/generic); "
            "with --diff, only the delta is sent",
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat | None,
        typer.Option("--format", "-f", help="Output format: table (default), json, csv, md, sarif"),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress decorative output"),
    ] = False,
) -> None:
    """Discover CVEs affecting a product by name and version.

    Supports product aliases (e.g., 'struts' -> 'Apache Struts'),
    version wildcards (e.g., '2.x'), and fuzzy matching.

    Results are grouped into three confidence tiers:
    - Confirmed: vendor AND product match AND version constraint is met
    - Possibly: vendor OR product matches but version info is unclear
    - Not enough data: CVE has insufficient product/version information
    """
    fmt, is_quiet = _resolve_output(ctx, output_format, quiet)

    # Suppress the stdout spinner in machine-readable / quiet modes.
    show_progress = fmt is OutputFormat.TABLE and not is_quiet
    progress_cm: Progress | nullcontext[None] = (
        Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        )
        if show_progress
        else nullcontext()
    )
    with ProductDiscoveryService() as service, progress_cm as progress:
        if progress is not None:
            progress.add_task(
                f"[bright_blue]Discovering CVEs for {product}...[/bright_blue]", total=None
            )
        try:
            result = service.discover_by_product(
                product=product,
                version=version,
                vendor=vendor,
                limit=limit,
            )
        except OfflineError as exc:
            raise _offline_exit(exc, fmt=fmt) from exc
        except Exception as exc:
            rprint(f"[red3]Error: {exc}[/red3]")
            raise typer.Exit(1) from exc

    tiers = (
        ("confirmed", result.confirmed_affected),
        ("possibly", result.possibly_affected),
        ("not_enough_data", result.not_enough_data),
    )
    is_empty = not (
        result.confirmed_affected or result.possibly_affected or result.not_enough_data
    )

    # Shared across every terminal path: the flat CVE list and the query dict
    # that identify this run (also the snapshot key for --diff and --notify).
    disc_all_cves = [cve for _tier, cves in tiers for cve in cves]
    disc_query: dict[str, object] = {
        "product": product,
        "version": version,
        "vendor": vendor,
        "limit": limit,
    }

    # Structured report (shared by JSON stdout + --output file; content unchanged).
    report_data: dict[str, object] = {
        "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "query": result.query,
        "normalized_vendor": result.normalized_vendor,
        "normalized_product": result.normalized_product,
        "version_constraint": result.version_constraint.model_dump(mode="json") if result.version_constraint else None,
        "total_found": result.total_found,
        "confirmed_affected": [cve.model_dump(mode="json") for cve in result.confirmed_affected],
        "possibly_affected": [cve.model_dump(mode="json") for cve in result.possibly_affected],
        "not_enough_data": [cve.model_dump(mode="json") for cve in result.not_enough_data],
    }

    def _write_output_file() -> None:
        """Persist ``report_data`` to ``--output`` (unchanged JSON contract)."""
        if not output:
            return
        import json as _json
        try:
            _safe_path(output)
        except ValueError as exc:
            rprint(f"[red3]Unsafe output path: {exc}[/red3]")
            raise typer.Exit(ExitCode.INVALID_INPUT) from exc
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(_json.dumps(report_data, indent=2, default=str), encoding="utf-8")
        if fmt is OutputFormat.TABLE and not is_quiet:
            rprint(f"\n[green1]Report saved to {output_path}[/green1]")

    # --diff: render only the delta vs. the previous identical run, then persist
    # the current result set (all tiers) as the new baseline. Respects --format.
    if diff:
        delta = _compute_diff("discover", disc_query, disc_all_cves)
        _render_diff(delta, fmt, label=f"Product Discovery: {result.query}")
        _write_output_file()
        _run_notify(
            notify,
            source="discover",
            label=f"Product Discovery: {result.query}",
            query=disc_query,
            items=_notable_diff_items(delta),
            is_quiet=is_quiet,
        )
        raise typer.Exit(ExitCode.OK)

    # Machine-readable formats: emit the view model, save the file, set exit code.
    if fmt is not OutputFormat.TABLE:
        if fmt is OutputFormat.SARIF:
            sarif_cves = [
                _cve_sarif_dict(cve, exploit_count=None)
                for _tier, cves in tiers
                for cve in cves
            ]
            render(sarif_cves, fmt, console=console)
        elif fmt is OutputFormat.JSON:
            render(report_data, fmt, console=console)
        else:  # csv / md
            rows = [
                _discover_cve_row(cve, tier=tier) for tier, cves in tiers for cve in cves
            ]
            render(rows, fmt, console=console, title=f"Product Discovery: {result.query}")
        _write_output_file()
        _run_notify(
            notify,
            source="discover",
            label=f"Product Discovery: {result.query}",
            query=disc_query,
            items=_notable_cve_items(disc_all_cves),
            is_quiet=is_quiet,
        )
        raise typer.Exit(ExitCode.NO_RESULTS if is_empty else ExitCode.OK)

    # Default table rendering (byte-for-byte as before).
    rprint("\n[bold]Product Discovery Results[/bold]")
    rprint(f"[dim]Query: {result.query}[/dim]")
    if result.normalized_vendor or result.normalized_product:
        norm_parts = []
        if result.normalized_vendor:
            norm_parts.append(f"vendor=[bright_cyan]{result.normalized_vendor}[/bright_cyan]")
        if result.normalized_product:
            norm_parts.append(f"product=[bright_yellow]{result.normalized_product}[/bright_yellow]")
        rprint(f"[dim]Normalized: {' | '.join(norm_parts)}[/dim]")
    if result.version_constraint and result.version_constraint.raw:
        rprint(f"[dim]Version: [bright_green]{result.version_constraint.raw}[/bright_green][/dim]")
    rprint(f"[dim]Total analyzed: {result.total_found}[/dim]")

    # Confirmed affected
    if result.confirmed_affected:
        rprint(f"\n[bold green1]Confirmed Affected ({len(result.confirmed_affected)})[/bold green1]")
        for cve in result.confirmed_affected[:limit]:
            rprint(format_cve_table(cve))
    else:
        rprint("\n[yellow]No confirmed matches found[/yellow]")

    # Possibly affected
    if result.possibly_affected:
        remaining = limit - len(result.confirmed_affected)
        if remaining > 0:
            rprint(f"\n[bold gold1]Possibly Affected ({len(result.possibly_affected)})[/bold gold1]")
            for cve in result.possibly_affected[:remaining]:
                rprint(format_cve_table(cve))

    # Not enough data
    if result.not_enough_data:
        rprint(f"\n[dim]Not Enough Data ({len(result.not_enough_data)})[/dim]")

    _write_output_file()
    # Notify (side effect; stdout above is untouched): critical/high + KEV CVEs.
    _run_notify(
        notify,
        source="discover",
        label=f"Product Discovery: {result.query}",
        query=disc_query,
        items=_notable_cve_items(disc_all_cves),
        is_quiet=is_quiet,
    )
    if is_empty:
        raise typer.Exit(ExitCode.NO_RESULTS)


# ---------------------------------------------------------------------------
# doctor / cache — self-diagnostics and cache management
# ---------------------------------------------------------------------------

# Rich colour per check status.
_STATUS_STYLE = {
    "PASS": "green1",
    "WARN": "yellow",
    "FAIL": "red3",
    "SKIPPED": "dim",
}


@dataclass
class CheckResult:
    """A single ``pocmap doctor`` result row.

    Attributes:
        name: Human-readable name of the check.
        status: One of ``PASS`` / ``WARN`` / ``FAIL`` / ``SKIPPED``.
        detail: A short, secret-free explanation. Never contains a token value.
        category: Coarse bucket used to pick the process exit code
            (e.g. ``connectivity`` failures map to ``UPSTREAM_ERROR``).
    """

    name: str
    status: str
    detail: str
    category: str = "general"


# A prober returns ``(endpoint-name, reachable?, short-detail)`` per upstream.
UpstreamProber = Callable[[], list[tuple[str, bool, str]]]

# Minimum supported interpreter (kept as data so the runtime check below is a
# genuine comparison rather than a statically-constant ``sys.version_info`` one).
_MIN_PYTHON = (3, 10)


def _human_size(num_bytes: int) -> str:
    """Return *num_bytes* as a compact human-readable string (B/KB/MB/GB)."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB"):
        if size < 1024.0:
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} GB"


def _probe_upstreams() -> list[tuple[str, bool, str]]:
    """Live connectivity probe of key upstreams — **[needs-user/network]**.

    Performs a real GET against a couple of upstream endpoints (NVD, GitHub)
    and reports whether each is reachable. This is the only network I/O in the
    ``doctor`` command; the offline test suite injects a fake prober in its
    place. Reachability means "a response came back" (any HTTP status), so a
    4xx still counts the host as up. Never raises.
    """
    targets = [("NVD", NVD_API_BASE), ("GitHub API", GITHUB_API_BASE)]
    results: list[tuple[str, bool, str]] = []
    with HTTPClient(timeout=10) as client:
        for name, url in targets:
            try:
                resp = client.get(url)
                results.append((name, True, f"HTTP {resp.status_code}"))
            except Exception as exc:
                results.append((name, False, type(exc).__name__))
    return results


def _check_python() -> CheckResult:
    """Check the running interpreter is Python 3.10+."""
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    current = (sys.version_info.major, sys.version_info.minor)
    if current >= _MIN_PYTHON:
        return CheckResult("Python version", "PASS", f"{version} (>= 3.10)", "python")
    return CheckResult("Python version", "FAIL", f"{version} (< 3.10 required)", "python")


def _check_mcp_extra() -> CheckResult:
    """Check the optional FastMCP SDK (the ``[server]`` extra) is importable."""
    if importlib.util.find_spec("mcp") is not None:
        return CheckResult("MCP server extra", "PASS", "FastMCP SDK importable", "extras")
    return CheckResult(
        "MCP server extra",
        "WARN",
        "MCP server needs pip install -e '.[server]'",
        "extras",
    )


def _check_github_token() -> CheckResult:
    """Check the GitHub token: absent -> WARN, present+malformed -> FAIL.

    The token value itself is never included in the result detail.
    """
    token = settings.github_api_token
    if not token:
        return CheckResult(
            "GitHub API token",
            "WARN",
            "not set (optional; raises GitHub rate limits)",
            "token",
        )
    if github_token_looks_valid(token):
        return CheckResult("GitHub API token", "PASS", "set and well-formed", "token")
    return CheckResult(
        "GitHub API token",
        "FAIL",
        "set but malformed (expected ghp_/github_pat_/... prefix)",
        "token",
    )


def _check_nvd_key() -> CheckResult:
    """Check the NVD API key: absent -> WARN, present+malformed -> FAIL."""
    key = settings.nvd_api_key
    if not key:
        return CheckResult(
            "NVD API key",
            "WARN",
            "not set (optional; raises NVD rate limits)",
            "token",
        )
    if nvd_api_key_looks_valid(key):
        return CheckResult("NVD API key", "PASS", "set and well-formed", "token")
    return CheckResult(
        "NVD API key",
        "FAIL",
        "set but malformed (expected UUID 8-4-4-4-12)",
        "token",
    )


def _dir_writable(path: Path) -> bool:
    """Return ``True`` if a probe file can be created and removed under *path*."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".pocmap-doctor-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def _check_cache() -> CheckResult:
    """Check the cache directory is writable and report its current size."""
    cache_dir = settings.cache_dir
    info = HTTPCache.from_settings().info()
    size = _human_size(info["bytes"])
    if _dir_writable(cache_dir):
        return CheckResult(
            "Cache directory",
            "PASS",
            f"{cache_dir} writable ({info['entries']} entries, {size})",
            "cache",
        )
    return CheckResult(
        "Cache directory",
        "WARN",
        f"{cache_dir} not writable ({info['entries']} entries, {size})",
        "cache",
    )


def _check_connectivity(offline: bool, prober: UpstreamProber) -> list[CheckResult]:
    """Run (or skip) the injected upstream connectivity probe."""
    if offline:
        return [
            CheckResult(
                "Upstream connectivity",
                "SKIPPED",
                "offline mode - live probe skipped",
                "connectivity",
            )
        ]
    return [
        CheckResult(
            f"Connectivity: {name}",
            "PASS" if ok else "FAIL",
            detail if ok else f"unreachable ({detail})",
            "connectivity",
        )
        for name, ok, detail in prober()
    ]


def _gather_doctor_checks(*, offline: bool, prober: UpstreamProber) -> list[CheckResult]:
    """Run every diagnostic and return the ordered result list.

    Everything except the injected *prober* is fully offline; the prober is the
    only component that performs network I/O (and is skipped when *offline*).
    """
    checks = [
        _check_python(),
        _check_mcp_extra(),
        _check_github_token(),
        _check_nvd_key(),
        _check_cache(),
    ]
    checks.extend(_check_connectivity(offline, prober))
    return checks


def _doctor_exit_code(checks: list[CheckResult]) -> ExitCode:
    """Pick the exit code: OK if no FAIL, else UPSTREAM_ERROR / ERROR."""
    fails = [c for c in checks if c.status == "FAIL"]
    if not fails:
        return ExitCode.OK
    if all(c.category == "connectivity" for c in fails):
        return ExitCode.UPSTREAM_ERROR
    return ExitCode.ERROR


@app.command()
def doctor(
    ctx: typer.Context,
    offline: Annotated[
        bool,
        typer.Option("--offline", help="Skip the live upstream connectivity probe"),
    ] = False,
    output_format: Annotated[
        OutputFormat | None,
        typer.Option("--format", "-f", help="Output format: table (default) or json"),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress banner and decorative output"),
    ] = False,
) -> None:
    """Run self-diagnostics: Python, extras, tokens, cache, and connectivity.

    Emits a PASS/WARN/FAIL table (or JSON with ``--format json``) and exits
    nonzero if any check FAILs. The live connectivity probe is skipped under
    ``--offline`` and labelled SKIPPED.
    """
    state = _state(ctx)
    fmt = output_format if output_format is not None else state.output_format
    is_quiet = quiet or state.quiet

    checks = _gather_doctor_checks(offline=offline, prober=_probe_upstreams)
    exit_code = _doctor_exit_code(checks)
    summary = {
        "pass": sum(1 for c in checks if c.status == "PASS"),
        "warn": sum(1 for c in checks if c.status == "WARN"),
        "fail": sum(1 for c in checks if c.status == "FAIL"),
        "skipped": sum(1 for c in checks if c.status == "SKIPPED"),
    }

    if fmt is OutputFormat.JSON:
        render(
            {
                "ok": exit_code == ExitCode.OK,
                "summary": summary,
                "checks": [
                    {
                        "name": c.name,
                        "status": c.status,
                        "detail": c.detail,
                        "category": c.category,
                    }
                    for c in checks
                ],
            },
            OutputFormat.JSON,
            console=console,
        )
        raise typer.Exit(exit_code)

    if not is_quiet:
        _banner()

    table = Table(show_lines=False, header_style="bold", title="PocMap Doctor")
    table.add_column("Check")
    table.add_column("Status", justify="center")
    table.add_column("Detail", overflow="fold")
    for c in checks:
        style = _STATUS_STYLE.get(c.status, "white")
        table.add_row(c.name, f"[{style}]{c.status}[/{style}]", c.detail)
    console.print(table)

    if not is_quiet:
        rprint(
            f"\n[dim]Summary: {summary['pass']} PASS | {summary['warn']} WARN | "
            f"{summary['fail']} FAIL | {summary['skipped']} SKIPPED[/dim]"
        )
    raise typer.Exit(exit_code)


cache_app = typer.Typer(
    name="cache",
    help="Inspect and manage the persistent HTTP response cache.",
    no_args_is_help=True,
)
app.add_typer(cache_app, name="cache")


@cache_app.command("info")
def cache_info(
    ctx: typer.Context,
    output_format: Annotated[
        OutputFormat | None,
        typer.Option("--format", "-f", help="Output format: table (default) or json"),
    ] = None,
) -> None:
    """Show the cache location, entry count, and on-disk size."""
    state = _state(ctx)
    fmt = output_format if output_format is not None else state.output_format
    cache = HTTPCache.from_settings()
    info = cache.info()

    if fmt is OutputFormat.JSON:
        render(
            {
                "cache_dir": str(settings.cache_dir),
                "enabled": settings.cache_enabled,
                "entries": info["entries"],
                "bytes": info["bytes"],
                "human_size": _human_size(info["bytes"]),
            },
            OutputFormat.JSON,
            console=console,
        )
        return

    table = Table(show_lines=False, header_style="bold", title="HTTP Response Cache")
    table.add_column("Field")
    table.add_column("Value", overflow="fold")
    table.add_row("Location", str(settings.cache_dir))
    table.add_row("Enabled", str(settings.cache_enabled))
    table.add_row("Entries", str(info["entries"]))
    table.add_row("Size", _human_size(info["bytes"]))
    console.print(table)


@cache_app.command("clear")
def cache_clear(
    ctx: typer.Context,
    output_format: Annotated[
        OutputFormat | None,
        typer.Option("--format", "-f", help="Output format: table (default) or json"),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress decorative output"),
    ] = False,
) -> None:
    """Delete every entry from the persistent HTTP response cache."""
    state = _state(ctx)
    fmt = output_format if output_format is not None else state.output_format
    is_quiet = quiet or state.quiet
    cache = HTTPCache.from_settings()
    before = cache.info()
    cache.clear()
    after = cache.info()
    removed = before["entries"] - after["entries"]
    freed = before["bytes"] - after["bytes"]

    if fmt is OutputFormat.JSON:
        render(
            {
                "cleared_entries": removed,
                "remaining_entries": after["entries"],
                "freed_bytes": freed,
            },
            OutputFormat.JSON,
            console=console,
        )
        return

    if not is_quiet:
        plural = "y" if removed == 1 else "ies"
        rprint(
            f"[green1]Cleared {removed} cache entr{plural} "
            f"({_human_size(freed)} freed)[/green1]"
        )


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version", "-v", help="Show version")] = False,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format for supported commands (table, json)"),
    ] = OutputFormat.TABLE,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Serve HTTP only from the cache; a cache miss errors instead of hitting the network",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress banner and decorative output"),
    ] = False,
) -> None:
    """PocMap: AI-friendly CVE PoC discovery tool."""
    # ``--offline`` must take effect process-wide *before* any subcommand runs,
    # so flip the settings singleton now (see config.enable_offline). Only ever
    # turn it on here — the env var POCMAP_OFFLINE may already have enabled it.
    if offline:
        enable_offline()
    ctx.obj = CLIState(output_format=output_format, quiet=quiet, offline=offline or settings.offline)
    if version:
        rprint(f"pocmap v{__version__}")
        raise typer.Exit(0)
    if ctx.invoked_subcommand is None and not quiet:
        _banner()
        rprint("\n[bold]Usage:[/bold] pocmap [COMMAND] [ARGS]")
        rprint("Run [bold]pocmap --help[/bold] for available commands.")
