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
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Annotated

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
from pocmap.config import (
    GITHUB_API_BASE,
    NVD_API_BASE,
    github_token_looks_valid,
    nvd_api_key_looks_valid,
    settings,
)
from pocmap.models import export_schemas
from pocmap.services.bb_service import BugBountyService
from pocmap.services.cve_service import CVEService
from pocmap.services.exploit_service import ExploitService
from pocmap.services.lab_service import LabService
from pocmap.services.product_service import ProductDiscoveryService
from pocmap.services.recent_service import RecentService
from pocmap.services.report_service import ReportService
from pocmap.utils.cache import HTTPCache
from pocmap.utils.exit_codes import ExitCode
from pocmap.utils.formatters import (
    format_bb_table,
    format_cve_table,
    format_exploit_table,
    format_recent_cves_table,
)
from pocmap.utils.http import HTTPClient, NotFoundError, ValidationError
from pocmap.utils.output import OutputFormat, render
from pocmap.utils.paths import safe_path as _safe_path

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

console = Console()
app = typer.Typer(
    name="pocmap",
    help="A modern, AI-friendly tool to find PoCs related to CVE IDs",
    no_args_is_help=True,
    add_completion=False,
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
    """

    output_format: OutputFormat = OutputFormat.TABLE
    quiet: bool = False


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
    file: Annotated[Path, typer.Argument(help="File containing CVE IDs (one per line)")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Output directory for reports")] = Path("."),
    threads: Annotated[int, typer.Option("--threads", "-t", help="Number of concurrent workers", min=1)] = 10,
) -> None:
    """Process multiple CVEs from a file and generate JSON and HTML reports."""
    if not file.exists():
        rprint(f"[red3]File not found: {file}[/red3]")
        raise typer.Exit(1)

    try:
        _safe_path(str(output))
    except ValueError as exc:
        rprint(f"[red3]Unsafe output path: {exc}[/red3]")
        raise typer.Exit(1) from exc

    output.mkdir(parents=True, exist_ok=True)

    with ReportService() as report_svc:
        try:
            report = report_svc.generate_bulk_report_from_file(file)
        except Exception as exc:
            rprint(f"[red3]Error generating report: {exc}[/red3]")
            raise typer.Exit(1) from exc

        if not report.entries:
            rprint("[red3]No valid CVE entries found in the report[/red3]")
            raise typer.Exit(1)

        # Save JSON
        json_path = report_svc.save_json_report(report, output)
        rprint(f"[green1]JSON report saved: {json_path}[/green1]")

        # Save HTML
        html_path = report_svc.save_html_report(report, output)
        rprint(f"[green1]HTML report saved: {html_path}[/green1]")

        rprint(f"\n[bold]Processed {len(report.entries)} CVE(s)[/bold]")


@app.command()
def labs(
    cve: Annotated[str, typer.Argument(help="CVE ID to search labs for")],
) -> None:
    """Search for CTF labs and vulnerable environments related to a CVE."""
    with LabService() as service:
        try:
            CVEService.validate_cve_id(cve)
        except ValidationError as exc:
            rprint(f"[red3]Error: {exc}[/red3]")
            raise typer.Exit(1) from exc

        results = service.find_labs(cve)

        if not results:
            rprint(f"[red3]No labs found for {cve}[/red3]")
            raise typer.Exit(0)

        rprint(f"\n[bold]Lab Environments for {cve}[/bold]")
        for lab in results:
            if lab.platform.value == "vulhub" and lab.setup_instructions:
                rprint(f"\n[bright_cyan]{lab.platform.value}[/bright_cyan]")
                rprint(lab.setup_instructions)
            else:
                rprint(f"[bright_cyan]{lab.platform.value}[/bright_cyan]: {lab.name} -> {lab.url}")


@app.command()
def bugbounty(
    cve: Annotated[str, typer.Argument(help="CVE ID to search bug bounty reports for")],
) -> None:
    """Search for bug bounty reports related to a CVE."""
    with BugBountyService() as service:
        try:
            CVEService.validate_cve_id(cve)
        except ValidationError as exc:
            rprint(f"[red3]Error: {exc}[/red3]")
            raise typer.Exit(1) from exc

        results = service.find_reports(cve)

        if not results:
            rprint(f"[red3]No bug bounty reports found for {cve}[/red3]")
            raise typer.Exit(0)

        rprint(f"\n[bold]Bug Bounty Reports for {cve}[/bold]")
        rprint(format_bb_table(results))


@app.command()
def cpes(
    cve: Annotated[str, typer.Argument(help="CVE ID to retrieve CPEs for")],
) -> None:
    """Retrieve CPE identifiers related to a CVE."""
    with CVEService() as service:
        try:
            CVEService.validate_cve_id(cve)
        except ValidationError as exc:
            rprint(f"[red3]Error: {exc}[/red3]")
            raise typer.Exit(1) from exc

        cpe_list = service.get_cpes(cve)

        if not cpe_list:
            rprint(f"[red3]No CPEs found for {cve}[/red3]")
            raise typer.Exit(0)

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
    cpe: Annotated[str, typer.Argument(help="CPE 2.3 string (e.g., cpe:2.3:o:microsoft:windows_10:1607)")],
    save: Annotated[Path | None, typer.Option("--save", "-s", help="Save results to file")] = None,
) -> None:
    """Retrieve CVE IDs related to a CPE identifier."""
    with CVEService() as service:
        try:
            cve_ids = service.cpe_to_cves(cpe)
        except ValidationError as exc:
            rprint(f"[red3]Error: {exc}[/red3]")
            raise typer.Exit(1) from exc

        if not cve_ids:
            rprint(f"[red3]No CVE IDs found for CPE: {cpe}[/red3]")
            raise typer.Exit(0)

        result = "\n".join(cve_ids)

        if save:
            save.write_text(result, encoding="utf-8")
            rprint(f"[green1]Results saved to {save}[/green1]")
        else:
            rprint("\n[bold]List of Affected CVE IDs[/bold]")
            rprint(result)


@app.command()
def readme(
    repo: Annotated[str, typer.Argument(help="GitHub repository URL")],
) -> None:
    """Display a GitHub repository's README file."""
    if not repo.startswith("https://github.com/"):
        rprint("[red3]Please provide a valid GitHub repository URL[/red3]")
        raise typer.Exit(1)

    with ExploitService() as exploit_svc:
        content = exploit_svc.get_readme(repo)

        if content:
            import platform
            import subprocess

            if platform.system() in ("Linux", "Darwin"):
                subprocess.run(["less"], input=content, text=True)
            else:
                console.print(content)
        else:
            rprint("[red3]README.md not found[/red3]")


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
) -> None:
    """Find recently published CVEs with exploit intelligence."""
    # Parse date arguments
    parsed_from: date | None = None
    parsed_to: date | None = None

    if from_date:
        try:
            parsed_from = date.fromisoformat(from_date)
        except ValueError as exc:
            rprint(f"[red3]Invalid --from date: {from_date}. Use YYYY-MM-DD format.[/red3]")
            raise typer.Exit(1) from exc

    if to_date:
        try:
            parsed_to = date.fromisoformat(to_date)
        except ValueError as exc:
            rprint(f"[red3]Invalid --to date: {to_date}. Use YYYY-MM-DD format.[/red3]")
            raise typer.Exit(1) from exc

    # Parse severity
    severity_list: list[str] | None = None
    if severity:
        severity_list = [s.strip() for s in severity.split(",") if s.strip()]

    # Validate sort
    if sort not in ("cve_date", "severity", "epss"):
        rprint(f"[red3]Invalid --sort: {sort}. Use: cve_date, severity, or epss[/red3]")
        raise typer.Exit(1)

    with RecentService() as service:
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
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
            raise typer.Exit(1) from exc
        except Exception as exc:
            rprint(f"[red3]Error fetching recent CVEs: {exc}[/red3]")
            raise typer.Exit(1) from exc

    if not results:
        rprint("[yellow]No CVEs found matching the specified criteria.[/yellow]")
        raise typer.Exit(0)

    # Display results
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

    # Save to file if requested
    if output:
        import json as _json
        try:
            _safe_path(output)
        except ValueError as exc:
            rprint(f"[red3]Unsafe output path: {exc}[/red3]")
            raise typer.Exit(1) from exc
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report_data = {
            "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            "query": {
                "since": since,
                "from_date": str(parsed_from) if parsed_from else None,
                "to_date": str(parsed_to) if parsed_to else None,
                "severity": severity_list,
                "kev_only": kev_only,
                "min_epss": min_epss,
                "only_with_poc": only_with_poc,
                "sort": sort,
                "limit": limit,
            },
            "total": len(results),
            "cves": [
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
            ],
        }
        output_path.write_text(_json.dumps(report_data, indent=2, default=str), encoding="utf-8")
        rprint(f"\n[green1]Report saved to {output_path}[/green1]")


@app.command()
def discover(
    product: Annotated[str, typer.Argument(help="Product name (e.g., 'Apache Struts', 'Log4j')")],
    version: Annotated[str | None, typer.Option("--version", "-v", help="Version: 2.x, 2.14.1, etc.")] = None,
    vendor: Annotated[str | None, typer.Option("--vendor", help="Vendor name (e.g., 'Apache')")] = None,
    limit: Annotated[int, typer.Option("--limit", help="Max CVEs to analyze", min=1, max=100)] = 50,
    output: Annotated[str | None, typer.Option("--output", "-o", help="Save JSON report to file")] = None,
) -> None:
    """Discover CVEs affecting a product by name and version.

    Supports product aliases (e.g., 'struts' -> 'Apache Struts'),
    version wildcards (e.g., '2.x'), and fuzzy matching.

    Results are grouped into three confidence tiers:
    - Confirmed: vendor AND product match AND version constraint is met
    - Possibly: vendor OR product matches but version info is unclear
    - Not enough data: CVE has insufficient product/version information
    """
    with ProductDiscoveryService() as service, Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
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
        except Exception as exc:
            rprint(f"[red3]Error: {exc}[/red3]")
            raise typer.Exit(1) from exc

    # Display summary
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

    # Save to file if requested
    if output:
        import json as _json
        try:
            _safe_path(output)
        except ValueError as exc:
            rprint(f"[red3]Unsafe output path: {exc}[/red3]")
            raise typer.Exit(1) from exc
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report_data = {
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
        output_path.write_text(_json.dumps(report_data, indent=2, default=str), encoding="utf-8")
        rprint(f"\n[green1]Report saved to {output_path}[/green1]")


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
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress banner and decorative output"),
    ] = False,
) -> None:
    """PocMap: AI-friendly CVE PoC discovery tool."""
    ctx.obj = CLIState(output_format=output_format, quiet=quiet)
    if version:
        rprint(f"pocmap v{__version__}")
        raise typer.Exit(0)
    if ctx.invoked_subcommand is None and not quiet:
        _banner()
        rprint("\n[bold]Usage:[/bold] pocmap [COMMAND] [ARGS]")
        rprint("Run [bold]pocmap --help[/bold] for available commands.")
