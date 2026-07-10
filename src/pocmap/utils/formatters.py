"""Output formatters for CLI and programmatic display.

Provides rich console tables and plain-text formatting for CVE information,
exploit listings, lab environments, and bug bounty reports.

Example::

    from pocmap.models import CVEInfo
    from pocmap.utils.formatters import format_cve_table
    table = format_cve_table(cve_info)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.table import Table

if TYPE_CHECKING:
    from pocmap.models import (
        BugBountyReport,
        CVEInfo,
        Exploit,
        LabEnvironment,
        RecentExploitResult,
        ReportEntry,
    )


# Color mappings for Rich console output
_SEVERITY_COLORS = {
    "LOW": "spring_green2",
    "MEDIUM": "gold1",
    "HIGH": "dark_orange",
    "CRITICAL": "red1",
    "UNKNOWN": "white",
}

_CWES_TOP_25 = {
    "CWE-79", "CWE-89", "CWE-352", "CWE-862", "CWE-787",
    "CWE-22", "CWE-416", "CWE-125", "CWE-78", "CWE-94",
    "CWE-120", "CWE-434", "CWE-476", "CWE-121", "CWE-502",
    "CWE-122", "CWE-863", "CWE-20", "CWE-284", "CWE-200",
    "CWE-306", "CWE-918", "CWE-77", "CWE-639", "CWE-770",
}

_MSF_RANK_COLORS = {
    "excellent": "spring_green2",
    "great": "spring_green2",
    "good": "spring_green2",
    "normal": "orange_red1",
    "average": "gold1",
    "low": "gold1",
    "manual": "white",
}


def _score_color(score: float | None) -> str:
    """Return a Rich color for a CVSS score."""
    if score is None:
        return "white"
    if score < 4:
        return "spring_green2"
    if score < 7:
        return "gold1"
    if score < 9:
        return "dark_orange"
    return "red1"


def _epss_color(epss: float | None) -> str:
    """Return a Rich color for an EPSS score."""
    if epss is None:
        return "white"
    if epss >= 70:
        return "red1"
    if epss >= 40:
        return "dark_orange"
    return "spring_green2"


def format_cve_table(cve: CVEInfo) -> Table:
    """Format a :class:`CVEInfo` as a Rich table for console display.

    Args:
        cve: The CVE information object.

    Returns:
        A ``rich.table.Table`` ready for printing.
    """
    cvss = cve.cvss
    base_score = cvss.base_score if cvss is not None else None
    severity = cvss.severity.value if cvss is not None else "UNKNOWN"
    vector_string = (cvss.vector_string if cvss is not None else None) or "N/A"

    score_str = f"[{_score_color(base_score)}]{base_score}[/{_score_color(base_score)}]" if base_score is not None else "N/A"

    epss_str = f"[{_epss_color(cve.epss)}]{cve.epss}%[/{_epss_color(cve.epss)}]" if cve.epss is not None else "N/A"

    sev_color = _SEVERITY_COLORS.get(severity, "white")
    severity_str = f"[{sev_color}]{severity}[/{sev_color}]"

    # Format CWEs with Top-25 highlighting
    if cve.cwes:
        cwes_colored = []
        for cwe in cve.cwes:
            if cwe in _CWES_TOP_25:
                cwes_colored.append(f"[bright_blue]{cwe}[/bright_blue]")
            else:
                cwes_colored.append(f"[bright_cyan]{cwe}[/bright_cyan]")
        cwe_str = ",".join(cwes_colored)
    else:
        cwe_str = "N/A"

    kev_str = "[red1]Yes[/red1]" if cve.kev_status else "No"

    table = Table(
        show_lines=True,
        header_style="bold",
        title=cve.id,
        title_style="bold",
        title_justify="center",
    )
    table.add_column("Publication Date", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Base Score", justify="center")
    table.add_column("EPSS", justify="center")
    table.add_column("Vendor", justify="center")
    table.add_column("Product", justify="center")
    table.add_column("CISA KEV", justify="center")
    table.add_column("CWE", justify="center")
    table.add_column("Vector String", overflow="fold", justify="center")
    table.add_row(
        cve.publication_date or "N/A",
        severity_str,
        score_str,
        epss_str,
        cve.vendor or "N/A",
        cve.product or "N/A",
        kev_str,
        cwe_str,
        vector_string,
    )
    return table


def format_exploit_table(exploits: list[Exploit]) -> Table:
    """Format a list of :class:`Exploit` objects as a Rich table.

    Args:
        exploits: List of exploit objects.

    Returns:
        A ``rich.table.Table`` ready for printing.
    """
    table = Table(show_lines=True, header_style="bold")
    table.add_column("#", justify="center", width=4)
    table.add_column("Source", justify="center")
    table.add_column("Title", overflow="fold")
    table.add_column("Language", justify="center")
    table.add_column("Stars", justify="center")
    table.add_column("Forks", justify="center")
    table.add_column("Rank", justify="center")
    table.add_column("URL", overflow="fold")

    for i, ex in enumerate(exploits, start=1):
        rank_color = _MSF_RANK_COLORS.get(str(ex.rank).lower(), "white") if ex.rank else "white"
        rank_str = f"[{rank_color}]{ex.rank.value}[/{rank_color}]" if ex.rank else "N/A"
        stars_str = str(ex.stars) if ex.stars is not None else "N/A"
        forks_str = str(ex.forks) if ex.forks is not None else "N/A"
        lang_str = ex.language or "N/A"

        table.add_row(
            str(i),
            ex.source.value,
            ex.title or "N/A",
            lang_str,
            stars_str,
            forks_str,
            rank_str,
            ex.url,
        )
    return table


def format_lab_table(labs: list[LabEnvironment]) -> Table:
    """Format a list of :class:`LabEnvironment` objects as a Rich table.

    Args:
        labs: List of lab environment objects.

    Returns:
        A ``rich.table.Table`` ready for printing.
    """
    table = Table(show_lines=True, header_style="bold")
    table.add_column("Platform", justify="center")
    table.add_column("Name", overflow="fold")
    table.add_column("URL", overflow="fold")

    for lab in labs:
        table.add_row(
            lab.platform.value,
            lab.name or "N/A",
            lab.url,
        )
    return table


def format_bb_table(reports: list[BugBountyReport]) -> Table:
    """Format a list of :class:`BugBountyReport` objects as a Rich table.

    Args:
        reports: List of bug bounty report objects.

    Returns:
        A ``rich.table.Table`` ready for printing.
    """
    table = Table(show_lines=True, header_style="bold")
    table.add_column("Source", justify="center")
    table.add_column("PoC Available", justify="center")
    table.add_column("Title", overflow="fold")
    table.add_column("URL", overflow="fold")

    for report in reports:
        if report.has_poc is True:
            poc_str = "[spring_green2]Yes[/spring_green2]"
        elif report.has_poc is False:
            poc_str = "[red3]No[/red3]"
        else:
            poc_str = "N/A"

        table.add_row(
            report.source.value,
            poc_str,
            report.title or "N/A",
            report.url,
        )
    return table


def format_recent_cves_table(results: list[RecentExploitResult]) -> Table:
    """Format recent CVE results as a Rich table for console display.

    Args:
        results: List of recent exploit result objects.

    Returns:
        A ``rich.table.Table`` ready for printing.
    """
    table = Table(
        show_lines=True,
        header_style="bold",
        title="Recent CVEs with Exploit Intelligence",
        title_style="bold",
        title_justify="center",
    )
    table.add_column("#", justify="center", width=4)
    table.add_column("CVE ID", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Score", justify="center")
    table.add_column("EPSS", justify="center")
    table.add_column("KEV", justify="center")
    table.add_column("Vendor", justify="center")
    table.add_column("Product", justify="center", overflow="fold")
    table.add_column("Published", justify="center")
    table.add_column("PoC", justify="center")
    table.add_column("PoC Sources", overflow="fold")

    for i, result in enumerate(results, start=1):
        cve = result.cve_info
        cvss = cve.cvss

        # Severity styling
        severity = cvss.severity.value if cvss and cvss.severity else "UNKNOWN"
        sev_color = _SEVERITY_COLORS.get(severity, "white")
        severity_str = f"[{sev_color}]{severity}[/{sev_color}]"

        # Score styling
        base_score = cvss.base_score if cvss else None
        score_str = (
            f"[{_score_color(base_score)}]{base_score}[/{_score_color(base_score)}]"
            if base_score is not None
            else "N/A"
        )

        # EPSS styling
        epss_str = (
            f"[{_epss_color(cve.epss)}]{cve.epss}%[/{_epss_color(cve.epss)}]"
            if cve.epss is not None
            else "N/A"
        )

        # KEV
        kev_str = "[red1]Yes[/red1]" if cve.kev_status else "No"

        # PoC
        poc_str = "[spring_green2]Yes[/spring_green2]" if result.has_poc else "No"

        # PoC sources
        poc_sources_str = ", ".join(s.value for s in result.poc_sources) if result.poc_sources else "N/A"

        table.add_row(
            str(i),
            f"[bold]{cve.id}[/bold]",
            severity_str,
            score_str,
            epss_str,
            kev_str,
            cve.vendor or "N/A",
            cve.product or "N/A",
            cve.publication_date or "N/A",
            poc_str,
            poc_sources_str,
        )

    return table


def format_report_summary(entry: ReportEntry) -> str:
    """Create a concise plain-text summary of a report entry.

    Args:
        entry: The report entry to summarize.

    Returns:
        A plain-text summary string.
    """
    _cvss = entry.cve_info.cvss
    _severity = _cvss.severity.value if _cvss is not None else "UNKNOWN"
    _base_score = _cvss.base_score if _cvss is not None else None
    lines = [
        f"CVE: {entry.cve_info.id}",
        f"  Severity: {_severity} ({_base_score})",
        f"  EPSS: {entry.cve_info.epss}%" if entry.cve_info.epss else "  EPSS: N/A",
        f"  KEV: {'Yes' if entry.cve_info.kev_status else 'No'}",
        f"  Vendor: {entry.cve_info.vendor or 'N/A'}",
        f"  Product: {entry.cve_info.product or 'N/A'}",
        f"  CWEs: {', '.join(entry.cve_info.cwes) if entry.cve_info.cwes else 'N/A'}",
        "",
        f"  Exploits found: {len(entry.exploits)}",
        f"  Lab environments: {len(entry.labs)}",
        f"  Bug bounty reports: {len(entry.bb_reports)}",
    ]
    return "\n".join(lines)
