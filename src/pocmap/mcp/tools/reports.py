"""JSON/HTML report MCP tools."""

from __future__ import annotations

from typing import Any

from pocmap.mcp.errors import _ok, _tool_error
from pocmap.mcp.registration import _tool
from pocmap.mcp.server import _svc


@_tool(
    name="generate_json_report",
    description=(
        "Full assessment for one or more known CVE IDs in a single call: description, "
        "CVSS, EPSS, KEV, exploits across GitHub/Metasploit/ExploitDB/Nuclei (plus plugins), "
        "practice labs, and bug bounty reports. Prefer this when the user wants a complete "
        "picture, prioritization, or compare/prioritize several CVEs — not when they only "
        "asked for a PoC or exploit repo (use find_github_pocs or the matching DB tool "
        "instead; those are faster and more focused). "
        "Beats calling lookup_cve + every exploit/lab/bounty tool separately for a full "
        "write-up. Each entry includes a sources block (ok/empty/rate_limited/error) so an "
        "empty exploit list is never a silent negative. Accepts comma-separated IDs. "
        "Also suitable for automation, CI/CD, and dashboards."
    ),
)
def generate_json_report(cve_ids: str) -> dict[str, Any]:
    """Generate a JSON report for one or more CVEs.

    Args:
        cve_ids: Comma-separated list of CVE identifiers
            (e.g. 'CVE-2021-44228' for a single CVE,
            or 'CVE-2021-44228,CVE-2023-44487,CVE-2024-21413'
            for multiple CVEs). Whitespace around commas is trimmed.

    Returns:
        JSON-formatted vulnerability report containing for each CVE:
        cve_info (description, CVSS, EPSS, KEV), exploits (all registered
        sources including plugins), labs, bug bounty reports, and a sources
        health block. The top-level object also includes generated_at,
        total_requested, total_entries, and any errors encountered.
    """
    try:
        ids = [c.strip().upper() for c in cve_ids.split(",") if c.strip()]
        if not ids:
            return _ok({
                "error": "No valid CVE IDs provided.",
                "category": "invalid_input",
                "hint": "Provide one or more comma-separated CVE IDs, e.g. 'CVE-2021-44228,CVE-2023-44487'",
            })
        return _svc.generate_json_report(ids)
    except Exception as e:
        return _tool_error(e, f"generate_json_report({cve_ids})")


@_tool(
    name="generate_html_report",
    description=(
        "Generate a comprehensive HTML vulnerability report for one or more CVEs. "
        "The report includes styled cards with CVE details (description, CVSS, EPSS, KEV status), "
        "all discovered exploits and PoCs with source badges, available practice labs, "
        "and bug bounty reports. The HTML is self-contained with embedded CSS for immediate viewing. "
        "Use this tool when creating human-readable reports for stakeholders, security teams, "
        "or documentation. The HTML report can be saved to a file and opened in any browser."
    ),
)
def generate_html_report(cve_ids: str) -> dict[str, Any]:
    """Generate an HTML report for one or more CVEs.

    Args:
        cve_ids: Comma-separated list of CVE identifiers
            (e.g. 'CVE-2021-44228' or 'CVE-2021-44228,CVE-2023-44487').
            Whitespace around commas is trimmed.

    Returns:
        Self-contained HTML vulnerability report with embedded CSS.
        The HTML includes styled cards for each CVE with CVSS/EPSS/KEV
        summaries, exploit lists with source badges, lab links, and
        bug bounty report references. Save the output to a .html file
        and open in any browser.
    """
    try:
        ids = [c.strip().upper() for c in cve_ids.split(",") if c.strip()]
        if not ids:
            return _ok({
                "error": "No valid CVE IDs provided.",
                "category": "invalid_input",
                "hint": "Provide one or more comma-separated CVE IDs, e.g. 'CVE-2021-44228,CVE-2023-44487'",
            })
        return _svc.generate_html_report(ids)
    except Exception as e:
        return _tool_error(e, f"generate_html_report({cve_ids})")
