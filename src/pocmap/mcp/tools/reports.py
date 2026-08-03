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
        "CVSS, EPSS, KEV, exploits across Metasploit/ExploitDB/Nuclei first then capped "
        "GitHub PoCs, practice labs, and bug bounty reports. Defaults drop "
        "labels=['index'] repos and keep top GitHub hits by trust_score (max_github=15) "
        "so famous-CVE reports stay agent-usable; each entry has exploit_trim counts. "
        "Also includes triage (priority/reasons/next_actions) and sources "
        "(ok/empty/rate_limited/error). Prefer this for a complete picture — not when "
        "they only asked for a PoC (use find_github_pocs). Cold start 10–30s. "
        "Accepts comma-separated IDs."
    ),
)
def generate_json_report(
    cve_ids: str,
    include_github: bool = True,
    max_github: int = 15,
    min_trust_score: float = 0.0,
    include_index_repos: bool = False,
) -> dict[str, Any]:
    """Generate a JSON report for one or more CVEs.

    Args:
        cve_ids: Comma-separated list of CVE identifiers
            (e.g. 'CVE-2021-44228' for a single CVE,
            or 'CVE-2021-44228,CVE-2023-44487,CVE-2024-21413'
            for multiple CVEs). Whitespace around commas is trimmed.
        include_github: Include GitHub PoCs (default True).
        max_github: Max GitHub repos kept after ranking (default 15).
        min_trust_score: Drop exploits below this trust_score (default 0).
        include_index_repos: Keep labels containing ``index`` (default False).

    Returns:
        JSON-formatted vulnerability report containing for each CVE:
        cve_info (description, CVSS, EPSS, KEV), exploits (shaped for agents),
        labs, bug bounty reports, sources health, and exploit_trim.
    """
    try:
        ids = [c.strip().upper() for c in cve_ids.split(",") if c.strip()]
        if not ids:
            return _ok({
                "error": "No valid CVE IDs provided.",
                "category": "invalid_input",
                "hint": "Provide one or more comma-separated CVE IDs, e.g. 'CVE-2021-44228,CVE-2023-44487'",
            })
        return _svc.generate_json_report(
            ids,
            include_github=include_github,
            max_github=max(0, max_github),
            min_trust_score=max(0.0, min_trust_score),
            include_index_repos=include_index_repos,
        )
    except Exception as e:
        return _tool_error(e, f"generate_json_report({cve_ids})")


@_tool(
    name="generate_html_report",
    description=(
        "Generate a comprehensive HTML vulnerability report for one or more CVEs. "
        "Uses the same agent-friendly exploit shaping as generate_json_report "
        "(Metasploit/EDB/Nuclei first, capped GitHub, index repos omitted by default). "
        "The HTML is self-contained with embedded CSS for immediate viewing."
    ),
)
def generate_html_report(
    cve_ids: str,
    include_github: bool = True,
    max_github: int = 15,
    min_trust_score: float = 0.0,
    include_index_repos: bool = False,
) -> dict[str, Any]:
    """Generate an HTML report for one or more CVEs.

    Args:
        cve_ids: Comma-separated list of CVE identifiers
            (e.g. 'CVE-2021-44228' or 'CVE-2021-44228,CVE-2023-44487').
            Whitespace around commas is trimmed.
        include_github: Include GitHub PoCs (default True).
        max_github: Max GitHub repos kept after ranking (default 15).
        min_trust_score: Drop exploits below this trust_score (default 0).
        include_index_repos: Keep labels containing ``index`` (default False).

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
        return _svc.generate_html_report(
            ids,
            include_github=include_github,
            max_github=max(0, max_github),
            min_trust_score=max(0.0, min_trust_score),
            include_index_repos=include_index_repos,
        )
    except Exception as e:
        return _tool_error(e, f"generate_html_report({cve_ids})")
