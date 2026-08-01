"""Bug bounty report MCP tools."""

from __future__ import annotations

from typing import Any

from pocmap.mcp.errors import _ok, _tool_error
from pocmap.mcp.registration import _tool
from pocmap.mcp.server import _svc


@_tool(
    name="find_bug_bounty_reports",
    description=(
        "Find bug bounty reports and write-ups for a CVE. "
        "Bug bounty reports provide real-world exploitation techniques, impact assessments, "
        "and detailed write-ups from security researchers who found the vulnerability in production. "
        "Returns reports from platforms like HackerOne, PentesterLand, and Bug Bounty Hunting "
        "with titles, URLs, and indicators of whether a Proof-of-Concept is included. "
        "Use this tool when you want to understand how a vulnerability is exploited in real-world "
        "scenarios, learn from security researchers' methodologies, or find detailed technical write-ups."
    ),
)
def find_bug_bounty_reports(cve_id: str) -> dict[str, Any]:
    """Find bug bounty reports for a CVE.

    Args:
        cve_id: The CVE identifier

    Returns:
        JSON string with cve_id, total_count, and a list of report objects
        (source, url, title, has_poc).
    """
    try:
        reports = _svc.find_bug_bounty_reports(cve_id)
        cve_clean = cve_id.upper().strip()
        return _ok({
            "cve_id": cve_clean,
            "total_count": len(reports),
            "reports": reports,
        })
    except Exception as e:
        return _tool_error(e, f"find_bug_bounty_reports({cve_id})")
