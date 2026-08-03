"""Recent exploit discovery MCP tools."""

from __future__ import annotations

from typing import Any

from pocmap.mcp.errors import _ok, _tool_error
from pocmap.mcp.registration import _tool
from pocmap.mcp.server import _svc


@_tool(
    name="find_recent_exploits",
    description=(
        "Find recently published CVEs with exploit and PoC intelligence. "
        "Scans the NVD for newly published vulnerabilities within a configurable time window, "
        "then enriches each CVE with CVSS scoring, CISA KEV status, and PoC availability from GitHub. "
        "Results can be filtered by severity, KEV status, minimum EPSS score, and PoC availability. "
        "Response includes filter_stats (fetched/after_severity/after_epss/after_poc/returned and "
        "poc_check ok/empty/error/rate_limited counts) so empty only_with_poc results are explainable. "
        "Each cve_info includes a triage summary. Cold start / first call can take 10–30s. "
        "Use for emerging threats, disclosure monitoring, or daily/weekly briefings."
    ),
)
def find_recent_exploits(
    since: str = "24h",
    from_date: str = "",
    to_date: str = "",
    only_with_poc: bool = False,
    kev_only: bool = False,
    min_epss: float = 0.0,
    severity: str = "",
    sort: str = "cve_date",
    limit: int = 50,
) -> dict[str, Any]:
    """Find recently published CVEs with exploit/PoC intelligence.

    Args:
        since: Relative time window (e.g., '1h', '24h', '7d', '30d').
            Ignored if from_date is provided.
        from_date: Explicit start date (YYYY-MM-DD). Overrides *since*.
        to_date: Explicit end date (YYYY-MM-DD). Defaults to today.
        only_with_poc: Only return CVEs with known PoCs on GitHub.
        kev_only: Only return CISA KEV entries.
        min_epss: Minimum EPSS score, expressed on the 0--100
            percentage scale (e.g. 50.0 means EPSS >= 50%%). EPSS is
            the Exploit Prediction Scoring System probability
            (0 = no filter, 100 = only the most likely to be
            exploited). Higher values filter for CVEs more likely
            to be exploited in the wild within 30 days. Note: this
            input uses the 0--100 scale, not the 0.0--1.0 scale.
        severity: Comma-separated severity levels
            (e.g., 'CRITICAL,HIGH' or 'critical,high').
        sort: Sort results by 'cve_date' (newest first), 'severity'
            (highest first), or 'epss' (highest first).
        limit: Maximum number of results (1--100, default: 50).

    Returns:
        Dict with success (bool), total (int), query (echoed filter
        parameters), and cves -- a list of
        {cve_info, has_poc, poc_sources, discovered_at}. CVE fields stay
        nested under ``cve_info`` (not hoisted). ``cve_info`` uses the
        same normalizer as ``lookup_cve``: ``cvss.score``, ``epss_score``
        on 0.0--1.0, ``references`` as a list, plus ``affected_products``.
        The ``min_epss`` *input* filter still uses the 0--100 scale.
    """
    try:
        limit = max(1, min(100, limit))
        result = _svc.find_recent_exploits(
            since=since,
            from_date=from_date,
            to_date=to_date,
            only_with_poc=only_with_poc,
            kev_only=kev_only,
            min_epss=min_epss,
            severity=severity,
            sort=sort,
            limit=limit,
        )
        return _ok(result)
    except Exception as e:
        return _tool_error(e, "find_recent_exploits()")
