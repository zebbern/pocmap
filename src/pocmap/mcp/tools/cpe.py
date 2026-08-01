"""CVE/CPE conversion MCP tools."""

from __future__ import annotations

from typing import Any

from pocmap.mcp.errors import _ok, _tool_error
from pocmap.mcp.registration import _tool
from pocmap.mcp.server import _svc


@_tool(
    name="cve_to_cpe",
    description=(
        "Convert a CVE ID to its associated CPE (Common Platform Enumeration) identifiers. "
        "CPEs are standardized identifiers for software and hardware products. "
        "This conversion helps identify the exact software versions and configurations "
        "that are affected by a vulnerability. "
        "Returns CPE 2.3 URIs with vendor, product, and version information. "
        "Use this tool for asset inventory correlation - map CVEs to actual products in your "
        "environment to determine exposure."
    ),
)
def cve_to_cpe(cve_id: str) -> dict[str, Any]:
    """Convert a CVE to its associated CPEs.

    Args:
        cve_id: The CVE identifier

    Returns:
        JSON string with cve_id, total_count, and a list of CPE objects
        (cpe, vendor, product, version).
    """
    try:
        cpes = _svc.cve_to_cpe(cve_id)
        cve_clean = cve_id.upper().strip()
        return _ok({
            "cve_id": cve_clean,
            "total_count": len(cpes),
            "cpes": cpes,
        })
    except Exception as e:
        return _tool_error(e, f"cve_to_cpe({cve_id})")


@_tool(
    name="cpe_to_cve",
    description=(
        "Convert a CPE (Common Platform Enumeration) identifier to its associated CVEs. "
        "Given a software/hardware product identifier, this finds all known vulnerabilities "
        "affecting that product. "
        "Returns a list of CVE identifiers. "
        "Use this tool for vulnerability assessment of specific products - provide a CPE or "
        "product name to discover all CVEs that affect it. This is essential for asset-based "
        "vulnerability management."
    ),
)
def cpe_to_cve(cpe: str) -> dict[str, Any]:
    """Convert a CPE to its associated CVEs.

    Args:
        cpe: CPE 2.3 URI or simplified product identifier

    Returns:
        JSON string with cpe, total_count, and a list of CVE identifiers.
    """
    try:
        cves = _svc.cpe_to_cve(cpe)
        return _ok({
            "cpe": cpe,
            "total_count": len(cves),
            "cve_ids": cves,
        })
    except Exception as e:
        return _tool_error(e, f"cpe_to_cve({cpe})")
