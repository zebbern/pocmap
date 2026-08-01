"""CVE intelligence MCP tools."""

from __future__ import annotations

from typing import Any

from pocmap.mcp.errors import _ok, _tool_error
from pocmap.mcp.registration import _tool
from pocmap.mcp.server import _svc


@_tool(
    name="lookup_cve",
    description=(
        "Look up detailed information about a CVE (Common Vulnerabilities and Exposures) identifier. "
        "Returns the CVE description, CVSS scores, EPSS probability, KEV status, CWE identifiers, "
        "affected vendor/product, publication date, and reference links. "
        "Use this tool when the user provides a CVE ID and wants to understand what the vulnerability is about. "
        "The CVE ID must be in the format CVE-YYYY-NNNN+ (e.g. CVE-2021-44228). "
        "Data sources: NVD, CVE.org, CISA KEV catalog, EPSS."
    ),
)
def lookup_cve(cve_id: str) -> dict[str, Any]:
    """Look up detailed CVE information.

    Args:
        cve_id: The CVE identifier (e.g. 'CVE-2021-44228')

    Returns:
        JSON string with structured CVE information including id (the CVE
        identifier), description, cvss (score, severity, version,
        vector_string), epss_score, kev_status, cwes, references, vendor,
        product, publication_date, and state.
    """
    try:
        data = _svc.lookup_cve(cve_id)
        if "error" in data:
            return _ok({
                "error": data["error"],
                "error_type": data.get("error_type", "unknown"),
                "category": data.get("category", "unknown"),
                "retryable": data.get("retryable", False),
                "context": f"lookup_cve({cve_id.upper().strip()})",
                "cve_id": data.get("cve_id", cve_id.upper().strip()),
            })
        return _ok(data)
    except Exception as e:
        return _tool_error(e, f"lookup_cve({cve_id})")


@_tool(
    name="get_epss_score",
    description=(
        "Get the EPSS (Exploit Prediction Scoring System) score for a CVE. "
        "EPSS is a probability score that predicts the likelihood a vulnerability "
        "will be exploited in the wild within the next 30 days. The returned score "
        "is on a 0.0--1.0 scale (e.g. 0.85 means 85%% probability). Higher scores mean greater risk. "
        "Use this tool when prioritizing vulnerability remediation - CVEs with EPSS > 0.5 should "
        "be patched urgently. EPSS complements CVSS by adding threat intelligence context."
    ),
)
def get_epss_score(cve_id: str) -> dict[str, Any]:
    """Get the EPSS probability score for a CVE.

    Args:
        cve_id: The CVE identifier

    Returns:
        JSON string with cve_id, epss_score (0.0-1.0), risk_level
        (LOW/MEDIUM/HIGH/CRITICAL), and interpretation guidance.
    """
    try:
        score = _svc.get_epss(cve_id)
        cve_clean = cve_id.upper().strip()
        if score is not None:
            risk = "CRITICAL" if score > 0.9 else "HIGH" if score > 0.5 else "MEDIUM" if score > 0.2 else "LOW"
            return _ok({
                "cve_id": cve_clean,
                "epss_score": score,
                "risk_level": risk,
                "available": True,
                "interpretation": (
                    "EPSS > 0.9: patch immediately. "
                    "EPSS > 0.5: high priority. "
                    "EPSS > 0.2: medium priority. "
                    "EPSS <= 0.2: lower priority."
                ),
            })
        return _ok({
            "cve_id": cve_clean,
            "epss_score": None,
            "risk_level": "UNKNOWN",
            "available": False,
            "interpretation": "No EPSS data available for this CVE.",
        })
    except Exception as e:
        return _tool_error(e, f"get_epss_score({cve_id})")


@_tool(
    name="check_kev_status",
    description=(
        "Check if a CVE is listed in the CISA Known Exploited Vulnerabilities (KEV) catalog. "
        "The KEV catalog contains vulnerabilities that have been actively exploited in the wild. "
        "CVEs in the KEV catalog are mandated for patching by US federal agencies within specific timeframes. "
        "Use this tool to determine if a vulnerability is being actively exploited - KEV entries "
        "should be prioritized for immediate remediation regardless of CVSS score."
    ),
)
def check_kev_status(cve_id: str) -> dict[str, Any]:
    """Check if a CVE is in the CISA KEV catalog.

    Args:
        cve_id: The CVE identifier

    Returns:
        JSON string with cve_id, kev_status (bool), description of what
        KEV means, and recommended action based on the result.
    """
    try:
        is_kev = _svc.check_kev(cve_id)
        cve_clean = cve_id.upper().strip()
        return _ok({
            "cve_id": cve_clean,
            "kev_status": is_kev,
            "in_kev_catalog": is_kev,
            "description": (
                "CISA Known Exploited Vulnerabilities (KEV) catalog lists "
                "vulnerabilities that have been actively exploited in the wild."
            ),
            "recommendation": (
                "PRIORITIZE FOR IMMEDIATE PATCHING - this CVE is actively exploited."
                if is_kev else
                "Not in KEV catalog - prioritize based on CVSS and EPSS scores."
            ),
        })
    except Exception as e:
        return _tool_error(e, f"check_kev_status({cve_id})")
