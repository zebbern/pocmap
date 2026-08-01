"""Structured MCP tool success/error envelopes."""

from __future__ import annotations

import json
import logging
from typing import Any

from pocmap.utils.http import categorize_exception

logger = logging.getLogger("pocmap-mcp")

def _format_cve_text(data: dict[str, Any]) -> str:
    """Format normalized CVE dict as human-readable text."""
    lines = [f"CVE: {data.get('id', 'N/A')}"]
    if data.get("description"):
        lines.append(f"Description: {data['description']}")
    cvss = data.get("cvss", {})
    if cvss.get("score") is not None:
        lines.append(f"CVSS: {cvss['score']} ({cvss.get('severity', 'N/A')}) - v{cvss.get('version', '?')}")
        if cvss.get("vector_string"):
            lines.append(f"Vector: {cvss['vector_string']}")
    epss = data.get("epss_score")
    if epss is not None:
        lines.append(f"EPSS: {epss:.4f}")
    kev = data.get("kev_status")
    lines.append(f"KEV: {'in_kev' if kev else 'not_in_kev'}")
    cwes = data.get("cwes", [])
    if cwes:
        lines.append(f"CWEs: {', '.join(cwes)}")
    vendor = data.get("vendor")
    product = data.get("product")
    if vendor or product:
        v = vendor or "N/A"
        p = product or "N/A"
        lines.append(f"Affected: {v} - {p}")
    if data.get("publication_date"):
        lines.append(f"Published: {data['publication_date']}")
    lines.append(f"State: {data.get('state', 'UNKNOWN')}")
    refs = data.get("references", [])
    if refs:
        lines.append(f"References ({len(refs)}):")
        for ref in refs[:10]:
            lines.append(f"  - {ref}")
    return "\n".join(lines)


def _format_error_json(e: Exception, context: str = "") -> dict[str, Any]:
    """Format an exception as a structured error object.

    Categorizes the error for programmatic handling by AI agents.
    Returns generic error messages without raw exception details.

    Deliberately carries ONLY error keys. A failure must never present a
    success key such as ``total_count`` or ``kev_status``, because an agent
    reading ``total_count: 0`` off a throttled lookup would report "no results"
    for a question that was never answered.
    """
    error_type = type(e).__name__
    category, retryable = categorize_exception(e)

    return {
        "error": f"An error occurred ({error_type})",
        "error_type": error_type,
        "category": category,
        "retryable": retryable,
        "context": context,
    }


def _tool_error(e: Exception, context: str) -> dict[str, Any]:
    """Log a tool failure and return the structured error object.

    Consolidates the ``logger.error(...); return _format_error_json(...)`` tail
    every ``@mcp.tool`` ``except`` block repeated; *context* is passed straight
    through, so the client-visible error payload is unchanged.
    """
    logger.error("%s: %s", context, e)
    return _format_error_json(e, context)


def _ok(data: Any) -> dict[str, Any]:
    """Normalize a successful tool result into a JSON-safe object.

    Tools return an object rather than a JSON *string* so the SDK can emit real
    ``structuredContent``. The round-trip through ``json.dumps(default=str)``
    keeps the previous coercion contract exactly — datetimes and enums still
    become strings — while handing back a dict instead of text.
    """
    coerced = json.loads(json.dumps(data, indent=2, default=str))
    return coerced if isinstance(coerced, dict) else {"result": coerced}
