"""Compact triage summaries for MCP CVE payloads.

Builds a small ``triage`` object agents can use for prioritization without
re-deriving KEV / EPSS / severity heuristics on every turn.
"""

from __future__ import annotations

from typing import Any


def build_cve_triage(
    *,
    severity: str | None = None,
    epss_score: float | None = None,
    kev_status: bool = False,
    has_poc: bool | None = None,
    exploit_count: int | None = None,
    lab_count: int | None = None,
    bb_count: int | None = None,
) -> dict[str, Any]:
    """Return ``{priority, reasons, next_actions}`` for a CVE context.

    ``epss_score`` is on the MCP 0.0–1.0 scale. ``has_poc`` / counts are
    optional and deepen reasons when a full report entry is available.
    """
    sev = (severity or "UNKNOWN").upper()
    reasons: list[str] = []
    next_actions: list[str] = []

    priority = _priority_from_severity(sev)

    if kev_status:
        priority = "critical"
        reasons.append("Listed in CISA KEV (known exploited)")
        next_actions.append("Treat as actively exploited; patch or mitigate immediately")

    if epss_score is not None:
        if epss_score >= 0.5:
            if priority in {"medium", "low", "info"}:
                priority = "high"
            reasons.append(f"High EPSS ({epss_score:.3f})")
            next_actions.append("Prioritize validation; EPSS suggests likely exploitation")
        elif epss_score >= 0.1:
            reasons.append(f"Elevated EPSS ({epss_score:.3f})")
        elif epss_score > 0:
            reasons.append(f"Low EPSS ({epss_score:.3f})")

    if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        reasons.append(f"CVSS severity {sev}")

    poc_present = has_poc
    if poc_present is None and exploit_count is not None:
        poc_present = exploit_count > 0

    if poc_present is True:
        reasons.append("Public PoC / exploit material available")
        next_actions.append("Review PoC labels and verify_github_pocs before use")
    elif poc_present is False:
        reasons.append("No public PoC found in current sources")

    if exploit_count is not None and exploit_count > 0:
        reasons.append(f"{exploit_count} exploit source hit(s)")
    if lab_count is not None and lab_count > 0:
        reasons.append(f"{lab_count} practice lab(s)")
        next_actions.append("Use find_vulhub_docker / find_practice_labs for a safe repro")
    if bb_count is not None and bb_count > 0:
        reasons.append(f"{bb_count} bug-bounty write-up(s)")

    if not next_actions:
        if priority in {"critical", "high"}:
            next_actions.append("Confirm affected assets, then patch or mitigate")
        else:
            next_actions.append("Track alongside higher-priority findings")

    # Stable, short lists for agents.
    return {
        "priority": priority,
        "reasons": reasons[:8],
        "next_actions": next_actions[:5],
    }


def _priority_from_severity(sev: str) -> str:
    if sev == "CRITICAL":
        return "critical"
    if sev == "HIGH":
        return "high"
    if sev == "MEDIUM":
        return "medium"
    if sev == "LOW":
        return "low"
    return "info"
