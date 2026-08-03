"""Offline tests for MCP triage summaries."""

from __future__ import annotations

from pocmap.utils.triage import build_cve_triage


def test_kev_forces_critical() -> None:
    t = build_cve_triage(severity="MEDIUM", kev_status=True, epss_score=0.01)
    assert t["priority"] == "critical"
    assert any("KEV" in r for r in t["reasons"])


def test_high_epss_elevates() -> None:
    t = build_cve_triage(severity="LOW", epss_score=0.6)
    assert t["priority"] == "high"


def test_exploit_counts_in_reasons() -> None:
    t = build_cve_triage(
        severity="HIGH",
        has_poc=True,
        exploit_count=3,
        lab_count=1,
    )
    assert any("PoC" in r for r in t["reasons"])
    assert any("lab" in r.lower() for r in t["reasons"])
