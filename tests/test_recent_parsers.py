"""Offline native tests for RecentService pure parser/sort helpers.

Covers:
- ``_sort_results`` no longer raising ``TypeError`` on a mixed list of
  tz-aware ISO and naive publication dates (regression), plus the epss and
  severity sort orderings.
- ``_parse_since`` bounds (1h min, 365d max) and bad-format rejection.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from pocmap.models import CVEInfo, CVSSScore, Severity
from pocmap.services.recent_service import RecentService


def _cve(cve_id: str, *, pub: str | None = None, epss: float | None = None,
         base_score: float | None = None, severity: Severity = Severity.UNKNOWN) -> CVEInfo:
    cvss = None
    if base_score is not None or severity is not Severity.UNKNOWN:
        cvss = CVSSScore(base_score=base_score, severity=severity)
    return CVEInfo(id=cve_id, publication_date=pub, epss=epss, cvss=cvss)


# ---------------------------------------------------------------------------
# _sort_results
# ---------------------------------------------------------------------------

def test_sort_cve_date_mixed_tzaware_and_naive_does_not_raise() -> None:
    """Regression: an aware ISO key must not blow up against naive keys."""
    cves = [
        _cve("CVE-2024-0002", pub="N/A"),
        _cve("CVE-2024-0001", pub="2024-01-15T10:00:00Z"),
        _cve("CVE-2024-0003", pub="05 Jan 2024"),
    ]
    result = RecentService._sort_results(cves, "cve_date")
    # Newest first: the tz-aware ISO date (2024-01-15) leads, then 05 Jan 2024,
    # then the unparseable "N/A" (datetime.min) sinks to the bottom.
    assert [c.id for c in result] == ["CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0002"]


def test_sort_epss_sinks_none_to_bottom() -> None:
    cves = [
        _cve("CVE-2024-0001", epss=None),
        _cve("CVE-2024-0002", epss=80.0),
        _cve("CVE-2024-0003", epss=10.0),
    ]
    result = RecentService._sort_results(cves, "epss")
    assert [c.id for c in result] == ["CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0001"]


def test_sort_severity_orders_by_score_then_rank() -> None:
    cves = [
        _cve("CVE-2024-0001", base_score=5.0, severity=Severity.MEDIUM),
        _cve("CVE-2024-0002", base_score=9.8, severity=Severity.CRITICAL),
        _cve("CVE-2024-0003", base_score=9.8, severity=Severity.HIGH),
        _cve("CVE-2024-0004", base_score=None, severity=Severity.UNKNOWN),
    ]
    result = RecentService._sort_results(cves, "severity")
    # 9.8 CRITICAL and 9.8 HIGH tie on score -> CRITICAL rank wins; 5.0 next;
    # the None-score UNKNOWN sinks last.
    assert [c.id for c in result] == [
        "CVE-2024-0002",
        "CVE-2024-0003",
        "CVE-2024-0001",
        "CVE-2024-0004",
    ]


# ---------------------------------------------------------------------------
# _parse_since
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["1h", "24h", "7d", "365d"])
def test_parse_since_accepts_valid(value: str) -> None:
    result = RecentService._parse_since(value)
    assert isinstance(result, datetime)
    assert result.tzinfo is None


def test_parse_since_wider_window_is_older() -> None:
    # A wider window resolves strictly further into the past than a narrow one.
    # The ~364-day gap dwarfs any wall-clock drift between the two calls, so no
    # reference "now" (and no tz-aware/deprecated utcnow) is needed.
    assert RecentService._parse_since("365d") < RecentService._parse_since("1h")


@pytest.mark.parametrize("value", ["0h", "366d", "", "7", "7w", "-1d"])
def test_parse_since_rejects_invalid(value: str) -> None:
    with pytest.raises(ValueError):
        RecentService._parse_since(value)


# ---------------------------------------------------------------------------
# _filter_by_epss
# ---------------------------------------------------------------------------

def test_filter_by_epss_falsy_threshold_passes_through() -> None:
    cves = [_cve("CVE-2024-0001", epss=None), _cve("CVE-2024-0002", epss=10.0)]
    # A 0/None threshold is a no-op: the input (including the None-epss CVE) is
    # returned unchanged.
    assert RecentService._filter_by_epss(cves, 0.0) is cves


def test_filter_by_epss_excludes_none_and_is_inclusive_at_boundary() -> None:
    cves = [
        _cve("CVE-2024-0001", epss=49.9),  # just below -> dropped
        _cve("CVE-2024-0002", epss=50.0),  # boundary -> retained (inclusive)
        _cve("CVE-2024-0003", epss=80.0),  # above -> retained
        _cve("CVE-2024-0004", epss=None),  # no score -> excluded
    ]
    result = RecentService._filter_by_epss(cves, 50.0)
    assert [c.id for c in result] == ["CVE-2024-0002", "CVE-2024-0003"]
