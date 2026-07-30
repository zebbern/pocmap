"""Native offline regression tests for PackageService.

Covers ``src/pocmap/services/package_service.py``. Both collaborators (the OSV
client and the CVE.org client used for EPSS/KEV) are injected as ``MagicMock``,
so no network or DNS call is ever made.

Invariants locked in here:

  * **Duplicate advisories for the same CVE collapse, richest record winning.**
    Several databases feed OSV, so one CVE arrives repeatedly (Django 3.2.0
    returns 56 records for 30 distinct CVEs). The duplicate is usually the
    *poorer* one — PYSEC entries carry no CVSS — so keeping both shows the same
    vulnerability as CRITICAL in one row and UNKNOWN in the next.
  * **Ranking is KEV, then EPSS, then CVSS.** The point of enriching OSV with
    pocmap's catalogues is that the top of the list is what is being exploited,
    which is frequently not the highest CVSS.
  * **Severity never guesses.** A CVSS 3.x vector is scored; a 4.0-only
    advisory falls back to the publisher's rating rather than a wrong number.
  * ``OfflineError`` / ``RateLimitError`` propagate through enrichment; a
    degraded enrichment must not fail the lookup, but a dead upstream must not
    read as "no vulnerabilities".
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from pocmap.models import Severity
from pocmap.services.package_service import PackageService
from pocmap.utils.http import OfflineError, RateLimitError

V3_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"  # 10.0
V3_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5
V3_MEDIUM = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"  # 4.4
V4_ONLY = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def _record(
    vuln_id: str,
    *,
    cve: str | None = None,
    vector: str | None = None,
    label: str | None = None,
    fixed: list[str] | None = None,
    ecosystem: str = "PyPI",
    package: str = "django",
    summary: str | None = None,
) -> dict[str, Any]:
    """Build a minimal but structurally faithful OSV record."""
    rec: dict[str, Any] = {"id": vuln_id, "aliases": [cve] if cve else []}
    if summary:
        rec["summary"] = summary
    if vector:
        kind = "CVSS_V4" if vector.startswith("CVSS:4") else "CVSS_V3"
        rec["severity"] = [{"type": kind, "score": vector}]
    if label:
        rec["database_specific"] = {"severity": label}
    rec["affected"] = [
        {
            "package": {"ecosystem": ecosystem, "name": package},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, *[{"fixed": f} for f in (fixed or [])]],
                }
            ],
        }
    ]
    return rec


def _service(
    records: list[dict[str, Any]],
    *,
    epss: dict[str, float] | None = None,
    kev: set[str] | None = None,
) -> PackageService:
    """Build a service over canned OSV records and canned EPSS/KEV lookups."""
    osv = MagicMock()
    osv.query.return_value = records
    cveorg = MagicMock()
    # Enrichment reads the catalogues in BULK (one cached download each), not
    # per CVE — a per-CVE fallback would be N network calls and would fail
    # offline.
    cveorg.epss_scores.return_value = dict(epss or {})
    cveorg.kev_ids.return_value = set(kev or set())
    return PackageService(osv_client=osv, cveorg_client=cveorg)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_duplicate_advisories_for_one_cve_collapse() -> None:
    svc = _service([
        _record("GHSA-rich", cve="CVE-2022-34265", vector=V3_CRITICAL, fixed=["3.2.14"]),
        _record("PYSEC-2022-213", cve="CVE-2022-34265", fixed=["3.2.14"]),
    ])
    result = svc.discover_package("PyPI", "django", enrich=False)
    assert result.total_found == 1


def test_the_richer_record_survives_a_merge() -> None:
    """The scored GHSA must win over the unscored PYSEC, whichever arrives first."""
    for order in ([0, 1], [1, 0]):
        records = [
            _record("GHSA-rich", cve="CVE-1", vector=V3_CRITICAL, fixed=["3.2.14"]),
            _record("PYSEC-poor", cve="CVE-1", fixed=["3.2.14"]),
        ]
        svc = _service([records[i] for i in order])
        vuln = svc.discover_package("PyPI", "django", enrich=False).vulnerabilities[0]
        assert vuln.id == "GHSA-rich", order
        assert vuln.severity is Severity.CRITICAL
        assert vuln.cvss_score == 10.0


def test_merging_keeps_identifiers_and_versions_from_the_dropped_record() -> None:
    svc = _service([
        _record("GHSA-rich", cve="CVE-1", vector=V3_CRITICAL, fixed=["3.2.14"]),
        _record("PYSEC-poor", cve="CVE-1", fixed=["4.0.6"]),
    ])
    vuln = svc.discover_package("PyPI", "django", enrich=False).vulnerabilities[0]
    assert "PYSEC-poor" in vuln.aliases
    assert set(vuln.fixed_versions) == {"3.2.14", "4.0.6"}


def test_advisories_without_a_cve_never_merge() -> None:
    """RUSTSEC/GHSA-only advisories are distinct issues, not duplicates."""
    svc = _service([
        _record("RUSTSEC-2021-0001", vector=V3_HIGH, ecosystem="crates.io", package="openssl"),
        _record("RUSTSEC-2021-0002", vector=V3_HIGH, ecosystem="crates.io", package="openssl"),
    ])
    assert svc.discover_package("crates.io", "openssl", enrich=False).total_found == 2


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------

def test_kev_outranks_a_higher_cvss() -> None:
    """A KEV-listed 7.5 is a more urgent fix than a non-KEV 10.0."""
    svc = _service(
        [
            _record("GHSA-big", cve="CVE-BIG", vector=V3_CRITICAL, fixed=["9.9"]),
            _record("GHSA-kev", cve="CVE-KEV", vector=V3_HIGH, fixed=["1.1"]),
        ],
        kev={"CVE-KEV"},
    )
    order = [v.id for v in svc.discover_package("PyPI", "django").vulnerabilities]
    assert order == ["GHSA-kev", "GHSA-big"]


def test_epss_breaks_ties_below_kev() -> None:
    svc = _service(
        [
            _record("GHSA-low-epss", cve="CVE-A", vector=V3_CRITICAL, fixed=["1"]),
            _record("GHSA-high-epss", cve="CVE-B", vector=V3_MEDIUM, fixed=["2"]),
        ],
        epss={"CVE-A": 0.5, "CVE-B": 90.0},
    )
    order = [v.id for v in svc.discover_package("PyPI", "django").vulnerabilities]
    assert order == ["GHSA-high-epss", "GHSA-low-epss"]


# ---------------------------------------------------------------------------
# Severity derivation
# ---------------------------------------------------------------------------

def test_v3_vector_is_scored_and_banded() -> None:
    svc = _service([_record("GHSA-a", cve="CVE-1", vector=V3_HIGH, fixed=["1"])])
    vuln = svc.discover_package("PyPI", "django", enrich=False).vulnerabilities[0]
    assert vuln.cvss_score == 7.5
    assert vuln.severity is Severity.HIGH


def test_v4_only_advisory_falls_back_to_the_publisher_rating() -> None:
    """pocmap does not score 4.0; a wrong number is worse than the label."""
    svc = _service([_record("GHSA-v4", cve="CVE-1", vector=V4_ONLY, label="MODERATE", fixed=["1"])])
    vuln = svc.discover_package("PyPI", "django", enrich=False).vulnerabilities[0]
    assert vuln.cvss_score is None
    assert vuln.cvss_vector == V4_ONLY
    assert vuln.severity is Severity.MEDIUM  # MODERATE normalized


def test_no_severity_information_stays_unknown() -> None:
    svc = _service([_record("GHSA-bare", cve="CVE-1", fixed=["1"])])
    vuln = svc.discover_package("PyPI", "django", enrich=False).vulnerabilities[0]
    assert vuln.severity is Severity.UNKNOWN
    assert vuln.cvss_score is None


# ---------------------------------------------------------------------------
# Fix accounting and the query contract
# ---------------------------------------------------------------------------

def test_fixable_and_unfixed_are_counted_separately() -> None:
    svc = _service([
        _record("GHSA-fixed", cve="CVE-1", vector=V3_HIGH, fixed=["1.2.3"]),
        _record("GHSA-nofix", cve="CVE-2", vector=V3_HIGH, fixed=[]),
    ])
    result = svc.discover_package("PyPI", "django", enrich=False)
    assert (result.fixable_count, result.unfixed_count) == (1, 1)
    assert {v.id: v.has_fix for v in result.vulnerabilities} == {
        "GHSA-fixed": True,
        "GHSA-nofix": False,
    }


def test_ecosystem_is_normalized_before_the_query() -> None:
    osv = MagicMock()
    osv.query.return_value = []
    svc = PackageService(osv_client=osv, cveorg_client=MagicMock())
    result = svc.discover_package("pypi", "django", version="3.2.0")
    assert osv.query.call_args[0][0] == "PyPI"
    assert result.ecosystem == "PyPI"


def test_unrecognized_ecosystem_is_forwarded_verbatim() -> None:
    """OSV grows ecosystems; pocmap must not gatekeep one it has not heard of."""
    osv = MagicMock()
    osv.query.return_value = []
    svc = PackageService(osv_client=osv, cveorg_client=MagicMock())
    svc.discover_package("BrandNewEcosystem", "thing")
    assert osv.query.call_args[0][0] == "BrandNewEcosystem"


def test_limit_keeps_the_highest_risk_entries() -> None:
    svc = _service(
        [
            _record(f"GHSA-{i}", cve=f"CVE-{i}", vector=V3_MEDIUM, fixed=["1"])
            for i in range(10)
        ],
        kev={"CVE-7"},
    )
    result = svc.discover_package("PyPI", "django", limit=3)
    # total_found is what was FOUND, not what survived the limit: reporting 3
    # here would understate exposure by more than 3x.
    assert result.total_found == 10
    assert result.returned == 3
    assert result.truncated is True
    assert len(result.vulnerabilities) == 3
    assert result.vulnerabilities[0].id == "GHSA-7"


@pytest.mark.parametrize("ecosystem,package", [("", "django"), ("  ", "django"), ("PyPI", ""), ("PyPI", "   ")])
def test_blank_input_raises_value_error(ecosystem: str, package: str) -> None:
    """Caller error is raised before any network I/O, so the CLI can exit 4."""
    osv = MagicMock()
    svc = PackageService(osv_client=osv, cveorg_client=MagicMock())
    with pytest.raises(ValueError):
        svc.discover_package(ecosystem, package)
    osv.query.assert_not_called()


def test_empty_result_is_reported_as_empty_not_as_failure() -> None:
    svc = _service([])
    result = svc.discover_package("PyPI", "django")
    assert result.total_found == 0
    assert result.vulnerabilities == []
    assert result.search_sources == ["osv"]


# ---------------------------------------------------------------------------
# Enrichment and failure taxonomy
# ---------------------------------------------------------------------------

def test_enrichment_attaches_epss_and_kev_and_is_recorded_in_sources() -> None:
    svc = _service(
        [_record("GHSA-a", cve="CVE-2021-44228", vector=V3_CRITICAL, fixed=["2.15.0"])],
        epss={"CVE-2021-44228": 99.99},
        kev={"CVE-2021-44228"},
    )
    result = svc.discover_package("PyPI", "django")
    vuln = result.vulnerabilities[0]
    assert (vuln.epss, vuln.kev_status) == (99.99, True)
    assert result.search_sources == ["osv", "epss", "cisa_kev"]


def test_enrich_false_skips_the_catalogues_entirely() -> None:
    osv = MagicMock()
    osv.query.return_value = [_record("GHSA-a", cve="CVE-1", vector=V3_HIGH, fixed=["1"])]
    cveorg = MagicMock()
    svc = PackageService(osv_client=osv, cveorg_client=cveorg)
    result = svc.discover_package("PyPI", "django", enrich=False)
    cveorg.epss_scores.assert_not_called()
    assert result.search_sources == ["osv"]


def test_failed_enrichment_degrades_but_still_returns_results() -> None:
    """Losing the ranking signal is survivable; losing the answer is not."""
    osv = MagicMock()
    osv.query.return_value = [_record("GHSA-a", cve="CVE-1", vector=V3_HIGH, fixed=["1"])]
    cveorg = MagicMock()
    cveorg.epss_scores.side_effect = RuntimeError("epss feed down")
    svc = PackageService(osv_client=osv, cveorg_client=cveorg)
    result = svc.discover_package("PyPI", "django")
    assert result.total_found == 1
    assert result.vulnerabilities[0].epss is None
    assert "epss" not in result.search_sources


@pytest.mark.parametrize("exc", [OfflineError("cache miss"), RateLimitError("429", status_code=429)])
def test_upstream_failures_propagate_from_the_query(exc: Exception) -> None:
    osv = MagicMock()
    osv.query.side_effect = exc
    svc = PackageService(osv_client=osv, cveorg_client=MagicMock())
    with pytest.raises(type(exc)):
        svc.discover_package("PyPI", "django")


@pytest.mark.parametrize("exc", [OfflineError("cache miss"), RateLimitError("429", status_code=429)])
def test_upstream_failures_propagate_from_enrichment(exc: Exception) -> None:
    """An offline EPSS miss is an upstream failure, not a missing score."""
    osv = MagicMock()
    osv.query.return_value = [_record("GHSA-a", cve="CVE-1", vector=V3_HIGH, fixed=["1"])]
    cveorg = MagicMock()
    cveorg.epss_scores.side_effect = exc
    svc = PackageService(osv_client=osv, cveorg_client=cveorg)
    with pytest.raises(type(exc)):
        svc.discover_package("PyPI", "django")


def test_programming_errors_are_never_swallowed_by_enrichment() -> None:
    osv = MagicMock()
    osv.query.return_value = [_record("GHSA-a", cve="CVE-1", vector=V3_HIGH, fixed=["1"])]
    cveorg = MagicMock()
    cveorg.epss_scores.side_effect = TypeError("signature drift")
    svc = PackageService(osv_client=osv, cveorg_client=cveorg)
    with pytest.raises(TypeError):
        svc.discover_package("PyPI", "django")


def test_close_releases_both_clients() -> None:
    osv, cveorg = MagicMock(), MagicMock()
    with PackageService(osv_client=osv, cveorg_client=cveorg):
        pass
    osv.close.assert_called_once()
    cveorg.close.assert_called_once()


def test_withdrawn_advisories_are_excluded() -> None:
    """A retracted advisory beside live findings is a false positive."""
    withdrawn = _record("GHSA-gone", cve="CVE-1", vector=V3_CRITICAL, fixed=["1"])
    withdrawn["withdrawn"] = "2022-06-01T17:40:51Z"
    svc = _service([withdrawn, _record("GHSA-live", cve="CVE-2", vector=V3_HIGH, fixed=["2"])])
    result = svc.discover_package("PyPI", "django", enrich=False)
    assert [v.id for v in result.vulnerabilities] == ["GHSA-live"]


def test_untruncated_result_is_not_flagged_as_truncated() -> None:
    svc = _service([_record("GHSA-a", cve="CVE-1", vector=V3_HIGH, fixed=["1"])])
    result = svc.discover_package("PyPI", "django", limit=100, enrich=False)
    assert (result.total_found, result.returned, result.truncated) == (1, 1, False)


def test_missing_epss_does_not_sink_a_critical_below_a_trivial_finding() -> None:
    """Treating an absent EPSS as -1 ranked a CRITICAL under a LOW with EPSS 0.1."""
    svc = _service(
        [
            _record("GHSA-crit-noepss", cve="CVE-NOEPSS", vector=V3_CRITICAL, fixed=["1"]),
            _record("GHSA-low-tiny-epss", cve="CVE-TINY", vector=V3_MEDIUM, fixed=["2"]),
        ],
        epss={"CVE-TINY": 0.1},
    )
    order = [v.id for v in svc.discover_package("PyPI", "django").vulnerabilities]
    assert order == ["GHSA-crit-noepss", "GHSA-low-tiny-epss"]


def test_an_unavailable_kev_catalogue_is_not_claimed_as_a_source() -> None:
    """kev_status=False off an empty catalogue understates every finding."""
    osv = MagicMock()
    osv.query.return_value = [_record("GHSA-a", cve="CVE-1", vector=V3_HIGH, fixed=["1"])]
    cveorg = MagicMock()
    cveorg.epss_scores.return_value = {"CVE-1": 50.0}
    cveorg.kev_ids.return_value = set()  # feed failed to load
    result = PackageService(osv_client=osv, cveorg_client=cveorg).discover_package("PyPI", "django")
    assert "epss" in result.search_sources
    assert "cisa_kev" not in result.search_sources


def test_cvss_vector_is_the_one_the_score_came_from() -> None:
    """Showing a 4.0 vector beside a score computed from a 3.x one is misleading."""
    rec = _record("GHSA-both", cve="CVE-1", vector=V3_HIGH, fixed=["1"])
    rec["severity"].insert(0, {"type": "CVSS_V4", "score": V4_ONLY})
    svc = _service([rec])
    vuln = svc.discover_package("PyPI", "django", enrich=False).vulnerabilities[0]
    assert vuln.cvss_score == 7.5
    assert vuln.cvss_vector == V3_HIGH


def test_a_genuinely_elevated_epss_still_outranks_a_higher_cvss() -> None:
    """Banding must not neuter EPSS — that is the whole point of the ranking."""
    svc = _service(
        [
            _record("GHSA-crit-quiet", cve="CVE-QUIET", vector=V3_CRITICAL, fixed=["1"]),
            _record("GHSA-med-hot", cve="CVE-HOT", vector=V3_MEDIUM, fixed=["2"]),
        ],
        epss={"CVE-QUIET": 0.2, "CVE-HOT": 88.0},
    )
    order = [v.id for v in svc.discover_package("PyPI", "django").vulnerabilities]
    assert order == ["GHSA-med-hot", "GHSA-crit-quiet"]
