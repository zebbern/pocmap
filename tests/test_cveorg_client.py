"""Native offline tests for :class:`pocmap.clients.cveorg_client.CVEOrgClient`.

These lock the CVE.org / CISA-KEV / EPSS parse contracts with no network I/O by
calling methods on canned dicts and seeding the in-memory caches directly. They
cover:

  * ``_extract_cvss_from_metrics`` CVSS v2 severity *derivation* (computed from
    the base score, not passed through).
  * ``_extract_cwes`` extraction paths: direct ``cweId``, ``CWE-NNN`` regex
    fallback from a description, ADP fallback when the CNA has none, and
    deterministic **first-seen** de-duplication (the ``list(dict.fromkeys(...))``
    fix — previously ``list(set(...))`` which was hash-seed dependent).
  * ``get_epss`` truncation math at source (``math.trunc(epss * 10000) / 100``).
  * ``is_kev`` case-insensitive ``cveID`` matching.
"""

from __future__ import annotations

from typing import Any

from pocmap.clients.cveorg_client import CVEOrgClient


class _FakeHTTP:
    """Inert stand-in for :class:`HTTPClient`; these tests never hit it."""

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _client() -> CVEOrgClient:
    return CVEOrgClient(http_client=_FakeHTTP())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _extract_cvss_from_metrics — CVSS v2 severity derivation thresholds
# ---------------------------------------------------------------------------


def _v2_severity(score: float) -> Any:
    record: dict[str, Any] = {}
    _client()._extract_cvss_from_metrics(
        record, {"cvssV2_0": {"baseScore": score, "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}
    )
    return record["severity"]


def test_v2_severity_low_threshold() -> None:
    assert _v2_severity(3.9) == "LOW"


def test_v2_severity_medium_threshold() -> None:
    assert _v2_severity(6.9) == "MEDIUM"


def test_v2_severity_high_threshold() -> None:
    assert _v2_severity(7.0) == "HIGH"


def test_v3_severity_passthrough_not_derived() -> None:
    """v3.x severity is taken verbatim from ``baseSeverity`` (not recomputed)."""
    record: dict[str, Any] = {}
    _client()._extract_cvss_from_metrics(
        record,
        {"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "V31"}},
    )
    assert record["cvss_version"] == "3.1"
    assert record["severity"] == "CRITICAL"
    assert record["base_score"] == 9.8


# ---------------------------------------------------------------------------
# _extract_cwes — direct id, regex fallback, ADP fallback, dedupe ordering
# ---------------------------------------------------------------------------


def test_extract_cwes_direct_cwe_id() -> None:
    cna = {"problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}]}
    assert _client()._extract_cwes(cna, []) == ["CWE-79"]


def test_extract_cwes_regex_from_description() -> None:
    cna = {"problemTypes": [{"descriptions": [{"description": "Classic CWE-120 buffer overflow"}]}]}
    assert _client()._extract_cwes(cna, []) == ["CWE-120"]


def test_extract_cwes_adp_fallback_when_cna_empty() -> None:
    cna = {"problemTypes": []}
    adps = [{"problemTypes": [{"descriptions": [{"cweId": "CWE-22"}]}]}]
    assert _client()._extract_cwes(cna, adps) == ["CWE-22"]


def test_extract_cwes_dedupe_preserves_first_seen_order() -> None:
    cna = {
        "problemTypes": [
            {
                "descriptions": [
                    {"cweId": "CWE-89"},
                    {"cweId": "CWE-79"},
                    {"cweId": "CWE-89"},
                ]
            }
        ]
    }
    assert _client()._extract_cwes(cna, []) == ["CWE-89", "CWE-79"]


# ---------------------------------------------------------------------------
# get_epss — truncation math at source (via seeded cache, no network)
# ---------------------------------------------------------------------------


def test_get_epss_truncates_high_score() -> None:
    client = _client()
    client._epss_cache = [{"cve": "CVE-2021-44228", "epss": "0.9753"}]
    assert client.get_epss("CVE-2021-44228") == 97.53


def test_get_epss_truncates_tiny_score() -> None:
    client = _client()
    client._epss_cache = [{"cve": "CVE-2000-0001", "epss": "0.00023"}]
    assert client.get_epss("CVE-2000-0001") == 0.02


def test_get_epss_case_insensitive_lookup() -> None:
    client = _client()
    client._epss_cache = [{"cve": "CVE-2021-44228", "epss": "0.5000"}]
    assert client.get_epss("cve-2021-44228") == 50.0


# ---------------------------------------------------------------------------
# is_kev — case-insensitive cveID matching (via seeded cache)
# ---------------------------------------------------------------------------


def test_is_kev_case_insensitive_hit() -> None:
    client = _client()
    client._kev_cache = [{"cveID": "CVE-2021-44228", "product": "Log4j"}]
    found, record = client.is_kev("cve-2021-44228")
    assert found is True
    assert record is not None
    assert record["cveID"] == "CVE-2021-44228"


def test_is_kev_miss_returns_none() -> None:
    client = _client()
    client._kev_cache = [{"cveID": "CVE-2021-44228"}]
    found, record = client.is_kev("CVE-9999-0000")
    assert found is False
    assert record is None
