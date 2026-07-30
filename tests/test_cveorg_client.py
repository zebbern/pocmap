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

import pytest

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


# ---------------------------------------------------------------------------
# EPSS bulk feed — indexed lookup and header handling
# ---------------------------------------------------------------------------
#
# The bulk feed had been dead: EPSS_CSV_URL pointed at a file that 404'd, so
# every score silently fell through to the per-CVE FIRST API — one HTTP request
# per CVE. These pin the two things that make the bulk path work.


def _seed_epss(client: CVEOrgClient, text: str) -> None:
    """Load *text* through the real CSV parsing path, without the network."""
    import csv as _csv

    rows = [line for line in text.splitlines() if not line.startswith("#")]
    client._epss_cache = list(_csv.DictReader(rows))
    client._epss_index = None


def test_epss_csv_metadata_comment_is_not_treated_as_the_header() -> None:
    """The feed opens with '#model_version:...'; DictReader would eat it as the header."""
    client = _client()
    _seed_epss(
        client,
        "#model_version:v2026.06.15,score_date:2026-07-30T12:03:05Z\n"
        "cve,epss,percentile\n"
        "CVE-2021-44228,0.94355,0.99943\n",
    )
    assert client.get_epss("CVE-2021-44228") == 94.35


def test_epss_lookup_is_indexed_not_scanned() -> None:
    """Scoring N CVEs must not cost N scans of a ~354k-row catalogue."""
    client = _client()
    rows = "\n".join(f"CVE-2021-{i},0.5,0.9" for i in range(1000))
    _seed_epss(client, f"cve,epss,percentile\n{rows}\n")
    index = client._ensure_epss_index()
    assert len(index) == 1000
    assert index["CVE-2021-500"] == 50.0
    # Built once and reused, not rebuilt per call.
    assert client._ensure_epss_index() is index


def test_epss_index_skips_unparseable_rows_without_losing_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client()
    # An index miss falls back to the per-CVE FIRST API; stub it so this stays
    # offline and so the assertion is about the index, not about the network.
    monkeypatch.setattr(CVEOrgClient, "_get_epss_from_api", lambda self, cve: None)
    _seed_epss(
        client,
        "cve,epss,percentile\n"
        "CVE-1111-1111,not-a-number,0.5\n"
        "CVE-2021-44228,0.94355,0.99\n",
    )
    assert client._ensure_epss_index() == {"CVE-2021-44228": 94.35}
    assert client.get_epss("CVE-1111-1111") is None
    assert client.get_epss("CVE-2021-44228") == 94.35
