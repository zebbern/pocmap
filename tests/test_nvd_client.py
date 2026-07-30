"""Native offline tests for :class:`pocmap.clients.nvd_client.NVDClient`.

These lock the NVD parse contracts without any network I/O by injecting a fake
HTTP client (mirroring the ``_FakeResponse``/stub pattern in
``tests/test_offline.py``). They cover:

  * ``extract_cvss`` version precedence (v4.0 > v3.1 > v3.0 > v2.0) and the
    empty-metrics default.
  * ``extract_cwes`` filtering, de-duplication, and deterministic **first-seen**
    ordering (the ``list(dict.fromkeys(...))`` fix — previously ``list(set(...))``
    which was non-deterministic across ``PYTHONHASHSEED``).
  * ``get_cpe_affected`` walking configurations -> nodes -> cpeMatch -> criteria.
  * ``get_cve`` error semantics: ``OfflineError`` is re-raised (not swallowed), a
    generic ``HTTPError`` degrades to ``None``, and ``totalResults == 0`` is
    ``None``.
"""

from __future__ import annotations

from typing import Any

import pytest

from pocmap.clients.nvd_client import NVDClient
from pocmap.models import CVSSVersion, Severity
from pocmap.utils.http import HTTPError, OfflineError, RateLimitError


class _FakeHTTP:
    """Minimal stand-in for :class:`HTTPClient` used by ``NVDClient``.

    Either returns a canned ``get_json`` payload or raises a configured
    exception. Records ``close()`` so context-manager use stays verifiable.
    """

    def __init__(
        self,
        *,
        json_result: Any = None,
        raise_exc: Exception | None = None,
    ) -> None:
        self.json_result = json_result
        self.raise_exc = raise_exc
        self.closed = False

    def get_json(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        **_: Any,
    ) -> Any:
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.json_result

    def close(self) -> None:
        self.closed = True


def _wrap(cve_record: dict[str, Any]) -> dict[str, Any]:
    """Wrap a raw ``cve`` record in the NVD envelope ``get_cve`` unpacks."""
    return {"totalResults": 1, "vulnerabilities": [{"cve": cve_record}]}


# ---------------------------------------------------------------------------
# extract_cvss — version precedence + empty default
# ---------------------------------------------------------------------------


def test_extract_cvss_prefers_v31_over_v2() -> None:
    client = NVDClient(http_client=_FakeHTTP())
    data = {
        "metrics": {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "V31"}}
            ],
            "cvssMetricV2": [
                {"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM", "vectorString": "V2"}}
            ],
        }
    }
    cvss = client.extract_cvss(data)
    assert cvss.version == CVSSVersion.V3_1
    assert cvss.base_score == 9.8
    assert cvss.severity == Severity.CRITICAL


def test_extract_cvss_v40_beats_all() -> None:
    client = NVDClient(http_client=_FakeHTTP())
    data = {
        "metrics": {
            "cvssMetricV40": [
                {"cvssData": {"baseScore": 7.7, "baseSeverity": "HIGH", "vectorString": "V40"}}
            ],
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "V31"}}
            ],
            "cvssMetricV2": [
                {"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM", "vectorString": "V2"}}
            ],
        }
    }
    cvss = client.extract_cvss(data)
    assert cvss.version == CVSSVersion.V4_0
    assert cvss.base_score == 7.7


def test_extract_cvss_empty_metrics_is_default() -> None:
    client = NVDClient(http_client=_FakeHTTP())
    cvss = client.extract_cvss({})
    assert cvss.version == CVSSVersion.UNKNOWN
    assert cvss.base_score is None
    assert cvss.severity == Severity.UNKNOWN
    assert cvss.vector_string is None


def test_extract_cvss_empty_metric_list_falls_through() -> None:
    """An empty list for the top version must not be selected (truthiness guard)."""
    client = NVDClient(http_client=_FakeHTTP())
    data = {
        "metrics": {
            "cvssMetricV40": [],
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "V31"}}
            ],
        }
    }
    cvss = client.extract_cvss(data)
    assert cvss.version == CVSSVersion.V3_1
    assert cvss.base_score == 9.8


# ---------------------------------------------------------------------------
# extract_cwes — filter + dedupe + deterministic first-seen order
# ---------------------------------------------------------------------------


def test_extract_cwes_filters_dedupes_and_preserves_first_seen_order() -> None:
    client = NVDClient(http_client=_FakeHTTP())
    data = {
        "weaknesses": [
            {"description": [{"value": "CWE-79"}, {"value": "NVD-CWE-noinfo"}]},
            {"description": [{"value": "CWE-89"}, {"value": "CWE-79"}]},
        ]
    }
    # Non-'CWE-' values dropped; 'CWE-79' de-duped; exact first-seen order.
    assert client.extract_cwes(data) == ["CWE-79", "CWE-89"]


def test_extract_cwes_empty_when_no_weaknesses() -> None:
    client = NVDClient(http_client=_FakeHTTP())
    assert client.extract_cwes({}) == []


# ---------------------------------------------------------------------------
# get_cpe_affected — walk configurations -> nodes -> cpeMatch -> criteria
# ---------------------------------------------------------------------------


def test_get_cpe_affected_walks_nested_configurations() -> None:
    cpe = "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"
    record = {"configurations": [{"nodes": [{"cpeMatch": [{"criteria": cpe}]}]}]}
    client = NVDClient(http_client=_FakeHTTP(json_result=_wrap(record)))
    assert client.get_cpe_affected("CVE-2021-44228") == [cpe]


def test_get_cpe_affected_empty_without_configurations() -> None:
    client = NVDClient(http_client=_FakeHTTP(json_result=_wrap({})))
    assert client.get_cpe_affected("CVE-2021-44228") == []


def test_get_cpe_affected_empty_when_cve_absent() -> None:
    client = NVDClient(http_client=_FakeHTTP(json_result={"totalResults": 0}))
    assert client.get_cpe_affected("CVE-9999-0000") == []


# ---------------------------------------------------------------------------
# get_cve — error semantics
# ---------------------------------------------------------------------------


def test_get_cve_offline_error_propagates() -> None:
    client = NVDClient(http_client=_FakeHTTP(raise_exc=OfflineError("offline: no cache")))
    with pytest.raises(OfflineError):
        client.get_cve("CVE-2021-44228")


def test_get_cve_http_error_degrades_to_none() -> None:
    client = NVDClient(http_client=_FakeHTTP(raise_exc=HTTPError("boom", status_code=503)))
    assert client.get_cve("CVE-2021-44228") is None


def test_get_cve_rate_limit_propagates() -> None:
    """A throttled NVD (429/403) must surface, not degrade to None.

    ``RateLimitError`` subclasses ``HTTPError`` but must be re-raised so the CLI
    can map it to UPSTREAM_ERROR (exit 5) rather than swallow it to NO_RESULTS.
    """
    client = NVDClient(
        http_client=_FakeHTTP(raise_exc=RateLimitError("throttled", status_code=429))
    )
    with pytest.raises(RateLimitError):
        client.get_cve("CVE-2021-44228")


def test_get_cve_zero_results_is_none() -> None:
    client = NVDClient(http_client=_FakeHTTP(json_result={"totalResults": 0, "vulnerabilities": []}))
    assert client.get_cve("CVE-2021-44228") is None


def test_get_cve_returns_record_on_hit() -> None:
    record = {"id": "CVE-2021-44228", "descriptions": []}
    client = NVDClient(http_client=_FakeHTTP(json_result=_wrap(record)))
    assert client.get_cve("CVE-2021-44228") == record
