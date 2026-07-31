"""Live checks that pocmap's upstream URLs still resolve.

These are ``network``-marked and excluded from the default offline run. They
exist because the entire rest of the suite mocks the HTTP layer, which means a
URL can be **completely dead** and every test still passes.

That is not hypothetical. ``CVE_ORG_GIT_RAW`` was missing the ``/cves`` path
segment, so every CVE.org record fetch 404'd, ``get_cve_record()`` silently fell
through to the CVE AWG API, and ``vendor`` / ``product`` / ``cwes`` /
``publication_date`` came back empty for **every CVE in the catalogue** — while
895 mocked tests stayed green. Run these when touching config URLs:

    pytest tests/test_upstream_urls.py -m network
"""

from __future__ import annotations

import pytest
import requests

from pocmap.config import (
    CISA_KEV_URL,
    CVE_ORG_GIT_RAW,
    EPSS_CSV_URL,
    NVD_API_BASE,
    NVD_CPE_API_BASE,
    OSV_API_BASE,
    settings,
)

pytestmark = pytest.mark.network

_TIMEOUT = 90


def _head_ok(url: str, **kwargs: object) -> requests.Response:
    return requests.get(url, timeout=_TIMEOUT, headers=settings.default_headers, **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "cve_id,year,batch",
    [("CVE-2021-44228", "2021", "44xxx"), ("CVE-2024-3094", "2024", "3xxx")],
)
def test_cve_org_record_url_resolves_and_carries_real_fields(
    cve_id: str, year: str, batch: str
) -> None:
    """The exact URL the client builds must 200 AND contain the parsed fields.

    Asserting only on the status code would not have caught the original bug's
    twin — a 200 that returns something the parser cannot read is equally dead.
    """
    resp = _head_ok(f"{CVE_ORG_GIT_RAW}/{year}/{batch}/{cve_id}.json")
    assert resp.status_code == 200, (
        f"{cve_id} record 404s — CVE_ORG_GIT_RAW is wrong. Records live under "
        f"cvelistV5/cves/<year>/<batch>/. Got: {resp.url}"
    )
    data = resp.json()
    assert data["cveMetadata"]["datePublished"], "no datePublished to parse"
    cna = data["containers"]["cna"]
    affected = cna.get("affected") or []
    assert any(a.get("product") or a.get("packageName") for a in affected), (
        "no affected entry names a product or packageName"
    )
    assert cna.get("problemTypes"), "no problemTypes — cwes would come back empty"


def test_nvd_cve_api_resolves() -> None:
    resp = _head_ok(NVD_API_BASE, params={"cveId": "CVE-2021-44228"})
    assert resp.status_code in (200, 403, 429), f"NVD CVE API unexpected: {resp.status_code}"
    if resp.status_code == 200:
        assert resp.json()["vulnerabilities"], "NVD returned no record for Log4Shell"


def test_nvd_cpe_dictionary_resolves() -> None:
    resp = _head_ok(NVD_CPE_API_BASE, params={"keywordSearch": "nginx", "resultsPerPage": 1})
    assert resp.status_code in (200, 403, 429)


def test_osv_api_resolves_and_returns_advisories() -> None:
    resp = requests.post(
        f"{OSV_API_BASE}/query",
        json={"package": {"name": "django", "ecosystem": "PyPI"}},
        timeout=_TIMEOUT,
    )
    assert resp.status_code == 200
    assert resp.json().get("vulns"), "OSV returned nothing for PyPI/django"


def test_cisa_kev_feed_resolves_and_is_populated() -> None:
    resp = _head_ok(CISA_KEV_URL)
    assert resp.status_code == 200
    vulns = resp.json()["vulnerabilities"]
    assert len(vulns) > 1000, f"KEV catalogue implausibly small ({len(vulns)})"


def test_epss_bulk_feed_resolves() -> None:
    """A dead EPSS feed silently degrades to one API call per CVE."""
    resp = _head_ok(EPSS_CSV_URL, stream=True)
    assert resp.status_code == 200, f"EPSS bulk feed dead: {EPSS_CSV_URL}"
    resp.close()
