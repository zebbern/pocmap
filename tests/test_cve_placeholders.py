"""CNA placeholder handling and the NVD gap-filling fallback.

A CNA may file a record with literal ``"n/a"`` for vendor and product. Measured
across a 180-CVE sample from cvelistV5, **12%** do. pocmap used to print that
verbatim, so a CRITICAL 9.8 command injection showed "n/a / n/a" — while NVD
knew the answer (CVE-2026-26832 is ``zapolnoch:tesseract_ocr`` there).

Fully offline: both upstream clients are mocks.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from pocmap.models import CVSSScore
from pocmap.services.cve_service import (
    CVEService,
    _affected_from_nvd,
    _blank_to_none,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("n/a", None), ("N/A", None), ("na", None), ("NA", None),
        ("unknown", None), ("Unknown", None), ("not applicable", None),
        ("-", None), ("", None), ("   ", None), (None, None), (123, None),
        ("Apache", "Apache"), ("  Apache  ", "Apache"),
        ("nasa", "nasa"),        # must not be eaten by the "na" placeholder
        ("Unknown Corp", "Unknown Corp"),
    ],
)
def test_blank_to_none_collapses_only_real_placeholders(raw: Any, expected: str | None) -> None:
    assert _blank_to_none(raw) == expected


def test_affected_from_nvd_extracts_pairs_in_order_without_duplicates() -> None:
    record = {
        "configurations": [
            {"nodes": [{"cpeMatch": [
                {"criteria": "cpe:2.3:a:zapolnoch:tesseract_ocr:*:*:*:*:*:node.js:*:*"},
                {"criteria": "cpe:2.3:a:zapolnoch:tesseract_ocr:1.0:*:*:*:*:*:*:*"},
                {"criteria": "cpe:2.3:o:redhat:enterprise_linux:9:*:*:*:*:*:*:*"},
                {"criteria": "malformed"},
                {"criteria": "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"},
            ]}]}
        ]
    }
    assert [(a.vendor, a.product) for a in _affected_from_nvd(record)] == [
        ("zapolnoch", "tesseract_ocr"),
        ("redhat", "enterprise_linux"),
    ]


def _service(cveorg_record: dict[str, Any], nvd_record: dict[str, Any] | None) -> CVEService:
    cveorg = MagicMock()
    cveorg.get_cve_record.return_value = cveorg_record
    cveorg.get_epss.return_value = None
    cveorg.is_kev.return_value = (False, None)
    cveorg.get_references.return_value = {}
    cveorg.get_ransomware_usage.return_value = "N/A"
    cveorg.get_description.return_value = "desc"

    nvd = MagicMock()
    nvd.get_cve.return_value = nvd_record
    nvd.extract_cvss.return_value = CVSSScore(base_score=9.8)
    nvd.extract_cwes.return_value = ["CWE-78"]
    return CVEService(cveorg_client=cveorg, nvd_client=nvd)


_NVD = {
    "configurations": [
        {"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:zapolnoch:tesseract_ocr:*:*:*:*:*:node.js:*:*"}
        ]}]}
    ]
}


def test_na_vendor_and_product_fall_back_to_nvd() -> None:
    """The CVE-2026-26832 case: "n/a / n/a" must not reach the user."""
    svc = _service(
        {"state": "PUBLISHED", "vendor": "n/a", "affected_product": "n/a",
         "affected_products": [], "publication_date": "2026-03-25T00:00:00Z"},
        _NVD,
    )
    info = svc.get_cve_info("CVE-2026-26832")

    assert (info.vendor, info.product) == ("zapolnoch", "tesseract_ocr")
    assert [(a.vendor, a.product) for a in info.affected_products] == [
        ("zapolnoch", "tesseract_ocr")
    ]


def test_cve_org_names_win_over_nvd_cpe_slugs() -> None:
    """CVE.org is the authoritative CNA record — NVD supplements, never overwrites.

    The advisory says "Apache Software Foundation / Apache Log4j2"; NVD's CPE
    slug is "apache / log4j2". Showing the slug would be a regression.
    """
    svc = _service(
        {"state": "PUBLISHED", "vendor": "Apache Software Foundation",
         "affected_product": "Apache Log4j2",
         "affected_products": [("Apache Software Foundation", "Apache Log4j2")],
         "publication_date": "2021-12-10T00:00:00Z", "cwe": ["CWE-502"]},
        _NVD,
    )
    info = svc.get_cve_info("CVE-2021-44228")

    assert (info.vendor, info.product) == ("Apache Software Foundation", "Apache Log4j2")
    assert [(a.vendor, a.product) for a in info.affected_products] == [
        ("Apache Software Foundation", "Apache Log4j2")
    ]


def test_no_nvd_request_when_cve_org_answered_everything() -> None:
    """NVD allows 5 requests / 30s unauthenticated — do not spend one needlessly."""
    svc = _service(
        {"state": "PUBLISHED", "vendor": "Apache", "affected_product": "Log4j2",
         "affected_products": [("Apache", "Log4j2")], "cwe": ["CWE-502"],
         "publication_date": "2021-12-10T00:00:00Z",
         "base_score": 10.0, "severity": "CRITICAL", "cvss_version": "3.1"},
        _NVD,
    )
    svc.get_cve_info("CVE-2021-44228")
    svc._nvd.get_cve.assert_not_called()  # type: ignore[attr-defined]


def test_unavailable_nvd_leaves_cve_org_data_intact() -> None:
    """NVD is a supplement here; its failure must not fail the whole lookup."""
    svc = _service(
        {"state": "PUBLISHED", "vendor": "n/a", "affected_product": "n/a",
         "affected_products": [], "publication_date": "2026-03-25T00:00:00Z"},
        None,
    )
    svc._nvd.get_cve.side_effect = RuntimeError("NVD throttled")  # type: ignore[attr-defined]

    info = svc.get_cve_info("CVE-2026-26832")

    assert info.id == "CVE-2026-26832"
    assert (info.vendor, info.product) == ("N/A", "N/A")
