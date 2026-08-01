"""Regression tests for EPSS 0-100 -> 0-1 conversion (guards a 100x bug).

``CVEInfo.epss`` is stored on a 0-100 percentage scale. Two independent
consumers must divide by 100 to expose a 0-1 probability:

  * ``mcp_server.ServiceAdapter._normalize_cve_info`` -> ``epss_score``
  * ``pocmap.bugbounty.prioritization._get_epss_score``

A previous magnitude-guessing heuristic mis-scaled any CVE whose EPSS
percentage was <= 1 (e.g. 0.23% became 0.23 instead of 0.0023). These tests
lock in the correct division. Fully offline -- no services or network.
"""

from __future__ import annotations

import math
from types import SimpleNamespace

import pocmap.mcp_server as mcp_server
from pocmap.bugbounty.prioritization import _get_epss_score
from pocmap.models import (
    CVEInfo,
    CVSSScore,
    CVSSVersion,
    ExploitSource,
    RecentExploitResult,
    Severity,
)

# ---------------------------------------------------------------------------
# ServiceAdapter._normalize_cve_info
# ---------------------------------------------------------------------------

def test_normalize_scales_small_epss():
    info = SimpleNamespace(epss=0.23)
    out = mcp_server.ServiceAdapter._normalize_cve_info(info)
    assert math.isclose(out["epss_score"], 0.0023, rel_tol=1e-9, abs_tol=1e-12)


def test_normalize_scales_high_epss():
    info = SimpleNamespace(epss=97.5)
    out = mcp_server.ServiceAdapter._normalize_cve_info(info)
    assert math.isclose(out["epss_score"], 0.975, rel_tol=1e-9)


def test_normalize_epss_none_stays_none():
    info = SimpleNamespace(epss=None)
    out = mcp_server.ServiceAdapter._normalize_cve_info(info)
    assert out["epss_score"] is None


# ---------------------------------------------------------------------------
# prioritization._get_epss_score
# ---------------------------------------------------------------------------

def test_prioritization_scales_small_epss():
    assert math.isclose(_get_epss_score(SimpleNamespace(epss=0.5)), 0.005, rel_tol=1e-9)


def test_prioritization_scales_high_epss():
    assert math.isclose(_get_epss_score(SimpleNamespace(epss=97.5)), 0.975, rel_tol=1e-9)


# ---------------------------------------------------------------------------
# The 0-100 -> 0-1 divide must not leak binary float noise into the payload
# ---------------------------------------------------------------------------

def test_normalize_rounds_away_float_noise():
    """``99.99 / 100`` is ``0.9998999999999999`` in binary floating point.

    That reached MCP clients verbatim as ``epss_score``. EPSS publishes 5
    decimal places, so rounding there is lossless and keeps 12 junk digits out
    of an agent-facing field.
    """
    info = SimpleNamespace(epss=99.99)
    assert mcp_server.ServiceAdapter._normalize_cve_info(info)["epss_score"] == 0.9999


def test_get_epss_rounds_away_float_noise(monkeypatch):
    """``get_epss_score`` divides on a separate path and must round identically."""
    adapter = mcp_server.ServiceAdapter.__new__(mcp_server.ServiceAdapter)
    adapter._cve = SimpleNamespace(  # type: ignore[attr-defined]
        get_cve_info=lambda _cve_id: SimpleNamespace(epss=99.99)
    )
    assert adapter.get_epss("CVE-2021-44228") == 0.9999


def test_rounding_preserves_epss_published_precision():
    """EPSS publishes 5 dp — rounding must not truncate a real value."""
    for pct, expected in [(0.001, 0.00001), (0.023, 0.00023), (12.345, 0.12345)]:
        info = SimpleNamespace(epss=pct)
        assert mcp_server.ServiceAdapter._normalize_cve_info(info)["epss_score"] == expected


# ---------------------------------------------------------------------------
# find_recent_exploits: cve_info must use the same normalizer (not raw dump)
# ---------------------------------------------------------------------------

def test_normalize_recent_result_scales_epss_and_cvss_score_key():
    """Agents must not see cvss.base_score / epss 0-100 from find_recent_exploits."""
    result = RecentExploitResult(
        cve_info=CVEInfo(
            id="CVE-2024-1234",
            epss=45.0,
            cvss=CVSSScore(
                version=CVSSVersion.V3_1,
                base_score=8.8,
                severity=Severity.HIGH,
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            ),
            references={"NVD": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
        ),
        has_poc=True,
        poc_sources=[ExploitSource.GITHUB],
    )
    out = mcp_server.ServiceAdapter._normalize_recent_result(result)
    assert out["cve_info"]["cvss"]["score"] == 8.8
    assert "base_score" not in out["cve_info"]["cvss"]
    assert math.isclose(out["cve_info"]["epss_score"], 0.45, rel_tol=1e-9)
    assert "epss" not in out["cve_info"]
    assert isinstance(out["cve_info"]["references"], list)
    assert out["poc_sources"] == ["github"]
