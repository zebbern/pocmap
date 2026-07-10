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

import mcp_server
from pocmap.bugbounty.prioritization import _get_epss_score

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
