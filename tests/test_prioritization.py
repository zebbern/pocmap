"""Native offline tests for the vulnerability prioritization engine.

``pocmap.bugbounty.prioritization`` is a pure, network-free scoring module, but
until now only ``_get_epss_score`` had native coverage (in ``test_epss_scale``).
These tests exercise the public surface — ``_has_public_exploit``,
``prioritize_cves``, ``get_priority_tiers`` and ``calculate_bounty_potential`` —
using the module's FLAT-dict input contract (``cvss_score``/``base_score`` +
``epss``, not nested ``cvss.base_score``) and ``SimpleNamespace`` models.

The ``_has_public_exploit`` cases pin the regression where a raw dict carrying an
explicit ``github_poc_count: None`` made ``None > 0`` raise ``TypeError`` (a
programming-error type that is not swallowed and crashed the whole run).
"""

from __future__ import annotations

from types import SimpleNamespace

from pocmap.bugbounty.prioritization import (
    _has_public_exploit,
    calculate_bounty_potential,
    get_priority_tiers,
    prioritize_cves,
)

# ---------------------------------------------------------------------------
# _has_public_exploit — regression: github_poc_count is an explicit None
# ---------------------------------------------------------------------------

def test_has_public_exploit_none_poc_count_returns_bool_not_raise():
    # dict.get returns the stored None (not the default) when the key exists,
    # so the old ``None > 0`` raised TypeError. Must degrade to a plain bool.
    result = _has_public_exploit({"id": "CVE-2021-44228", "github_poc_count": None})
    assert result is False


def test_has_public_exploit_positive_poc_count():
    assert _has_public_exploit({"id": "CVE-2021-44228", "github_poc_count": 3}) is True


def test_has_public_exploit_no_signals():
    assert _has_public_exploit({"id": "CVE-2000-0001"}) is False


def test_has_public_exploit_via_exploit_list():
    assert _has_public_exploit({"id": "CVE-2000-0002", "exploits": ["poc"]}) is True


# ---------------------------------------------------------------------------
# prioritize_cves — ordering
# ---------------------------------------------------------------------------

def test_prioritize_cves_orders_critical_kev_above_low():
    critical = {
        "id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "epss": 95,          # flat-dict contract: >1 is treated as a percentage
        "kev_listed": True,
        "github_poc_count": 5,
    }
    low = {"id": "CVE-2000-0001", "cvss_score": 2.0}

    ordered = prioritize_cves([low, critical], strategy="composite")

    assert [c["id"] for c in ordered] == ["CVE-2021-44228", "CVE-2000-0001"]
    assert ordered[0]["priority_score"] > ordered[1]["priority_score"]


def test_prioritize_cves_adds_priority_score():
    ordered = prioritize_cves([{"id": "CVE-2000-0001", "cvss_score": 7.5}], strategy="cvss")
    assert "priority_score" in ordered[0]


# ---------------------------------------------------------------------------
# get_priority_tiers — bucketing
# ---------------------------------------------------------------------------

def test_get_priority_tiers_buckets_into_p0_through_p4():
    cves = [
        {"id": "CVE-A", "priority_score": 95},
        {"id": "CVE-B", "priority_score": 80},
        {"id": "CVE-C", "priority_score": 65},
        {"id": "CVE-D", "priority_score": 45},
        {"id": "CVE-E", "priority_score": 10},
    ]
    tiers = get_priority_tiers(cves)

    assert set(tiers) == {
        "p0_drop_everything",
        "p1_act_today",
        "p2_act_this_week",
        "p3_plan_for",
        "p4_monitor",
    }
    assert tiers["p0_drop_everything"][0]["id"] == "CVE-A"
    assert tiers["p1_act_today"][0]["id"] == "CVE-B"
    assert tiers["p2_act_this_week"][0]["id"] == "CVE-C"
    assert tiers["p3_plan_for"][0]["id"] == "CVE-D"
    assert tiers["p4_monitor"][0]["id"] == "CVE-E"


# ---------------------------------------------------------------------------
# calculate_bounty_potential — insufficient data for RESERVED/REJECTED
# ---------------------------------------------------------------------------

def test_calculate_bounty_potential_reserved_is_insufficient_data():
    result = calculate_bounty_potential({"id": "CVE-2099-9999", "state": "RESERVED"})
    assert result["estimated_range_usd"] == "N/A (insufficient data)"
    assert result["estimated_median"] == 0


def test_calculate_bounty_potential_reserved_enum_state():
    # ``state`` carries a CVEState-style enum whose ``.name`` is RESERVED; the
    # module reads it via ``getattr(state, "name", str(state))``.
    reserved = {"id": "CVE-2099-9998", "state": SimpleNamespace(name="RESERVED")}
    result = calculate_bounty_potential(reserved)
    assert result["estimated_range_usd"] == "N/A (insufficient data)"


def test_calculate_bounty_potential_critical_has_range():
    result = calculate_bounty_potential(
        {"id": "CVE-2021-44228", "cvss_score": 9.8, "github_poc_count": 3, "state": "PUBLISHED"}
    )
    assert result["severity"] == "Critical"
    assert result["estimated_high"] > 0
