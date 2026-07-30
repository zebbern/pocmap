"""Offline native tests for ProductDiscoveryService pure logic.

Regression guards (not a spec) for the fully offline-testable helpers:
``parse_version``, ``normalize_product``, the static ``_cpe_version_matches``,
and ``match_cves_to_product`` bucketing. None of these touch the network.
"""

from __future__ import annotations

from pocmap.models import CPEInfo, CVEInfo, VersionConstraint
from pocmap.services.product_service import ProductDiscoveryService

svc = ProductDiscoveryService()


# ---------------------------------------------------------------------------
# parse_version
# ---------------------------------------------------------------------------

def test_parse_version_none_empty_and_unparseable_return_none() -> None:
    assert svc.parse_version(None) is None
    assert svc.parse_version("") is None
    assert svc.parse_version("   ") is None
    assert svc.parse_version("latest") is None


def test_parse_version_wildcard() -> None:
    vc = svc.parse_version("2.x")
    assert vc is not None
    assert vc.is_wildcard is True
    assert vc.major == 2
    assert vc.minor == "x"


def test_parse_version_strips_v_prefix_exact() -> None:
    vc = svc.parse_version("v2.14.1")
    assert vc is not None
    assert vc.major == 2
    assert vc.minor == 14
    assert vc.patch == 1
    assert vc.is_wildcard is False
    assert vc.raw == "2.14.1"


def test_parse_version_range_operator() -> None:
    vc = svc.parse_version(">= 2.0")
    assert vc is not None
    assert vc.range_op == ">="
    assert vc.major == 2
    assert vc.minor == 0


# ---------------------------------------------------------------------------
# normalize_product
# ---------------------------------------------------------------------------

def test_normalize_product_struts_case_insensitive() -> None:
    vendor, product = svc.normalize_product("STRUTS")
    assert vendor == "apache"
    assert product == "apache struts"


def test_normalize_product_unknown_passes_through_lowercased() -> None:
    vendor, product = svc.normalize_product("unknown_product_12345")
    assert vendor is None
    assert product == "unknown_product_12345"


# ---------------------------------------------------------------------------
# _cpe_version_matches (static)
# ---------------------------------------------------------------------------

def _cpe(version: str) -> CPEInfo:
    return CPEInfo.parse(f"cpe:2.3:a:apache:struts:{version}:*:*:*:*:*:*:*")


def test_cpe_version_matches_wildcard() -> None:
    vc = svc.parse_version("2.x")
    assert vc is not None
    assert ProductDiscoveryService._cpe_version_matches(_cpe("2.5"), vc) is True
    assert ProductDiscoveryService._cpe_version_matches(_cpe("3.0"), vc) is False


def test_cpe_version_matches_range() -> None:
    vc = svc.parse_version(">= 2.0")
    assert vc is not None
    assert ProductDiscoveryService._cpe_version_matches(_cpe("2.5"), vc) is True
    assert ProductDiscoveryService._cpe_version_matches(_cpe("1.9"), vc) is False


def test_cpe_version_matches_exact() -> None:
    vc = svc.parse_version("2.14.1")
    assert vc is not None
    assert ProductDiscoveryService._cpe_version_matches(_cpe("2.14.1"), vc) is True
    assert ProductDiscoveryService._cpe_version_matches(_cpe("2.15.0"), vc) is False


def test_cpe_version_matches_permissive_on_wildcard_cpe() -> None:
    vc = svc.parse_version("2.14.1")
    assert vc is not None
    # A CPE whose version is "*" or "-" is permissive -- matches anything.
    assert ProductDiscoveryService._cpe_version_matches(_cpe("*"), vc) is True
    assert ProductDiscoveryService._cpe_version_matches(_cpe("-"), vc) is True


# ---------------------------------------------------------------------------
# match_cves_to_product (bucketing)
# ---------------------------------------------------------------------------

def test_match_cves_to_product_buckets_by_confidence() -> None:
    confirmed = CVEInfo(id="CVE-2024-0001", vendor="apache", product="struts")
    possible = CVEInfo(id="CVE-2024-0002", vendor="apache", product="tomcat")
    unknown = CVEInfo(id="CVE-2024-0003")

    vc = svc.parse_version("2.x")
    result = svc.match_cves_to_product(
        [confirmed, possible, unknown],
        product="struts",
        version_constraint=vc,
        vendor="apache",
    )
    assert [c.id for c in result.confirmed_affected] == ["CVE-2024-0001"]
    assert [c.id for c in result.possibly_affected] == ["CVE-2024-0002"]
    assert [c.id for c in result.not_enough_data] == ["CVE-2024-0003"]


def test_match_cves_to_product_no_constraint_confirms_on_vendor_and_product() -> None:
    confirmed = CVEInfo(id="CVE-2024-0010", vendor="apache", product="struts")
    result = svc.match_cves_to_product(
        [confirmed],
        product="struts",
        version_constraint=None,
        vendor="apache",
    )
    assert [c.id for c in result.confirmed_affected] == ["CVE-2024-0010"]


def test_version_constraint_type_round_trips() -> None:
    # Guard the model default: an empty constraint has no parts and no range op.
    vc = VersionConstraint(raw="")
    assert vc.major is None
    assert vc.range_op is None
    assert vc.is_wildcard is False
