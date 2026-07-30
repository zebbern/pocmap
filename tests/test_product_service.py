"""Offline native tests for ProductDiscoveryService pure logic.

Regression guards (not a spec) for the fully offline-testable helpers:
``parse_version``, ``normalize_product``, the static ``_cpe_version_matches``,
and ``match_cves_to_product`` bucketing. None of these touch the network.
"""

from __future__ import annotations

import pytest

from pocmap.models import CPEInfo, CPEMatch, CVEInfo, VersionConstraint
from pocmap.services.product_service import (
    ProductDiscoveryService,
    _cpe_search_params,
)
from pocmap.utils.http import OfflineError

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


def test_normalize_product_does_not_substring_match_across_words() -> None:
    """"ios" occurs inside "fortios" -- that must not resolve to Apple iOS."""
    assert svc.normalize_product("Fortinet FortiOS") == ("fortinet", "fortios")
    # "node" occurs at a separator boundary in "node-red", but they are
    # different products; defer to the CPE dictionary rather than guess.
    assert svc.normalize_product("node-red") == (None, "node-red")


def test_normalize_product_is_separator_insensitive() -> None:
    for spelling in ("Apache Struts", "apache_struts", "Apache-Struts"):
        assert svc.normalize_product(spelling) == ("apache", "apache struts")


def test_normalize_product_peels_multiword_vendor() -> None:
    assert svc.normalize_product("Palo Alto PAN-OS") == ("palo alto", "pan-os")


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


# ---------------------------------------------------------------------------
# Every CPE counts, not just the last one
# ---------------------------------------------------------------------------

# Shape of a real NVD record: the vulnerable component first, then the distros
# that shipped it. Keeping only the last CPE made this look like a Fedora CVE.
_NVD_MULTI_CPE = {
    "id": "CVE-2009-2629",
    "descriptions": [{"lang": "en", "value": "Buffer underflow in nginx."}],
    "published": "2009-09-15T17:30:00.437",
    "configurations": [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:*:f5:nginx:*:*:*:*:*:*:*:*", "vulnerable": True,
                         "versionEndIncluding": "0.8.14"},
                        {"criteria": "cpe:2.3:o:debian:debian_linux:8.0:*:*:*:*:*:*:*",
                         "vulnerable": True},
                        {"criteria": "cpe:2.3:o:fedoraproject:fedora:12:*:*:*:*:*:*:*",
                         "vulnerable": True},
                    ]
                }
            ]
        }
    ],
}


def test_parse_nvd_cve_keeps_every_vendor_product_pair() -> None:
    info = svc._parse_nvd_cve(_NVD_MULTI_CPE)
    assert info is not None
    assert [(a.vendor, a.product) for a in info.affected_products] == [
        ("f5", "nginx"),
        ("debian", "debian_linux"),
        ("fedoraproject", "fedora"),
    ]
    # The scalar fields expose the vulnerable component, not the last distro.
    assert (info.vendor, info.product) == ("f5", "nginx")


def test_classify_uses_any_affected_pair_not_just_the_last() -> None:
    info = svc._parse_nvd_cve(_NVD_MULTI_CPE)
    assert info is not None
    # Previously "unknown" -> the CVE landed in not_enough_data.
    assert svc._classify_cve(info, "nginx", None, "f5") == "confirmed"


def test_primary_pair_skips_non_vulnerable_platform_cpes() -> None:
    data = {
        "id": "CVE-2024-1234",
        "descriptions": [{"lang": "en", "value": "x"}],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {"criteria": "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*",
                             "vulnerable": False},
                            {"criteria": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
                             "vulnerable": True},
                        ]
                    }
                ]
            }
        ],
    }
    info = svc._parse_nvd_cve(data)
    assert info is not None
    assert (info.vendor, info.product) == ("acme", "widget")


# ---------------------------------------------------------------------------
# Out-of-band version ranges (versionStart* / versionEnd*)
# ---------------------------------------------------------------------------

def _ranged_cve(**bounds: str) -> CVEInfo:
    """A CVE whose CPE version is ``*`` and whose real range is out-of-band."""
    return CVEInfo(
        id="CVE-2024-0001",
        vendor="apache",
        product="struts",
        cpe_matches=[
            CPEMatch(criteria="cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*", **bounds)
        ],
    )


def test_version_matches_honours_out_of_band_range() -> None:
    """A ``*`` CPE version used to make every constraint match."""
    cve = _ranged_cve(version_start_including="2.0.0", version_end_excluding="2.5.30")

    for accepted in ("2.x", "2.5.29", ">= 2.5", "2.0.0"):
        vc = svc.parse_version(accepted)
        assert vc is not None
        assert svc._version_matches(cve, vc) is True, accepted

    for rejected in ("1.x", "7.x", ">= 900", "<= 1.0", "2.5.30", "2.5.31"):
        vc = svc.parse_version(rejected)
        assert vc is not None
        assert svc._version_matches(cve, vc) is False, rejected


def test_version_matches_exclusive_upper_bound_excludes_the_bound_itself() -> None:
    cve = _ranged_cve(version_end_excluding="2.5.30")
    vc = svc.parse_version("2.5.30")
    assert vc is not None
    assert svc._version_matches(cve, vc) is False

    inclusive = _ranged_cve(version_end_including="2.5.30")
    assert svc._version_matches(inclusive, vc) is True


def test_version_matches_still_permissive_without_any_cpe_data() -> None:
    bare = CVEInfo(id="CVE-2024-0002", vendor="apache", product="struts")
    vc = svc.parse_version("2.x")
    assert vc is not None
    assert svc._version_matches(bare, vc) is True


# ---------------------------------------------------------------------------
# Version constraints are pushed to NVD, not evaluated client-side
# ---------------------------------------------------------------------------

def _params(raw: str | None) -> dict[str, object]:
    vc = svc.parse_version(raw) if raw else None
    return dict(_cpe_search_params("f5", "nginx", vc))


def test_cpe_search_params_without_constraint_is_the_bare_match_string() -> None:
    assert _params(None) == {"virtualMatchString": "cpe:2.3:*:f5:nginx"}


def test_cpe_search_params_exact_version_is_embedded_in_the_match_string() -> None:
    assert _params("2.14.1") == {"virtualMatchString": "cpe:2.3:*:f5:nginx:2.14.1"}


def test_cpe_search_params_range_operators_map_to_version_bounds() -> None:
    assert _params(">= 2.0") == {
        "virtualMatchString": "cpe:2.3:*:f5:nginx",
        "versionStart": "2.0",
        "versionStartType": "including",
    }
    assert _params("> 1.0")["versionStartType"] == "excluding"
    assert _params("<= 1.20") == {
        "virtualMatchString": "cpe:2.3:*:f5:nginx",
        "versionEnd": "1.20",
        "versionEndType": "including",
    }
    assert _params("< 3.0")["versionEndType"] == "excluding"


def test_cpe_search_params_prefix_versions_become_half_open_ranges() -> None:
    # "2.x" and "2.14" are prefixes: [2, 3) and [2.14, 2.15).
    assert _params("2.x") == {
        "virtualMatchString": "cpe:2.3:*:f5:nginx",
        "versionStart": "2",
        "versionStartType": "including",
        "versionEnd": "3",
        "versionEndType": "excluding",
    }
    assert _params("2.14")["versionEnd"] == "2.15"


def test_cpe_search_params_unparseable_version_applies_no_bound() -> None:
    assert _params("latest") == {"virtualMatchString": "cpe:2.3:*:f5:nginx"}


# ---------------------------------------------------------------------------
# discover_by_product routing: CPE first, keyword only as a fallback
# ---------------------------------------------------------------------------

def _routed_service(
    monkeypatch: pytest.MonkeyPatch, pairs: list[tuple[str, str]]
) -> tuple[ProductDiscoveryService, list[str]]:
    """A service whose CPE resolution is stubbed and whose searches are recorded."""
    service = ProductDiscoveryService()
    calls: list[str] = []

    monkeypatch.setattr(service._cpe_client, "resolve", lambda *a, **k: pairs)

    def fake_by_cpe(p: list[tuple[str, str]], vc: object = None, limit: int = 50) -> list[CVEInfo]:
        calls.append("cpe")
        return [CVEInfo(id="CVE-2024-1111", vendor=p[0][0], product=p[0][1])]

    def fake_by_keyword(keyword: str, limit: int = 50) -> list[CVEInfo]:
        calls.append("keyword")
        return [CVEInfo(id="CVE-2024-2222")]

    monkeypatch.setattr(service, "search_nvd_by_cpe", fake_by_cpe)
    monkeypatch.setattr(service, "search_nvd_by_keyword", fake_by_keyword)
    return service, calls


def test_discover_uses_cpe_match_when_the_product_resolves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, calls = _routed_service(monkeypatch, [("f5", "nginx")])
    result = service.discover_by_product("nginx")

    assert calls == ["cpe"]
    assert result.search_sources == ["nvd_cpe_match"]
    assert result.matched_cpes == ["cpe:2.3:*:f5:nginx"]
    # The CPE vendor replaces the alias table's (absent) guess.
    assert result.normalized_vendor == "f5"


def test_discover_falls_back_to_keyword_when_unresolvable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, calls = _routed_service(monkeypatch, [])
    result = service.discover_by_product("some-unknown-thing")

    assert calls == ["keyword"]
    # The weaker path is visible rather than indistinguishable.
    assert result.search_sources == ["nvd_keyword_search"]
    assert result.matched_cpes == []


def test_discover_keeps_an_explicit_vendor_over_the_resolved_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _ = _routed_service(monkeypatch, [("f5", "nginx")])
    result = service.discover_by_product("nginx", vendor="Ipswitch")
    assert result.normalized_vendor == "ipswitch"


# ---------------------------------------------------------------------------
# Oversized result sets are truncated from the NEWEST end
# ---------------------------------------------------------------------------

def _nvd_page(total: int, start: int, per_page: int) -> dict[str, object]:
    """Fake NVD page. NVD orders oldest-first, so index N == year 2000+N."""
    items = []
    for i in range(start, min(start + per_page, total)):
        items.append(
            {
                "cve": {
                    "id": f"CVE-{2000 + i}-0001",
                    "descriptions": [{"lang": "en", "value": "x"}],
                    "published": f"{2000 + i}-01-01T00:00:00.000",
                }
            }
        )
    return {"totalResults": total, "vulnerabilities": items}


def test_paged_query_seeks_to_the_newest_when_results_exceed_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NVD has no sortBy and returns oldest-first, so the head is the wrong end."""
    service = ProductDiscoveryService()
    requested: list[int] = []

    def fake_get_json(url: str, **kw: object) -> dict[str, object]:
        params = kw.get("params") or {}
        assert isinstance(params, dict)
        start = int(params["startIndex"])  # type: ignore[arg-type]
        per_page = int(params["resultsPerPage"])  # type: ignore[arg-type]
        requested.append(start)
        return _nvd_page(total=278, start=start, per_page=per_page)

    monkeypatch.setattr(service._client, "get_json", fake_get_json)

    got = service._paged_nvd_query({"virtualMatchString": "cpe:2.3:*:v:p"}, limit=20, label="t")

    assert len(got) == 20
    # 278 total, limit 20 -> the tail, i.e. CVE-2258.. not CVE-2000..
    assert got[0].id == "CVE-2258-0001"
    assert got[-1].id == "CVE-2277-0001"
    assert requested[0] == 0 and 258 in requested  # probed, then seeked


def test_paged_query_does_not_seek_when_everything_fits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = ProductDiscoveryService()
    requested: list[int] = []

    def fake_get_json(url: str, **kw: object) -> dict[str, object]:
        params = kw.get("params") or {}
        assert isinstance(params, dict)
        start = int(params["startIndex"])  # type: ignore[arg-type]
        requested.append(start)
        return _nvd_page(total=5, start=start, per_page=int(params["resultsPerPage"]))  # type: ignore[arg-type]

    monkeypatch.setattr(service._client, "get_json", fake_get_json)

    got = service._paged_nvd_query({"keywordSearch": "x"}, limit=50, label="t")

    assert [c.id for c in got] == [f"CVE-{2000 + i}-0001" for i in range(5)]
    assert requested == [0]  # no wasted extra request


def test_discover_propagates_offline_error_from_cpe_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An offline cache-miss must not silently downgrade to keyword search."""
    service, calls = _routed_service(monkeypatch, [])

    def boom(*_a: object, **_k: object) -> list[tuple[str, str]]:
        raise OfflineError("cache miss")

    monkeypatch.setattr(service._cpe_client, "resolve", boom)
    with pytest.raises(OfflineError):
        service.discover_by_product("nginx")
    assert calls == []
