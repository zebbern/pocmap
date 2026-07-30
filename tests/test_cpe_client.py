"""Native offline regression tests for CPEDictionaryClient.

Covers ``src/pocmap/clients/cpe_client.py``. Each case constructs the client
with a ``MagicMock`` HTTP client so no network I/O happens.

Invariants locked in here:

  * ALL vendor:product pairs are returned, ranked by CPE-entry count — a
    product that changed hands (nginx: igor_sysoev -> nginx -> f5) files its
    CVEs under the newest vendor, so taking only the top hit finds nothing.
  * Exact product matches win over neighbours (``nginx_ingress_controller``).
  * A vendor hint that matches nothing is IGNORED rather than emptying the
    result, because the hint may be the alias table's guess.
  * ``RateLimitError`` / ``OfflineError`` PROPAGATE — a throttled or offline
    lookup must never read as "this product has no CPEs".
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from pocmap.clients.cpe_client import CPEDictionaryClient
from pocmap.utils.http import HTTPError, OfflineError, RateLimitError


def _products(*cpe_names: str) -> dict[str, Any]:
    """Build an NVD CPE-dictionary payload from bare CPE names."""
    return {"products": [{"cpe": {"cpeName": name}} for name in cpe_names]}


def _client(payload: Any) -> CPEDictionaryClient:
    http = MagicMock()
    http.get_json.return_value = payload
    return CPEDictionaryClient(http_client=http)


def _raising_client(exc: Exception) -> CPEDictionaryClient:
    http = MagicMock()
    http.get_json.side_effect = exc
    return CPEDictionaryClient(http_client=http)


# ---------------------------------------------------------------------------
# Ranking and multi-vendor resolution
# ---------------------------------------------------------------------------

def test_resolve_returns_every_vendor_pair_ranked_by_entry_count() -> None:
    client = _client(
        _products(
            "cpe:2.3:a:igor_sysoev:nginx:0.1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:f5:nginx:1.20.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:f5:nginx:1.20.1:*:*:*:*:*:*:*",
            "cpe:2.3:a:f5:nginx:1.21.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:nginx:nginx:1.0.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:nginx:nginx:1.1.0:*:*:*:*:*:*:*",
        )
    )
    assert client.resolve("nginx") == [
        ("f5", "nginx"),
        ("nginx", "nginx"),
        ("igor_sysoev", "nginx"),
    ]


def test_resolve_prefers_exact_product_over_neighbours() -> None:
    client = _client(
        _products(
            # Neighbours dominate by count but are a different product.
            "cpe:2.3:a:kubernetes:nginx_ingress_controller:1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:kubernetes:nginx_ingress_controller:1.1:*:*:*:*:*:*:*",
            "cpe:2.3:a:kubernetes:nginx_ingress_controller:1.2:*:*:*:*:*:*:*",
            "cpe:2.3:a:f5:nginx:1.20.0:*:*:*:*:*:*:*",
        )
    )
    assert client.resolve("nginx") == [("f5", "nginx")]


def test_resolve_treats_vendor_prefixed_query_as_exact() -> None:
    """"Fortinet FortiOS" must narrow to fortios, not its sibling products."""
    client = _client(
        _products(
            "cpe:2.3:o:fortinet:fortios:7.0.0:*:*:*:*:*:*:*",
            "cpe:2.3:o:fortinet:fortios_ips_engine:1.0:*:*:*:*:*:*:*",
            "cpe:2.3:o:fortinet:fortios-6k7k:6.0:*:*:*:*:*:*:*",
        )
    )
    assert client.resolve("Fortinet FortiOS") == [("fortinet", "fortios")]


def test_resolve_falls_back_to_neighbours_when_nothing_matches_exactly() -> None:
    client = _client(_products("cpe:2.3:a:acme:widget_pro:1.0:*:*:*:*:*:*:*"))
    assert client.resolve("widget") == [("acme", "widget_pro")]


def test_resolve_caps_pairs_and_keeps_the_highest_ranked() -> None:
    client = _client(
        _products(*[f"cpe:2.3:a:vendor{i}:thing:1.0:*:*:*:*:*:*:*" for i in range(9)])
    )
    assert len(client.resolve("thing", max_pairs=3)) == 3


# ---------------------------------------------------------------------------
# Vendor hint is a soft filter
# ---------------------------------------------------------------------------

def test_vendor_hint_narrows_when_it_matches() -> None:
    client = _client(
        _products(
            "cpe:2.3:a:progress:moveit_transfer:2023:*:*:*:*:*:*:*",
            "cpe:2.3:a:ipswitch:moveit_transfer:2017:*:*:*:*:*:*:*",
        )
    )
    assert client.resolve("MOVEit Transfer", vendor_hint="ipswitch") == [
        ("ipswitch", "moveit_transfer")
    ]


def test_vendor_hint_is_ignored_when_it_matches_nothing() -> None:
    """A wrong hint must not empty the result — it may be an inferred guess."""
    client = _client(_products("cpe:2.3:a:f5:nginx:1.20.0:*:*:*:*:*:*:*"))
    assert client.resolve("nginx", vendor_hint="apache") == [("f5", "nginx")]


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------

def test_rate_limit_error_propagates() -> None:
    client = _raising_client(RateLimitError("429", status_code=429))
    with pytest.raises(RateLimitError):
        client.resolve("nginx")


def test_offline_error_propagates() -> None:
    client = _raising_client(OfflineError("cache miss"))
    with pytest.raises(OfflineError):
        client.resolve("nginx")


def test_generic_http_error_degrades_to_empty() -> None:
    client = _raising_client(HTTPError("500", status_code=500))
    assert client.resolve("nginx") == []


def test_blank_product_short_circuits_without_a_request() -> None:
    http = MagicMock()
    client = CPEDictionaryClient(http_client=http)
    assert client.resolve("   ") == []
    http.get_json.assert_not_called()


def test_malformed_payload_yields_no_pairs() -> None:
    assert _client({"products": [{"cpe": {}}]}).resolve("nginx") == []
    assert _client({"products": "nope"}).resolve("nginx") == []
    assert _client(None).resolve("nginx") == []
