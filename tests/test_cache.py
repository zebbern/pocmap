"""Native pytest tests for the persistent HTTP response cache (utils/cache.py).

Two layers are covered, all fully offline:

  * **Unit** — :class:`HTTPCache` directly: set/get roundtrip, key stability,
    TTL expiry, corruption tolerance, size-cap eviction, the 200-only rule, and
    the disabled no-op behaviour.
  * **Integration** — :meth:`HTTPClient.get_json`/`get_text` wiring: the first
    call hits the transport and writes the cache; an identical second call is
    served from disk (transport NOT re-invoked); an expired TTL refetches; a
    corrupt entry falls back to the network; a disabled cache always fetches;
    and only ``200`` responses are ever cached.

The SSRF anti-rebinding DNS check is neutralized (``resolves_to_internal_ip``),
and the ``requests.Session`` transport is replaced with a counting fake, so no
network or DNS call is ever made. ``test_ssrf.py`` proves the SSRF guard on
:meth:`HTTPClient.get` itself remains intact and untouched by this feature.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import pocmap.utils.cache as cache_mod
from pocmap.utils import http as http_mod
from pocmap.utils.cache import HTTPCache
from pocmap.utils.http import HTTPClient

_BIG_CAP = 200 * 1024 * 1024


# ---------------------------------------------------------------------------
# Offline fakes
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Minimal stand-in for requests.Response used by HTTPClient.get_json/text."""

    def __init__(self, status_code: int = 200, body: str = '{"v": 1}') -> None:
        self.status_code = status_code
        self.text = body
        self.headers: dict[str, str] = {}
        self.is_redirect = False

    def json(self) -> Any:
        return json.loads(self.text)


class _CountingTransport:
    """Callable replacement for ``session.get`` that counts invocations."""

    def __init__(self, response: _FakeResponse) -> None:
        self.response = response
        self.calls = 0

    def __call__(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls += 1
        return self.response


class _Clock:
    """Injectable clock so TTL expiry is deterministic (no real sleeping)."""

    def __init__(self, now: float) -> None:
        self.t = now

    def time(self) -> float:
        return self.t


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client_with_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Yield ``(client, cache)`` wired to a temp-dir cache; offline-safe.

    The module-global ``http._cache`` is swapped for a temp-backed instance and
    the anti-rebinding DNS probe is stubbed out, so ``get_json``/``get_text``
    never touch the network.
    """
    monkeypatch.setattr(http_mod, "resolves_to_internal_ip", lambda host: False)
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP, enabled=True)
    monkeypatch.setattr(http_mod, "_cache", cache)
    client = HTTPClient()
    try:
        yield client, cache
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Unit: HTTPCache in isolation
# ---------------------------------------------------------------------------

def test_make_key_is_stable_and_param_order_insensitive() -> None:
    k1 = HTTPCache.make_key("GET", "https://x/y", {"a": 1, "b": 2})
    k2 = HTTPCache.make_key("GET", "https://x/y", {"b": 2, "a": 1})
    k3 = HTTPCache.make_key("get", "https://x/y", {"a": 1, "b": 2})  # method normalized
    assert k1 == k2 == k3
    assert len(k1) == 64  # sha256 hex digest
    # Different params -> different key.
    assert HTTPCache.make_key("GET", "https://x/y", {"a": 1}) != k1
    # Different URL -> different key.
    assert HTTPCache.make_key("GET", "https://x/z", {"a": 1, "b": 2}) != k1


def test_set_get_roundtrip(tmp_path: Path) -> None:
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP)
    assert cache.get("missing") is None
    cache.set("k1", "hello-body")
    assert cache.get("k1") == "hello-body"
    info = cache.info()
    assert info["entries"] == 1
    assert info["bytes"] > 0


def test_set_ignores_non_200(tmp_path: Path) -> None:
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP)
    cache.set("k", "error-body", status=500)
    cache.set("k2", "not-found", status=404)
    assert cache.get("k") is None
    assert cache.get("k2") is None
    assert cache.info()["entries"] == 0


def test_disabled_cache_is_noop(tmp_path: Path) -> None:
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP, enabled=False)
    cache.set("k", "v")
    assert cache.get("k") is None
    assert cache.info()["entries"] == 0


def test_expired_entry_is_a_miss(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _Clock(1000.0)
    monkeypatch.setattr(cache_mod, "time", clock)
    cache = HTTPCache(cache_dir=tmp_path, ttl=60, max_bytes=_BIG_CAP)
    cache.set("k", "fresh")
    assert cache.get("k") == "fresh"
    clock.t = 1000.0 + 61  # advance just past the TTL window
    assert cache.get("k") is None
    # Expired entry was purged on access.
    assert cache.info()["entries"] == 0


def test_corrupt_entry_is_treated_as_miss(tmp_path: Path) -> None:
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP)
    cache.set("k", "good")
    # Corrupt every on-disk entry.
    for entry in (tmp_path / "http").glob("*.json"):
        entry.write_text("}{ not valid json", encoding="utf-8")
    assert cache.get("k") is None


def test_clear_empties_cache(tmp_path: Path) -> None:
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP)
    cache.set("a", "1")
    cache.set("b", "2")
    assert cache.info()["entries"] == 2
    cache.clear()
    assert cache.info()["entries"] == 0
    assert cache.get("a") is None


def test_size_cap_evicts_to_stay_bounded(tmp_path: Path) -> None:
    # Bodies ~2 KB each; cap 5 KB -> at most two entries can coexist.
    cap = 5000
    body = "x" * 2000
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=cap)
    for i in range(5):
        cache.set(f"key{i}", body)
    info = cache.info()
    assert info["bytes"] <= cap
    assert 1 <= info["entries"] < 5  # eviction happened, but the cache is not empty


# ---------------------------------------------------------------------------
# Integration: HTTPClient.get_json / get_text wiring
# ---------------------------------------------------------------------------

def test_get_json_second_call_served_from_cache(client_with_cache, monkeypatch) -> None:
    client, cache = client_with_cache
    transport = _CountingTransport(_FakeResponse(200, '{"v": 42}'))
    monkeypatch.setattr(client._session, "get", transport)

    first = client.get_json("https://api.example/data")
    second = client.get_json("https://api.example/data")

    assert first == {"v": 42}
    assert second == {"v": 42}
    assert transport.calls == 1  # network hit exactly once
    assert cache.info()["entries"] == 1


def test_get_text_second_call_served_from_cache(client_with_cache, monkeypatch) -> None:
    client, cache = client_with_cache
    transport = _CountingTransport(_FakeResponse(200, "plain body"))
    monkeypatch.setattr(client._session, "get", transport)

    first = client.get_text("https://api.example/page")
    second = client.get_text("https://api.example/page")

    assert first == "plain body"
    assert second == "plain body"
    assert transport.calls == 1
    assert cache.info()["entries"] == 1


def test_no_cache_flag_bypasses_cache(client_with_cache, monkeypatch) -> None:
    client, cache = client_with_cache
    transport = _CountingTransport(_FakeResponse(200, '{"v": 1}'))
    monkeypatch.setattr(client._session, "get", transport)

    client.get_json("https://api.example/data", no_cache=True)
    client.get_json("https://api.example/data", no_cache=True)

    assert transport.calls == 2  # every call fetches
    assert cache.info()["entries"] == 0  # nothing written


def test_expired_ttl_triggers_refetch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http_mod, "resolves_to_internal_ip", lambda host: False)
    clock = _Clock(1000.0)
    monkeypatch.setattr(cache_mod, "time", clock)
    cache = HTTPCache(cache_dir=tmp_path, ttl=60, max_bytes=_BIG_CAP, enabled=True)
    monkeypatch.setattr(http_mod, "_cache", cache)

    client = HTTPClient()
    try:
        transport = _CountingTransport(_FakeResponse(200, '{"v": 1}'))
        monkeypatch.setattr(client._session, "get", transport)

        client.get_json("https://api.example/data")
        assert transport.calls == 1
        # Still fresh -> served from cache.
        client.get_json("https://api.example/data")
        assert transport.calls == 1
        # Advance past the TTL -> must refetch.
        clock.t = 1000.0 + 61
        client.get_json("https://api.example/data")
        assert transport.calls == 2
    finally:
        client.close()


def test_corrupt_cache_file_falls_back_to_network(client_with_cache, monkeypatch) -> None:
    client, cache = client_with_cache
    transport = _CountingTransport(_FakeResponse(200, '{"v": 7}'))
    monkeypatch.setattr(client._session, "get", transport)

    client.get_json("https://api.example/data")
    assert transport.calls == 1

    # Corrupt the on-disk entry, then request again.
    for entry in cache._dir.glob("*.json"):
        entry.write_text("not-json-at-all", encoding="utf-8")

    out = client.get_json("https://api.example/data")
    assert out == {"v": 7}
    assert transport.calls == 2  # fell back to the network


def test_disabled_cache_always_fetches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http_mod, "resolves_to_internal_ip", lambda host: False)
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP, enabled=False)
    monkeypatch.setattr(http_mod, "_cache", cache)

    client = HTTPClient()
    try:
        transport = _CountingTransport(_FakeResponse(200, '{"v": 1}'))
        monkeypatch.setattr(client._session, "get", transport)

        client.get_json("https://api.example/data")
        client.get_json("https://api.example/data")

        assert transport.calls == 2
        assert cache.info()["entries"] == 0
    finally:
        client.close()


def test_non_200_responses_are_not_cached(client_with_cache, monkeypatch) -> None:
    client, cache = client_with_cache
    # A 500 that survives the (bypassed) retry layer: returned but never cached.
    transport = _CountingTransport(_FakeResponse(500, '{"err": true}'))
    monkeypatch.setattr(client._session, "get", transport)

    client.get_json("https://api.example/data")
    assert cache.info()["entries"] == 0
    client.get_json("https://api.example/data")
    assert transport.calls == 2  # nothing was cached, so it fetched again


def test_404_is_not_cached_and_returns_default(client_with_cache, monkeypatch) -> None:
    client, cache = client_with_cache
    transport = _CountingTransport(_FakeResponse(404, ""))
    monkeypatch.setattr(client._session, "get", transport)

    out = client.get_json("https://api.example/data", default={"d": True})
    assert out == {"d": True}
    assert cache.info()["entries"] == 0
