"""Native pytest tests for OFFLINE-MODE (utils/http.py + utils/cache.py).

Offline mode makes ``HTTPClient.get_json``/``get_text`` serve *only* from the
persistent cache and never touch the network. These tests lock in:

  * **Warm cache + offline on** -> the cached body is returned and the transport
    (``requests.Session.get``) is **never** called. Both ``settings.offline``
    (process-wide) and the per-client ``HTTPClient(offline=True)`` paths are
    covered, for JSON and text.
  * **Cold cache + offline on** -> a distinct, categorizable
    :class:`OfflineError` is raised (``category == "offline"``, NOT
    ``network_error``), never a silent empty ``default``.
  * **no_cache / disabled cache + offline** -> still an :class:`OfflineError`
    (there is nothing to serve), even when a warm entry exists but is bypassed.
  * **Offline off** -> completely normal behavior: the transport is used and the
    response is returned/cached as before.
  * **HTTPCache.peek** -> distinguishes "present" (fresh hit) from "absent"
    (miss/expiry) and is side-effect free (expired entries are not purged).

Everything is fully offline. The transport is a fake that *fails the test* if it
is ever called on the offline path, and the anti-rebinding DNS check is stubbed
for the online path, so no network or DNS call is ever made. ``test_ssrf.py``
proves the SSRF guard on :meth:`HTTPClient.get` remains intact and untouched.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import pocmap.utils.cache as cache_mod
from pocmap.config import settings
from pocmap.utils import http as http_mod
from pocmap.utils.cache import HTTPCache
from pocmap.utils.http import (
    HTTPClient,
    HTTPError,
    OfflineError,
    categorize_exception,
)

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


def _exploding_transport(*args: Any, **kwargs: Any) -> Any:
    """A ``session.get`` stand-in that fails the test if offline touches network."""
    raise AssertionError("offline mode must not touch the network")


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
def offline_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HTTPCache:
    """Install a temp-dir HTTP cache as the module global and enable offline mode.

    Offline is switched on process-wide by replacing ``http_mod.settings`` with a
    frozen copy whose ``offline=True`` (monkeypatch of the settings singleton).
    """
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP, enabled=True)
    monkeypatch.setattr(http_mod, "_cache", cache)
    monkeypatch.setattr(http_mod, "settings", replace(settings, offline=True))
    return cache


# ---------------------------------------------------------------------------
# Warm cache + offline -> served from cache, transport NEVER called
# ---------------------------------------------------------------------------


def test_offline_warm_cache_json_served_and_transport_never_called(
    offline_cache: HTTPCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = "https://api.example/data"
    offline_cache.set(HTTPCache.make_key("GET", url, None), '{"v": 99}')

    client = HTTPClient()
    try:
        monkeypatch.setattr(client._session, "get", _exploding_transport)
        out = client.get_json(url)
        assert out == {"v": 99}  # served from cache
    finally:
        client.close()


def test_offline_warm_cache_text_served_and_transport_never_called(
    offline_cache: HTTPCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = "https://api.example/page"
    offline_cache.set(HTTPCache.make_key("GET", url, None), "plain-body")

    client = HTTPClient()
    try:
        monkeypatch.setattr(client._session, "get", _exploding_transport)
        assert client.get_text(url) == "plain-body"
    finally:
        client.close()


def test_offline_warm_cache_with_params(
    offline_cache: HTTPCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cache key includes params, so a warm entry keyed with params hits."""
    url = "https://api.example/data"
    params = {"q": "log4j", "n": 3}
    offline_cache.set(HTTPCache.make_key("GET", url, params), '{"hit": true}')

    client = HTTPClient()
    try:
        monkeypatch.setattr(client._session, "get", _exploding_transport)
        assert client.get_json(url, params=params) == {"hit": True}
    finally:
        client.close()


def test_offline_per_client_override_warm_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``HTTPClient(offline=True)`` forces offline even when settings.offline is off."""
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP, enabled=True)
    monkeypatch.setattr(http_mod, "_cache", cache)
    assert settings.offline is False  # process default: online

    url = "https://api.example/data"
    cache.set(HTTPCache.make_key("GET", url, None), '{"v": 7}')

    client = HTTPClient(offline=True)
    try:
        monkeypatch.setattr(client._session, "get", _exploding_transport)
        assert client.get_json(url) == {"v": 7}
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Cold cache + offline -> clear, categorized OfflineError (not empty, not net err)
# ---------------------------------------------------------------------------


def test_offline_cold_cache_json_raises_offline_error(
    offline_cache: HTTPCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = HTTPClient()
    try:
        monkeypatch.setattr(client._session, "get", _exploding_transport)
        with pytest.raises(OfflineError) as excinfo:
            client.get_json("https://api.example/missing", default={"d": True})
    finally:
        client.close()

    err = excinfo.value
    # Clear message referencing the URL...
    assert "offline" in str(err).lower()
    assert "https://api.example/missing" in str(err)
    # ...distinct + categorizable, NOT a generic network error...
    category, retryable = categorize_exception(err)
    assert category == "offline"
    assert category != "network_error"
    assert retryable is False
    # ...still catchable by existing ``except HTTPError`` handlers (additive).
    assert isinstance(err, HTTPError)


def test_offline_cold_cache_text_raises_offline_error(
    offline_cache: HTTPCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = HTTPClient()
    try:
        monkeypatch.setattr(client._session, "get", _exploding_transport)
        with pytest.raises(OfflineError):
            client.get_text("https://api.example/missing", default="fallback")
    finally:
        client.close()


def test_offline_does_not_silently_return_default(
    offline_cache: HTTPCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cold offline lookup must RAISE, never return the empty ``default``."""
    client = HTTPClient()
    try:
        monkeypatch.setattr(client._session, "get", _exploding_transport)
        raised = False
        try:
            client.get_json("https://api.example/none", default=[])
        except OfflineError:
            raised = True
        assert raised, "offline cache-miss must raise, not return default=[]"
    finally:
        client.close()


# ---------------------------------------------------------------------------
# no_cache / disabled-cache coherence: offline + nothing-to-serve -> OfflineError
# ---------------------------------------------------------------------------


def test_offline_with_no_cache_raises_even_with_warm_entry(
    offline_cache: HTTPCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``no_cache=True`` bypasses the cache -> offline has nothing to serve."""
    url = "https://api.example/data"
    offline_cache.set(HTTPCache.make_key("GET", url, None), '{"v": 1}')  # warm

    client = HTTPClient()
    try:
        monkeypatch.setattr(client._session, "get", _exploding_transport)
        with pytest.raises(OfflineError):
            client.get_json(url, no_cache=True)
    finally:
        client.close()


def test_offline_with_disabled_cache_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A disabled cache offline has nothing to serve -> OfflineError."""
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP, enabled=False)
    monkeypatch.setattr(http_mod, "_cache", cache)
    monkeypatch.setattr(http_mod, "settings", replace(settings, offline=True))

    client = HTTPClient()
    try:
        monkeypatch.setattr(client._session, "get", _exploding_transport)
        with pytest.raises(OfflineError):
            client.get_json("https://api.example/data")
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Offline OFF -> normal behavior: transport is used
# ---------------------------------------------------------------------------


def test_offline_off_uses_transport_normally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(http_mod, "resolves_to_internal_ip", lambda host: False)
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP, enabled=True)
    monkeypatch.setattr(http_mod, "_cache", cache)
    assert settings.offline is False  # default is online

    client = HTTPClient()
    try:
        transport = _CountingTransport(_FakeResponse(200, '{"v": 7}'))
        monkeypatch.setattr(client._session, "get", transport)

        out = client.get_json("https://api.example/data")
        assert out == {"v": 7}
        assert transport.calls == 1  # transport WAS used
        assert cache.info()["entries"] == 1  # and the response was cached
    finally:
        client.close()


def test_offline_off_then_on_serves_the_freshly_cached_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Online populates the cache; a subsequent offline client serves it offline."""
    monkeypatch.setattr(http_mod, "resolves_to_internal_ip", lambda host: False)
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP, enabled=True)
    monkeypatch.setattr(http_mod, "_cache", cache)
    url = "https://api.example/data"

    # Phase 1: online client fetches + caches.
    online = HTTPClient()
    try:
        transport = _CountingTransport(_FakeResponse(200, '{"v": 5}'))
        monkeypatch.setattr(online._session, "get", transport)
        assert online.get_json(url) == {"v": 5}
        assert transport.calls == 1
    finally:
        online.close()

    # Phase 2: offline client serves the warm entry with no network.
    offline = HTTPClient(offline=True)
    try:
        monkeypatch.setattr(offline._session, "get", _exploding_transport)
        assert offline.get_json(url) == {"v": 5}
    finally:
        offline.close()


# ---------------------------------------------------------------------------
# HTTPCache.peek: present vs absent, side-effect free
# ---------------------------------------------------------------------------


def test_cache_peek_present_vs_absent(tmp_path: Path) -> None:
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP)
    assert cache.peek("missing") is None  # absent
    cache.set("k", "body")
    assert cache.peek("k") == "body"  # present


def test_cache_peek_is_read_only_on_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An expired entry peeks as absent but is NOT purged (unlike get)."""
    clock = _Clock(1000.0)
    monkeypatch.setattr(cache_mod, "time", clock)
    cache = HTTPCache(cache_dir=tmp_path, ttl=60, max_bytes=_BIG_CAP)
    cache.set("k", "fresh")
    clock.t = 1000.0 + 61  # advance past the TTL

    assert cache.peek("k") is None  # expired -> absent
    assert cache.info()["entries"] == 1  # but left on disk (read-only peek)
    # get() on the same expired entry DOES purge it (behavior preserved).
    assert cache.get("k") is None
    assert cache.info()["entries"] == 0


def test_cache_peek_disabled_is_absent(tmp_path: Path) -> None:
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP, enabled=False)
    cache.set("k", "v")
    assert cache.peek("k") is None
