"""Native offline tests for the cached-POST and gzip-decode HTTP additions.

Covers ``HTTPClient.post_json_cached``, ``HTTPCache.make_key(body=...)`` and the
gzip handling in ``HTTPClient.get_text`` (``src/pocmap/utils/http.py``,
``src/pocmap/utils/cache.py``).

Offline by construction: ``client._session`` is replaced with a stub, so no
socket is ever opened.

Invariants locked in here:

  * **Existing GET cache keys are byte-identical.** ``body`` is folded into the
    key only when supplied; otherwise an upgrade would silently invalidate every
    entry already on disk. The expected digests below are pinned literals for
    exactly that reason.
  * A POST whose query lives in its body caches like a GET, honours offline
    mode, and raises on a throttle instead of degrading to an empty result.
  * **An HTTP error body is never parsed as data.** OSV answers a bad ecosystem
    with a 200-shaped JSON error at status 400; returning it would let a
    rejected request read as an empty result.
  * A gzip *file* (``Content-Type: application/gzip``, which ``requests`` does
    not auto-decompress) is decoded before it is cached, so the cache never
    stores mojibake.
"""

from __future__ import annotations

import gzip
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from pocmap import config as config_module
from pocmap.utils import cache as cache_module
from pocmap.utils import http as http_module
from pocmap.utils.cache import HTTPCache
from pocmap.utils.http import HTTPClient, HTTPError, OfflineError, RateLimitError


class _FakeResponse:
    """Structurally faithful stand-in for ``requests.Response``."""

    def __init__(
        self,
        status_code: int = 200,
        body: str = '{"vulns": []}',
        *,
        raw: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.text = body
        self.content = raw if raw is not None else body.encode("utf-8")
        self.encoding = "utf-8"
        self.url = "https://api.example/query"
        self.headers = headers or {}
        self.is_redirect = False

    def json(self) -> Any:
        return json.loads(self.text)


class _CountingPost:
    """Replacement for ``session.post`` that counts calls."""

    def __init__(self, *responses: _FakeResponse) -> None:
        self._responses = list(responses)
        self.calls = 0
        self.last_kwargs: dict[str, Any] = {}

    def __call__(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls += 1
        self.last_kwargs = kwargs
        index = min(self.calls - 1, len(self._responses) - 1)
        return self._responses[index]


@pytest.fixture
def client_with_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[HTTPClient, HTTPCache]:
    """An HTTPClient wired to a fresh on-disk cache in *tmp_path*.

    ``Settings`` is frozen+slots, so it is rebuilt with :func:`dataclasses.replace`
    and rebound in every module that imported the name.
    """
    settings = replace(
        config_module.settings,
        cache_enabled=True,
        cache_dir=str(tmp_path / "cache"),
        offline=False,
    )
    for module in (config_module, cache_module, http_module):
        monkeypatch.setattr(module, "settings", settings, raising=False)
    cache = HTTPCache.from_settings()
    monkeypatch.setattr(http_module, "_get_cache", lambda: cache)
    return HTTPClient(), cache


# ---------------------------------------------------------------------------
# Cache-key stability
# ---------------------------------------------------------------------------

def test_existing_get_keys_are_unchanged_by_the_new_body_field() -> None:
    """Pinned digests: adding ``body`` must not invalidate anyone's cache."""
    assert (
        HTTPCache.make_key("GET", "https://api.example/data", {"a": 1, "b": "x"})
        == "e0af125a21af98d76350a05a3713a765e5bec41db242bdd9a97852ec142be206"
    )
    assert (
        HTTPCache.make_key("GET", "https://api.example/data")
        == "8e0b1e6f11d652dfe207d2f2d670c70e3eb35474156f39b8e4f4d1d1a4e8a167"
    )


def test_different_bodies_key_differently() -> None:
    url = "https://api.osv.dev/v1/query"
    a = HTTPCache.make_key("POST", url, body={"package": {"name": "django"}})
    b = HTTPCache.make_key("POST", url, body={"package": {"name": "flask"}})
    assert a != b


def test_body_key_is_order_independent() -> None:
    """A payload built in a different order must hit the same cache entry."""
    url = "https://api.osv.dev/v1/query"
    a = HTTPCache.make_key("POST", url, body={"version": "3.2", "package": {"n": 1, "e": 2}})
    b = HTTPCache.make_key("POST", url, body={"package": {"e": 2, "n": 1}, "version": "3.2"})
    assert a == b


# ---------------------------------------------------------------------------
# post_json_cached
# ---------------------------------------------------------------------------

def test_second_identical_post_is_served_from_cache(
    client_with_cache: tuple[HTTPClient, HTTPCache], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, cache = client_with_cache
    post = _CountingPost(_FakeResponse(200, '{"vulns": [{"id": "GHSA-1"}]}'))
    monkeypatch.setattr(client._session, "post", post)

    body = {"package": {"name": "django", "ecosystem": "PyPI"}}
    first = client.post_json_cached("https://api.example/query", body)
    second = client.post_json_cached("https://api.example/query", body)

    assert first == second == {"vulns": [{"id": "GHSA-1"}]}
    assert post.calls == 1
    assert cache.info()["entries"] == 1


def test_a_different_body_is_a_different_entry(
    client_with_cache: tuple[HTTPClient, HTTPCache], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _cache = client_with_cache
    post = _CountingPost(_FakeResponse(200, '{"vulns": []}'))
    monkeypatch.setattr(client._session, "post", post)

    client.post_json_cached("https://api.example/query", {"package": {"name": "a"}})
    client.post_json_cached("https://api.example/query", {"package": {"name": "b"}})
    assert post.calls == 2


def test_post_is_sent_without_following_redirects(
    client_with_cache: tuple[HTTPClient, HTTPCache], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 3xx must not bounce the body to an internal host."""
    client, _cache = client_with_cache
    post = _CountingPost(_FakeResponse())
    monkeypatch.setattr(client._session, "post", post)
    client.post_json_cached("https://api.example/query", {"x": 1})
    assert post.last_kwargs["allow_redirects"] is False


def test_ssrf_guard_blocks_an_internal_post(
    client_with_cache: tuple[HTTPClient, HTTPCache],
) -> None:
    client, _cache = client_with_cache
    with pytest.raises(HTTPError, match="SSRF"):
        client.post_json_cached("http://169.254.169.254/latest/meta-data", {"x": 1})


def test_http_error_body_is_not_returned_as_data(
    client_with_cache: tuple[HTTPClient, HTTPCache], monkeypatch: pytest.MonkeyPatch
) -> None:
    """OSV answers a bad ecosystem with valid JSON at status 400.

    Parsing it would hand the caller ``{"code": 3, "message": ...}`` and let a
    rejected request read as an empty result.
    """
    client, _cache = client_with_cache
    body = '{"code":3,"message":"invalid ecosystem"}'
    monkeypatch.setattr(client._session, "post", _CountingPost(_FakeResponse(400, body)))
    with pytest.raises(HTTPError) as excinfo:
        client.post_json_cached("https://api.example/query", {"x": 1})
    assert excinfo.value.status_code == 400
    assert "invalid ecosystem" in str(excinfo.value)


def test_error_responses_are_never_cached(
    client_with_cache: tuple[HTTPClient, HTTPCache], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, cache = client_with_cache
    monkeypatch.setattr(client._session, "post", _CountingPost(_FakeResponse(500, "nope")))
    with pytest.raises(HTTPError):
        client.post_json_cached("https://api.example/query", {"x": 1})
    assert cache.info()["entries"] == 0


def test_throttle_raises_rate_limit_error(
    client_with_cache: tuple[HTTPClient, HTTPCache], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _cache = client_with_cache
    monkeypatch.setattr(
        client._session, "post", _CountingPost(_FakeResponse(429, "slow down"))
    )
    with pytest.raises(RateLimitError):
        client.post_json_cached("https://api.example/query", {"x": 1})


def test_offline_miss_raises_instead_of_hitting_the_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = replace(
        config_module.settings,
        cache_enabled=True,
        cache_dir=str(tmp_path / "cache"),
        offline=True,
    )
    for module in (config_module, cache_module, http_module):
        monkeypatch.setattr(module, "settings", settings, raising=False)
    monkeypatch.setattr(http_module, "_get_cache", lambda: HTTPCache.from_settings())
    client = HTTPClient()
    post = _CountingPost(_FakeResponse())
    monkeypatch.setattr(client._session, "post", post)

    with pytest.raises(OfflineError):
        client.post_json_cached("https://api.example/query", {"x": 1})
    assert post.calls == 0


def test_offline_serves_a_previously_cached_post(
    client_with_cache: tuple[HTTPClient, HTTPCache], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _cache = client_with_cache
    post = _CountingPost(_FakeResponse(200, '{"vulns": [{"id": "A"}]}'))
    monkeypatch.setattr(client._session, "post", post)
    body = {"package": {"name": "django"}}
    client.post_json_cached("https://api.example/query", body)

    monkeypatch.setattr(client, "_is_offline", lambda: True)
    assert client.post_json_cached("https://api.example/query", body) == {
        "vulns": [{"id": "A"}]
    }
    assert post.calls == 1


def test_no_cache_bypasses_the_cache_entirely(
    client_with_cache: tuple[HTTPClient, HTTPCache], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, cache = client_with_cache
    post = _CountingPost(_FakeResponse())
    monkeypatch.setattr(client._session, "post", post)
    client.post_json_cached("https://api.example/query", {"x": 1}, no_cache=True)
    client.post_json_cached("https://api.example/query", {"x": 1}, no_cache=True)
    assert post.calls == 2
    assert cache.info()["entries"] == 0


# ---------------------------------------------------------------------------
# gzip-aware text decoding
# ---------------------------------------------------------------------------

def test_gzip_file_body_is_decompressed_before_caching(
    client_with_cache: tuple[HTTPClient, HTTPCache], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``.gz`` served as application/gzip is not auto-decompressed by requests.

    The EPSS bulk feed ships exactly this way; without the gzip sniff, mojibake
    would be cached as if it were a valid CSV.
    """
    client, cache = client_with_cache
    csv_text = "#model_version:v2026.06.15\ncve,epss,percentile\nCVE-2021-44228,0.94355,0.99\n"
    packed = gzip.compress(csv_text.encode("utf-8"))
    resp = _FakeResponse(200, body="<mojibake>", raw=packed)
    monkeypatch.setattr(client, "get", lambda *a, **k: resp)

    out = client.get_text("https://epss.example/scores.csv.gz")
    assert out == csv_text
    # The cached copy is the decoded text, not the compressed bytes.
    key = HTTPCache.make_key("GET", "https://epss.example/scores.csv.gz", None)
    assert cache.get(key) == csv_text


def test_plain_text_body_is_untouched(
    client_with_cache: tuple[HTTPClient, HTTPCache], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _cache = client_with_cache
    monkeypatch.setattr(client, "get", lambda *a, **k: _FakeResponse(200, "hello, world"))
    assert client.get_text("https://example.com/page") == "hello, world"


def test_a_truncated_gzip_body_falls_back_to_text(
    client_with_cache: tuple[HTTPClient, HTTPCache], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Never make a working feed fail because the sniff misfired."""
    client, _cache = client_with_cache
    broken = gzip.compress(b"hello")[:6]  # keeps the magic, loses the rest
    resp = _FakeResponse(200, body="fallback", raw=broken)
    monkeypatch.setattr(client, "get", lambda *a, **k: resp)
    assert client.get_text("https://example.com/x.gz") == "fallback"
