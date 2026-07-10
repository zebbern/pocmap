"""Native pytest regression tests for the SSRF guard (utils/http.py).

These lock in the fixes made this session so they cannot silently regress:

  * ``is_safe_url`` must block numeric-encoded loopback, IPv4-mapped IPv6,
    DNS-rebinding suffixes, cloud-metadata IPs, private ranges, localhost, and
    non-HTTP schemes -- while still allowing legitimate public API hosts.
  * ``HTTPClient.get`` must re-validate EVERY redirect hop (a 3xx ``Location``
    pointing at cloud metadata must not be followed) and must cap redirects.
  * ``HTTPClient.post_json`` (outbound webhooks) must apply the same guard,
    send with ``allow_redirects=False``, and never leak a URL-embedded secret
    into the raised error message.

Everything here is fully offline: DNS resolution (``resolves_to_internal_ip``)
is monkeypatched and the ``requests.Session`` transport is replaced with fakes,
so no network or DNS call is ever made.
"""

from __future__ import annotations

import pytest

from pocmap.utils import http as http_mod
from pocmap.utils.http import _MAX_REDIRECTS, HTTPClient, HTTPError, is_safe_url

# ---------------------------------------------------------------------------
# is_safe_url: static SSRF classification
# ---------------------------------------------------------------------------

BLOCKED_URLS = [
    "http://2130706433/",                     # decimal-encoded 127.0.0.1
    "http://0x7f000001/",                      # hex-encoded 127.0.0.1
    "http://0177.0.0.1/",                      # octal-octet 127.0.0.1
    "http://1.1.1.1.nip.io",                   # DNS-rebinding wildcard suffix
    "http://[::ffff:169.254.169.254]/",        # IPv4-mapped IPv6 -> metadata IP
    "http://169.254.169.254/",                 # AWS/link-local metadata
    "http://10.0.0.1/",                        # RFC1918 private range
    "http://localhost/",                       # loopback hostname
    "file:///etc/passwd",                      # non-HTTP scheme
]

ALLOWED_URLS = [
    "https://api.github.com",
    "https://services.nvd.nist.gov",
]


@pytest.mark.parametrize("url", BLOCKED_URLS)
def test_is_safe_url_blocks_ssrf_vectors(url: str) -> None:
    assert is_safe_url(url) is False, f"expected {url!r} to be blocked"


@pytest.mark.parametrize("url", ALLOWED_URLS)
def test_is_safe_url_allows_public_apis(url: str) -> None:
    assert is_safe_url(url) is True, f"expected {url!r} to be allowed"


# ---------------------------------------------------------------------------
# Offline HTTP fakes
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Minimal stand-in for requests.Response used by HTTPClient.get/post_json."""

    def __init__(
        self,
        status_code: int = 200,
        location: str | None = None,
        is_redirect: bool | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        if location is not None:
            self.headers["location"] = location
        self.is_redirect = (location is not None) if is_redirect is None else is_redirect
        self.text = ""

    def json(self) -> dict[str, object]:
        return {}


@pytest.fixture
def no_dns(monkeypatch: pytest.MonkeyPatch):
    """Neutralize the anti-rebinding DNS check so tests stay offline.

    Returns a helper to flip it to "always internal" for block-path tests.
    """

    def set_internal(value: bool) -> None:
        monkeypatch.setattr(http_mod, "resolves_to_internal_ip", lambda host: value)

    set_internal(False)
    return set_internal


# ---------------------------------------------------------------------------
# HTTPClient.get: per-hop redirect re-validation
# ---------------------------------------------------------------------------

def test_get_redirect_to_metadata_is_revalidated_and_blocked(monkeypatch, no_dns):
    """A 302 whose Location is the cloud-metadata IP must NOT be followed."""
    client = HTTPClient()
    try:
        seen: list[str] = []

        def fake_get(url, **kwargs):
            seen.append(url)
            # First (and only) hop redirects to the AWS metadata endpoint.
            return _FakeResponse(
                status_code=302, location="http://169.254.169.254/latest/meta-data/"
            )

        monkeypatch.setattr(client._session, "get", fake_get)

        with pytest.raises(HTTPError) as excinfo:
            client.get("https://api.github.example/repo")

        # The redirect target was rejected by the static guard on re-validation.
        assert "169.254.169.254" in str(excinfo.value)
        # The transport was hit exactly once (the first URL); the metadata hop
        # was blocked BEFORE any second request went out.
        assert seen == ["https://api.github.example/repo"]
    finally:
        client.close()


def test_get_normal_200_is_returned(monkeypatch, no_dns):
    client = HTTPClient()
    try:
        resp = _FakeResponse(status_code=200)
        monkeypatch.setattr(client._session, "get", lambda url, **kw: resp)

        out = client.get("https://api.github.example/repo")

        assert out is resp
        assert out.status_code == 200
    finally:
        client.close()


def test_get_redirect_loop_raises_after_cap(monkeypatch, no_dns):
    """An endless chain of (safe) redirects must terminate with an HTTPError."""
    client = HTTPClient()
    try:
        calls = {"n": 0}

        def fake_get(url, **kwargs):
            calls["n"] += 1
            # Always redirect to another statically-safe URL so the loop only
            # ends via the hop cap, not via the SSRF guard.
            return _FakeResponse(status_code=302, location="https://loop.example/next")

        monkeypatch.setattr(client._session, "get", fake_get)

        with pytest.raises(HTTPError) as excinfo:
            client.get("https://loop.example/start")

        assert "redirect" in str(excinfo.value).lower()
        # The client tries _MAX_REDIRECTS + 1 hops, then gives up.
        assert calls["n"] == _MAX_REDIRECTS + 1
    finally:
        client.close()


# ---------------------------------------------------------------------------
# HTTPClient.post_json: outbound-webhook SSRF guard
# ---------------------------------------------------------------------------

def test_post_json_blocks_metadata_host_without_leaking_secret(monkeypatch, no_dns):
    """A statically-unsafe webhook host is blocked; the URL secret must not leak."""
    client = HTTPClient()
    try:
        def must_not_post(*args, **kwargs):
            raise AssertionError("session.post must not run for a blocked URL")

        monkeypatch.setattr(client._session, "post", must_not_post)

        with pytest.raises(HTTPError) as excinfo:
            client.post_json("http://169.254.169.254/webhook/SECRET-TOKEN", {"x": 1})

        msg = str(excinfo.value)
        assert "169.254.169.254" in msg          # host is fine to report
        assert "SECRET-TOKEN" not in msg          # path secret must be stripped
    finally:
        client.close()


def test_post_json_blocks_host_resolving_internal(monkeypatch, no_dns):
    """A host that RESOLVES to an internal IP is blocked by the DNS check."""
    client = HTTPClient()
    try:
        no_dns(True)  # every host now "resolves" internal

        def must_not_post(*args, **kwargs):
            raise AssertionError("session.post must not run for a blocked URL")

        monkeypatch.setattr(client._session, "post", must_not_post)

        with pytest.raises(HTTPError) as excinfo:
            client.post_json(
                "https://hooks.internal.example/services/SUPERSECRET", {"x": 1}
            )

        assert "SUPERSECRET" not in str(excinfo.value)
    finally:
        client.close()


def test_post_json_normal_uses_allow_redirects_false(monkeypatch, no_dns):
    client = HTTPClient()
    try:
        captured: dict[str, object] = {}
        resp = _FakeResponse(status_code=200)

        def fake_post(url, **kwargs):
            captured["url"] = url
            captured["kwargs"] = kwargs
            return resp

        monkeypatch.setattr(client._session, "post", fake_post)

        out = client.post_json("https://hooks.example/services/abc", {"text": "hi"})

        assert out is resp
        assert captured["kwargs"]["allow_redirects"] is False
    finally:
        client.close()


def test_post_json_302_is_not_followed(monkeypatch, no_dns):
    """A 302 response is returned as-is; post_json never chases the Location."""
    client = HTTPClient()
    try:
        calls = {"n": 0}
        redirect = _FakeResponse(status_code=302, location="http://169.254.169.254/")

        def fake_post(url, **kwargs):
            calls["n"] += 1
            assert kwargs["allow_redirects"] is False
            return redirect

        monkeypatch.setattr(client._session, "post", fake_post)

        out = client.post_json("https://hooks.example/services/abc", {"text": "hi"})

        assert out is redirect
        assert calls["n"] == 1  # exactly one POST, no follow to metadata
    finally:
        client.close()
