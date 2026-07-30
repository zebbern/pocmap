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

import socket

import pytest

from pocmap.utils import http as http_mod
from pocmap.utils.http import (
    _MAX_REDIRECTS,
    HTTPClient,
    HTTPError,
    _should_strip_auth,
    is_safe_url,
    resolves_to_internal_ip,
)

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
    "http://metadata.google.internal/",        # GCP metadata hostname (exact)
    "http://x.metadata.google.internal/",      # ...and any subdomain (suffix)
    "file:///etc/passwd",                      # non-HTTP scheme
    "http://127.1/",                           # short-form loopback (127.0.0.1)
    "http://0x7f.1/",                          # hex short-form loopback
    "http://[::1]/",                           # IPv6 loopback literal
    "http://0.0.0.0/",                         # unspecified/any address
    # userinfo-smuggle: is_safe_url keys on .hostname, NOT .netloc, so the
    # "legit.example.com@" userinfo prefix cannot mask the metadata host.
    "http://legit.example.com@169.254.169.254/",
    "http://[::ffff:a9fe:a9fe]/",              # hex-compressed IPv4-mapped metadata
    "http://2852039166/",                      # decimal-encoded 169.254.169.254
    "http://[fd00::1]/",                        # ULA IPv6 (fc00::/7) private range
    "http://[fc00::1]/",                        # ULA IPv6 (fc00::/7) private range
    "http://[fe80::1]/",                        # link-local IPv6
]

ALLOWED_URLS = [
    "https://api.github.com",
    "https://services.nvd.nist.gov",
    # Regression: a public IPv6 literal that CONTAINS the substring "::1"
    # must not be blocked by naive substring matching against "::1".
    "https://[2606:4700:4700::1111]/",
    # Regression: a public host that merely CONTAINS "localhost" as a substring
    # (but is not localhost / a *.localhost subdomain) must be allowed.
    "https://notlocalhost.example.com/",
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


def test_get_blocks_host_resolving_internal_before_any_request(monkeypatch, no_dns):
    """get() applies the DNS-rebind check: a host resolving internal never fires a request."""
    client = HTTPClient()
    try:
        no_dns(True)  # every host now "resolves" internal

        def must_not_get(*args, **kwargs):
            raise AssertionError("session.get must not run for a rebinding host")

        monkeypatch.setattr(client._session, "get", must_not_get)

        with pytest.raises(HTTPError) as excinfo:
            client.get("https://rebind.example/x")

        assert "non-public address" in str(excinfo.value)
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


# ---------------------------------------------------------------------------
# HTTPClient.get: cross-host redirect must not replay credentials
# ---------------------------------------------------------------------------

def test_get_strips_credentials_on_cross_host_redirect(monkeypatch, no_dns):
    """A cross-origin 302 must NOT resend Authorization / apiKey to the new host.

    ``allow_redirects=False`` bypasses requests' built-in cross-host auth
    stripping, so the manual redirect loop must reproduce it — otherwise a
    bearer token (GitHub) or API key (NVD) would leak to a redirect target.
    """
    client = HTTPClient(
        headers={"Authorization": "Bearer SECRET", "apiKey": "NVDKEY", "User-Agent": "x"}
    )
    try:
        seen: list[dict[str, str | None]] = []

        def fake_get(url, **kwargs):
            # Copy: merged_headers is one dict mutated in place across hops.
            seen.append(dict(kwargs.get("headers") or {}))
            if url == "https://api.example.com/start":
                return _FakeResponse(
                    status_code=302, location="https://evil.example.net/collect"
                )
            return _FakeResponse(status_code=200)

        monkeypatch.setattr(client._session, "get", fake_get)
        client.get("https://api.example.com/start")

        assert len(seen) == 2
        # First hop (original host) carries the credentials as normal.
        assert seen[0].get("Authorization") == "Bearer SECRET"
        assert seen[0].get("apiKey") == "NVDKEY"
        # Second hop is a DIFFERENT host: credentials dropped (None == removed
        # from the requests session/request header merge).
        assert seen[1].get("Authorization") is None
        assert seen[1].get("apiKey") is None
        # A non-credential header still rides along.
        assert seen[1].get("User-Agent") == "x"
    finally:
        client.close()


def test_get_keeps_credentials_on_same_host_redirect(monkeypatch, no_dns):
    """A same-origin redirect keeps auth (matches requests' behavior)."""
    client = HTTPClient(headers={"Authorization": "Bearer SECRET", "User-Agent": "x"})
    try:
        seen: list[dict[str, str | None]] = []

        def fake_get(url, **kwargs):
            seen.append(dict(kwargs.get("headers") or {}))
            if url.endswith("/start"):
                return _FakeResponse(
                    status_code=302, location="https://api.example.com/final"
                )
            return _FakeResponse(status_code=200)

        monkeypatch.setattr(client._session, "get", fake_get)
        client.get("https://api.example.com/start")

        assert len(seen) == 2
        assert seen[0].get("Authorization") == "Bearer SECRET"
        assert seen[1].get("Authorization") == "Bearer SECRET"  # same host -> kept
    finally:
        client.close()


@pytest.mark.parametrize(
    ("old", "new", "strip"),
    [
        ("https://a.example/x", "https://b.example/y", True),   # host change
        ("https://a.example/x", "https://a.example/y", False),  # same origin
        ("http://a.example/x", "https://a.example/y", False),   # http->https upgrade
        ("https://a.example/x", "http://a.example/y", True),    # https->http downgrade
        ("https://a.example:443/x", "https://a.example/y", False),  # explicit default
        ("https://a.example/x", "https://a.example:8443/y", True),  # port change
        ("https://a.example/x", "https://a.example:bad/y", True),   # malformed port -> strip
    ],
)
def test_should_strip_auth(old: str, new: str, strip: bool) -> None:
    assert _should_strip_auth(old, new) is strip


# ---------------------------------------------------------------------------
# resolves_to_internal_ip: anti-DNS-rebinding resolution check (http.py:214)
# ---------------------------------------------------------------------------

def _fake_getaddrinfo(addr: str):
    """Return a getaddrinfo stand-in that always resolves to *addr*."""

    def _inner(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 0))]

    return _inner


def test_resolves_to_internal_ip_loopback_is_internal(monkeypatch) -> None:
    monkeypatch.setattr(http_mod.socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    assert resolves_to_internal_ip("evil.example") is True


def test_resolves_to_internal_ip_public_is_external(monkeypatch) -> None:
    monkeypatch.setattr(http_mod.socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    assert resolves_to_internal_ip("example.com") is False


def test_resolves_to_internal_ip_link_local_with_zone_id(monkeypatch) -> None:
    """A link-local IPv6 with a ``%zone`` suffix is still classed internal."""
    monkeypatch.setattr(http_mod.socket, "getaddrinfo", _fake_getaddrinfo("fe80::1%eth0"))
    assert resolves_to_internal_ip("rebind.example") is True


def test_resolves_to_internal_ip_ipv4_mapped_metadata_is_internal(monkeypatch) -> None:
    """An IPv4-mapped IPv6 resolution (``::ffff:a.b.c.d``) is unwrapped and classed internal."""
    monkeypatch.setattr(
        http_mod.socket, "getaddrinfo", _fake_getaddrinfo("::ffff:169.254.169.254")
    )
    assert resolves_to_internal_ip("rebind.example") is True


def test_resolves_to_internal_ip_ula_is_internal(monkeypatch) -> None:
    """A ULA IPv6 (``fc00::/7``, e.g. ``fd00::1``) resolution is classed internal."""
    monkeypatch.setattr(http_mod.socket, "getaddrinfo", _fake_getaddrinfo("fd00::1"))
    assert resolves_to_internal_ip("rebind.example") is True


def test_resolves_to_internal_ip_dns_failure_is_not_internal(monkeypatch) -> None:
    """A resolution error returns False so it surfaces later as a real net error."""

    def _boom(host, *args, **kwargs):
        raise socket.gaierror("name resolution failed")

    monkeypatch.setattr(http_mod.socket, "getaddrinfo", _boom)
    assert resolves_to_internal_ip("nxdomain.invalid") is False
