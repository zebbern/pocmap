"""HTTP utilities with retry logic, session management, and async support.

This module provides robust HTTP request handling with:
    - Exponential backoff retry logic
    - JSON and text response helpers
    - Both sync and async interfaces
    - Automatic header management
    - Thread-safe session access via locking

Example::

    from pocmap.utils.http import HTTPClient

    client = HTTPClient()
    data = client.get_json("https://api.example.com/data")
    text = client.get_text("https://example.com/page")
"""

from __future__ import annotations

import gzip
import io
import ipaddress
import json
import logging
import socket
import threading
import urllib.parse
import zlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal, TypeVar

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from pocmap.config import settings
from pocmap.utils.cache import HTTPCache

BLOCKED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",  # noqa: S104 - a DENYlist entry; nothing here binds a socket
    "::1",
    "169.254.169.254",  # AWS metadata
    "metadata.google.internal",  # GCP metadata
    "100.100.100.200",  # Alibaba metadata
}
BLOCKED_SCHEMES = {"file", "ftp", "gopher", "dict"}

# Wildcard-DNS / DNS-rebinding services. A hostname like
# "169.254.169.254.nip.io" resolves to the embedded IP, so a static host/IP
# blocklist alone is bypassable. Deny these services outright (offline-safe).
BLOCKED_DOMAIN_SUFFIXES = {
    "nip.io",
    "sslip.io",
    "xip.io",
    "nip.name",
    "traefik.me",
    "local.gd",
}

# Max redirect hops to follow while re-validating each one (SSRF safety).
_MAX_REDIRECTS = 5

# Credential-bearing headers that must be dropped when a redirect crosses to a
# different origin, so a bearer token / API key / cookie is never replayed to
# the redirect target. Covers the standard headers ``requests`` itself strips
# plus ``apiKey`` (the secret header this codebase sends to the NVD API).
# Compared case-insensitively.
_SENSITIVE_REDIRECT_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "apikey"}
)


def _should_strip_auth(old_url: str, new_url: str) -> bool:
    """Return True if a redirect ``old_url`` -> ``new_url`` crosses origin.

    Mirrors :meth:`requests.Session.should_strip_auth`, which our manual
    redirect loop must reproduce because ``allow_redirects=False`` bypasses
    requests' built-in cross-host auth stripping. A plain ``http`` -> ``https``
    upgrade on default ports is *not* a cross-origin move (auth is kept); any
    change of hostname, or a change of port/scheme away from the defaults, is.
    """
    old = urllib.parse.urlparse(old_url)
    new = urllib.parse.urlparse(new_url)
    if old.hostname != new.hostname:
        return True
    # ``.port`` raises ValueError on a malformed port (e.g. a hostile redirect
    # ``Location``). Since this runs before the next hop's SSRF re-check, err on
    # the safe side and strip credentials rather than letting it escape get().
    try:
        old_port = old.port
        new_port = new.port
    except ValueError:
        return True
    # Allow the http -> https upgrade on standard ports without dropping auth.
    if (
        old.scheme == "http"
        and old_port in (80, None)
        and new.scheme == "https"
        and new_port in (443, None)
    ):
        return False
    default_ports = {"http": 80, "https": 443}
    changed_port = old_port != new_port
    changed_scheme = old.scheme != new.scheme
    default_pair = (default_ports.get(old.scheme), None)
    if not changed_scheme and old_port in default_pair and new_port in default_pair:
        return False
    return changed_port or changed_scheme


def _ip_is_internal(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True for any address that must never be reached from a fetch.

    IPv4-mapped IPv6 addresses (``::ffff:a.b.c.d``) are unwrapped to their
    embedded IPv4 form before classification. On Python 3.10 the IPv6 flags
    (``is_private``/``is_link_local``/…) do not reliably reflect the mapped
    address, so ``::ffff:169.254.169.254`` would otherwise slip through.
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _numeric_host_to_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Best-effort canonicalization of a numeric-encoded host to an IPv4 address.

    ``urllib``/``ipaddress`` only recognize dotted-quad and bracketed IPv6
    literals, so an attacker can smuggle an internal address past a literal-IP
    check as a decimal (``2130706433``), hex (``0x7f000001``), octal
    (``0o17700000001``) integer, or a dotted form with octal/hex octets
    (``0177.0.0.1``). This resolves all of those to their canonical IPv4 form
    so :func:`_ip_is_internal` can classify them. Returns ``None`` when *host*
    is not a numeric IPv4 encoding. Purely offline — performs no DNS.
    """
    # Integer forms: int(host, 0) auto-detects decimal / 0x hex / 0o octal / 0b.
    try:
        value = int(host, 0)
    except ValueError:
        value = None
    if value is not None and 0 <= value <= 0xFFFFFFFF:
        try:
            return ipaddress.IPv4Address(value)
        except (ipaddress.AddressValueError, ValueError):
            return None
    # Dotted forms with octal/hex octets (e.g. "0177.0.0.1") via inet_aton.
    try:
        packed = socket.inet_aton(host)
    except OSError:
        return None
    try:
        return ipaddress.IPv4Address(packed)
    except (ipaddress.AddressValueError, ValueError):
        return None


def is_safe_url(url: str) -> bool:
    """Validate URL is safe to fetch (SSRF prevention).

    Blocks non-HTTP(S) schemes, known internal hosts, literal private/loopback/
    link-local/reserved IPs, and wildcard-DNS rebinding services (nip.io etc.).

    This is a fast, offline, static check. Hostnames that resolve to internal
    IPs (the general DNS-rebinding case) are additionally rejected at request
    time by :meth:`HTTPClient.get` via :func:`resolves_to_internal_ip`.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        hostname_lower = hostname.lower()
        # Block internal hosts by EXACT host or dotted-suffix match. A substring
        # test both over-blocks legitimate hosts (a public IPv6 literal such as
        # ``2606:4700:4700::1111`` contains the substring ``::1``; a domain like
        # ``notlocalhost.com`` contains ``localhost``) and is not what keeps us
        # safe: literal internal IPs are caught by ``_ip_is_internal`` below, and
        # hostnames that resolve internally are caught at request time by
        # ``resolves_to_internal_ip``.
        for blocked in BLOCKED_HOSTS:
            if hostname_lower == blocked or hostname_lower.endswith("." + blocked):
                return False
        # Block wildcard-DNS / DNS-rebinding services outright
        for suffix in BLOCKED_DOMAIN_SUFFIXES:
            if hostname_lower == suffix or hostname_lower.endswith("." + suffix):
                return False
        # Block literal private IP ranges
        try:
            ip = ipaddress.ip_address(hostname)
            if _ip_is_internal(ip):
                return False
        except ValueError:
            # Not a standard dotted-quad/IPv6 literal. Guard against
            # numeric-encoded IPv4 (decimal/hex/octal) that canonicalizes to an
            # internal address, e.g. http://2130706433/ == 127.0.0.1.
            numeric_ip = _numeric_host_to_ipv4(hostname)
            if numeric_ip is not None and _ip_is_internal(numeric_ip):
                return False
        return True
    except Exception:
        return False


def resolves_to_internal_ip(hostname: str) -> bool:
    """Best-effort anti-DNS-rebinding: resolve *hostname* and flag internal IPs.

    Returns True if the hostname resolves to any private/loopback/link-local/
    reserved/multicast address. Resolution failures return False so a transient
    DNS error surfaces as the real network error at connect time rather than a
    misleading SSRF block.

    Note: this narrows but does not fully close the TOCTOU rebinding window
    (the value we resolve here can differ from the one the socket later
    resolves). Full closure would require pinning the validated IP for the
    connection.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (OSError, UnicodeError):
        return False
    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]  # drop IPv6 zone id
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _ip_is_internal(ip):
            return True
    return False


logger = logging.getLogger(__name__)


class PocMapError(Exception):
    """Base exception for all package errors."""

    pass


class HTTPError(PocMapError):
    """Raised when an HTTP request fails after all retries."""

    def __init__(self, message: str, status_code: int | None = None, url: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.url = url


class RateLimitError(HTTPError):
    """Raised when an upstream signals rate limiting.

    A distinct :class:`HTTPError` subclass so callers can tell a *throttled*
    source (HTTP 429, or GitHub's HTTP 403 with ``X-RateLimit-Remaining: 0``)
    apart from a generic failure or a genuine empty result. Because it still
    subclasses :class:`HTTPError`, every existing ``except HTTPError`` handler
    keeps catching it — the distinction is purely additive.
    """

    pass


class OfflineError(HTTPError):
    """Raised when offline mode is active and no cached response is available.

    Offline mode (``settings.offline`` / ``POCMAP_OFFLINE`` / a per-client
    ``HTTPClient(offline=True)``) makes :meth:`HTTPClient.get_json` and
    :meth:`HTTPClient.get_text` serve *only* from the persistent cache and never
    touch the network. A cache **hit** is returned as usual — including an
    **expired** entry, which is served stale because an air-gapped run cannot
    refresh it and stale data beats none. Only a genuinely **absent** (or
    corrupt) entry raises this error, instead of silently returning the
    ``default`` (empty) value — a source that is merely unreachable offline must
    never be indistinguishable from "no results".

    It subclasses :class:`HTTPError` so existing ``except HTTPError`` handlers
    keep degrading gracefully, but it is a *distinct* type (and maps to the
    dedicated ``"offline"`` category via :func:`categorize_exception`) so a
    caller can tell an offline cache-miss apart from a real network failure or a
    genuinely empty result.
    """

    pass


class ValidationError(PocMapError, ValueError):
    """Raised when input validation fails.

    Also a :class:`ValueError`: bad input *is* a value error, callers reasonably
    write ``except ValueError``, and :func:`categorize_exception` keys
    ``invalid_input`` off it. Without that base a malformed CVE ID was reported
    to agents as ``category: "unknown"`` despite the documented contract
    promising ``invalid_input``.
    """

    pass


class NotFoundError(PocMapError):
    """Raised when a requested resource is not found."""

    pass


# ---------------------------------------------------------------------------
# Per-source reliability status (ERR-RESULT)
#
# Lets an aggregating service report *why* a source contributed no rows so a
# down/throttled upstream can never masquerade as "nothing found" — a
# trust-critical distinction for a security tool.
# ---------------------------------------------------------------------------


class FetchStatus(str, Enum):
    """Outcome of querying a single upstream source."""

    OK = "ok"  # source responded and returned >= 1 result
    EMPTY = "empty"  # source responded successfully with 0 results
    RATE_LIMITED = "rate_limited"  # source throttled us (HTTP 429 / 403 rl)
    ERROR = "error"  # source failed (network / HTTP / parse error)


# Exceptions that indicate a bug in *our own* code rather than an upstream
# problem. These must never be silently degraded into an "empty" result:
# swallowing one is exactly what hid the FIX-GHPOC ``TypeError`` (an adapter
# calling a service method with the wrong signature) for so long. They are
# re-raised by :func:`collect_source` so they surface in tests/CI.
#
# Deliberately conservative: ``KeyError``/``AttributeError``/``IndexError`` are
# routinely raised while parsing volatile external HTML/CSV/JSON and must still
# degrade gracefully, so they are NOT treated as programming errors here.
_PROGRAMMING_ERRORS: tuple[type[BaseException], ...] = (
    TypeError,
    NameError,
    UnboundLocalError,
)


def is_programming_error(exc: BaseException) -> bool:
    """Return True if *exc* is a programming bug that must not be swallowed."""
    return isinstance(exc, _PROGRAMMING_ERRORS)


def categorize_exception(exc: BaseException) -> tuple[str, bool]:
    """Map *exc* to the MCP ``(category, retryable)`` taxonomy.

    Mirrors ``mcp_server._format_error_json`` so the CLI, service, and MCP
    layers describe a failed source with the same vocabulary.
    """
    if isinstance(exc, RateLimitError):
        return "rate_limited", True
    if isinstance(exc, OfflineError):
        # Distinct from a real network failure: retrying now won't help until
        # connectivity/offline mode changes, so it is not retryable in-state.
        return "offline", False
    if isinstance(exc, PermissionError):
        return "permission_error", False
    if isinstance(exc, NotFoundError):
        # Checked before the network bucket: the resource genuinely does not
        # exist upstream, so retrying will not change the answer.
        return "not_found", False
    if isinstance(exc, (TimeoutError, ConnectionError, OSError, HTTPError)):
        return "network_error", True
    if isinstance(exc, ValueError):
        # Includes ValidationError, which subclasses ValueError.
        return "invalid_input", False
    return "unknown", False


def _is_rate_limited(resp: requests.Response) -> bool:
    """Detect an upstream rate-limit signal on a completed response.

    True for HTTP 429, or HTTP 403 with GitHub's ``X-RateLimit-Remaining: 0``
    header. urllib3's ``Retry`` already retries 429 (and 5xx); this only
    classifies what remains *after* retries so a throttled source is
    distinguishable from a generic failure or an empty result.
    """
    if resp.status_code == 429:
        return True
    if resp.status_code == 403:
        remaining = resp.headers.get("X-RateLimit-Remaining")
        if remaining is not None and remaining.strip() == "0":
            return True
    return False


# Ceiling on a decompressed text body. The largest legitimate feed pocmap reads
# is the EPSS catalogue at ~13 MB decompressed, so this leaves ample headroom
# while keeping a decompression bomb from exhausting memory.
_MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024


def _decode_text_body(resp: requests.Response) -> str:
    """Return *resp*'s body as text, transparently gunzipping a ``.gz`` payload.

    ``requests`` only auto-decompresses when the server sets
    ``Content-Encoding: gzip``. A gzip *file* served as ``application/gzip`` —
    which is how the EPSS bulk feed ships — arrives as raw deflate bytes, and
    ``resp.text`` would then be mojibake that gets cached as if it were valid.
    Detect the gzip magic on the raw body instead of trusting headers.

    Falls back to ``resp.text`` whenever the body is not gzip-framed or the
    stream is truncated, so this can never make a working feed fail.
    """
    raw = resp.content
    if raw[:2] != b"\x1f\x8b":
        return resp.text
    try:
        # Decompress incrementally against a cap rather than calling
        # gzip.decompress(), which is unbounded: a few KB of crafted deflate
        # expands to gigabytes and would exhaust memory before any size check.
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            data = stream.read(_MAX_DECOMPRESSED_BYTES + 1)
            if len(data) > _MAX_DECOMPRESSED_BYTES:
                logger.warning(
                    "Gzipped body of %s exceeds the %d MB decompression cap; using it raw",
                    resp.url,
                    _MAX_DECOMPRESSED_BYTES // (1024 * 1024),
                )
                return resp.text
        return data.decode(resp.encoding or "utf-8", errors="replace")
    except (OSError, EOFError, zlib.error):
        logger.warning("Body of %s looked gzipped but did not decompress", resp.url)
        return resp.text


@dataclass(frozen=True)
class SourceStatus:
    """Health record for a single source, produced while aggregating a lookup.

    Serializes (via :meth:`to_dict`) into the ``sources`` block of MCP/JSON
    output using the same ``category``/``retryable`` taxonomy as the MCP error
    envelope.
    """

    name: str
    status: FetchStatus
    count: int = 0
    category: str = "ok"
    retryable: bool = False
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "source": self.name,
            "status": self.status.value,
            "count": self.count,
            "retryable": self.retryable,
        }
        if self.category and self.category != "ok":
            payload["category"] = self.category
        if self.detail:
            payload["detail"] = self.detail
        return payload


_T = TypeVar("_T")


def collect_source(name: str, fn: Callable[[], list[_T]]) -> tuple[list[_T], SourceStatus]:
    """Run source callable *fn*, classifying its outcome into a :class:`SourceStatus`.

    - A programming bug (``TypeError``/``NameError``/``UnboundLocalError``) is
      **re-raised**, never masked as empty — the FIX-GHPOC-class regression guard.
    - :class:`RateLimitError` -> ``RATE_LIMITED``; any other operational failure
      (HTTP/network) -> ``ERROR``; both degrade gracefully (return ``[]``).
    - A successful call yields ``OK`` (non-empty) or ``EMPTY`` (zero rows).
    """
    try:
        results = fn()
    except Exception as exc:
        if is_programming_error(exc):
            raise
        category, retryable = categorize_exception(exc)
        status = (
            FetchStatus.RATE_LIMITED
            if isinstance(exc, RateLimitError)
            else FetchStatus.ERROR
        )
        logger.warning("source %s degraded (%s): %s", name, status.value, type(exc).__name__)
        return [], SourceStatus(
            name=name,
            status=status,
            category=category,
            retryable=retryable,
            detail=type(exc).__name__,
        )
    result_list = list(results)
    outcome = FetchStatus.OK if result_list else FetchStatus.EMPTY
    return result_list, SourceStatus(name=name, status=outcome, count=len(result_list))


class HTTPClient:
    """HTTP client with retry logic and configurable timeouts.

    This client uses a ``threading.Lock`` to serialize access to the
    underlying ``requests.Session``, making it safe to share across threads.

    Args:
        headers: Default headers to include in every request.
        timeout: Request timeout in seconds.
        max_retries: Maximum retry attempts for failed requests.
        backoff_factor: Exponential backoff multiplier.
        pool_connections: Connection pool size.
        retry_methods: HTTP methods eligible for automatic retry. Defaults to
            ``("HEAD", "GET", "OPTIONS")``; pass a sequence including ``"POST"``
            only when the POST is idempotent (a lookup, not a notification).

    Example::

        client = HTTPClient()
        data = client.get_json("https://api.github.com/repos/owner/repo")
    """

    def __init__(
        self,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
        max_retries: int | None = None,
        backoff_factor: float | None = None,
        pool_connections: int = 10,
        offline: bool | None = None,
        retry_methods: Sequence[str] | None = None,
    ) -> None:
        self.headers = headers or settings.default_headers
        self.timeout = timeout or settings.http_timeout
        self.max_retries = max_retries or settings.max_retries
        self.backoff_factor = backoff_factor or settings.backoff_factor
        # ``None`` -> defer to the process-wide ``settings.offline`` at call
        # time (so a future ``--offline`` flag / ``POCMAP_OFFLINE`` can switch it
        # on); an explicit bool forces offline on/off for just this client.
        self._offline_override = offline

        # POST is excluded by default *on purpose*: the only POST in the default
        # client is an outbound webhook notification, and an automatic retry
        # would re-send it. A caller whose POST is a pure lookup (OSV's query
        # endpoint) opts in via ``retry_methods`` rather than widening this for
        # everyone.
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=list(retry_methods or ("HEAD", "GET", "OPTIONS")),
            raise_on_status=False,
        )

        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=pool_connections,
            pool_maxsize=pool_connections,
        )

        self._session = requests.Session()
        self._session.headers.update(self.headers)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)
        self._lock = threading.Lock()

        logger.debug(
            "HTTPClient initialized (timeout=%s, max_retries=%s)",
            self.timeout,
            self.max_retries,
        )

    @staticmethod
    def _assert_url_safe(url: str) -> None:
        """Raise HTTPError if *url* is unsafe (static check + DNS resolution)."""
        if not is_safe_url(url):
            raise HTTPError(f"SSRF: blocked request to unsafe URL: {url}", url=url)
        host = urllib.parse.urlparse(url).hostname
        if host and resolves_to_internal_ip(host):
            raise HTTPError(
                f"SSRF: host resolves to a non-public address: {url}", url=url
            )

    def _is_offline(self) -> bool:
        """Return whether this client must serve from cache only (no network).

        A per-client override (``HTTPClient(offline=...)``) wins; otherwise the
        process-wide :data:`pocmap.config.settings.offline` is read *at call
        time* so a future ``--offline`` CLI flag / ``POCMAP_OFFLINE`` can toggle
        it without rebuilding the client.
        """
        if self._offline_override is not None:
            return self._offline_override
        return settings.offline

    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        timeout: int | None = None,
    ) -> requests.Response:
        """POST *payload* as JSON to *url* with SSRF validation and no redirects.

        Applies the same guard as :meth:`get` — the static :func:`is_safe_url`
        check plus the :func:`resolves_to_internal_ip` DNS check via
        :meth:`_assert_url_safe` — and sends with ``allow_redirects=False`` so a
        3xx ``Location`` cannot bounce the POST to an internal host (cloud
        metadata, localhost). Intended for outbound webhook notifications.

        Error messages are reduced to the target hostname so any secret carried
        in the URL path/query (e.g. a Slack/Discord webhook token) is never
        placed in an exception message or log line.

        Args:
            url: Target URL.
            payload: JSON-serializable body to POST.
            timeout: Per-request timeout override (falls back to instance default).

        Returns:
            The HTTP response object.

        Raises:
            HTTPError: If the URL is unsafe/internal or the request fails.
        """
        request_timeout = timeout if timeout is not None else self.timeout
        host = urllib.parse.urlparse(url).hostname or "webhook"
        try:
            self._assert_url_safe(url)
        except HTTPError as exc:
            # Re-raise without the full URL (it may embed a webhook token).
            raise HTTPError(f"SSRF: blocked webhook POST to {host}", url=url) from exc
        try:
            with self._lock:
                resp = self._session.post(
                    url,
                    json=payload,
                    headers={**self.headers, "Content-Type": "application/json"},
                    timeout=request_timeout,
                    allow_redirects=False,
                )
            logger.debug("POST %s -> %d", host, resp.status_code)
            return resp
        except requests.RequestException as exc:
            raise HTTPError(f"POST to {host} failed: {type(exc).__name__}", url=url) from exc

    def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        timeout: int | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a GET request and return the response.

        Args:
            url: Target URL.
            headers: Additional headers merged with defaults.
            params: URL query parameters.
            timeout: Per-request timeout override (falls back to instance default).
            **kwargs: Additional arguments passed to ``requests.get``.

        Returns:
            The HTTP response object.

        Raises:
            HTTPError: If the request fails after all retries.
        """
        # ``str | None`` values: a header set to ``None`` is *removed* by
        # requests during session/request header merge, which is how we drop a
        # credential header carried at the session level on a cross-host redirect.
        merged_headers: dict[str, str | None] = {**self.headers, **(headers or {})}
        request_timeout = timeout if timeout is not None else self.timeout
        # Follow redirects manually so EVERY hop is SSRF-validated. requests'
        # default auto-follow would let a 3xx Location reach an internal host
        # (cloud metadata, localhost) after the initial URL already passed.
        kwargs.pop("allow_redirects", None)

        current_url = url
        current_params = params
        try:
            with self._lock:
                for _hop in range(_MAX_REDIRECTS + 1):
                    self._assert_url_safe(current_url)
                    resp = self._session.get(
                        current_url,
                        headers=merged_headers,
                        params=current_params,
                        timeout=request_timeout,
                        allow_redirects=False,
                        **kwargs,
                    )
                    if resp.is_redirect and resp.headers.get("location"):
                        next_url = urllib.parse.urljoin(
                            current_url, resp.headers["location"]
                        )
                        # Drop credential-bearing headers before following a
                        # cross-origin redirect so a token is never replayed to
                        # the target. Setting to None also removes the
                        # session-level copy during requests' header merge.
                        if _should_strip_auth(current_url, next_url):
                            for _name in list(merged_headers):
                                if _name.lower() in _SENSITIVE_REDIRECT_HEADERS:
                                    merged_headers[_name] = None
                        current_url = next_url
                        current_params = None  # query is carried in the target
                        continue
                    logger.debug("GET %s -> %d", current_url, resp.status_code)
                    # Distinguish throttling from a generic failure so callers
                    # can report RATE_LIMITED instead of masking it as "empty".
                    # urllib3 already retried 429/5xx before we get here.
                    if _is_rate_limited(resp):
                        raise RateLimitError(
                            f"Rate limited by upstream (HTTP {resp.status_code})",
                            status_code=resp.status_code,
                            url=current_url,
                        )
                    return resp
            raise HTTPError(f"Too many redirects (> {_MAX_REDIRECTS}): {url}", url=url)
        except requests.RequestException as exc:
            logger.error("GET %s failed: %s", current_url, exc)
            raise HTTPError(str(exc), url=current_url) from exc

    def get_json(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        default: Any = None,
        timeout: int | None = None,
        no_cache: bool = False,
        **kwargs: Any,
    ) -> Any:
        """Send a GET request and parse the response as JSON.

        When the persistent cache is enabled, a fresh cached ``200`` body for the
        same ``(method, url, params)`` is returned **without any network call**;
        the SSRF-validated :meth:`get` path runs only on a cache miss/expiry, and
        only ``200`` responses are written back.

        Args:
            url: Target URL.
            headers: Additional headers merged with defaults.
            params: URL query parameters.
            default: Value to return if the response is not valid JSON.
            timeout: Per-request timeout override (falls back to instance default).
            no_cache: When ``True``, bypass the cache entirely (no read, no write).
            **kwargs: Additional arguments passed to ``requests.get``.

        Returns:
            Parsed JSON data, or *default* if parsing fails.
        """
        cache = _get_cache()
        offline = self._is_offline()
        cache_key: str | None = None
        if cache.enabled and not no_cache:
            cache_key = HTTPCache.make_key("GET", url, params)
            # Offline reads are side-effect-free (peek) and serve stale entries
            # (air-gapped runs can't refresh, so stale beats nothing); online
            # keeps the mutating, fresh-only LRU read (get) unchanged.
            cached_body = (
                cache.peek(cache_key, allow_stale=True) if offline else cache.get(cache_key)
            )
            if cached_body is not None:
                try:
                    return json.loads(cached_body)
                except (ValueError, TypeError):
                    logger.warning("Discarding corrupt cached JSON for %s", url)
                    # fall through: refetch when online; offline-miss when not
        if offline:
            # Serve only from cache; never hit the network. A miss (incl. a
            # disabled cache or no_cache=True) is a clear, categorized error,
            # never a silent empty ``default``.
            raise OfflineError(f"offline: no cached response for {url}", url=url)

        resp = self.get(url, headers=headers, params=params, timeout=timeout, **kwargs)
        if resp.status_code == 404:
            return default
        try:
            data = resp.json()
        except (ValueError, TypeError):
            logger.warning("Failed to parse JSON from %s", url)
            return default
        if cache_key is not None and resp.status_code == 200:
            cache.set(cache_key, resp.text, status=resp.status_code)
        return data

    def get_text(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        default: str = "",
        timeout: int | None = None,
        no_cache: bool = False,
        **kwargs: Any,
    ) -> str:
        """Send a GET request and return the response body as text.

        When the persistent cache is enabled, a fresh cached ``200`` body for the
        same ``(method, url, params)`` is returned **without any network call**;
        the SSRF-validated :meth:`get` path runs only on a cache miss/expiry, and
        only ``200`` responses are written back.

        Args:
            url: Target URL.
            headers: Additional headers.
            params: URL query parameters.
            default: Value to return on failure.
            timeout: Per-request timeout override (falls back to instance default).
            no_cache: When ``True``, bypass the cache entirely (no read, no write).
            **kwargs: Additional arguments.

        Returns:
            Response body text, or *default* on failure.
        """
        cache = _get_cache()
        offline = self._is_offline()
        cache_key: str | None = None
        if cache.enabled and not no_cache:
            cache_key = HTTPCache.make_key("GET", url, params)
            # Offline reads are side-effect-free (peek) and serve stale entries
            # (air-gapped runs can't refresh, so stale beats nothing); online
            # keeps the mutating, fresh-only LRU read (get) unchanged.
            cached_body = (
                cache.peek(cache_key, allow_stale=True) if offline else cache.get(cache_key)
            )
            if cached_body is not None:
                return cached_body
        if offline:
            # Serve only from cache; never hit the network. A miss (incl. a
            # disabled cache or no_cache=True) is a clear, categorized error,
            # never a silent empty ``default``.
            raise OfflineError(f"offline: no cached response for {url}", url=url)

        resp = self.get(url, headers=headers, params=params, timeout=timeout, **kwargs)
        if resp.status_code == 404:
            return default
        text = _decode_text_body(resp)
        if cache_key is not None and resp.status_code == 200:
            cache.set(cache_key, text, status=resp.status_code)
        return text

    def post_json_cached(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
        default: Any = None,
        timeout: int | None = None,
        no_cache: bool = False,
    ) -> Any:
        """POST a JSON body, parse the JSON reply, and cache it like a GET.

        For an API whose *query* lives in the request body rather than the URL —
        OSV's ``/v1/query`` — a POST is semantically a read. This gives it the
        same guarantees every GET already has and which :meth:`post_json`
        deliberately lacks (it exists for webhook delivery):

        * **Persistent cache**, keyed on ``(POST, url, body)``.
        * **Offline mode** — served from cache, and a miss raises
          :class:`OfflineError` instead of quietly hitting the network.
        * **Throttle detection** — a surviving 429 raises :class:`RateLimitError`
          rather than degrading into an empty result.
        * **SSRF validation** and ``allow_redirects=False``, so a 3xx cannot
          bounce the body to an internal host.

        Args:
            url: Target URL.
            payload: JSON-serializable request body.
            headers: Additional headers merged with defaults.
            default: Value returned when the reply is 404 or not valid JSON.
            timeout: Per-request timeout override.
            no_cache: Bypass the cache entirely (no read, no write).

        Returns:
            Parsed JSON, or *default*.

        Raises:
            OfflineError: Offline mode with no cached response.
            RateLimitError: Upstream throttled the request.
            HTTPError: The URL is unsafe or the request failed.
        """
        cache = _get_cache()
        offline = self._is_offline()
        cache_key: str | None = None
        if cache.enabled and not no_cache:
            cache_key = HTTPCache.make_key("POST", url, body=payload)
            cached_body = (
                cache.peek(cache_key, allow_stale=True) if offline else cache.get(cache_key)
            )
            if cached_body is not None:
                try:
                    return json.loads(cached_body)
                except (ValueError, TypeError):
                    logger.warning("Discarding corrupt cached JSON for %s", url)
        if offline:
            raise OfflineError(f"offline: no cached response for {url}", url=url)

        merged_headers = {**self.headers, **(headers or {}), "Content-Type": "application/json"}
        request_timeout = timeout if timeout is not None else self.timeout
        self._assert_url_safe(url)
        try:
            with self._lock:
                resp = self._session.post(
                    url,
                    json=payload,
                    headers=merged_headers,
                    timeout=request_timeout,
                    allow_redirects=False,
                )
        except requests.RequestException as exc:
            logger.error("POST %s failed: %s", url, exc)
            raise HTTPError(str(exc), url=url) from exc

        logger.debug("POST %s -> %d", url, resp.status_code)
        if _is_rate_limited(resp):
            raise RateLimitError(
                f"Rate limited by upstream (HTTP {resp.status_code})",
                status_code=resp.status_code,
                url=url,
            )
        if resp.status_code == 404:
            return default
        if not 200 <= resp.status_code < 300:
            # Anything that is not a success is an error, including a 3xx:
            # redirects are not followed here, so a 302 would otherwise fall
            # through to a failed JSON parse and return ``default``. An error
            # body is also still valid JSON, so parsing it blindly would hand
            # the caller ``{"code": 3, "message": "invalid ecosystem"}``. Both
            # paths let a failed *request* read as an empty *result*.
            detail = resp.text.strip()[:200]
            raise HTTPError(
                f"HTTP {resp.status_code} from {url}: {detail}",
                status_code=resp.status_code,
                url=url,
            )
        try:
            data = resp.json()
        except (ValueError, TypeError) as exc:
            # A success status with an unparseable body means something is
            # intercepting or mangling the response (a captive portal, a proxy
            # error page). Never silently return "nothing found" for that.
            raise HTTPError(
                f"Unparseable JSON from {url} (HTTP {resp.status_code})",
                status_code=resp.status_code,
                url=url,
            ) from exc
        if cache_key is not None and resp.status_code == 200:
            cache.set(cache_key, resp.text, status=resp.status_code)
        return data

    def close(self) -> None:
        """Close the underlying session and release connections."""
        self._session.close()
        logger.debug("HTTPClient session closed")

    def __enter__(self) -> HTTPClient:
        return self

    def __exit__(self, *exc: Any) -> Literal[False]:
        self.close()
        return False


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

_client: HTTPClient | None = None
_cache: HTTPCache | None = None


def _get_default_client() -> HTTPClient:
    """Return a lazily-initialized default HTTP client."""
    global _client
    if _client is None:
        _client = HTTPClient()
    return _client


def _get_cache() -> HTTPCache:
    """Return the lazily-initialized shared HTTP response cache.

    Built once from :data:`pocmap.config.settings`. Tests may replace the module
    global ``_cache`` to inject a temp-dir-backed cache.
    """
    global _cache
    if _cache is None:
        _cache = HTTPCache.from_settings()
    return _cache


def fetch_json(
    url: str,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    default: Any = None,
    timeout: int | None = None,
) -> Any:
    """Fetch and parse JSON from a URL using the default client.

    Args:
        url: Target URL.
        headers: Additional headers.
        params: URL query parameters.
        default: Fallback value on failure.
        timeout: Request timeout override.

    Returns:
        Parsed JSON data, or *default*.
    """
    client = _get_default_client()
    return client.get_json(url, headers=headers, params=params, default=default, timeout=timeout)


def fetch_text(
    url: str,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    default: str = "",
    timeout: int | None = None,
) -> str:
    """Fetch text from a URL using the default client.

    Args:
        url: Target URL.
        headers: Additional headers.
        params: URL query parameters.
        default: Fallback value on failure.
        timeout: Request timeout override.

    Returns:
        Response body text, or *default*.
    """
    client = _get_default_client()
    return client.get_text(url, headers=headers, params=params, default=default, timeout=timeout)
