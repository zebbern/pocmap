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

import ipaddress
import json
import logging
import socket
import threading
import urllib.parse
from collections.abc import Callable
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
    "0.0.0.0",
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
        # Block internal hosts
        for blocked in BLOCKED_HOSTS:
            if blocked in hostname_lower:
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
    touch the network. A cache **hit** is returned as usual; a cache **miss**
    raises this error instead of silently returning the ``default`` (empty)
    value — a source that is merely unreachable offline must never be
    indistinguishable from "no results".

    It subclasses :class:`HTTPError` so existing ``except HTTPError`` handlers
    keep degrading gracefully, but it is a *distinct* type (and maps to the
    dedicated ``"offline"`` category via :func:`categorize_exception`) so a
    caller can tell an offline cache-miss apart from a real network failure or a
    genuinely empty result.
    """

    pass


class ValidationError(PocMapError):
    """Raised when input validation fails."""

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
    if isinstance(exc, (TimeoutError, ConnectionError, OSError, HTTPError)):
        return "network_error", True
    if isinstance(exc, ValueError):
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
    except Exception as exc:  # noqa: BLE001 - deliberately broad; re-raises bugs
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
    ) -> None:
        self.headers = headers or settings.default_headers
        self.timeout = timeout or settings.http_timeout
        self.max_retries = max_retries or settings.max_retries
        self.backoff_factor = backoff_factor or settings.backoff_factor
        # ``None`` -> defer to the process-wide ``settings.offline`` at call
        # time (so a future ``--offline`` flag / ``POCMAP_OFFLINE`` can switch it
        # on); an explicit bool forces offline on/off for just this client.
        self._offline_override = offline

        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
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
        merged_headers = {**self.headers, **(headers or {})}
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
                        current_url = urllib.parse.urljoin(
                            current_url, resp.headers["location"]
                        )
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
            # Offline reads are side-effect-free (peek); online keeps the
            # mutating LRU read (get) so cache behavior is otherwise unchanged.
            cached_body = cache.peek(cache_key) if offline else cache.get(cache_key)
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
            # Offline reads are side-effect-free (peek); online keeps the
            # mutating LRU read (get) so cache behavior is otherwise unchanged.
            cached_body = cache.peek(cache_key) if offline else cache.get(cache_key)
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
        text = resp.text
        if cache_key is not None and resp.status_code == 200:
            cache.set(cache_key, text, status=resp.status_code)
        return text

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
