"""File-backed, TTL'd HTTP response cache.

A small, dependency-free on-disk cache used by :class:`pocmap.utils.http.HTTPClient`
to serve repeated GET requests without hitting the network. It exists to make the
CLI/MCP fast, resilient to transient upstream failures, and gentle on API rate
limits (GitHub, NVD, EPSS, etc.).

Design:
    * **Key** — a SHA-256 hex digest of ``(method, url, sorted-params)``. Keys are
      filesystem-safe by construction; every path is additionally run through
      :func:`pocmap.utils.paths.safe_path` for containment.
    * **Entry** — a JSON envelope ``{status, created, ttl, body}`` written to
      ``<cache_dir>/http/<key>.json``.
    * **Freshness** — per-entry TTL; an entry older than its ``ttl`` is a miss and
      is removed on access.
    * **Atomic writes** — content is written to a temp file in the same directory
      and then :func:`os.replace`\\d into place (atomic, overwrites on Windows).
    * **Bounded size** — a total-byte cap with oldest-first (LRU-ish) eviction.
      Read hits refresh the entry's mtime, so eviction approximates LRU.
    * **Corruption-safe** — any unreadable/corrupt/partial entry is treated as a
      miss (falls back to the network); the cache never raises to its callers.

Only successful ``200`` bodies are ever stored — error and non-200 responses are
never cached.

Example::

    from pocmap.utils.cache import HTTPCache

    cache = HTTPCache.from_settings()
    key = HTTPCache.make_key("GET", "https://api.example/data", {"q": "x"})
    body = cache.get(key)          # None on miss/expiry/corruption
    if body is None:
        body = fetch_from_network()
        cache.set(key, body)       # status defaults to 200
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pocmap.config import DEFAULT_CACHE_MAX_MB, DEFAULT_CACHE_TTL, settings
from pocmap.utils.paths import safe_path

logger = logging.getLogger(__name__)

# Subdirectory under ``cache_dir`` reserved for HTTP response entries, so the
# HTTP cache never collides with other consumers of the cache directory.
_HTTP_SUBDIR = "http"
_ENTRY_SUFFIX = ".json"


def _normalize_params(params: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return *params* as a key-sorted plain dict (stable for hashing)."""
    if not params:
        return {}
    return {str(key): params[key] for key in sorted(params)}


class HTTPCache:
    """A keyed, TTL'd, size-bounded on-disk cache for HTTP response bodies.

    Args:
        cache_dir: Base cache directory. HTTP entries live under ``<cache_dir>/http``.
        ttl: Default freshness window, in seconds, for newly written entries.
        max_bytes: Total on-disk cap (bytes). ``<= 0`` disables eviction.
        enabled: When ``False``, :meth:`get`/:meth:`set` are no-ops (always a miss).
    """

    def __init__(
        self,
        cache_dir: Path | str,
        ttl: int = DEFAULT_CACHE_TTL,
        max_bytes: int = DEFAULT_CACHE_MAX_MB * 1024 * 1024,
        enabled: bool = True,
    ) -> None:
        self._dir = Path(cache_dir) / _HTTP_SUBDIR
        self.ttl = ttl
        self.max_bytes = max_bytes
        self.enabled = enabled
        self._lock = threading.Lock()

    @classmethod
    def from_settings(cls) -> HTTPCache:
        """Build a cache from the global :data:`pocmap.config.settings`."""
        return cls(
            cache_dir=settings.cache_dir,
            ttl=settings.cache_ttl,
            max_bytes=settings.cache_max_mb * 1024 * 1024,
            enabled=settings.cache_enabled,
        )

    # -- key derivation -----------------------------------------------------

    @staticmethod
    def make_key(
        method: str,
        url: str,
        params: Mapping[str, Any] | None = None,
    ) -> str:
        """Return a stable SHA-256 hex key for ``(method, url, sorted-params)``."""
        payload = {
            "method": method.upper(),
            "url": url,
            "params": _normalize_params(params),
        }
        raw = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # -- public API ---------------------------------------------------------

    def get(self, key: str) -> str | None:
        """Return the cached body for *key*, or ``None`` on miss/expiry/corruption.

        Corrupt, partial, or expired entries are removed as a side effect and
        reported as a miss so the caller transparently falls back to the network.
        A read hit refreshes the entry's mtime so eviction approximates LRU.
        """
        return self._read(key, mutate=True)

    def peek(self, key: str) -> str | None:
        """Read-only presence check for a fresh cached body (offline path).

        Returns the body on a fresh hit and ``None`` when absent — i.e. missing,
        expired, or corrupt — so a caller can distinguish "present" from
        "absent" without falling back to the network. Unlike :meth:`get` this is
        **side-effect free**: it never deletes expired/corrupt entries and never
        bumps the mtime. Offline mode uses it because a ``None`` here means
        "raise a cache-miss (offline)", not "refetch"; entries are left on disk
        for a later online run to reuse or refresh.
        """
        return self._read(key, mutate=False)

    def _read(self, key: str, *, mutate: bool) -> str | None:
        """Shared read for :meth:`get` (``mutate=True``) and :meth:`peek`.

        When *mutate* is ``True`` (the :meth:`get` contract) corrupt/expired
        entries are purged on access and a hit refreshes the mtime for LRU;
        when ``False`` (the :meth:`peek` contract) the read has no side effects.
        """
        if not self.enabled:
            return None
        try:
            path = self._path_for(key)
        except ValueError:
            return None
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return None  # missing / unreadable -> miss
        try:
            entry = json.loads(raw)
        except (ValueError, TypeError):
            if mutate:
                self._safe_unlink(path)  # corrupt -> discard + miss
            return None
        if not isinstance(entry, dict):
            if mutate:
                self._safe_unlink(path)
            return None

        created = entry.get("created")
        body = entry.get("body")
        if not isinstance(created, (int, float)) or not isinstance(body, str):
            if mutate:
                self._safe_unlink(path)
            return None

        ttl_raw = entry.get("ttl", self.ttl)
        ttl = ttl_raw if isinstance(ttl_raw, (int, float)) else self.ttl
        if ttl >= 0 and (time.time() - created) > ttl:
            if mutate:
                self._safe_unlink(path)  # expired -> discard + miss
            return None

        if mutate:
            # Read hit: refresh mtime so eviction approximates LRU (best-effort).
            with contextlib.suppress(OSError):
                os.utime(path, None)
        return body

    def set(
        self,
        key: str,
        value: str,
        status: int = 200,
        ttl: int | None = None,
    ) -> None:
        """Store *value* under *key*. Only ``200`` responses are ever cached.

        A non-200 *status*, a disabled cache, or any filesystem error is a silent
        no-op — caching must never break the request path.
        """
        if not self.enabled or status != 200:
            return
        try:
            path = self._path_for(key)
        except ValueError:
            return
        entry: dict[str, Any] = {
            "status": status,
            "created": time.time(),
            "ttl": self.ttl if ttl is None else ttl,
            "body": value,
        }
        with self._lock:
            try:
                self._dir.mkdir(parents=True, exist_ok=True)
                self._atomic_write(path, entry)
            except OSError as exc:
                logger.debug("cache write failed for %s: %s", key, exc)
                return
            self._enforce_size_cap()

    def clear(self) -> None:
        """Remove every HTTP cache entry (best-effort)."""
        with self._lock:
            for path, _mtime, _size in self._entry_files():
                self._safe_unlink(path)

    def info(self) -> dict[str, int]:
        """Return ``{"entries": <count>, "bytes": <total-size>}``."""
        files = self._entry_files()
        return {"entries": len(files), "bytes": sum(size for _p, _m, size in files)}

    # -- internals ----------------------------------------------------------

    def _path_for(self, key: str) -> Path:
        """Resolve the on-disk path for *key*, guarded against traversal."""
        return Path(safe_path(f"{key}{_ENTRY_SUFFIX}", base_dir=str(self._dir)))

    def _atomic_write(self, path: Path, entry: dict[str, Any]) -> None:
        """Write *entry* as JSON to *path* atomically (temp file + os.replace)."""
        fd, tmp = tempfile.mkstemp(dir=str(self._dir), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(entry, handle)
            os.replace(tmp, str(path))
        except OSError:
            self._safe_unlink(Path(tmp))
            raise

    def _entry_files(self) -> list[tuple[Path, float, int]]:
        """Return ``(path, mtime, size)`` for every cache entry currently on disk."""
        out: list[tuple[Path, float, int]] = []
        try:
            candidates = list(self._dir.glob(f"*{_ENTRY_SUFFIX}"))
        except OSError:
            return out
        for candidate in candidates:
            try:
                stat = candidate.stat()
            except OSError:
                continue
            out.append((candidate, stat.st_mtime, stat.st_size))
        return out

    def _enforce_size_cap(self) -> None:
        """Evict oldest entries until total size is within ``max_bytes``."""
        if self.max_bytes <= 0:
            return
        files = self._entry_files()
        total = sum(size for _p, _m, size in files)
        if total <= self.max_bytes:
            return
        for path, _mtime, size in sorted(files, key=lambda item: item[1]):
            if total <= self.max_bytes:
                break
            if self._safe_unlink(path):
                total -= size

    @staticmethod
    def _safe_unlink(path: Path) -> bool:
        """Delete *path*, swallowing errors. Returns ``True`` if it was removed."""
        try:
            path.unlink()
            return True
        except OSError:
            return False
