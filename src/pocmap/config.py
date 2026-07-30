"""Configuration management for PocMap.

Settings are loaded from environment variables and an optional ``.env`` file.
All settings can be overridden via environment variables prefixed with ``POCMAP_``
(``POCMAP_`` is also accepted for backward compatibility).

Example::

    from pocmap.config import settings
    print(settings.github_api_token)
    print(settings.http_timeout)
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PACKAGE_ROOT: Final[Path] = Path(__file__).resolve().parent
PROJECT_ROOT: Final[Path] = PACKAGE_ROOT.parent.parent

DEFAULT_HTTP_TIMEOUT: Final[int] = 30
DEFAULT_MAX_RETRIES: Final[int] = 3
DEFAULT_BACKOFF_FACTOR: Final[float] = 1.5
DEFAULT_THREAD_POOL_SIZE: Final[int] = 10

# Persistent HTTP response cache (see utils/cache.py).
DEFAULT_CACHE_TTL: Final[int] = 3600  # seconds an entry stays fresh
DEFAULT_CACHE_MAX_MB: Final[int] = 200  # total on-disk cap before LRU eviction
# Per-repo cap for fetched PoC source. Applied to the download *and* the
# extracted bytes: a small tar.gz can expand to gigabytes, so the extraction
# side is the one that actually stops a decompression bomb.
#
# 100 MB, not 20: real PoC repos routinely bundle a JRE, a vulnerable target
# app or a packet capture. kozmer/log4j-shell-poc (1851 stars, the canonical
# Log4Shell PoC) is 38.5 MB and was rejected outright under the old cap, which
# made the flagship case for verify_github_pocs fail. The cap exists to stop a
# decompression bomb, not to second-guess repo size.
DEFAULT_POC_SOURCE_MAX_MB: Final[int] = 100
# Kept at 10x the per-repo cap: a default verify run fetches 5 repos, so a
# total equal to 5x would saturate on one run and evict trees it is about to
# re-fetch on the next.
DEFAULT_POC_SOURCE_TOTAL_MAX_MB: Final[int] = 1000

# API endpoint URLs
NVD_API_BASE: Final[str] = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# The CPE *dictionary* — maps a product name to the canonical vendor:product
# pairs NVD files CVEs under. Distinct from NVD_API_BASE, which serves CVEs.
NVD_CPE_API_BASE: Final[str] = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

# OSV.dev — vulnerabilities keyed by *package* (PyPI, npm, Maven, Go, distro
# packages, ...) rather than by CPE product. Complements the NVD path rather
# than replacing it: OSV cannot answer "is nginx 1.20.1 vulnerable" (it rejects
# a bare product name outright), but it is the only source here that answers
# "which release fixes this" for a dependency. Needs no API key.
OSV_API_BASE: Final[str] = "https://api.osv.dev/v1"
OSV_QUERY_URL: Final[str] = f"{OSV_API_BASE}/query"
OSV_VULN_URL: Final[str] = f"{OSV_API_BASE}/vulns"

# CVE -> MITRE ATT&CK technique mappings, curated by the Center for Threat-Informed
# Defense over the CISA KEV catalogue. Expert-reviewed rather than inferred: the
# CWE -> CAPEC -> ATT&CK chain that would cover every CVE was measured against this
# data and produced zero overlap, so only this authoritative set is used.
#
# The published path carries both an ATT&CK version and a snapshot date, with no
# "latest" alias. The pinned URL is tried first (no API budget); if CTID publishes
# a newer snapshot and the pin 404s, the directory listing below is walked to find
# it, so the feed self-heals.
_CTID_RAW: Final[str] = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense"
    "/mappings-explorer/main/mappings/kev"
)
ATTACK_KEV_PINNED_URL: Final[str] = (
    f"{_CTID_RAW}/attack-16.1/kev-07.28.2025/enterprise/"
    "kev-07.28.2025_attack-16.1-enterprise.json"
)
ATTACK_KEV_CONTENTS_API: Final[str] = (
    "https://api.github.com/repos/center-for-threat-informed-defense"
    "/mappings-explorer/contents/mappings/kev"
)
CVE_ORG_GIT_RAW: Final[str] = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main"
)
CISA_KEV_URL: Final[str] = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
# FIRST's official EPSS bulk feed (gzipped CSV, ~354k rows, refreshed daily).
# The previous value pointed at a file in this repo that does not exist, so the
# bulk path 404'd on every run and every EPSS lookup silently fell back to the
# per-CVE FIRST API — one HTTP request per CVE. Scoring is now one download.
EPSS_CSV_URL: Final[str] = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_API_URL: Final[str] = "https://api.first.org/data/v1/epss"
SHODAN_CVEDB_URL: Final[str] = "https://cvedb.shodan.io/cve"
GITHUB_API_BASE: Final[str] = "https://api.github.com"
GITHUB_RAW_BASE: Final[str] = "https://raw.githubusercontent.com"

# Exploit database URLs
MSF_MODULES_DB_URL: Final[str] = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework"
    "/refs/heads/master/db/modules_metadata_base.json"
)
EXPLOITDB_CSV_URL: Final[str] = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)
NUCLEI_TEMPLATES_URL: Final[str] = (
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates"
    "/refs/heads/main/cves.json"
)
NOMI_SEC_POC_BASE: Final[str] = (
    "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/refs/heads/master"
)
TRICKEST_CVE_BASE: Final[str] = (
    "https://raw.githubusercontent.com/trickest/cve/refs/heads/main"
)

# Lab / bug bounty URLs
VULHUB_TOML_URL: Final[str] = (
    "https://raw.githubusercontent.com/vulhub/vulhub/refs/heads/master/environments.toml"
)
HTB_TAGS_URL: Final[str] = "https://0xdf.gitlab.io/tags"
THM_ROOMS_URL: Final[str] = (
    "https://raw.githubusercontent.com/zebbern/pocmap/refs/heads/main"
    "/latest_thm_rooms.txt"
)
H1_REPORTS_URL: Final[str] = (
    "https://raw.githubusercontent.com/reddelexc/hackerone-reports"
    "/refs/heads/master/data.csv"
)
H1_POC_FLAGS_URL: Final[str] = "https://reports.fortisec.co.uk/data/poc-flags.json"
PENTESTERLAND_URL: Final[str] = "https://pentester.land/writeups.json"
BB_HUNTING_URL: Final[str] = "https://www.bugbountyhunting.com/script.js"

# User agent data file
USER_AGENTS_FILE: Final[Path] = PACKAGE_ROOT / "data" / "user_agents.txt"


# ---------------------------------------------------------------------------
# Settings class
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable application settings.

    Load order (later overrides earlier):
        1. Default values defined here.
        2. ``.env`` file in the project root.
        3. Environment variables.

    Attributes:
        github_api_token: Optional GitHub personal access token.
        nvd_api_key: Optional NVD API key for higher rate limits.
        http_timeout: Request timeout in seconds.
        max_retries: Maximum number of retries for failed requests.
        backoff_factor: Exponential backoff multiplier.
        thread_pool_size: Default worker count for thread pools.
        user_agents_file: Path to the user agents list file.
        cache_dir: Directory for cached data.
        cache_enabled: Whether the persistent HTTP response cache is active.
        cache_ttl: Seconds a cached HTTP response stays fresh.
        cache_max_mb: Total on-disk cache cap in MB before LRU eviction.
        offline: When ``True``, HTTP GETs are served only from the cache; a
            cache miss raises a clear offline error instead of hitting the
            network (``POCMAP_OFFLINE``).
        allow_fetch_poc_source: Opt-in switch for downloading PoC *source code*
            to disk (``POCMAP_ALLOW_FETCH_POC_SOURCE``). **Off by default and
            deliberately not inferable**: fetching writes third-party exploit
            code into ``poc_source_dir``, which endpoint protection will often
            quarantine and which the operator must consciously accept. Intended
            for an isolated VM / research host.
        poc_source_dir: Where fetched PoC source is extracted
            (``POCMAP_POC_SOURCE_DIR``); defaults to ``<cache_dir>/poc-source``.
        poc_source_max_mb: Per-repository cap in MB, applied to both the
            download and the *extracted* size, so a decompression bomb cannot
            fill the disk (``POCMAP_POC_SOURCE_MAX_MB``).
        poc_source_total_max_mb: Total on-disk cap in MB for all fetched
            sources (``POCMAP_POC_SOURCE_TOTAL_MAX_MB``).
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR).
    """

    github_api_token: str | None = None
    nvd_api_key: str | None = None
    http_timeout: int = DEFAULT_HTTP_TIMEOUT
    max_retries: int = DEFAULT_MAX_RETRIES
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR
    thread_pool_size: int = DEFAULT_THREAD_POOL_SIZE
    user_agents_file: Path = USER_AGENTS_FILE
    cache_dir: Path = field(default_factory=lambda: PROJECT_ROOT / ".cache")
    cache_enabled: bool = True
    cache_ttl: int = DEFAULT_CACHE_TTL
    cache_max_mb: int = DEFAULT_CACHE_MAX_MB
    offline: bool = False
    allow_fetch_poc_source: bool = False
    poc_source_dir: Path = field(
        default_factory=lambda: PROJECT_ROOT / ".cache" / "poc-source"
    )
    poc_source_max_mb: int = DEFAULT_POC_SOURCE_MAX_MB
    poc_source_total_max_mb: int = DEFAULT_POC_SOURCE_TOTAL_MAX_MB
    log_level: str = "INFO"

    @property
    def github_headers(self) -> dict[str, str]:
        """Return HTTP headers for GitHub API requests."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": self._get_user_agent(),
        }
        if self.github_api_token:
            headers["Authorization"] = f"Bearer {self.github_api_token}"
        return headers

    @property
    def nvd_headers(self) -> dict[str, str]:
        """Return HTTP headers for NVD API requests."""
        headers = {"User-Agent": self._get_user_agent()}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        return headers

    @property
    def default_headers(self) -> dict[str, str]:
        """Return generic HTTP headers."""
        return {"User-Agent": self._get_user_agent()}

    def _get_user_agent(self) -> str:
        """Return a random user agent string from the data file."""
        import random

        if self.user_agents_file.exists():
            agents = self.user_agents_file.read_text(encoding="utf-8").splitlines()
            if agents:
                return random.choice(agents).strip()
        from pocmap import __version__

        return f"pocmap/{__version__}"


def _load_env_file(env_path: Path) -> None:
    """Parse a simple ``.env`` file and inject values into ``os.environ``."""
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ[key] = value


def _build_settings() -> Settings:
    """Construct a :class:`Settings` instance from all configuration sources."""
    # Attempt to load python-dotenv if available
    try:
        from dotenv import load_dotenv
        load_dotenv(PROJECT_ROOT / ".env")
    except ImportError:
        _load_env_file(PROJECT_ROOT / ".env")

    prefix = "POCMAP_"
    def _safe_int(env_var: str, default: int) -> int:
        """Parse an environment variable as an integer with fallback."""
        try:
            return int(os.getenv(env_var, default))
        except (ValueError, TypeError):
            return default

    def _safe_float(env_var: str, default: float) -> float:
        """Parse an environment variable as a float with fallback."""
        try:
            return float(os.getenv(env_var, default))
        except (ValueError, TypeError):
            return default

    def _safe_bool(env_var: str, default: bool) -> bool:
        """Parse an environment variable as a boolean with fallback."""
        raw = os.getenv(env_var)
        if raw is None:
            return default
        return raw.strip().lower() in {"1", "true", "yes", "on"}

    def _safe_dir(env_var: str, default: Path) -> Path:
        """Parse an environment variable as a directory path with fallback.

        An empty or whitespace-only value is treated as *unset*. ``Path("")``
        is the current working directory, which would silently retarget a
        directory pocmap manages — and the PoC-source directory is one pocmap
        evicts from.
        """
        raw = os.getenv(env_var)
        if raw is None or not raw.strip():
            return default
        return Path(raw.strip())

    return Settings(
        github_api_token=os.getenv(f"{prefix}GITHUB_API_TOKEN")
        or os.getenv("GITHUB_API_TOKEN"),
        nvd_api_key=os.getenv(f"{prefix}NVD_API_KEY") or os.getenv("NVD_API_KEY"),
        http_timeout=_safe_int(f"{prefix}HTTP_TIMEOUT", DEFAULT_HTTP_TIMEOUT),
        max_retries=_safe_int(f"{prefix}MAX_RETRIES", DEFAULT_MAX_RETRIES),
        backoff_factor=_safe_float(
            f"{prefix}BACKOFF_FACTOR", DEFAULT_BACKOFF_FACTOR
        ),
        thread_pool_size=_safe_int(
            f"{prefix}THREAD_POOL_SIZE", DEFAULT_THREAD_POOL_SIZE
        ),
        user_agents_file=Path(
            os.getenv(f"{prefix}USER_AGENTS_FILE", str(USER_AGENTS_FILE))
        ),
        cache_dir=_safe_dir(f"{prefix}CACHE_DIR", PROJECT_ROOT / ".cache"),
        cache_enabled=_safe_bool(f"{prefix}CACHE_ENABLED", True),
        cache_ttl=_safe_int(f"{prefix}CACHE_TTL", DEFAULT_CACHE_TTL),
        cache_max_mb=_safe_int(f"{prefix}CACHE_MAX_MB", DEFAULT_CACHE_MAX_MB),
        allow_fetch_poc_source=_safe_bool(f"{prefix}ALLOW_FETCH_POC_SOURCE", False),
        # ``_safe_dir`` rather than ``Path(os.getenv(...))``: an env var set to
        # the empty string would otherwise yield ``Path("")``, which is the CWD
        # — and the fetcher evicts from this directory.
        poc_source_dir=_safe_dir(
            f"{prefix}POC_SOURCE_DIR",
            _safe_dir(f"{prefix}CACHE_DIR", PROJECT_ROOT / ".cache") / "poc-source",
        ),
        poc_source_max_mb=_safe_int(
            f"{prefix}POC_SOURCE_MAX_MB", DEFAULT_POC_SOURCE_MAX_MB
        ),
        poc_source_total_max_mb=_safe_int(
            f"{prefix}POC_SOURCE_TOTAL_MAX_MB", DEFAULT_POC_SOURCE_TOTAL_MAX_MB
        ),
        offline=_safe_bool(f"{prefix}OFFLINE", False),
        log_level=os.getenv(f"{prefix}LOG_LEVEL", "INFO"),
    )


# Global singleton -- imported by other modules
settings: Settings = _build_settings()


def enable_offline(enabled: bool = True) -> None:
    """Force process-wide offline mode by mutating the ``settings`` singleton.

    This is the last hop for the CLI ``--offline`` flag. ``Settings`` is a
    ``frozen=True, slots=True`` dataclass, so ``settings.offline = True`` would
    raise; instead the field is set via :func:`object.__setattr__`, which writes
    the slot directly and bypasses the frozen ``__setattr__`` guard.

    Crucially the *same* singleton object is mutated in place, so every module
    that did ``from pocmap.config import settings`` (notably
    :mod:`pocmap.utils.http`, whose ``HTTPClient._is_offline`` reads
    ``settings.offline`` at call time) observes the change immediately — no
    rebinding or client rebuild required. Idempotent; safe to call repeatedly.

    Args:
        enabled: The value to force onto ``settings.offline`` (default ``True``).
    """
    object.__setattr__(settings, "offline", enabled)


# ---------------------------------------------------------------------------
# Credential format validation (offline shape checks used by `pocmap doctor`)
# ---------------------------------------------------------------------------

# Modern prefixed GitHub tokens: ghp_ (classic PAT), gho_ (OAuth), ghu_
# (user-to-server), ghs_ (server-to-server), ghr_ (refresh) + >=36 body chars.
_GITHUB_PREFIXED_RE: Final = re.compile(r"^gh[posru]_[A-Za-z0-9]{36,255}$")
# Fine-grained personal access tokens.
_GITHUB_PAT_RE: Final = re.compile(r"^github_pat_[A-Za-z0-9_]{22,255}$")
# Legacy (pre-2021) 40-char hex OAuth tokens.
_GITHUB_LEGACY_RE: Final = re.compile(r"^[0-9a-fA-F]{40}$")
# NVD API keys are UUID-style 8-4-4-4-12 hex strings.
_NVD_KEY_RE: Final = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def github_token_looks_valid(token: str) -> bool:
    """Return ``True`` if *token* has a plausible GitHub token shape.

    Recognizes modern prefixed tokens (``ghp_``/``gho_``/``ghu_``/``ghs_``/
    ``ghr_``), fine-grained PATs (``github_pat_``), and legacy 40-char hex OAuth
    tokens. This is a cheap, offline *shape* check only — it never contacts
    GitHub and the token value is never logged or echoed by callers.
    """
    candidate = token.strip()
    return bool(
        _GITHUB_PREFIXED_RE.match(candidate)
        or _GITHUB_PAT_RE.match(candidate)
        or _GITHUB_LEGACY_RE.match(candidate)
    )


def nvd_api_key_looks_valid(key: str) -> bool:
    """Return ``True`` if *key* looks like an NVD API key (UUID 8-4-4-4-12 hex)."""
    return bool(_NVD_KEY_RE.match(key.strip()))
