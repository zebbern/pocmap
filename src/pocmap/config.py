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

# API endpoint URLs
NVD_API_BASE: Final[str] = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ORG_GIT_RAW: Final[str] = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main"
)
CISA_KEV_URL: Final[str] = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
EPSS_CSV_URL: Final[str] = (
    "https://raw.githubusercontent.com/zebbern/pocmap/refs/heads/main"
    "/epss_scores-current.csv"
)
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
            agents = self.user_agents_file.read_text().splitlines()
            if agents:
                return random.choice(agents).strip()
        return "pocmap/2.0.0"


def _load_env_file(env_path: Path) -> None:
    """Parse a simple ``.env`` file and inject values into ``os.environ``."""
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
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
        cache_dir=Path(os.getenv(f"{prefix}CACHE_DIR", str(PROJECT_ROOT / ".cache"))),
        cache_enabled=_safe_bool(f"{prefix}CACHE_ENABLED", True),
        cache_ttl=_safe_int(f"{prefix}CACHE_TTL", DEFAULT_CACHE_TTL),
        cache_max_mb=_safe_int(f"{prefix}CACHE_MAX_MB", DEFAULT_CACHE_MAX_MB),
        offline=_safe_bool(f"{prefix}OFFLINE", False),
        log_level=os.getenv(f"{prefix}LOG_LEVEL", "INFO"),
    )


# Global singleton -- imported by other modules
settings: Settings = _build_settings()


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
