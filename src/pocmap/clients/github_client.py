"""GitHub API client for PoC discovery.

Searches for exploit code on GitHub via the Nomi-sec and TrickestCVE curated
indexes, with a GitHub Search API fallback when both indexes are empty, plus
direct repository metadata lookups. PoC-like CVE reference URLs can also be
promoted via :func:`exploits_from_reference_urls`.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

from pocmap.config import (
    GITHUB_API_BASE,
    GITHUB_RAW_BASE,
    NOMI_SEC_POC_BASE,
    TRICKEST_CVE_BASE,
    settings,
)
from pocmap.models import Exploit, ExploitSource
from pocmap.utils.http import HTTPClient, HTTPError, OfflineError, RateLimitError
from pocmap.utils.poc_labels import classify_poc_labels, trust_score

logger = logging.getLogger(__name__)

# Known false-positive repositories to filter out
_FALSE_POSITIVE_REPOS = {
    "https://github.com/fkie-cad/nvd-json-data-feeds",
    "https://github.com/nomi-sec/PoC-in-GitHub",
    "https://github.com/ARPSyndicate/cvemon",
    "https://github.com/ARPSyndicate/cve-scores",
}

# Aggregators that mention thousands of CVE IDs without containing any exploit
# code — CVE mirrors, "awesome" link lists, room/writeup indexes. These dominate
# the TrickestCVE lists, so a name-shape predicate scales better than extending
# the literal set above one repository at a time.
_AGGREGATOR_NAME_RE = re.compile(
    r"""
    awesome                       # awesome-list, awesome-security, ...
    | poc[-_]?in[-_]?github
    | nvd[-_]?json
    | cve[-_]?(list|db|mon|monitor|scores?|feeds?|data|database|collection)
    | (list|db|mirror|archive)[-_]?of[-_]?cves?
    | tryhackme | thm[-_]?rooms | free[-_]?rooms
    """,
    re.IGNORECASE | re.VERBOSE,
)

_POC_NAME_RE = re.compile(r"(?i)(poc|exploit|vulnerability)")

# Cap Search API pages — one call, small page, only used when indexes are empty.
_SEARCH_PER_PAGE = 10


def _is_aggregator(url: str) -> bool:
    """Whether *url* looks like a CVE index rather than a PoC."""
    if url in _FALSE_POSITIVE_REPOS:
        return True
    name = url.rstrip("/").rsplit("/", 1)[-1]
    return bool(_AGGREGATOR_NAME_RE.search(name))


def _repo_key(url: str) -> str:
    """Normalized identity for a repo URL, for cross-source dedup."""
    return url.rstrip("/").lower()


def normalize_github_repo_url(url: str) -> str | None:
    """Return ``https://github.com/{owner}/{repo}`` or ``None`` if not a repo URL."""
    raw = (url or "").strip()
    if not raw:
        return None
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        return None
    host = (parsed.netloc or "").lower()
    if host not in ("github.com", "www.github.com"):
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    # Drop .git suffix if present
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        return None
    return f"https://github.com/{owner}/{repo}"


def exploits_from_reference_urls(urls: Iterable[str], cve_id: str) -> list[Exploit]:
    """Promote PoC-like GitHub URLs from CVE reference lists.

    Only repos that look like dedicated PoCs are kept — not every vendor/upstream
    link. A URL qualifies when the CVE id appears in the repo path, or the repo
    name looks like a PoC/exploit/vulnerability *and* the CVE id appears somewhere
    in the URL. Aggregator indexes are rejected.
    """
    cve_norm = cve_id.upper().strip()
    cve_lower = cve_norm.lower()
    seen: set[str] = set()
    out: list[Exploit] = []
    for raw in urls:
        repo_url = normalize_github_repo_url(str(raw))
        if not repo_url or _is_aggregator(repo_url):
            continue
        key = _repo_key(repo_url)
        if key in seen:
            continue
        path_lower = urlparse(repo_url).path.lower()
        repo_name = path_lower.rstrip("/").rsplit("/", 1)[-1]
        cve_in_path = cve_lower in path_lower
        poc_named = bool(_POC_NAME_RE.search(repo_name)) and cve_lower in str(raw).lower()
        if not (cve_in_path or poc_named):
            continue
        seen.add(key)
        out.append(
            Exploit(
                source=ExploitSource.GITHUB,
                url=repo_url,
                title=repo_url.rstrip("/").rsplit("/", 1)[-1],
            )
        )
    return out


# How many repos to enrich when the caller sets no limit. Enrichment costs one
# GitHub API call each and the unauthenticated budget is 60/hour, so this bounds
# a single lookup to a fraction of it. Results beyond this are still returned,
# just without language / live star counts.
DEFAULT_ENRICH_LIMIT = 10


class GitHubClient:
    """Client for GitHub API and raw content access.

    Args:
        api_token: Optional GitHub personal access token.
        http_client: Optional HTTP client instance.

    Example::

        client = GitHubClient()
        exploits = client.search_pocs("CVE-2021-44228")
        for ex in exploits:
            print(ex.url, ex.stars)
    """

    def __init__(
        self,
        api_token: str | None = None,
        http_client: HTTPClient | None = None,
    ) -> None:
        self.api_token = api_token or settings.github_api_token
        self._client = http_client or HTTPClient(headers=settings.github_headers)
        # Short, agent-quotable note about the last ``search_pocs`` path taken
        # (indexes vs Search fallback). Consumed by ExploitService status.
        self.last_search_detail: str = ""

    def search_pocs(self, cve_id: str, limit: int | None = None) -> list[Exploit]:
        """Search for PoCs on GitHub via Nomi-sec, TrickestCVE, and Search fallback.

        Curated indexes are consulted first and unioned (deduped by repo URL).
        Nomi-sec indexes repositories whose name or description names the CVE;
        TrickestCVE is broader but noisier. When **both** indexes yield no
        candidates after aggregator filtering, the GitHub Search API is queried
        so index lag does not look like "no PoCs exist".

        **Ranking matters more than the union.** TrickestCVE lists include
        repositories that merely mention a CVE (personal dotfile repos, course
        notes), and they arrive with no star count, so they sort *below* every
        Nomi-sec entry. Callers that apply a ``limit`` — the CLI and the MCP
        tool both default to 10 — therefore see the curated source first and
        reach the supplementary one only once it is exhausted.

        Per-repository enrichment costs one GitHub API call each against an
        unauthenticated budget of 60/hour, so *limit* is applied **before**
        enrichment, and an unbounded call enriches only the first
        :data:`DEFAULT_ENRICH_LIMIT`.

        Args:
            cve_id: The CVE identifier.
            limit: Optional cap on results. Applied before enrichment.

        Returns:
            :class:`Exploit` objects sorted by stars (descending). Entries past
            the enrichment budget carry ``language=None`` (unknown).
        """
        cve_id = cve_id.upper()
        cve_year = cve_id.split("-")[1]
        self.last_search_detail = ""

        # Nomi-sec entries carry stars/forks inline, so they seed the ranking.
        candidates: dict[str, Exploit] = {}
        for repo in self._fetch_nomi(cve_id, cve_year):
            url = repo.get("html_url", "")
            if not url or _is_aggregator(url):
                continue
            title = repo.get("description") or "N/A"
            stars = repo.get("stargazers_count", 0) or 0
            forks = repo.get("forks_count", 0) or 0
            labels = classify_poc_labels(title if title != "N/A" else None, url)
            candidates.setdefault(
                _repo_key(url),
                Exploit(
                    source=ExploitSource.GITHUB,
                    url=url,
                    title=title,
                    stars=stars,
                    forks=forks,
                    labels=labels,
                    trust_score=trust_score(stars=stars, forks=forks, labels=labels),
                ),
            )

        for url in self._fetch_trickest(cve_id, cve_year):
            if _is_aggregator(url):
                continue
            key = _repo_key(url)
            if key in candidates:
                continue
            is_github = url.startswith("https://github.com/")
            title = url.rstrip("/").rsplit("/", 1)[-1] if is_github else url
            labels = classify_poc_labels(title, url)
            candidates[key] = Exploit(
                source=ExploitSource.GITHUB if is_github else ExploitSource.OTHER,
                url=url,
                # No metadata from Trickest; the repo name is the best label
                # available without spending an API call on it.
                title=title,
                labels=labels,
                trust_score=trust_score(labels=labels),
            )

        used_search_fallback = False
        # Index lag: curated feeds often miss fresh / low-star PoC repos that
        # GitHub Search already knows about (e.g. CVE-YYYY-NNNNN-named repos).
        if not candidates:
            used_search_fallback = True
            for repo in self._fetch_github_search(cve_id):
                url = repo.get("html_url", "")
                if not url or _is_aggregator(url):
                    continue
                title = repo.get("description") or repo.get("full_name") or "N/A"
                stars = repo.get("stargazers_count", 0) or 0
                forks = repo.get("forks_count", 0) or 0
                labels = classify_poc_labels(title if title != "N/A" else None, url)
                candidates.setdefault(
                    _repo_key(url),
                    Exploit(
                        source=ExploitSource.GITHUB,
                        url=url,
                        title=title,
                        stars=stars,
                        forks=forks,
                        labels=labels,
                        trust_score=trust_score(stars=stars, forks=forks, labels=labels),
                    ),
                )

        if used_search_fallback:
            self.last_search_detail = (
                "Nomi-sec and TrickestCVE indexes empty; used GitHub Search API fallback"
            )
        elif candidates:
            self.last_search_detail = "Results from Nomi-sec and/or TrickestCVE indexes"
        else:
            self.last_search_detail = (
                "No PoC repositories found in indexes or GitHub Search"
            )

        exploits = sorted(
            candidates.values(),
            key=lambda x: (x.trust_score or 0.0, x.stars or 0, x.forks or 0),
            reverse=True,
        )
        if limit is not None:
            exploits = exploits[:limit]

        # Enrichment is one GitHub API call per repo against a 60/hour
        # unauthenticated budget, so an unbounded caller (``pocmap lookup``,
        # which shows every PoC) gets a bounded prefix rather than a blown
        # budget: the union of both indexes can be 70+ repos for a popular CVE.
        # Un-enriched entries keep ``language=None`` — unknown, not "N/A".
        enrich_count = limit if limit is not None else DEFAULT_ENRICH_LIMIT
        return [
            self._enrich(ex) if i < enrich_count else ex
            for i, ex in enumerate(exploits)
        ]

    def _fetch_nomi(self, cve_id: str, cve_year: str) -> list[dict[str, Any]]:
        """Fetch the Nomi-sec PoC index entry for a CVE."""
        url = f"{NOMI_SEC_POC_BASE}/{cve_year}/{cve_id}.json"
        try:
            data = self._client.get_json(url, headers=settings.github_headers)
        except (RateLimitError, OfflineError):
            # Throttling / offline cache-miss must surface, never read as
            # "no PoCs found".
            raise
        except HTTPError:
            logger.debug("Nomi-sec lookup failed for %s", cve_id)
            return []
        return data if isinstance(data, list) else []

    def _fetch_trickest(self, cve_id: str, cve_year: str) -> list[str]:
        """Fetch and parse the TrickestCVE markdown page for a CVE."""
        url = f"{TRICKEST_CVE_BASE}/{cve_year}/{cve_id}.md"
        try:
            text = self._client.get_text(url, headers=settings.github_headers)
        except (RateLimitError, OfflineError):
            raise
        except HTTPError:
            logger.debug("TrickestCVE lookup failed for %s", cve_id)
            return []
        return self._parse_trickest_md(text) if text else []

    def _fetch_github_search(self, cve_id: str) -> list[dict[str, Any]]:
        """Search GitHub repositories by CVE id (recall fallback).

        Used only when Nomi-sec and TrickestCVE produced no candidates.
        ``RateLimitError`` / ``OfflineError`` propagate so throttling is never
        reported as "no PoCs found".
        """
        url = f"{GITHUB_API_BASE}/search/repositories"
        try:
            data = self._client.get_json(
                url,
                headers=settings.github_headers,
                params={"q": cve_id, "per_page": _SEARCH_PER_PAGE},
            )
        except (RateLimitError, OfflineError):
            raise
        except HTTPError:
            logger.debug("GitHub Search lookup failed for %s", cve_id)
            return []
        if not isinstance(data, dict):
            return []
        items = data.get("items")
        return items if isinstance(items, list) else []

    def _enrich(self, exploit: Exploit) -> Exploit:
        """Fill in language, freshness, labels, and trust from the GitHub API."""
        if exploit.source is not ExploitSource.GITHUB:
            return exploit
        if not exploit.url.startswith("https://github.com/"):
            return exploit

        full_name = exploit.url.split("https://github.com/")[-1].rstrip("/")
        info = self._get_repo_info(full_name)
        if not info:
            # Looked up and genuinely has no metadata (404 / deleted repo), as
            # opposed to never looked up — which stays ``None``.
            exploit.language = "N/A"
            if not exploit.labels:
                exploit.labels = classify_poc_labels(exploit.title, exploit.url)
            exploit.trust_score = trust_score(
                stars=exploit.stars,
                forks=exploit.forks,
                last_commit=exploit.last_commit,
                labels=exploit.labels,
            )
            return exploit

        exploit.language = info.get("language") or "N/A"
        if info.get("description"):
            exploit.title = info["description"]
        # Trickest-sourced entries arrive with no counts; Nomi-sec's are cached
        # snapshots, so live values are preferred when present.
        if info.get("stargazers_count") is not None:
            exploit.stars = info.get("stargazers_count") or 0
        if info.get("forks_count") is not None:
            exploit.forks = info.get("forks_count") or 0
        pushed = info.get("pushed_at")
        if isinstance(pushed, str) and pushed:
            exploit.last_commit = pushed
        exploit.labels = classify_poc_labels(exploit.title, exploit.url)
        exploit.trust_score = trust_score(
            stars=exploit.stars,
            forks=exploit.forks,
            last_commit=exploit.last_commit,
            labels=exploit.labels,
        )
        return exploit

    def _parse_trickest_md(self, text: str) -> list[str]:
        """Extract repository URLs from the ``Github`` section of a Trickest page.

        Trickest emits bare URLs (``- https://github.com/owner/repo``), which
        python-markdown renders as plain ``<li>`` text with no anchor. Requiring
        an ``<a>`` tag therefore silently yielded zero results for every CVE.
        """
        from bs4 import BeautifulSoup, Tag
        from markdown import markdown

        soup = BeautifulSoup(markdown(text), "html.parser")
        github_section = soup.find("h4", string="Github")
        if not github_section:
            return []

        ul = github_section.find_next("ul")
        if not isinstance(ul, Tag):
            return []

        urls: list[str] = []
        for li in ul.find_all("li"):
            link = li.find("a")
            # Accept both markdown links and bare URLs.
            raw = link.get("href", "") if link else li.get_text()
            candidate = (raw or "").strip()
            if candidate.startswith(("http://", "https://")):
                urls.append(candidate)
        return urls

    def _get_repo_info(self, full_name: str) -> dict[str, Any] | None:
        """Fetch repository metadata from the GitHub API.

        Raises:
            RateLimitError: GitHub throttled the request. This PROPAGATES: a
                throttled lookup is an upstream failure, and swallowing it here
                (``RateLimitError`` subclasses :class:`HTTPError`) reported every
                repo as ``language="N/A"`` while the aggregate status still said
                ``ok`` — so ``--language Python`` silently returned nothing.
            OfflineError: Offline mode with no cached response.
        """
        url = f"{GITHUB_API_BASE}/repos/{full_name}"
        try:
            data = self._client.get_json(url, headers=settings.github_headers)
            if isinstance(data, dict) and "html_url" in data:
                return data
        except (RateLimitError, OfflineError):
            raise
        except HTTPError as exc:
            if exc.status_code == 404:
                return None
            logger.debug("GitHub API error for %s: %s", full_name, exc)
        return None

    def _get_repo_language(self, full_name: str) -> str:
        """Fetch the primary programming language of a repository."""
        info = self._get_repo_info(full_name)
        if info:
            return info.get("language") or "N/A"
        return "N/A"

    def get_readme(self, repo_url: str) -> str:
        """Fetch the README.md content of a GitHub repository.

        Tries ``main`` branch first, then falls back to ``master``.

        Args:
            repo_url: Full GitHub repository URL.

        Returns:
            README text content, or empty string if not found.
        """
        from bs4 import BeautifulSoup
        from markdown import markdown

        if not repo_url.startswith("https://github.com/"):
            return ""

        repo_path = repo_url.split("https://github.com/")[-1]
        for branch in ("main", "master"):
            url = f"{GITHUB_RAW_BASE}/{repo_path}/refs/heads/{branch}/README.md"
            try:
                text = self._client.get_text(url, headers=settings.github_headers)
                if text:
                    md = markdown(text)
                    soup = BeautifulSoup(md, "html.parser")
                    return soup.get_text()
            except OfflineError:
                raise
            except RateLimitError:
                # A throttled fetch is an upstream failure, not a missing README:
                # let it propagate so the caller can report UPSTREAM_ERROR instead
                # of masquerading as a genuine 404 (NO_RESULTS) via the loop below.
                raise
            except HTTPError:
                continue
        return ""

    def close(self) -> None:
        """Release the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> GitHubClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
