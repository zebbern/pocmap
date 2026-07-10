"""GitHub API client for PoC discovery.

Searches for exploit code on GitHub via the Nomi-sec and TrickestCVE
curated repositories, plus direct repository metadata lookups.
"""

from __future__ import annotations

import logging
from typing import Any

from pocmap.config import (
    GITHUB_API_BASE,
    GITHUB_RAW_BASE,
    NOMI_SEC_POC_BASE,
    TRICKEST_CVE_BASE,
    settings,
)
from pocmap.models import Exploit, ExploitSource
from pocmap.utils.http import HTTPClient, HTTPError, OfflineError, RateLimitError

logger = logging.getLogger(__name__)

# Known false-positive repositories to filter out
_FALSE_POSITIVE_REPOS = {
    "https://github.com/fkie-cad/nvd-json-data-feeds",
    "https://github.com/nomi-sec/PoC-in-GitHub",
    "https://github.com/ARPSyndicate/cvemon",
    "https://github.com/ARPSyndicate/cve-scores",
}


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

    def search_pocs(self, cve_id: str) -> list[Exploit]:
        """Search for PoCs on GitHub via Nomi-sec and TrickestCVE.

        Args:
            cve_id: The CVE identifier.

        Returns:
            List of :class:`Exploit` objects sorted by stars (descending).
        """
        cve_id = cve_id.upper()
        cve_year = cve_id.split("-")[1]
        exploits: list[Exploit] = []

        # Try Nomi-sec first
        nomi_url = f"{NOMI_SEC_POC_BASE}/{cve_year}/{cve_id}.json"
        try:
            data = self._client.get_json(nomi_url, headers=settings.github_headers)
            if isinstance(data, list):
                for repo in data:
                    ex = self._exploit_from_nomi(repo)
                    if ex:
                        exploits.append(ex)
                exploits.sort(key=lambda x: (x.stars or 0, x.forks or 0), reverse=True)
                return exploits
        except RateLimitError:
            # Propagate throttling so the aggregator reports RATE_LIMITED rather
            # than treating a rate-limited GitHub as "no PoCs found".
            raise
        except OfflineError:
            # Likewise, an offline cache-miss must surface, not read as "no PoCs".
            raise
        except HTTPError:
            logger.debug("Nomi-sec lookup failed for %s", cve_id)

        # Fallback to TrickestCVE
        trick_url = f"{TRICKEST_CVE_BASE}/{cve_year}/{cve_id}.md"
        try:
            text = self._client.get_text(trick_url, headers=settings.github_headers)
            if text:
                exploits = self._parse_trickest_md(text)
                exploits.sort(key=lambda x: (x.stars or 0, x.forks or 0), reverse=True)
                return exploits
        except RateLimitError:
            raise
        except OfflineError:
            raise
        except HTTPError:
            logger.debug("TrickestCVE lookup failed for %s", cve_id)

        return []

    def _exploit_from_nomi(self, repo: dict[str, Any]) -> Exploit | None:
        """Create an Exploit from a Nomi-sec repository entry."""
        full_name = repo.get("full_name", "")
        if not full_name:
            return None
        lang = self._get_repo_language(full_name)
        return Exploit(
            source=ExploitSource.GITHUB,
            url=repo.get("html_url", ""),
            title=repo.get("description") or "N/A",
            language=lang,
            stars=repo.get("stargazers_count", 0) or 0,
            forks=repo.get("forks_count", 0) or 0,
        )

    def _parse_trickest_md(self, text: str) -> list[Exploit]:
        """Parse TrickestCVE markdown and return enriched exploit list."""
        from bs4 import BeautifulSoup, Tag
        from markdown import markdown

        html = markdown(text)
        soup = BeautifulSoup(html, "html.parser")
        github_section = soup.find("h4", string="Github")
        if not github_section:
            return []

        ul = github_section.find_next("ul")
        if not isinstance(ul, Tag):
            return []

        exploits: list[Exploit] = []
        for li in ul.find_all("li"):
            link = li.find("a")
            if not link:
                continue
            html_url = link.get("href", "").strip()
            if not html_url or html_url in _FALSE_POSITIVE_REPOS:
                continue

            if html_url.startswith("https://github.com/"):
                full_name = html_url.split("https://github.com/")[-1]
                repo_info = self._get_repo_info(full_name)
                if repo_info:
                    exploits.append(Exploit.from_github_repo({
                        "html_url": repo_info.get("html_url", html_url),
                        "description": repo_info.get("description"),
                        "language": repo_info.get("language"),
                        "stargazers_count": repo_info.get("stargazers_count", 0),
                        "forks_count": repo_info.get("forks_count", 0),
                    }))
                else:
                    exploits.append(Exploit(
                        source=ExploitSource.GITHUB,
                        url=html_url,
                        title=html_url.split("/")[-1],
                    ))
            else:
                exploits.append(Exploit(
                    source=ExploitSource.OTHER,
                    url=html_url,
                    title=html_url,
                ))

        return exploits

    def _get_repo_info(self, full_name: str) -> dict[str, Any] | None:
        """Fetch repository metadata from the GitHub API."""
        url = f"{GITHUB_API_BASE}/repos/{full_name}"
        try:
            data = self._client.get_json(url, headers=settings.github_headers)
            if isinstance(data, dict) and "html_url" in data:
                return data
        except OfflineError:
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
