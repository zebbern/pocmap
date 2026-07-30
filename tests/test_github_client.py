"""Native offline regression tests for GitHubClient.search_pocs.

Covers ``src/pocmap/clients/github_client.py`` at the client layer (the
service/adapter slicing above it is exercised by ``test_ghpoc.py``). Each case
constructs :class:`GitHubClient` with a ``MagicMock`` HTTP client so no network
I/O happens.

Invariants locked in here:

  * PoCs are returned sorted by stars descending.
  * A :class:`RateLimitError` from the GitHub API PROPAGATES — a rate-limited
    GitHub must never be read as "no PoCs found".
  * An :class:`OfflineError` likewise PROPAGATES.
  * An :class:`HTTPError` on the Nomi-sec path falls back to TrickestCVE via
    ``get_text`` and returns ``[]`` when the fallback is empty.
  * ``_exploit_from_nomi`` returns ``None`` when ``full_name`` is missing.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from pocmap.clients.github_client import DEFAULT_ENRICH_LIMIT, GitHubClient
from pocmap.models import ExploitSource
from pocmap.utils.http import HTTPError, OfflineError, RateLimitError


def _nomi_repos(*star_counts: int) -> list[dict[str, Any]]:
    """Build a list of Nomi-sec repo entries with the given star counts."""
    return [
        {
            "full_name": f"user/repo{i}",
            "html_url": f"https://github.com/user/repo{i}",
            "description": "PoC",
            "stargazers_count": stars,
            "forks_count": 0,
        }
        for i, stars in enumerate(star_counts)
    ]


def _client_returning(nomi_payload: list[dict[str, Any]]) -> GitHubClient:
    """A GitHubClient whose mock returns ``nomi_payload`` for the Nomi-sec URL.

    Any subsequent per-repo metadata lookup (``/repos/...``) returns an empty
    dict, so language enrichment degrades to "N/A" without extra network work.
    """
    http = MagicMock()

    def fake_get_json(url: str, **_: Any) -> Any:
        if url.endswith(".json"):
            return nomi_payload
        return {}

    http.get_json.side_effect = fake_get_json
    return GitHubClient(http_client=http)


def test_search_pocs_sorted_by_stars_descending() -> None:
    client = _client_returning(_nomi_repos(5, 50))
    result = client.search_pocs("CVE-2021-44228")

    assert [ex.stars for ex in result] == [50, 5]
    assert all(ex.source == ExploitSource.GITHUB for ex in result)


def test_rate_limit_error_propagates() -> None:
    """A rate-limited GitHub must surface, not read as an empty PoC list."""
    http = MagicMock()
    http.get_json.side_effect = RateLimitError("throttled", status_code=403)
    client = GitHubClient(http_client=http)

    with pytest.raises(RateLimitError):
        client.search_pocs("CVE-2021-44228")


def test_offline_error_propagates() -> None:
    http = MagicMock()
    http.get_json.side_effect = OfflineError("offline")
    client = GitHubClient(http_client=http)

    with pytest.raises(OfflineError):
        client.search_pocs("CVE-2021-44228")


def test_http_error_falls_back_to_trickest_and_returns_empty() -> None:
    """A Nomi-sec HTTPError falls back to TrickestCVE; empty fallback -> []."""
    http = MagicMock()
    http.get_json.side_effect = HTTPError("nomi down", status_code=500)
    http.get_text.return_value = ""
    client = GitHubClient(http_client=http)

    result = client.search_pocs("CVE-2021-44228")

    assert result == []
    http.get_text.assert_called_once()


def test_nomi_entry_without_a_url_is_skipped() -> None:
    client = _client_returning([{"description": "no url"}, *_nomi_repos(7)])
    assert [ex.stars for ex in client.search_pocs("CVE-2021-44228")] == [7]


# ---------------------------------------------------------------------------
# TrickestCVE: bare-URL parsing, and union rather than dead fallback
# ---------------------------------------------------------------------------

# Trickest emits bare URLs under an h4. python-markdown does not autolink them,
# so requiring an <a> tag yielded zero results for every CVE.
_TRICKEST_MD = """
### CVE-2021-44228

#### Reference
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228

#### Github
- https://github.com/hunter/real-poc
- https://github.com/0xor0ne/awesome-list
- https://github.com/0xfke/500-free-TryHackMe-rooms
- https://github.com/other/second-poc
"""


def _union_client(nomi: list[dict[str, Any]], markdown: str) -> GitHubClient:
    http = MagicMock()

    def fake_get_json(url: str, **_: Any) -> Any:
        return nomi if url.endswith(".json") else {}

    http.get_json.side_effect = fake_get_json
    http.get_text.return_value = markdown
    return GitHubClient(http_client=http)


def test_parse_trickest_md_reads_bare_urls() -> None:
    client = GitHubClient(http_client=MagicMock())
    assert client._parse_trickest_md(_TRICKEST_MD) == [
        "https://github.com/hunter/real-poc",
        "https://github.com/0xor0ne/awesome-list",
        "https://github.com/0xfke/500-free-TryHackMe-rooms",
        "https://github.com/other/second-poc",
    ]


def test_trickest_is_unioned_with_nomi_not_used_only_as_a_fallback() -> None:
    """A populated Nomi-sec response used to short-circuit Trickest entirely."""
    client = _union_client(_nomi_repos(100), _TRICKEST_MD)
    urls = {ex.url for ex in client.search_pocs("CVE-2021-44228")}

    assert "https://github.com/user/repo0" in urls  # from Nomi-sec
    assert "https://github.com/hunter/real-poc" in urls  # from Trickest


def test_empty_nomi_list_still_consults_trickest() -> None:
    """An empty (but successful) Nomi-sec response returned early before."""
    client = _union_client([], _TRICKEST_MD)
    urls = {ex.url for ex in client.search_pocs("CVE-2021-44228")}
    assert "https://github.com/hunter/real-poc" in urls


def test_aggregator_repos_are_filtered_out() -> None:
    client = _union_client([], _TRICKEST_MD)
    urls = {ex.url for ex in client.search_pocs("CVE-2021-44228")}

    assert "https://github.com/0xor0ne/awesome-list" not in urls
    assert "https://github.com/0xfke/500-free-TryHackMe-rooms" not in urls
    assert len(urls) == 2


def test_duplicate_repo_across_sources_is_deduped() -> None:
    nomi = [
        {
            "full_name": "hunter/real-poc",
            "html_url": "https://github.com/hunter/real-poc",
            "description": "PoC",
            "stargazers_count": 42,
            "forks_count": 3,
        }
    ]
    client = _union_client(nomi, _TRICKEST_MD)
    result = client.search_pocs("CVE-2021-44228")

    matching = [ex for ex in result if ex.url == "https://github.com/hunter/real-poc"]
    assert len(matching) == 1
    # The Nomi-sec entry wins, so its star count is preserved.
    assert matching[0].stars == 42


# ---------------------------------------------------------------------------
# The limit must be applied BEFORE per-repo enrichment
# ---------------------------------------------------------------------------

def test_limit_is_applied_before_enrichment_api_calls() -> None:
    """Enrichment costs one GitHub API call per repo against a 60/hour budget."""
    http = MagicMock()
    repo_calls: list[str] = []

    def fake_get_json(url: str, **_: Any) -> Any:
        if url.endswith(".json"):
            return _nomi_repos(*range(40))
        repo_calls.append(url)
        return {}

    http.get_json.side_effect = fake_get_json
    http.get_text.return_value = ""
    client = GitHubClient(http_client=http)

    result = client.search_pocs("CVE-2021-44228", limit=3)

    assert len(result) == 3
    assert len(repo_calls) == 3  # not 40


def test_unlimited_search_bounds_enrichment_but_returns_everything() -> None:
    """``pocmap lookup`` passes no limit; the union can be 70+ repos.

    Enriching all of them would blow the 60/hour unauthenticated budget, so the
    call is bounded — without dropping results.
    """
    http = MagicMock()
    repo_calls: list[str] = []
    markdown = "#### Github\n" + "\n".join(
        f"- https://github.com/t/poc{i}" for i in range(60)
    )

    def fake_get_json(url: str, **_: Any) -> Any:
        if url.endswith(".json"):
            return _nomi_repos(*range(9))
        repo_calls.append(url)
        return {}

    http.get_json.side_effect = fake_get_json
    http.get_text.return_value = markdown
    client = GitHubClient(http_client=http)

    result = client.search_pocs("CVE-2023-38408")

    assert len(result) == 69  # nothing dropped
    assert len(repo_calls) == DEFAULT_ENRICH_LIMIT  # not 69
    # Un-enriched entries are "unknown" (None), not the "N/A" of a real lookup.
    assert all(ex.language is not None for ex in result[:DEFAULT_ENRICH_LIMIT])
    assert all(ex.language is None for ex in result[DEFAULT_ENRICH_LIMIT:])


def test_trickest_only_entries_rank_below_nomi_sec_entries() -> None:
    """Trickest lists include repos that merely mention the CVE."""
    http = MagicMock()
    http.get_json.side_effect = lambda url, **_: (
        _nomi_repos(3, 1) if url.endswith(".json") else {}
    )
    http.get_text.return_value = "#### Github\n- https://github.com/t/mentions-it\n"
    client = GitHubClient(http_client=http)

    urls = [ex.url for ex in client.search_pocs("CVE-2021-44228")]
    assert urls[-1] == "https://github.com/t/mentions-it"


def test_rate_limit_during_enrichment_propagates() -> None:
    """A 429 mid-enrichment must not degrade to language="N/A" under an ok status."""
    http = MagicMock()

    def fake_get_json(url: str, **_: Any) -> Any:
        if url.endswith(".json"):
            return _nomi_repos(5)
        raise RateLimitError("throttled", status_code=403)

    http.get_json.side_effect = fake_get_json
    http.get_text.return_value = ""
    client = GitHubClient(http_client=http)

    with pytest.raises(RateLimitError):
        client.search_pocs("CVE-2021-44228")
