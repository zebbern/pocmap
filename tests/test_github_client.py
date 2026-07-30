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

from pocmap.clients.github_client import GitHubClient
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


def test_exploit_from_nomi_missing_full_name_returns_none() -> None:
    client = GitHubClient(http_client=MagicMock())

    assert client._exploit_from_nomi({}) is None
    assert client._exploit_from_nomi({"html_url": "https://github.com/x/y"}) is None
