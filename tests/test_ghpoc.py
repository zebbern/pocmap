"""Regression tests for FIX-GHPOC.

Guards the MCP GitHub-PoC discovery path. Previously
``ServiceAdapter.find_github_pocs`` called
``ExploitService.find_github_pocs(cve_id, limit=limit)`` while the service
method took **no** ``limit`` argument, raising ``TypeError`` that the adapter's
broad ``except Exception`` swallowed -> the tool silently returned ``[]``.

These tests are fully offline: the underlying GitHub search
(``GitHubClient.search_pocs``) is monkeypatched to return fabricated
``Exploit`` objects, so no network is touched.
"""

from __future__ import annotations

import inspect

import pytest

# mcp_server lives at the repo root and adds src/ to sys.path on import.
import mcp_server  # noqa: E402
from pocmap.models import Exploit, ExploitSource
from pocmap.services.exploit_service import ExploitService

CVE = "CVE-2021-44228"


def _fake_pocs(n: int) -> list[Exploit]:
    """Build ``n`` fabricated GitHub PoC Exploit objects."""
    return [
        Exploit(
            source=ExploitSource.GITHUB,
            url=f"https://github.com/example/poc-{i}",
            title=f"PoC {i}",
            language="Python",
            stars=max(0, 1000 - i),
            forks=max(0, 100 - i),
        )
        for i in range(n)
    ]


def test_adapter_find_github_pocs_returns_normalized_dicts(monkeypatch):
    """ServiceAdapter.find_github_pocs(cve, limit=3) returns 3 dicts, not []."""
    adapter = mcp_server.ServiceAdapter()
    monkeypatch.setattr(
        adapter._exploit._github, "search_pocs", lambda cve_id: _fake_pocs(5)
    )

    result = adapter.find_github_pocs(CVE, limit=3)

    assert result != []  # the core bug: this used to be [] due to swallowed TypeError
    assert isinstance(result, list)
    assert len(result) == 3
    assert all(isinstance(r, dict) for r in result)
    # normalized shape produced by ServiceAdapter._normalize_exploit
    first = result[0]
    assert first["source"] == "github"
    assert first["url"] == "https://github.com/example/poc-0"
    assert first["title"] == "PoC 0"
    assert first["language"] == "Python"


def test_adapter_find_github_pocs_default_limit(monkeypatch):
    """The adapter's default limit (10) caps results and never errors."""
    adapter = mcp_server.ServiceAdapter()
    monkeypatch.setattr(
        adapter._exploit._github, "search_pocs", lambda cve_id: _fake_pocs(25)
    )

    result = adapter.find_github_pocs(CVE)

    assert len(result) == 10
    assert all(r["source"] == "github" for r in result)


def test_service_find_github_pocs_no_limit_returns_all(monkeypatch):
    """CLI path: ExploitService.find_github_pocs(cve) with no limit returns all."""
    svc = ExploitService()
    monkeypatch.setattr(svc._github, "search_pocs", lambda cve_id: _fake_pocs(7))

    result = svc.find_github_pocs(CVE)

    assert len(result) == 7  # nothing truncated when limit is omitted


def test_service_find_github_pocs_with_limit_slices(monkeypatch):
    """ExploitService.find_github_pocs(cve, limit=N) slices to N."""
    svc = ExploitService()
    monkeypatch.setattr(svc._github, "search_pocs", lambda cve_id: _fake_pocs(9))

    assert len(svc.find_github_pocs(CVE, limit=4)) == 4
    # limit larger than available returns everything
    assert len(svc.find_github_pocs(CVE, limit=50)) == 9


def test_service_find_github_pocs_accepts_limit_kwarg_no_typeerror(monkeypatch):
    """Regression: the signature accepts `limit=` so the adapter path no longer
    raises (and thus no longer silently swallows) a TypeError."""
    # 1. The public signature really carries `limit`.
    sig = inspect.signature(ExploitService.find_github_pocs)
    assert "limit" in sig.parameters

    svc = ExploitService()
    monkeypatch.setattr(svc._github, "search_pocs", lambda cve_id: _fake_pocs(2))

    # 2. Calling with limit= must NOT raise TypeError (it did before the fix).
    try:
        out = svc.find_github_pocs(CVE, limit=3)
    except TypeError as exc:  # pragma: no cover - only hit on regression
        pytest.fail(f"find_github_pocs rejected limit kwarg: {exc}")

    assert len(out) == 2


def test_adapter_does_not_mask_populated_results(monkeypatch):
    """End-to-end guard: a non-empty upstream must surface as non-empty output.

    If the TypeError regression returned, the adapter's broad except would turn
    this into [] -- so a populated mock proving non-empty output is the guard.
    """
    adapter = mcp_server.ServiceAdapter()
    monkeypatch.setattr(
        adapter._exploit._github, "search_pocs", lambda cve_id: _fake_pocs(4)
    )

    result = adapter.find_github_pocs(CVE, limit=10)

    assert len(result) == 4
    assert result[0]["url"].startswith("https://github.com/example/poc-")
