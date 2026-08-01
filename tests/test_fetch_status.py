"""Native pytest tests for ERR-RESULT: distinguish "no results" from "source failed".

A rate-limited or down upstream must never masquerade as "nothing found" — that
is a trust-critical distinction for a security tool. These tests lock in:

  * ``HTTPClient.get`` raises the distinct :class:`RateLimitError` for HTTP 429
    and for GitHub's HTTP 403 + ``X-RateLimit-Remaining: 0`` (but NOT a plain
    403), while keeping urllib3's retry behavior.
  * :func:`collect_source` classifies a source outcome into ``FetchStatus``:
    ``RATE_LIMITED`` for throttling, ``ERROR`` for network/HTTP failure,
    ``EMPTY`` for a genuinely empty success, ``OK`` otherwise — and **re-raises
    programming bugs** (``TypeError``) instead of masking them as ``[]`` (the
    FIX-GHPOC-class regression guard).
  * ``ExploitService.find_exploits_with_status`` / ``find_github_pocs_with_status``
    surface per-source health, and the MCP adapter exposes a ``sources`` block.

Everything is fully offline: the anti-rebinding DNS check is monkeypatched and
the ``requests.Session`` transport / source callables are replaced with fakes,
so no network or DNS call is ever made.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

import pocmap.mcp_server as mcp_server
from pocmap.models import Exploit, ExploitSource
from pocmap.services.exploit_service import ExploitFindResult, ExploitService
from pocmap.utils import http as http_mod
from pocmap.utils.http import (
    FetchStatus,
    HTTPClient,
    HTTPError,
    NotFoundError,
    RateLimitError,
    SourceStatus,
    ValidationError,
    categorize_exception,
    collect_source,
    is_programming_error,
)


@pytest.fixture(autouse=True)
def _no_cve_reference_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep ERR-RESULT tests offline: stub CVE reference promotion."""
    monkeypatch.setattr(
        ExploitService,
        "_pocs_from_cve_references",
        lambda self, cve_id: [],
    )


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


def _fake_search(n: int) -> Callable[..., list[Exploit]]:
    """Stand-in for ``GitHubClient.search_pocs``, honouring ``limit``."""

    def _search(cve_id: str, limit: int | None = None) -> list[Exploit]:
        pocs = _fake_pocs(n)
        return pocs[:limit] if limit else pocs

    return _search


# ---------------------------------------------------------------------------
# Offline HTTP fake
# ---------------------------------------------------------------------------


class _FakeResponse:
    """Minimal stand-in for requests.Response used by HTTPClient.get."""

    def __init__(
        self,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = headers or {}
        self.is_redirect = 300 <= status_code < 400
        self.text = text

    def json(self) -> dict[str, object]:
        return {}


@pytest.fixture
def no_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutralize the anti-rebinding DNS check so tests stay offline."""
    monkeypatch.setattr(http_mod, "resolves_to_internal_ip", lambda host: False)


# ---------------------------------------------------------------------------
# HTTPClient.get: rate-limit detection -> RateLimitError
# ---------------------------------------------------------------------------


def test_get_429_raises_rate_limit_error(monkeypatch, no_dns) -> None:
    """A 429 (after urllib3 retries) is surfaced as the distinct RateLimitError."""
    client = HTTPClient()
    try:
        monkeypatch.setattr(
            client._session, "get", lambda url, **kw: _FakeResponse(status_code=429)
        )
        with pytest.raises(RateLimitError) as excinfo:
            client.get("https://api.github.example/repo")
        assert excinfo.value.status_code == 429
        # Rate limiting must be distinguishable, not a generic HTTPError only.
        assert isinstance(excinfo.value, HTTPError)  # still catchable by old handlers
    finally:
        client.close()


def test_get_403_ratelimited_header_raises_rate_limit_error(monkeypatch, no_dns) -> None:
    """GitHub's 403 + X-RateLimit-Remaining: 0 is classified as RATE_LIMITED."""
    client = HTTPClient()
    try:
        resp = _FakeResponse(status_code=403, headers={"X-RateLimit-Remaining": "0"})
        monkeypatch.setattr(client._session, "get", lambda url, **kw: resp)
        with pytest.raises(RateLimitError) as excinfo:
            client.get("https://api.github.example/repo")
        assert excinfo.value.status_code == 403
    finally:
        client.close()


def test_get_plain_403_is_not_rate_limited(monkeypatch, no_dns) -> None:
    """A 403 WITHOUT the rate-limit header must NOT be treated as throttling.

    It is returned to the caller (e.g. Nuclei's 'template not found' 403), not
    raised as RateLimitError — that would over-report throttling.
    """
    client = HTTPClient()
    try:
        resp = _FakeResponse(status_code=403, headers={"X-RateLimit-Remaining": "57"})
        monkeypatch.setattr(client._session, "get", lambda url, **kw: resp)
        out = client.get("https://api.github.example/repo")
        assert out is resp
        assert out.status_code == 403
    finally:
        client.close()


def test_get_normal_200_still_returned(monkeypatch, no_dns) -> None:
    client = HTTPClient()
    try:
        resp = _FakeResponse(status_code=200)
        monkeypatch.setattr(client._session, "get", lambda url, **kw: resp)
        assert client.get("https://api.github.example/repo") is resp
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------


def test_rate_limit_error_is_http_error_subclass() -> None:
    """Additive: RateLimitError stays catchable by existing `except HTTPError`."""
    assert issubclass(RateLimitError, HTTPError)


def test_categorize_exception_taxonomy() -> None:
    assert categorize_exception(RateLimitError("x")) == ("rate_limited", True)
    assert categorize_exception(HTTPError("x")) == ("network_error", True)
    assert categorize_exception(ConnectionError("x")) == ("network_error", True)
    assert categorize_exception(ValueError("x")) == ("invalid_input", False)
    assert categorize_exception(RuntimeError("x")) == ("unknown", False)
    # Package-specific errors must map to their documented categories rather
    # than falling through to "unknown".
    assert categorize_exception(ValidationError("x")) == ("invalid_input", False)
    assert categorize_exception(NotFoundError("x")) == ("not_found", False)


def test_validation_error_is_also_a_value_error() -> None:
    """``except ValueError`` is the idiomatic guard callers reach for.

    It is also what ``categorize_exception`` keys ``invalid_input`` off, so
    without this base a malformed CVE ID reached agents as ``unknown``.
    """
    assert issubclass(ValidationError, ValueError)
    assert isinstance(ValidationError("x"), ValueError)


def test_is_programming_error_targets_our_bugs() -> None:
    assert is_programming_error(TypeError("bad call"))
    assert is_programming_error(NameError("typo"))
    # External-data parsing errors must still degrade gracefully, not blow up.
    assert not is_programming_error(KeyError("missing"))
    assert not is_programming_error(IndexError("range"))
    assert not is_programming_error(HTTPError("net"))


# ---------------------------------------------------------------------------
# collect_source: the core classifier
# ---------------------------------------------------------------------------


def test_collect_source_ok_and_empty() -> None:
    results, status = collect_source("github", lambda: _fake_pocs(3))
    assert status.status is FetchStatus.OK
    assert status.count == 3
    assert len(results) == 3

    results, status = collect_source("github", lambda: [])
    assert status.status is FetchStatus.EMPTY
    assert status.count == 0
    assert results == []


def test_collect_source_rate_limited(monkeypatch) -> None:
    """A RateLimitError -> RATE_LIMITED (never ERROR/EMPTY)."""

    def _boom() -> list[Exploit]:
        raise RateLimitError("throttled", status_code=403)

    results, status = collect_source("github", _boom)
    assert status.status is FetchStatus.RATE_LIMITED
    assert status.status is not FetchStatus.ERROR
    assert status.status is not FetchStatus.EMPTY
    assert status.category == "rate_limited"
    assert status.retryable is True
    assert results == []  # degrades gracefully, aggregate keeps running


def test_collect_source_network_error_degrades() -> None:
    """A genuine network/HTTP error -> ERROR, but does not crash the aggregate."""

    def _boom() -> list[Exploit]:
        raise HTTPError("connection reset", status_code=500)

    results, status = collect_source("github", _boom)
    assert status.status is FetchStatus.ERROR
    assert status.category == "network_error"
    assert results == []


def test_collect_source_reraises_programming_bug() -> None:
    """A TypeError inside a source is NOT swallowed into [] (FIX-GHPOC guard)."""

    def _bug() -> list[Exploit]:
        raise TypeError("find_github_pocs() got an unexpected keyword 'limit'")

    with pytest.raises(TypeError):
        collect_source("github", _bug)


# ---------------------------------------------------------------------------
# ExploitService.find_exploits_with_status
# ---------------------------------------------------------------------------


def test_find_exploits_with_status_rate_limited_github(monkeypatch) -> None:
    """A rate-limited GitHub reports RATE_LIMITED rather than looking empty."""
    svc = ExploitService()

    def _rl(cve_id: str, limit: int | None = None) -> list[Exploit]:
        raise RateLimitError("gh throttled", status_code=403)

    monkeypatch.setattr(svc._github, "search_pocs", _rl)
    monkeypatch.setattr(svc._exploits, "search_all", lambda cve_id, limit=None: [])

    result = svc.find_exploits_with_status(CVE)
    assert isinstance(result, ExploitFindResult)
    statuses = {s.name: s.status for s in result.sources}
    assert statuses["github"] is FetchStatus.RATE_LIMITED
    assert statuses["db"] is FetchStatus.EMPTY
    assert result.exploits == []  # no results, but caller can SEE why


def test_find_exploits_with_status_empty_is_empty(monkeypatch) -> None:
    """A genuinely empty (successful) lookup is EMPTY, distinct from a failure."""
    svc = ExploitService()
    monkeypatch.setattr(svc._github, "search_pocs", lambda cve_id, limit=None: [])
    monkeypatch.setattr(svc._exploits, "search_all", lambda cve_id, limit=None: [])

    result = svc.find_exploits_with_status(CVE)
    statuses = {s.name: s.status for s in result.sources}
    assert statuses["github"] is FetchStatus.EMPTY
    assert statuses["db"] is FetchStatus.EMPTY


def test_find_exploits_with_status_network_error_degrades(monkeypatch) -> None:
    """A network ERROR in one source degrades without crashing the aggregate."""
    svc = ExploitService()

    def _net(cve_id: str, limit: int | None = None) -> list[Exploit]:
        raise HTTPError("NVD down", status_code=503)

    db_hit = Exploit(source=ExploitSource.METASPLOIT, url="msf://x", title="mod")
    monkeypatch.setattr(svc._github, "search_pocs", _net)
    monkeypatch.setattr(svc._exploits, "search_all", lambda cve_id: [db_hit])

    result = svc.find_exploits_with_status(CVE)
    statuses = {s.name: s.status for s in result.sources}
    assert statuses["github"] is FetchStatus.ERROR
    assert statuses["db"] is FetchStatus.OK
    # The aggregate still returns the source that succeeded.
    assert [e.source for e in result.exploits] == [ExploitSource.METASPLOIT]


def test_find_exploits_with_status_propagates_typeerror(monkeypatch) -> None:
    """A programming bug in a source propagates (not masked as empty results)."""
    svc = ExploitService()

    def _bug(cve_id: str, limit: int | None = None) -> list[Exploit]:
        raise TypeError("bug in our own code")

    monkeypatch.setattr(svc._github, "search_pocs", _bug)

    with pytest.raises(TypeError):
        svc.find_exploits_with_status(CVE)


# ---------------------------------------------------------------------------
# ExploitService.find_github_pocs_with_status + legacy degradation
# ---------------------------------------------------------------------------


def test_find_github_pocs_with_status_rate_limited(monkeypatch) -> None:
    svc = ExploitService()

    def _rl(cve_id: str, limit: int | None = None) -> list[Exploit]:
        raise RateLimitError("throttled", status_code=429)

    monkeypatch.setattr(svc._github, "search_pocs", _rl)
    result = svc.find_github_pocs_with_status(CVE, limit=5)
    assert result.exploits == []
    assert len(result.sources) == 1
    assert result.sources[0].status is FetchStatus.RATE_LIMITED


def test_legacy_find_github_pocs_still_degrades_on_rate_limit(monkeypatch) -> None:
    """Non-breaking: the bare-list method keeps returning [] on a throttle."""
    svc = ExploitService()

    def _rl(cve_id: str, limit: int | None = None) -> list[Exploit]:
        raise RateLimitError("throttled", status_code=429)

    monkeypatch.setattr(svc._github, "search_pocs", _rl)
    assert svc.find_github_pocs(CVE) == []
    assert svc.find_github_pocs(CVE, limit=3) == []


def test_legacy_find_exploits_does_not_raise_on_rate_limit(monkeypatch) -> None:
    """find_exploits keeps its list contract and degrades on a throttled source."""
    svc = ExploitService()

    def _rl(cve_id: str, limit: int | None = None) -> list[Exploit]:
        raise RateLimitError("throttled", status_code=403)

    monkeypatch.setattr(svc._github, "search_pocs", _rl)
    monkeypatch.setattr(svc._exploits, "search_all", lambda cve_id, limit=None: [])
    assert svc.find_exploits(CVE) == []  # no crash, just empty


# ---------------------------------------------------------------------------
# SourceStatus serialization
# ---------------------------------------------------------------------------


def test_source_status_to_dict_shape() -> None:
    ok = SourceStatus(name="github", status=FetchStatus.OK, count=4)
    d = ok.to_dict()
    assert d == {"source": "github", "status": "ok", "count": 4, "retryable": False}

    rl = SourceStatus(
        name="github",
        status=FetchStatus.RATE_LIMITED,
        category="rate_limited",
        retryable=True,
        detail="RateLimitError",
    )
    d = rl.to_dict()
    assert d["status"] == "rate_limited"
    assert d["category"] == "rate_limited"
    assert d["retryable"] is True
    assert d["detail"] == "RateLimitError"


# ---------------------------------------------------------------------------
# MCP adapter: sources block + no-swallow guard
# ---------------------------------------------------------------------------


def test_adapter_find_github_pocs_with_sources_reports_rate_limit(monkeypatch) -> None:
    adapter = mcp_server.ServiceAdapter()

    def _rl(cve_id: str, limit: int | None = None) -> list[Exploit]:
        raise RateLimitError("throttled", status_code=403)

    monkeypatch.setattr(adapter._exploit._github, "search_pocs", _rl)
    out = adapter.find_github_pocs_with_sources(CVE, limit=5)

    assert out["pocs"] == []
    assert isinstance(out["sources"], list) and out["sources"]
    gh = out["sources"][0]
    assert gh["source"] == "github"
    assert gh["status"] == "rate_limited"  # NOT "empty"
    assert gh["retryable"] is True


def test_adapter_find_github_pocs_with_sources_ok(monkeypatch) -> None:
    adapter = mcp_server.ServiceAdapter()
    monkeypatch.setattr(
        adapter._exploit._github, "search_pocs", _fake_search(4)
    )
    out = adapter.find_github_pocs_with_sources(CVE, limit=3)
    assert len(out["pocs"]) == 3
    assert out["sources"][0]["status"] == "ok"


def test_adapter_find_github_pocs_does_not_swallow_typeerror(monkeypatch) -> None:
    """Regression guard: a programming bug in the adapter path must surface,
    not be silently turned into [] (the class of bug that hid FIX-GHPOC)."""
    adapter = mcp_server.ServiceAdapter()

    def _bug(cve_id: str, limit: int | None = None) -> list[Exploit]:
        raise TypeError("wrong signature")

    monkeypatch.setattr(adapter._exploit, "find_github_pocs", _bug)
    with pytest.raises(TypeError):
        adapter.find_github_pocs(CVE, limit=3)


# ---------------------------------------------------------------------------
# generate_json_report: sources block (no silent-empty exploits)
# ---------------------------------------------------------------------------


def test_generate_json_report_includes_sources_and_uses_with_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Report entries must expose per-source health; empty exploits ≠ silent miss."""
    adapter = mcp_server.ServiceAdapter()
    monkeypatch.setattr(
        adapter,
        "lookup_cve",
        lambda cve_id: {
            "id": cve_id,
            "description": "test",
            "cvss": {"version": "3.1", "score": 9.8, "severity": "CRITICAL", "vector_string": None},
            "epss_score": 0.9,
            "kev_status": True,
            "cwes": [],
            "references": [],
            "vendor": "apache",
            "product": "log4j",
            "affected_products": [],
            "publication_date": "2021-12-10",
            "state": "PUBLISHED",
        },
    )
    monkeypatch.setattr(adapter, "find_labs", lambda _cve: [])
    monkeypatch.setattr(adapter, "find_bug_bounty_reports", lambda _cve: [])

    statuses = [
        SourceStatus(name="github", status=FetchStatus.RATE_LIMITED, count=0, retryable=True),
        SourceStatus(name="db", status=FetchStatus.EMPTY, count=0),
    ]
    monkeypatch.setattr(
        adapter._exploit,
        "find_exploits_with_status",
        lambda _cve: ExploitFindResult(exploits=[], sources=statuses),
    )

    report = adapter.generate_json_report([CVE])
    assert report["total_entries"] == 1
    entry = report["entries"][0]
    assert entry["exploits"] == []
    assert "sources" in entry
    by_name = {s["source"]: s for s in entry["sources"]}
    assert by_name["github"]["status"] == "rate_limited"
    assert by_name["github"]["retryable"] is True
    assert by_name["db"]["status"] == "empty"


def test_scope_monitor_fetch_raises_instead_of_silent_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default ScopeMonitor path must not pretend 'no CVEs' when the fetch fails."""
    from pocmap.bugbounty.automation import ScopeMonitor

    class _BoomRecent:
        def __enter__(self) -> _BoomRecent:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def find_recent_cves(self, **_kwargs: object) -> list[object]:
            raise HTTPError("nvd down", status_code=503)

    monkeypatch.setattr(
        "pocmap.bugbounty.automation.RecentService",
        lambda: _BoomRecent(),
    )
    with pytest.raises(RuntimeError, match="could not fetch recent CVEs"):
        ScopeMonitor()._fetch_recent_cves()


def test_scope_monitor_fetch_returns_cve_dicts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pocmap.bugbounty.automation import ScopeMonitor
    from pocmap.models import CVEInfo, RecentExploitResult

    class _FakeRecent:
        def __enter__(self) -> _FakeRecent:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def find_recent_cves(self, **_kwargs: object) -> list[RecentExploitResult]:
            return [
                RecentExploitResult(
                    cve_info=CVEInfo(id="CVE-2024-0001", product="nginx", vendor="f5"),
                )
            ]

    monkeypatch.setattr(
        "pocmap.bugbounty.automation.RecentService",
        lambda: _FakeRecent(),
    )
    rows = ScopeMonitor()._fetch_recent_cves()
    assert len(rows) == 1
    assert rows[0]["id"] == "CVE-2024-0001"
    assert rows[0]["product"] == "nginx"


def test_scope_monitor_rejects_empty_scope() -> None:
    """Empty scope must not look like 'no new CVEs' — fail before fetching."""
    from pocmap.bugbounty.automation import ScopeMonitor

    monitor = ScopeMonitor()
    with pytest.raises(RuntimeError, match="no in-scope assets"):
        monitor.check_new_cves(cve_source=lambda: [{"id": "CVE-2024-1", "cvss_score": 9.0}])


def test_scope_monitor_alerts_on_model_dump_cvss_above_threshold() -> None:
    """RecentService feeds CVEInfo.model_dump(); nested cvss.base_score must alert.

    Flat ``cvss_score`` fixtures give false confidence — the live path dumps
    ``cvss: {"base_score": ...}``, and the threshold check needs that unwrapped.
    """
    from pocmap.bugbounty.automation import ScopeMonitor
    from pocmap.bugbounty.scope_manager import ScopeManager
    from pocmap.models import CVEInfo, CVSSScore, CVSSVersion, Severity

    scope = ScopeManager()
    scope.add_program("hackerone", "example", ["nginx.example.com"])
    monitor = ScopeMonitor(scope)
    monitor.set_alert_threshold(7.0)

    dumped = CVEInfo(
        id="CVE-2024-9999",
        product="nginx",
        vendor="f5",
        cvss=CVSSScore(
            version=CVSSVersion.V3_1,
            base_score=9.8,
            severity=Severity.CRITICAL,
        ),
    ).model_dump(mode="json")
    assert isinstance(dumped["cvss"], dict)
    assert dumped["cvss"]["base_score"] == 9.8

    alerts = monitor.check_new_cves(cve_source=lambda: [dumped])
    assert len(alerts) == 1
    assert alerts[0]["id"] == "CVE-2024-9999"


def test_generate_html_report_renders_source_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTML must surface per-source health so empty exploits are not silent misses."""
    adapter = mcp_server.ServiceAdapter()
    monkeypatch.setattr(
        adapter,
        "lookup_cve",
        lambda cve_id: {
            "id": cve_id,
            "description": "test",
            "cvss": {"version": "3.1", "score": 9.8, "severity": "CRITICAL"},
            "epss_score": 0.9,
            "kev_status": True,
            "cwes": [],
            "references": [],
            "vendor": "apache",
            "product": "log4j",
            "affected_products": [],
            "publication_date": "2021-12-10",
            "state": "PUBLISHED",
        },
    )
    monkeypatch.setattr(adapter, "find_labs", lambda _cve: [])
    monkeypatch.setattr(adapter, "find_bug_bounty_reports", lambda _cve: [])
    statuses = [
        SourceStatus(name="github", status=FetchStatus.RATE_LIMITED, count=0, retryable=True),
        SourceStatus(name="db", status=FetchStatus.EMPTY, count=0),
    ]
    monkeypatch.setattr(
        adapter._exploit,
        "find_exploits_with_status",
        lambda _cve: ExploitFindResult(exploits=[], sources=statuses),
    )

    report = adapter.generate_html_report([CVE])
    html_out = report["content"]
    assert "Source Status" in html_out
    assert "github: rate_limited" in html_out
    assert "db: empty" in html_out
