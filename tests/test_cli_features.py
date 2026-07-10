"""Native offline pytest for the CI-gate / watch-diff / offline CLI features.

Covers the three roadmap items wired into ``pocmap.cli``:

  * **STDIN-BULK-CI** — ``bulk -`` reads CVE ids from stdin; ``bulk --format
    {json,csv,sarif}`` emits a clean stdout summary; ``bulk --fail-on
    {critical,high,kev,epss>=N}`` turns pocmap into a build gate that exits
    ``POLICY_FAIL`` (6) on a match and ``0`` otherwise; a malformed
    ``--fail-on`` exits ``INVALID_INPUT`` (4).
  * **WATCH-DIFF** — ``latest --diff`` reports every CVE as *added* on the first
    run (no baseline) and reports the delta (e.g. a KEV flip) on the second run,
    against a temp cache dir.
  * **OFFLINE-MODE** — the global ``--offline`` flag actually flips
    ``settings.offline`` process-wide (via ``config.enable_offline``) so
    ``HTTPClient`` serves only from the cache: a warm cache is served with no
    network, and a cold cache surfaces a clean CLI error (``OfflineError``
    path), never an uncaught traceback.

Everything is fully offline: services are monkeypatched and the one real HTTP
call in the offline test is answered from a temp cache (or raises before any
socket is opened). No network or DNS call is ever made.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import pocmap.services.snapshot as snapshot_mod
import pocmap.utils.http as http_mod
from pocmap.cli import app
from pocmap.config import settings
from pocmap.models import (
    CVEInfo,
    CVSSScore,
    CVSSVersion,
    Exploit,
    ExploitSource,
    MultiReport,
    RecentExploitResult,
    ReportEntry,
    Severity,
)
from pocmap.services.cve_service import CVEService
from pocmap.services.exploit_service import ExploitService
from pocmap.services.lab_service import LabService
from pocmap.services.recent_service import RecentService
from pocmap.services.report_service import ReportService
from pocmap.utils.cache import HTTPCache
from pocmap.utils.exit_codes import ExitCode

runner = CliRunner()

_BIG_CAP = 200 * 1024 * 1024


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _cve(
    cve_id: str,
    *,
    severity: Severity = Severity.CRITICAL,
    score: float | None = 9.8,
    epss: float | None = 42.0,
    kev: bool = False,
) -> CVEInfo:
    return CVEInfo(
        id=cve_id,
        description=f"{cve_id} description",
        cvss=CVSSScore(version=CVSSVersion.V3_1, base_score=score, severity=severity),
        epss=epss,
        kev_status=kev,
        cwes=["CWE-79"],
        vendor="Acme",
        product="Widget",
    )


def _entry(cve: CVEInfo, *, exploits: int = 0) -> ReportEntry:
    exs = [
        Exploit(source=ExploitSource.GITHUB, url=f"https://github.com/x/poc{i}")
        for i in range(exploits)
    ]
    return ReportEntry(cve_info=cve, exploits=exs)


def _multi(entries: list[ReportEntry]) -> MultiReport:
    return MultiReport(entries={e.cve_info.id: e for e in entries})


# ---------------------------------------------------------------------------
# STDIN-BULK-CI
# ---------------------------------------------------------------------------


def test_bulk_dash_reads_two_cves_from_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    """``bulk -`` reads the piped ids and reports both (via --format json)."""
    seen: dict[str, list[str]] = {}

    def fake_generate(self: ReportService, ids: list[str]) -> MultiReport:
        seen["ids"] = list(ids)
        return _multi([_entry(_cve(cid.upper())) for cid in ids])

    monkeypatch.setattr(ReportService, "generate_bulk_report", fake_generate)

    result = runner.invoke(
        app,
        ["bulk", "-", "--format", "json"],
        input="CVE-2021-44228\nCVE-2023-38408\n",
    )
    assert result.exit_code == ExitCode.OK, result.stdout
    # stdin was read, both ids reached the service.
    assert seen["ids"] == ["CVE-2021-44228", "CVE-2023-38408"]
    data = json.loads(result.stdout)
    assert data["total"] == 2
    ids = {row["cve_id"] for row in data["cves"]}
    assert ids == {"CVE-2021-44228", "CVE-2023-38408"}


def test_bulk_dash_skips_blank_and_comment_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, list[str]] = {}

    def fake_generate(self: ReportService, ids: list[str]) -> MultiReport:
        captured["ids"] = list(ids)
        return _multi([_entry(_cve(cid.upper())) for cid in ids])

    monkeypatch.setattr(ReportService, "generate_bulk_report", fake_generate)
    result = runner.invoke(
        app,
        ["bulk", "-", "--format", "json"],
        input="# a comment\nCVE-2021-44228\n\n   \nCVE-2023-38408\n",
    )
    assert result.exit_code == ExitCode.OK, result.stdout
    assert captured["ids"] == ["CVE-2021-44228", "CVE-2023-38408"]


def test_bulk_fail_on_kev_hit_exits_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    """A KEV CVE in the set trips ``--fail-on kev`` -> exit 6 (ExitCode.POLICY_FAIL)."""
    monkeypatch.setattr(
        ReportService,
        "generate_bulk_report",
        lambda self, ids: _multi(
            [
                _entry(_cve("CVE-2021-44228", kev=True)),
                _entry(_cve("CVE-2023-38408", kev=False)),
            ]
        ),
    )
    result = runner.invoke(
        app, ["bulk", "-", "--format", "json", "--fail-on", "kev"], input="x\n"
    )
    assert result.exit_code == ExitCode.POLICY_FAIL  # 6
    # stdout stays parseable JSON; the gate note is on stderr.
    data = json.loads(result.stdout)
    assert data["total"] == 2
    assert "CVE-2021-44228" in result.stderr


def test_bulk_fail_on_kev_no_hit_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """No KEV CVE -> ``--fail-on kev`` passes the gate (exit 0)."""
    monkeypatch.setattr(
        ReportService,
        "generate_bulk_report",
        lambda self, ids: _multi(
            [
                _entry(_cve("CVE-2021-44228", kev=False)),
                _entry(_cve("CVE-2023-38408", kev=False)),
            ]
        ),
    )
    result = runner.invoke(
        app, ["bulk", "-", "--format", "json", "--fail-on", "kev"], input="x\n"
    )
    assert result.exit_code == ExitCode.OK  # 0


def test_bulk_fail_on_epss_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    """``--fail-on epss>=50`` trips only when some EPSS clears the threshold."""
    monkeypatch.setattr(
        ReportService,
        "generate_bulk_report",
        lambda self, ids: _multi(
            [
                _entry(_cve("CVE-2021-44228", epss=80.0)),
                _entry(_cve("CVE-2023-38408", epss=10.0)),
            ]
        ),
    )
    hit = runner.invoke(
        app, ["bulk", "-", "--format", "json", "--fail-on", "epss>=50"], input="x\n"
    )
    assert hit.exit_code == ExitCode.POLICY_FAIL


def test_bulk_fail_on_high_matches_critical(monkeypatch: pytest.MonkeyPatch) -> None:
    """``--fail-on high`` means HIGH *or worse*, so a CRITICAL trips it."""
    monkeypatch.setattr(
        ReportService,
        "generate_bulk_report",
        lambda self, ids: _multi([_entry(_cve("CVE-2021-44228", severity=Severity.CRITICAL))]),
    )
    result = runner.invoke(
        app, ["bulk", "-", "--format", "json", "--fail-on", "high"], input="x\n"
    )
    assert result.exit_code == ExitCode.POLICY_FAIL


def test_bulk_bad_fail_on_exits_invalid_input(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ReportService,
        "generate_bulk_report",
        lambda self, ids: _multi([_entry(_cve("CVE-2021-44228"))]),
    )
    result = runner.invoke(
        app, ["bulk", "-", "--fail-on", "banana"], input="x\n"
    )
    assert result.exit_code == ExitCode.INVALID_INPUT  # 4


def test_bulk_sarif_is_valid_2_1_0(monkeypatch: pytest.MonkeyPatch) -> None:
    """``bulk --format sarif`` emits a valid SARIF 2.1.0 log for the CVE set."""
    monkeypatch.setattr(
        ReportService,
        "generate_bulk_report",
        lambda self, ids: _multi(
            [
                _entry(_cve("CVE-2021-44228", severity=Severity.CRITICAL, kev=True), exploits=3),
                _entry(_cve("CVE-2023-38408", severity=Severity.MEDIUM, score=5.0), exploits=1),
            ]
        ),
    )
    result = runner.invoke(app, ["bulk", "-", "--format", "sarif"], input="x\n")
    assert result.exit_code == ExitCode.OK, result.stdout
    log = json.loads(result.stdout)
    assert log["version"] == "2.1.0"
    assert log["$schema"]
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "pocmap"
    results = log["runs"][0]["results"]
    by_id = {r["ruleId"]: r for r in results}
    assert set(by_id) == {"CVE-2021-44228", "CVE-2023-38408"}
    # CRITICAL -> error; MEDIUM -> warning; exploit_count carried in properties.
    assert by_id["CVE-2021-44228"]["level"] == "error"
    assert by_id["CVE-2023-38408"]["level"] == "warning"
    assert by_id["CVE-2021-44228"]["properties"]["exploit_count"] == 3
    assert by_id["CVE-2021-44228"]["properties"]["kev"] is True


def test_bulk_table_default_writes_reports(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The default (table) format keeps the historical JSON+HTML file output."""
    monkeypatch.setattr(
        ReportService,
        "generate_bulk_report",
        lambda self, ids: _multi([_entry(_cve("CVE-2021-44228"))]),
    )
    # ``--output`` is validated against the CWD by safe_path, so run inside a
    # temp dir (portable across click versions) and write to a relative subdir.
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app, ["bulk", "-", "--output", "reports"], input="CVE-2021-44228\n"
    )
    assert result.exit_code == ExitCode.OK, result.stdout
    written = list((tmp_path / "reports").iterdir())
    assert any(p.suffix == ".json" for p in written)
    assert any(p.suffix == ".html" for p in written)


def test_bulk_file_still_works(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A real file path still routes through ``generate_bulk_report_from_file``."""
    seen: dict[str, Any] = {}

    def fake_from_file(self: ReportService, path: Any) -> MultiReport:
        seen["path"] = str(path)
        return _multi([_entry(_cve("CVE-2021-44228"))])

    monkeypatch.setattr(ReportService, "generate_bulk_report_from_file", fake_from_file)
    cve_file = tmp_path / "cves.txt"
    cve_file.write_text("CVE-2021-44228\n", encoding="utf-8")

    result = runner.invoke(app, ["bulk", str(cve_file), "--format", "json"])
    assert result.exit_code == ExitCode.OK, result.stdout
    assert seen["path"] == str(cve_file)
    assert json.loads(result.stdout)["total"] == 1


def test_bulk_missing_file_exits_invalid_input() -> None:
    result = runner.invoke(app, ["bulk", "does-not-exist.txt"])
    assert result.exit_code == ExitCode.INVALID_INPUT  # 4


# ---------------------------------------------------------------------------
# WATCH-DIFF: latest --diff
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_snapshot_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the snapshot engine at an isolated temp cache dir."""
    monkeypatch.setattr(snapshot_mod, "settings", replace(settings, cache_dir=tmp_path))
    return tmp_path


def _recent(cve: CVEInfo, *, has_poc: bool = False) -> RecentExploitResult:
    sources = [ExploitSource.GITHUB] if has_poc else []
    return RecentExploitResult(cve_info=cve, has_poc=has_poc, poc_sources=sources)


def test_latest_diff_first_run_all_added(
    temp_snapshot_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """First ``latest --diff`` run has no baseline -> everything is 'added'."""
    monkeypatch.setattr(
        RecentService,
        "find_recent_cves",
        lambda self, **kw: [
            _recent(_cve("CVE-2024-0001")),
            _recent(_cve("CVE-2024-0002")),
        ],
    )
    result = runner.invoke(app, ["latest", "--diff", "--format", "json"])
    assert result.exit_code == ExitCode.OK, result.stdout
    diff = json.loads(result.stdout)
    added = {row["cve_id"] for row in diff["added"]}
    assert added == {"CVE-2024-0001", "CVE-2024-0002"}
    assert diff["removed"] == []
    assert diff["changed"] == []


def test_latest_diff_second_run_shows_change(
    temp_snapshot_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second run over a changed fixture reports the delta (KEV gained)."""
    # Run 1: baseline (CVE-2024-0001 NOT in KEV).
    monkeypatch.setattr(
        RecentService,
        "find_recent_cves",
        lambda self, **kw: [
            _recent(_cve("CVE-2024-0001", kev=False)),
            _recent(_cve("CVE-2024-0002")),
        ],
    )
    first = runner.invoke(app, ["latest", "--diff", "--format", "json"])
    assert first.exit_code == ExitCode.OK, first.stdout
    assert {r["cve_id"] for r in json.loads(first.stdout)["added"]} == {
        "CVE-2024-0001",
        "CVE-2024-0002",
    }

    # Run 2 (same query args -> same snapshot key): CVE-2024-0001 gains KEV,
    # CVE-2024-0002 drops out entirely.
    monkeypatch.setattr(
        RecentService,
        "find_recent_cves",
        lambda self, **kw: [_recent(_cve("CVE-2024-0001", kev=True))],
    )
    second = runner.invoke(app, ["latest", "--diff", "--format", "json"])
    assert second.exit_code == ExitCode.OK, second.stdout
    diff = json.loads(second.stdout)

    assert diff["added"] == []
    changed = {c["cve_id"]: c for c in diff["changed"]}
    assert "CVE-2024-0001" in changed
    assert "kev_gained" in changed["CVE-2024-0001"]["reasons"]
    assert {r["cve_id"] for r in diff["removed"]} == {"CVE-2024-0002"}


def test_latest_diff_no_changes_second_run(
    temp_snapshot_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two identical runs -> an empty diff (nothing added/removed/changed)."""
    monkeypatch.setattr(
        RecentService,
        "find_recent_cves",
        lambda self, **kw: [_recent(_cve("CVE-2024-0001"))],
    )
    runner.invoke(app, ["latest", "--diff", "--format", "json"])
    second = runner.invoke(app, ["latest", "--diff", "--format", "json"])
    assert second.exit_code == ExitCode.OK, second.stdout
    diff = json.loads(second.stdout)
    assert diff["added"] == []
    assert diff["removed"] == []
    assert diff["changed"] == []
    assert "No changes" in diff["summary"]


def test_latest_diff_table_render(
    temp_snapshot_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default (table) --diff render shows a human 'changes since' view."""
    monkeypatch.setattr(
        RecentService,
        "find_recent_cves",
        lambda self, **kw: [_recent(_cve("CVE-2024-0001"))],
    )
    result = runner.invoke(app, ["latest", "--diff"])
    assert result.exit_code == ExitCode.OK, result.stdout
    assert "changes since last run" in result.stdout
    assert "CVE-2024-0001" in result.stdout


# ---------------------------------------------------------------------------
# OFFLINE-MODE: global --offline flag, end-to-end
# ---------------------------------------------------------------------------

_OFFLINE_URL = "https://api.example/cve"


@pytest.fixture
def restore_offline() -> Any:
    """Restore the process-wide ``settings.offline`` after a test flips it."""
    original = settings.offline
    yield
    object.__setattr__(settings, "offline", original)


@pytest.fixture
def offline_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore_offline: Any
) -> HTTPCache:
    """Install a temp HTTP cache and neutralize the non-CVE lookups.

    ``get_cve_info`` is redirected through the *real* module-level
    ``fetch_json`` so the offline+cache path is exercised end-to-end; the
    exploit/lab lookups are stubbed to empty so ``lookup`` completes without any
    other network dependency.
    """
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP, enabled=True)
    monkeypatch.setattr(http_mod, "_cache", cache)
    monkeypatch.setattr(http_mod, "_client", None)  # force a fresh default client

    def fake_get_cve_info(self: CVEService, cve: str) -> CVEInfo:
        # Real offline resolution: cache hit returns, cache miss raises OfflineError.
        http_mod.fetch_json(_OFFLINE_URL)
        return _cve("CVE-2021-44228", kev=True)

    monkeypatch.setattr(CVEService, "get_cve_info", fake_get_cve_info)
    monkeypatch.setattr(ExploitService, "find_github_pocs", lambda self, cve: [])
    monkeypatch.setattr(ExploitService, "find_db_exploits", lambda self, cve: [])
    monkeypatch.setattr(LabService, "find_labs", lambda self, cve: [])
    return cache


def test_offline_warm_cache_served_end_to_end(offline_env: HTTPCache) -> None:
    """``--offline`` + a warm cache -> lookup succeeds and the flag really flipped."""
    offline_env.set(HTTPCache.make_key("GET", _OFFLINE_URL, None), '{"ok": true}')

    result = runner.invoke(app, ["--offline", "lookup", "CVE-2021-44228", "--no-banner"])
    assert result.exit_code == ExitCode.OK, result.stdout
    assert "CVE-2021-44228" in result.stdout
    # Proof the flag flipped the process-wide setting that http.py reads.
    assert settings.offline is True


def test_offline_cold_cache_clean_error_not_traceback(offline_env: HTTPCache) -> None:
    """``--offline`` + a cold cache -> a clean CLI error, never an uncaught trace."""
    result = runner.invoke(app, ["--offline", "lookup", "CVE-2021-44228", "--no-banner"])

    assert result.exit_code == ExitCode.UPSTREAM_ERROR  # 5, a clean categorized exit
    assert "offline" in result.stdout.lower()
    # The OfflineError was handled (turned into typer.Exit), not left uncaught.
    assert not isinstance(result.exception, http_mod.OfflineError)


def test_offline_cold_cache_json_clean_error(offline_env: HTTPCache) -> None:
    """The JSON path emits a categorized offline error object (no traceback)."""
    result = runner.invoke(
        app, ["--offline", "--format", "json", "lookup", "CVE-2021-44228"]
    )
    assert result.exit_code == ExitCode.UPSTREAM_ERROR
    payload = json.loads(result.stdout)
    assert payload["category"] == "offline"
    assert not isinstance(result.exception, http_mod.OfflineError)
