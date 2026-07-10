"""End-to-end offline pytest: ``--offline`` must surface distinctly, not as empty.

Two honest gaps closed by the surrounding change are locked in here:

  * **GAP 1 — POLICY_FAIL (6).** ``bulk --fail-on`` exits the dedicated
    :attr:`ExitCode.POLICY_FAIL` (6) when the gate trips, and ``0`` when it does
    not — so CI can tell a *policy match* apart from an operational failure.

  * **GAP 2 — offline propagates end-to-end.** With offline mode on and a COLD
    cache, the real service objects raise :class:`OfflineError` from the very
    first fetch. That error must reach the CLI and produce a clean
    :attr:`ExitCode.UPSTREAM_ERROR` (5) with the offline hint — NEVER a silent
    exit 3 "not found" / exit 2 "no results", and never an uncaught traceback.
    Previously the services'/clients' broad ``except HTTPError``/``except
    Exception`` blocks swallowed it (``OfflineError`` subclasses ``HTTPError``)
    and degraded the source to empty/None.

These exercise the REAL ``CVEService``/``RecentService``/``ProductDiscoveryService``/
``LabService``/``ReportService`` objects. Only the cache (made cold + temp) and
the transport (``HTTPClient.get`` patched to fail loudly) are stubbed, so a fetch
*would* occur but there is nothing cached — and no socket is ever opened.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import pocmap.utils.http as http_mod
from pocmap.cli import app
from pocmap.config import enable_offline, settings
from pocmap.models import (
    CVEInfo,
    CVSSScore,
    CVSSVersion,
    MultiReport,
    ReportEntry,
    Severity,
)
from pocmap.services.report_service import ReportService
from pocmap.utils.cache import HTTPCache
from pocmap.utils.exit_codes import ExitCode
from pocmap.utils.http import OfflineError

runner = CliRunner()

_BIG_CAP = 200 * 1024 * 1024
_CVE = "CVE-2021-44228"


# ---------------------------------------------------------------------------
# Fixture: offline mode ON + a cold temp cache + a transport that never fires
# ---------------------------------------------------------------------------


def _boom_get(self: Any, *args: Any, **kwargs: Any) -> Any:
    """A ``HTTPClient.get`` stand-in that fails the test if a real fetch occurs.

    Offline ``get_json``/``get_text`` raise :class:`OfflineError` on a cache miss
    *before* ever calling ``self.get``, so reaching this is a bug (a real socket
    would have been opened).
    """
    raise AssertionError("offline mode must not touch the network")


@pytest.fixture
def offline_cold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[HTTPCache]:
    """Enable process-wide offline mode against a COLD temp cache; restore after.

    Offline is switched on via :func:`config.enable_offline` (mutating the shared
    ``settings`` singleton that ``HTTPClient._is_offline`` reads at call time) and
    restored to its original value on teardown so no other test is affected.
    """
    cache = HTTPCache(cache_dir=tmp_path / "cache", ttl=3600, max_bytes=_BIG_CAP, enabled=True)
    monkeypatch.setattr(http_mod, "_cache", cache)
    # Safety net: if any code path bypasses the offline guard and tries a real
    # GET, fail loudly instead of hitting the network.
    monkeypatch.setattr(http_mod.HTTPClient, "get", _boom_get)

    original = settings.offline
    enable_offline(True)
    try:
        yield cache
    finally:
        enable_offline(original)


# ---------------------------------------------------------------------------
# Builders (self-contained) for the --fail-on gate tests
# ---------------------------------------------------------------------------


def _cve(cve_id: str, *, kev: bool = False, epss: float | None = 42.0) -> CVEInfo:
    return CVEInfo(
        id=cve_id,
        description=f"{cve_id} description",
        cvss=CVSSScore(version=CVSSVersion.V3_1, base_score=9.8, severity=Severity.CRITICAL),
        epss=epss,
        kev_status=kev,
        vendor="Acme",
        product="Widget",
    )


def _multi(cves: list[CVEInfo]) -> MultiReport:
    return MultiReport(entries={c.id: ReportEntry(cve_info=c, exploits=[]) for c in cves})


# ---------------------------------------------------------------------------
# GAP 2 — offline cold cache surfaces distinctly (UPSTREAM_ERROR, not 3/2)
# ---------------------------------------------------------------------------


def _assert_clean_offline(result: Any) -> None:
    """A command's offline outcome: exit 5, hint shown, no uncaught OfflineError."""
    assert result.exit_code == ExitCode.UPSTREAM_ERROR, result.stdout
    # NOT mistaken for "not found" (3) or "no results" (2).
    assert result.exit_code != ExitCode.NOT_FOUND
    assert result.exit_code != ExitCode.NO_RESULTS
    assert "offline" in result.stdout.lower()
    # The OfflineError was handled (turned into typer.Exit), never left uncaught.
    assert not isinstance(result.exception, OfflineError)


def test_lookup_offline_cold_cache_is_upstream_error(offline_cold: HTTPCache) -> None:
    """``lookup`` on a cold offline cache -> exit 5, not exit 3 "not found"."""
    result = runner.invoke(app, ["--offline", "lookup", _CVE, "--no-banner"])
    _assert_clean_offline(result)


def test_latest_offline_cold_cache_is_upstream_error(offline_cold: HTTPCache) -> None:
    """``latest`` on a cold offline cache -> exit 5, not exit 2 "no results"."""
    result = runner.invoke(app, ["--offline", "latest", "--since", "24h"])
    _assert_clean_offline(result)


def test_discover_offline_cold_cache_is_upstream_error(offline_cold: HTTPCache) -> None:
    """``discover`` on a cold offline cache -> exit 5, not exit 2/1."""
    result = runner.invoke(app, ["--offline", "discover", "Apache Struts", "--version", "2.x"])
    _assert_clean_offline(result)


def test_labs_offline_cold_cache_is_upstream_error(offline_cold: HTTPCache) -> None:
    """``labs`` on a cold offline cache -> exit 5, not exit 2 "no labs found"."""
    result = runner.invoke(app, ["--offline", "labs", _CVE])
    _assert_clean_offline(result)


def test_bulk_offline_cold_cache_is_upstream_error(offline_cold: HTTPCache) -> None:
    """``bulk`` (real ReportService) on a cold offline cache -> exit 5, not "no entries".

    Proves ``ReportService.generate_bulk_report`` re-raises ``OfflineError`` instead
    of skipping every CVE (which would have looked like an empty report).
    """
    result = runner.invoke(app, ["--offline", "bulk", "-"], input=f"{_CVE}\n")
    _assert_clean_offline(result)


def test_offline_json_mode_emits_offline_category(offline_cold: HTTPCache) -> None:
    """The JSON path emits a categorized offline error object (no traceback)."""
    result = runner.invoke(app, ["--offline", "--format", "json", "latest", "--since", "24h"])
    assert result.exit_code == ExitCode.UPSTREAM_ERROR, result.stdout
    payload = json.loads(result.stdout)
    assert payload["category"] == "offline"
    assert payload["error_type"] == "OfflineError"
    assert not isinstance(result.exception, OfflineError)


def test_offline_cold_cache_opened_no_socket(offline_cold: HTTPCache) -> None:
    """Belt-and-braces: the offline path never falls through to ``HTTPClient.get``.

    The fixture patches ``get`` to raise ``AssertionError``; a clean exit 5 (rather
    than an AssertionError leaking out) proves the transport was never invoked.
    """
    result = runner.invoke(app, ["--offline", "lookup", _CVE, "--no-banner"])
    assert result.exit_code == ExitCode.UPSTREAM_ERROR
    assert not isinstance(result.exception, AssertionError)


# ---------------------------------------------------------------------------
# GAP 1 — bulk --fail-on trips POLICY_FAIL (6), passes with OK (0)
# ---------------------------------------------------------------------------


def test_bulk_fail_on_match_exits_policy_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A KEV CVE trips ``--fail-on kev`` -> the dedicated exit 6 (POLICY_FAIL)."""
    monkeypatch.setattr(
        ReportService,
        "generate_bulk_report",
        lambda self, ids: _multi([_cve("CVE-2021-44228", kev=True)]),
    )
    result = runner.invoke(
        app, ["bulk", "-", "--format", "json", "--fail-on", "kev"], input="x\n"
    )
    assert result.exit_code == ExitCode.POLICY_FAIL  # 6, distinct from ERROR (1)
    assert result.exit_code != ExitCode.ERROR
    # stdout stays parseable JSON even though the gate tripped.
    assert json.loads(result.stdout)["total"] == 1


def test_bulk_fail_on_no_match_exits_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """No KEV CVE -> ``--fail-on kev`` passes the gate -> exit 0 (unchanged)."""
    monkeypatch.setattr(
        ReportService,
        "generate_bulk_report",
        lambda self, ids: _multi([_cve("CVE-2021-44228", kev=False)]),
    )
    result = runner.invoke(
        app, ["bulk", "-", "--format", "json", "--fail-on", "kev"], input="x\n"
    )
    assert result.exit_code == ExitCode.OK  # 0


def test_bulk_no_fail_on_flag_exits_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without ``--fail-on`` a KEV CVE is reported but the gate never trips (exit 0)."""
    monkeypatch.setattr(
        ReportService,
        "generate_bulk_report",
        lambda self, ids: _multi([_cve("CVE-2021-44228", kev=True)]),
    )
    result = runner.invoke(app, ["bulk", "-", "--format", "json"], input="x\n")
    assert result.exit_code == ExitCode.OK
