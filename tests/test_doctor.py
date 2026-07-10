"""Native pytest tests for the DOCTOR item: ``doctor`` + ``cache`` commands.

Everything here is fully offline. The only part of ``pocmap doctor`` that
touches the network is the upstream connectivity probe (``_probe_upstreams``,
flagged ``[needs-user/network]``); every test injects a *fake* prober in its
place (or uses ``--offline`` to skip it), so no network or DNS call is made.

Coverage:
  * ``doctor`` with an all-green injected prober exits 0.
  * A prober reporting an unreachable upstream -> FAIL -> nonzero
    (``UPSTREAM_ERROR``) exit.
  * A malformed ``GITHUB_API_TOKEN`` is flagged FAIL and the token value never
    appears anywhere in the output.
  * ``doctor --format json`` emits valid JSON carrying a per-check status list.
  * ``--offline`` skips the live probe (prober never called) and labels it
    SKIPPED.
  * ``cache info`` on a seeded temp cache reports the correct entry count/bytes.
  * ``cache clear`` empties the cache.
  * Unit tests for the token/key format validators and the exit-code mapping.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import pocmap.cli as cli
from pocmap.cli import (
    CheckResult,
    _doctor_exit_code,
    _gather_doctor_checks,
    app,
)
from pocmap.config import (
    Settings,
    github_token_looks_valid,
    nvd_api_key_looks_valid,
)
from pocmap.utils.cache import HTTPCache
from pocmap.utils.exit_codes import ExitCode

runner = CliRunner()

_BIG_CAP = 200 * 1024 * 1024
_SECRET_TOKEN = "totally-bogus-token-value-1234567890"


def _all_ok_prober() -> list[tuple[str, bool, str]]:
    """A fake prober where every upstream is reachable."""
    return [("NVD", True, "HTTP 200"), ("GitHub API", True, "HTTP 200")]


def _one_down_prober() -> list[tuple[str, bool, str]]:
    """A fake prober where one upstream is unreachable."""
    return [("NVD", True, "HTTP 200"), ("GitHub API", False, "HTTPError")]


@pytest.fixture
def clean_settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    """Rebind ``cli.settings`` to a token-less Settings so token checks WARN.

    Rebinds the module-level name (the frozen singleton itself cannot be
    mutated), which is exactly what ``doctor`` reads for the token/cache checks.
    """
    fresh = Settings()
    monkeypatch.setattr(cli, "settings", fresh)
    return fresh


@pytest.fixture
def temp_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HTTPCache:
    """A temp-dir-backed cache wired in as ``HTTPCache.from_settings()``."""
    cache = HTTPCache(cache_dir=tmp_path, ttl=3600, max_bytes=_BIG_CAP, enabled=True)
    monkeypatch.setattr(HTTPCache, "from_settings", classmethod(lambda cls: cache))
    return cache


# ---------------------------------------------------------------------------
# doctor — exit codes
# ---------------------------------------------------------------------------

def test_doctor_all_green_exits_ok(
    clean_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "_probe_upstreams", _all_ok_prober)
    result = runner.invoke(app, ["doctor", "--quiet"])
    assert result.exit_code == ExitCode.OK
    # The table actually rendered with passing checks and no leaked banner.
    assert "PASS" in result.stdout
    assert "AI-Enhanced Edition" not in result.stdout


def test_doctor_unreachable_upstream_exits_upstream_error(
    clean_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "_probe_upstreams", _one_down_prober)
    result = runner.invoke(app, ["doctor", "--quiet"])
    assert result.exit_code != ExitCode.OK
    assert result.exit_code == ExitCode.UPSTREAM_ERROR  # 5


def test_doctor_malformed_github_token_fails_without_leaking_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "settings", Settings(github_api_token=_SECRET_TOKEN))
    monkeypatch.setattr(cli, "_probe_upstreams", _all_ok_prober)

    result = runner.invoke(app, ["doctor", "--format", "json"])

    # Malformed credential is a hard failure (non-connectivity -> generic ERROR).
    assert result.exit_code == ExitCode.ERROR  # 1
    # The token value must never be echoed, in any format.
    assert _SECRET_TOKEN not in result.stdout

    data = json.loads(result.stdout)
    gh = next(c for c in data["checks"] if c["name"] == "GitHub API token")
    assert gh["status"] == "FAIL"
    assert _SECRET_TOKEN not in gh["detail"]


# ---------------------------------------------------------------------------
# doctor --format json
# ---------------------------------------------------------------------------

def test_doctor_json_has_per_check_status_list(
    clean_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "_probe_upstreams", _all_ok_prober)
    result = runner.invoke(app, ["doctor", "--format", "json"])
    assert result.exit_code == ExitCode.OK

    data = json.loads(result.stdout)
    assert data["ok"] is True
    assert isinstance(data["checks"], list) and data["checks"]
    valid = {"PASS", "WARN", "FAIL", "SKIPPED"}
    for check in data["checks"]:
        assert set(check) >= {"name", "status", "detail", "category"}
        assert check["status"] in valid
    # Summary counts are present and internally consistent.
    assert data["summary"]["fail"] == 0
    assert sum(data["summary"].values()) == len(data["checks"])


def test_doctor_offline_skips_probe(
    clean_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _must_not_run() -> list[tuple[str, bool, str]]:
        raise AssertionError("the live prober must not run under --offline")

    monkeypatch.setattr(cli, "_probe_upstreams", _must_not_run)
    result = runner.invoke(app, ["doctor", "--offline", "--format", "json"])

    assert result.exit_code == ExitCode.OK
    data = json.loads(result.stdout)
    conn = [c for c in data["checks"] if c["category"] == "connectivity"]
    assert len(conn) == 1
    assert conn[0]["status"] == "SKIPPED"


# ---------------------------------------------------------------------------
# cache info / clear
# ---------------------------------------------------------------------------

def test_cache_info_reports_entries_and_bytes(temp_cache: HTTPCache) -> None:
    temp_cache.set("k1", "hello-body")
    temp_cache.set("k2", "another-body")
    expected = temp_cache.info()
    assert expected["entries"] == 2

    result = runner.invoke(app, ["cache", "info", "--format", "json"])
    assert result.exit_code == ExitCode.OK

    data = json.loads(result.stdout)
    assert data["entries"] == 2
    assert data["bytes"] == expected["bytes"]
    assert data["bytes"] > 0


def test_cache_info_table_mode_renders(temp_cache: HTTPCache) -> None:
    temp_cache.set("k1", "hello-body")
    result = runner.invoke(app, ["cache", "info"])
    assert result.exit_code == ExitCode.OK
    assert "Entries" in result.stdout
    assert "1" in result.stdout


def test_cache_clear_empties_cache(temp_cache: HTTPCache) -> None:
    temp_cache.set("k1", "a")
    temp_cache.set("k2", "b")
    assert temp_cache.info()["entries"] == 2

    result = runner.invoke(app, ["cache", "clear", "--format", "json"])
    assert result.exit_code == ExitCode.OK

    data = json.loads(result.stdout)
    assert data["cleared_entries"] == 2
    assert data["remaining_entries"] == 0
    # The on-disk cache is genuinely empty afterwards.
    assert temp_cache.info()["entries"] == 0


# ---------------------------------------------------------------------------
# --help surface (doctor + cache visible)
# ---------------------------------------------------------------------------

def test_help_lists_doctor_and_cache() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "doctor" in result.stdout
    assert "cache" in result.stdout


# ---------------------------------------------------------------------------
# Unit: check gatherer + exit-code mapping (no CLI, no network)
# ---------------------------------------------------------------------------

def test_gather_offline_marks_connectivity_skipped(clean_settings: Settings) -> None:
    def _boom() -> list[tuple[str, bool, str]]:
        raise AssertionError("prober should be skipped offline")

    checks = _gather_doctor_checks(offline=True, prober=_boom)
    conn = [c for c in checks if c.category == "connectivity"]
    assert len(conn) == 1 and conn[0].status == "SKIPPED"
    assert _doctor_exit_code(checks) == ExitCode.OK


def test_exit_code_connectivity_fail_is_upstream_error() -> None:
    checks = [
        CheckResult("Python version", "PASS", "3.12", "python"),
        CheckResult("Connectivity: NVD", "FAIL", "unreachable", "connectivity"),
    ]
    assert _doctor_exit_code(checks) == ExitCode.UPSTREAM_ERROR


def test_exit_code_token_fail_is_generic_error() -> None:
    checks = [
        CheckResult("GitHub API token", "FAIL", "malformed", "token"),
        CheckResult("Connectivity: NVD", "FAIL", "unreachable", "connectivity"),
    ]
    # A non-connectivity FAIL present -> generic ERROR, not UPSTREAM_ERROR.
    assert _doctor_exit_code(checks) == ExitCode.ERROR


def test_exit_code_no_fail_is_ok() -> None:
    checks = [
        CheckResult("Python version", "PASS", "3.12", "python"),
        CheckResult("GitHub API token", "WARN", "not set", "token"),
    ]
    assert _doctor_exit_code(checks) == ExitCode.OK


# ---------------------------------------------------------------------------
# Unit: credential format validators
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "token",
    [
        "ghp_" + "a" * 36,
        "github_pat_" + "A1b2" * 8,
        "f" * 40,  # legacy 40-char hex OAuth token
        "gho_" + "Z" * 36,
    ],
)
def test_github_token_valid_shapes(token: str) -> None:
    assert github_token_looks_valid(token) is True


@pytest.mark.parametrize(
    "token",
    ["", "not-a-token", "ghp_short", "1234567890", "ghp_" + "a" * 10],
)
def test_github_token_invalid_shapes(token: str) -> None:
    assert github_token_looks_valid(token) is False


def test_nvd_key_valid_and_invalid() -> None:
    assert nvd_api_key_looks_valid("12345678-1234-1234-1234-123456789abc") is True
    assert nvd_api_key_looks_valid("not-a-uuid") is False
    assert nvd_api_key_looks_valid("") is False
