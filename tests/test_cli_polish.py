"""Native pytest tests for the CLI polish pass (COMPLETION + PAGER-FIX), offline.

Covers two Phase-3 roadmap items, both fully offline via :class:`CliRunner`:

  * ``COMPLETION`` — Typer shell completion is enabled (``add_completion=True``),
    so ``--show-completion`` emits a non-empty script and the app still boots
    with all 13 commands and its global callback options intact.
  * ``PAGER-FIX`` — ``readme`` pages through the portable ``click.echo_via_pager``
    on every platform (Windows included) with a plain-write fallback on a
    non-TTY stream, and never shells out to ``less``. The URL guard and the
    empty-README message are preserved.

No network or subprocess is ever touched: ``ExploitService.get_readme`` is
monkeypatched and ``subprocess.run`` is stubbed with an assert-not-called spy.
"""

from __future__ import annotations

import re
import subprocess
from typing import Any

import pytest
import requests
from typer.testing import CliRunner

from pocmap.cli import app
from pocmap.config import settings
from pocmap.services.exploit_service import ExploitService
from pocmap.services.product_service import ProductDiscoveryService
from pocmap.utils.exit_codes import ExitCode
from pocmap.utils.http import OfflineError

runner = CliRunner()

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


@pytest.fixture(autouse=True)
def _restore_offline() -> Any:
    """Restore the process-wide ``settings.offline`` after any test flips it.

    The CLI ``--offline`` flag calls ``config.enable_offline()``, which mutates the
    global ``settings`` singleton in place. Without this autouse guard a test that
    invokes ``--offline`` (the readme/doctor cases below) leaks ``offline=True`` into
    later test files such as ``test_offline.py``. Mirrors the guard in
    ``test_cli_features.py``.
    """
    original = settings.offline
    yield
    object.__setattr__(settings, "offline", original)


def _help_text(*argv: str) -> str:
    """Render help WIDE and ANSI-stripped.

    Rich renders Typer's help into a bordered panel whose width defaults to
    ~80 cols on a non-TTY (CI). At that width it wraps long option names like
    ``--install-completion`` across lines, so a naive substring check fails on
    CI while passing on a wide local terminal. Forcing ``COLUMNS`` wide + no
    color makes the assertions deterministic.
    """
    result = runner.invoke(
        app, list(argv), env={"COLUMNS": "400", "NO_COLOR": "1", "TERM": "dumb"}
    )
    assert result.exit_code == 0, result.output
    return _ANSI_RE.sub("", result.output)

# Every command that must appear in ``pocmap --help`` (12 @app.command() plus the
# ``cache`` sub-Typer) — the roadmap's "13 commands" contract.
EXPECTED_COMMANDS = [
    "lookup",
    "bulk",
    "labs",
    "bugbounty",
    "cpes",
    "cpe2cve",
    "readme",
    "schemas",
    "latest",
    "package",
    "discover",
    "doctor",
    "cache",
]

README_URL = "https://github.com/example/poc"
README_BODY = "# Example PoC\n\nProof-of-concept exploit for CVE-2021-44228.\n"


# ---------------------------------------------------------------------------
# COMPLETION — shell completion is enabled
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("argv", [["--show-completion"], ["--show-completion", "bash"]])
def test_show_completion_emits_script(argv: list[str]) -> None:
    """``--show-completion`` (default and explicit shell) prints a non-empty script."""
    result = runner.invoke(app, argv)
    assert result.exit_code == 0, result.output
    assert result.output.strip(), "expected a non-empty completion script"


def test_install_completion_option_exists() -> None:
    """Enabling completion exposes ``--install-completion`` on the root help."""
    text = _help_text("--help")
    assert "--install-completion" in text
    assert "--show-completion" in text


# ---------------------------------------------------------------------------
# App still boots: 13 commands + global callback options intact
# ---------------------------------------------------------------------------


def test_help_lists_all_thirteen_commands() -> None:
    text = _help_text("--help")
    for command in EXPECTED_COMMANDS:
        assert command in text, f"missing command in --help: {command}"


def test_global_callback_options_intact() -> None:
    """The global ``--format`` / ``--quiet`` / ``--offline`` options survive."""
    text = _help_text("--help")
    for option in ("--format", "--quiet", "--offline"):
        assert option in text, f"missing global option: {option}"


# ---------------------------------------------------------------------------
# PAGER-FIX — portable paging, no `less` subprocess, guards preserved
# ---------------------------------------------------------------------------


@pytest.fixture
def no_subprocess(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Stub ``subprocess.run`` with a spy so any shell-out fails the test.

    Returns the (expected-empty) call log so a test can assert on it directly.
    """
    calls: list[object] = []

    def _spy(*args: object, **kwargs: object) -> None:
        calls.append((args, kwargs))

    monkeypatch.setattr(subprocess, "run", _spy)
    return calls


def test_readme_renders_content_without_pager_subprocess(
    monkeypatch: pytest.MonkeyPatch, no_subprocess: list[object]
) -> None:
    """A found README reaches stdout via the portable pager, never via ``less``."""
    monkeypatch.setattr(ExploitService, "get_readme", lambda self, repo: README_BODY)

    result = runner.invoke(app, ["readme", README_URL])

    assert result.exit_code == 0, result.output
    assert "Example PoC" in result.output
    assert "CVE-2021-44228" in result.output
    # No `less` (or any) subprocess was spawned on any platform.
    assert no_subprocess == []


def test_readme_quiet_prints_plainly(
    monkeypatch: pytest.MonkeyPatch, no_subprocess: list[object]
) -> None:
    """``--quiet`` bypasses the pager and prints the README directly."""
    monkeypatch.setattr(ExploitService, "get_readme", lambda self, repo: README_BODY)

    result = runner.invoke(app, ["readme", README_URL, "--quiet"])

    assert result.exit_code == 0, result.output
    assert "Example PoC" in result.output
    assert no_subprocess == []


def test_readme_non_github_url_errors(no_subprocess: list[object]) -> None:
    """A non-GitHub URL is malformed caller input -> INVALID_INPUT (4), no subprocess."""
    result = runner.invoke(app, ["readme", "https://evil.example.com/x"])
    assert result.exit_code == ExitCode.INVALID_INPUT
    assert "valid GitHub repository URL" in result.output
    assert no_subprocess == []


def test_readme_empty_reports_not_found(
    monkeypatch: pytest.MonkeyPatch, no_subprocess: list[object]
) -> None:
    """An empty README is NO_RESULTS (2), not a false success, and no pager subprocess."""
    monkeypatch.setattr(ExploitService, "get_readme", lambda self, repo: "")

    result = runner.invoke(app, ["readme", README_URL])

    assert result.exit_code == ExitCode.NO_RESULTS
    assert "README.md not found" in result.output
    assert no_subprocess == []


def test_readme_offline_cache_miss_exits_upstream(
    monkeypatch: pytest.MonkeyPatch, no_subprocess: list[object]
) -> None:
    """An offline cache miss surfaces cleanly as UPSTREAM_ERROR (5), no traceback."""

    def _raise(self: ExploitService, repo: str) -> str:
        raise OfflineError("no cached data for this query")

    monkeypatch.setattr(ExploitService, "get_readme", _raise)

    result = runner.invoke(app, ["--offline", "readme", README_URL])

    assert result.exit_code == ExitCode.UPSTREAM_ERROR
    # A clean typer.Exit, not an uncaught OfflineError bubbling to a traceback.
    assert not isinstance(result.exception, OfflineError)
    assert "Offline" in result.output
    assert no_subprocess == []


# ---------------------------------------------------------------------------
# EXIT-CODE CONTRACT — format rejection + discover upstream failure
# ---------------------------------------------------------------------------


def test_discover_upstream_error_exits_five(monkeypatch: pytest.MonkeyPatch) -> None:
    """A network/5xx failure in ``discover`` maps to UPSTREAM_ERROR (5), like ``latest``."""

    def _raise(self: ProductDiscoveryService, **kwargs: object) -> object:
        raise requests.HTTPError("503 Server Error")

    monkeypatch.setattr(ProductDiscoveryService, "discover_by_product", _raise)

    result = runner.invoke(app, ["discover", "Apache Struts"])

    assert result.exit_code == ExitCode.UPSTREAM_ERROR


def test_discover_blank_product_exits_invalid_input() -> None:
    """A whitespace product is malformed caller input -> INVALID_INPUT (4).

    ``ProductDiscoveryService.discover_by_product`` raises a plain ``ValueError``
    for an empty/whitespace product *before* any network I/O, so this stays
    offline and must map to exit 4, not UPSTREAM_ERROR (5).
    """
    result = runner.invoke(app, ["discover", "   "])

    assert result.exit_code == ExitCode.INVALID_INPUT


@pytest.mark.parametrize(
    "argv",
    [
        ["doctor", "--offline", "--format", "sarif"],
        ["doctor", "--format", "csv"],
        ["cache", "info", "--format", "sarif"],
    ],
)
def test_table_json_only_commands_reject_other_formats(argv: list[str]) -> None:
    """``doctor``/``cache info`` reject csv/md/sarif with INVALID_INPUT (4)."""
    result = runner.invoke(app, argv)
    assert result.exit_code == ExitCode.INVALID_INPUT
    assert "only table and json" in result.output


if __name__ == "__main__":  # pragma: no cover - convenience direct runner
    raise SystemExit(pytest.main([__file__, "-q"]))


# ---------------------------------------------------------------------------
# EPSS display never rounds across an endpoint
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        (None, "-"),
        (0.0, "0.0"),        # genuine zero stays zero
        (0.004, "<0.1"),     # nonzero must not read as "will not be exploited"
        (0.04, "<0.1"),
        (0.05, "0.1"),
        (12.34, "12.3"),
        (97.53, "97.5"),
        (99.9, "99.9"),
        (99.96, "99.9"),     # the real bug: EPSS 99.96 is not certainty
        (99.999, "99.9"),
        (100.0, "100.0"),    # a genuine 100 is still allowed to say 100
    ],
)
def test_fmt_epss_never_rounds_across_an_endpoint(value: float | None, expected: str) -> None:
    """Rounding 99.99 to "100.0" claims certainty EPSS never expressed.

    EPSS tops out at 0.99999 (=99.999 on the 0-100 scale), so a printed
    "100.0" that came from rounding is always a lie about the model's output.
    """
    from pocmap.cli import _fmt_epss

    assert _fmt_epss(value) == expected
