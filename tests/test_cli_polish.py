"""Native pytest tests for the CLI polish pass (COMPLETION + PAGER-FIX), offline.

Covers two Phase-3 roadmap items, both fully offline via :class:`CliRunner`:

  * ``COMPLETION`` — Typer shell completion is enabled (``add_completion=True``),
    so ``--show-completion`` emits a non-empty script and the app still boots
    with all 12 commands and its global callback options intact.
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

import pytest
from typer.testing import CliRunner

from pocmap.cli import app
from pocmap.services.exploit_service import ExploitService

runner = CliRunner()

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


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

# Every command that must appear in ``pocmap --help`` (11 @app.command() plus the
# ``cache`` sub-Typer) — the roadmap's "12 commands" contract.
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
# App still boots: 12 commands + global callback options intact
# ---------------------------------------------------------------------------


def test_help_lists_all_twelve_commands() -> None:
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
    """A non-GitHub URL is rejected before any fetch, exit 1, no subprocess."""
    result = runner.invoke(app, ["readme", "https://evil.example.com/x"])
    assert result.exit_code == 1
    assert "valid GitHub repository URL" in result.output
    assert no_subprocess == []


def test_readme_empty_reports_not_found(
    monkeypatch: pytest.MonkeyPatch, no_subprocess: list[object]
) -> None:
    """An empty README yields the 'not found' message (and no pager subprocess)."""
    monkeypatch.setattr(ExploitService, "get_readme", lambda self, repo: "")

    result = runner.invoke(app, ["readme", README_URL])

    assert result.exit_code == 0, result.output
    assert "README.md not found" in result.output
    assert no_subprocess == []


if __name__ == "__main__":  # pragma: no cover - convenience direct runner
    raise SystemExit(pytest.main([__file__, "-q"]))
