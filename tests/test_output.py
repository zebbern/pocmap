"""Native pytest tests for the RENDER-LAYER output abstraction (offline).

Covers:
  * ``utils/output.render`` for both ``json`` and ``table`` formats.
  * The ``lookup`` command as the reference implementation of the layer:
      - ``--format json`` emits a parseable JSON view-model to stdout;
      - default (table) output still renders and is byte-stable vs a baseline
        produced directly by the existing ``format_cve_table`` formatter;
      - ``--quiet --format json`` prints ONLY JSON (no banner);
      - exit codes: invalid CVE id -> 4, mocked not-found -> 3, success -> 0.

Everything is fully offline: the CVE/exploit/lab service methods are
monkeypatched, so no network or DNS call is ever made.
"""

from __future__ import annotations

import io
import json
from datetime import datetime

import pytest
from rich.console import Console
from typer.testing import CliRunner

from pocmap.cli import app
from pocmap.models import CVEInfo, CVEState, CVSSScore, CVSSVersion, Severity
from pocmap.services.cve_service import CVEService
from pocmap.services.exploit_service import ExploitService
from pocmap.services.lab_service import LabService
from pocmap.utils.exit_codes import ExitCode
from pocmap.utils.formatters import format_cve_table
from pocmap.utils.http import NotFoundError
from pocmap.utils.output import OutputFormat, render

runner = CliRunner()

# A fully-populated, deterministic CVE used across the CLI tests.
FIXTURE = CVEInfo(
    id="CVE-2021-44228",
    description="Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP.",
    cvss=CVSSScore(
        version=CVSSVersion.V3_1,
        base_score=10.0,
        severity=Severity.CRITICAL,
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    ),
    epss=97.53,
    kev_status=True,
    cwes=["CWE-502", "CWE-917"],
    vendor="Apache",
    product="Log4j",
    publication_date="10 Dec 2021",
    state=CVEState.PUBLISHED,
)


def _normalize(text: str) -> str:
    """Collapse trailing per-line whitespace so width-padding doesn't matter."""
    return "\n".join(line.rstrip() for line in text.strip().splitlines())


@pytest.fixture
def stub_exploits_and_labs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutralize the exploit/lab network calls used by ``lookup``."""
    monkeypatch.setattr(
        ExploitService, "find_github_pocs", lambda self, cve, limit=None: []
    )
    monkeypatch.setattr(ExploitService, "find_db_exploits", lambda self, cve: [])
    monkeypatch.setattr(LabService, "find_labs", lambda self, cve: [])


@pytest.fixture
def stub_cve_ok(monkeypatch: pytest.MonkeyPatch, stub_exploits_and_labs: None) -> None:
    """A successful CVE lookup that returns the fixture with no network."""
    monkeypatch.setattr(CVEService, "get_cve_info", lambda self, cve: FIXTURE)


# ---------------------------------------------------------------------------
# render() unit tests — both formats
# ---------------------------------------------------------------------------

def test_render_json_emits_parseable_json() -> None:
    console = Console(file=io.StringIO(), width=80)
    render(
        {"id": "CVE-2021-44228", "score": 10.0, "when": datetime(2021, 12, 10)},
        OutputFormat.JSON,
        console=console,
    )
    parsed = json.loads(console.file.getvalue())
    assert parsed["id"] == "CVE-2021-44228"
    assert parsed["score"] == 10.0
    # default=str is applied to non-JSON-native objects (datetime).
    assert parsed["when"] == "2021-12-10 00:00:00"


def test_render_json_handles_list_view_model() -> None:
    console = Console(file=io.StringIO(), width=40)
    render([{"a": 1}, {"a": 2}], OutputFormat.JSON, console=console)
    assert json.loads(console.file.getvalue()) == [{"a": 1}, {"a": 2}]


def test_render_table_prints_renderable() -> None:
    console = Console(file=io.StringIO(), width=200)
    render(format_cve_table(FIXTURE), OutputFormat.TABLE, console=console)
    out = console.file.getvalue()
    assert "CVE-2021-44228" in out
    assert "CRITICAL" in out


def test_render_table_none_prints_nothing() -> None:
    console = Console(file=io.StringIO(), width=80)
    render(None, OutputFormat.TABLE, console=console)
    assert console.file.getvalue() == ""


# ---------------------------------------------------------------------------
# render() must not let Rich rewrite the payload
# ---------------------------------------------------------------------------

def test_render_json_does_not_substitute_emoji_shortcodes() -> None:
    """CPE strings survive verbatim (regression: ``:apple:`` -> apple emoji).

    Rich replaces ``:shortcode:`` sequences with emoji by default. CVE data is
    full of colon-delimited text that collides with real shortcodes, and the
    corrupted output is still *valid JSON* — so this asserts on the exact byte
    sequence rather than merely round-tripping through ``json.loads``.
    """
    cpe = "cpe:2.3:a:apple:xcode:*:*:*:*:*:*:*:*"
    # A default Console (emoji enabled) — render() itself must suppress it.
    console = Console(file=io.StringIO(), width=200)
    render({"cpes": [cpe], "note": "flagged :warning: and :x:"}, OutputFormat.JSON, console=console)

    raw = console.file.getvalue()
    assert cpe in raw
    assert ":warning:" in raw and ":x:" in raw
    assert json.loads(raw)["cpes"] == [cpe]


def test_cli_consoles_have_emoji_substitution_disabled() -> None:
    """The table path shares the same hazard as ``--format json``."""
    from pocmap.cli import console as cli_console
    from pocmap.cli import err_console

    for con in (cli_console, err_console):
        assert con.render_str("cpe:2.3:a:apple:xcode").plain == "cpe:2.3:a:apple:xcode"


# ---------------------------------------------------------------------------
# lookup --format json
# ---------------------------------------------------------------------------

def test_lookup_json_outputs_valid_json(stub_cve_ok: None) -> None:
    result = runner.invoke(app, ["lookup", "CVE-2021-44228", "--format", "json"])
    assert result.exit_code == ExitCode.OK
    data = json.loads(result.stdout)
    assert data["cve"]["id"] == "CVE-2021-44228"
    assert data["cve"]["cvss"]["severity"] == "CRITICAL"
    assert data["cve"]["epss"] == 97.53
    assert data["cve"]["kev_status"] is True
    # Envelope carries the discovery sections (empty here, but present).
    for key in ("github_pocs", "db_exploits", "labs"):
        assert key in data


def test_lookup_quiet_json_prints_only_json(stub_cve_ok: None) -> None:
    # Global-position flags (before the subcommand) exercise the callback path.
    result = runner.invoke(
        app, ["--quiet", "--format", "json", "lookup", "CVE-2021-44228"]
    )
    assert result.exit_code == ExitCode.OK
    # No decorative banner leaked into stdout.
    assert "AI-Enhanced Edition" not in result.stdout
    # The ENTIRE stdout parses as a single JSON document.
    data = json.loads(result.stdout)
    assert data["cve"]["id"] == "CVE-2021-44228"


# ---------------------------------------------------------------------------
# lookup default (table) — must stay byte-stable
# ---------------------------------------------------------------------------

def test_lookup_table_default_unchanged(
    stub_cve_ok: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Pin width for both the CLI ``rprint`` path and the baseline: CliRunner's
    # fake TTY is narrow, and ``rich.print`` does not use ``cli.console``.
    import pocmap.cli as cli_mod

    monkeypatch.setenv("COLUMNS", "200")
    wide = Console(width=200, emoji=False, force_terminal=True, record=True)
    monkeypatch.setattr(cli_mod, "rprint", wide.print)
    monkeypatch.setattr(cli_mod, "console", wide)

    baseline = Console(width=200, emoji=False, force_terminal=True, record=True)
    baseline.print(format_cve_table(FIXTURE))
    baseline_table = baseline.export_text()

    result = runner.invoke(
        app, ["lookup", "CVE-2021-44228", "--no-banner"], env={"COLUMNS": "200"}
    )
    assert result.exit_code == ExitCode.OK
    out = wide.export_text()

    # Known cells are present (table actually rendered). CWE cell may ellipsize
    # under some Rich versions; require the prefix at minimum.
    for token in ("CVE-2021-44228", "CRITICAL", "10.0", "97.53%", "Apache", "Log4j"):
        assert token in out, f"expected {token!r} in table output"
    assert "CWE-5" in out

    # The CVE table block matches the standalone formatter render
    # (guards against accidental drift in the table output).
    assert _normalize(baseline_table) in _normalize(out)


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

def test_lookup_invalid_cve_exits_invalid_input() -> None:
    # No mocking: real validation rejects the id before any network call.
    result = runner.invoke(app, ["lookup", "NOTACVE", "--no-banner"])
    assert result.exit_code == ExitCode.INVALID_INPUT  # 4


def test_lookup_not_found_exits_not_found(
    monkeypatch: pytest.MonkeyPatch, stub_exploits_and_labs: None
) -> None:
    def _raise_not_found(self: CVEService, cve: str) -> CVEInfo:
        raise NotFoundError(f"No CVE record found for {cve}")

    monkeypatch.setattr(CVEService, "get_cve_info", _raise_not_found)
    result = runner.invoke(app, ["lookup", "CVE-2021-40000", "--no-banner"])
    assert result.exit_code == ExitCode.NOT_FOUND  # 3


def test_lookup_json_invalid_exits_invalid_input() -> None:
    result = runner.invoke(app, ["--format", "json", "lookup", "NOTACVE"])
    assert result.exit_code == ExitCode.INVALID_INPUT  # 4
    data = json.loads(result.stdout)
    assert data["category"] == "invalid_input"
    assert data["error_type"] == "ValidationError"


def test_lookup_json_not_found_exits_not_found(
    monkeypatch: pytest.MonkeyPatch, stub_exploits_and_labs: None
) -> None:
    def _raise_not_found(self: CVEService, cve: str) -> CVEInfo:
        raise NotFoundError(f"No CVE record found for {cve}")

    monkeypatch.setattr(CVEService, "get_cve_info", _raise_not_found)
    result = runner.invoke(app, ["--format", "json", "lookup", "CVE-2021-40000"])
    assert result.exit_code == ExitCode.NOT_FOUND  # 3
    data = json.loads(result.stdout)
    assert data["category"] == "not_found"


# ---------------------------------------------------------------------------
# render_to_string — what --output writes
# ---------------------------------------------------------------------------

def test_render_to_string_matches_what_stdout_receives() -> None:
    """The saved file must be byte-identical to the piped stream.

    ``render_to_string`` originally referenced ``Console`` at runtime while the
    module only imports it under ``TYPE_CHECKING`` — mypy was happy and every
    test passed, but ``--output`` raised NameError for csv/md/sarif in the wild.
    Comparing against a real render is what catches that.
    """
    import io

    from rich.console import Console

    from pocmap.utils.output import OutputFormat, render, render_to_string

    rows = [
        {"id": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0, "epss": 99.99},
        {"id": "CVE-2019-11358", "severity": "MEDIUM", "cvss": 6.1, "epss": 3.0},
    ]
    for fmt in (OutputFormat.JSON, OutputFormat.CSV, OutputFormat.MARKDOWN):
        buf = io.StringIO()
        render(rows, fmt, console=Console(file=buf, width=10_000), title="T")
        assert render_to_string(rows, fmt, title="T") == buf.getvalue(), fmt


def test_render_to_string_produces_valid_sarif() -> None:
    """SARIF is the format --output was silently getting wrong."""
    import json

    from pocmap.utils.output import OutputFormat, render_to_string

    rows = [{"id": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0}]
    doc = json.loads(render_to_string(rows, OutputFormat.SARIF))

    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "CVE-2021-44228"


def test_render_to_string_emits_no_ansi_escapes() -> None:
    """A file full of terminal colour codes is not machine-readable."""
    from pocmap.utils.output import OutputFormat, render_to_string

    rows = [{"id": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0}]
    for fmt in (OutputFormat.JSON, OutputFormat.CSV, OutputFormat.MARKDOWN, OutputFormat.SARIF):
        assert "\x1b[" not in render_to_string(rows, fmt), fmt
