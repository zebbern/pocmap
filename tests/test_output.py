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
    # Pin the render width so the CLI console and the baseline console agree.
    monkeypatch.setenv("COLUMNS", "200")

    baseline_console = Console(width=200, file=io.StringIO())
    baseline_console.print(format_cve_table(FIXTURE))
    baseline_table = baseline_console.file.getvalue()

    result = runner.invoke(app, ["lookup", "CVE-2021-44228", "--no-banner"])
    assert result.exit_code == ExitCode.OK

    # Known cells are present (table actually rendered).
    for token in ("CVE-2021-44228", "CRITICAL", "10.0", "97.53%", "Apache", "Log4j", "CWE-502"):
        assert token in result.stdout, f"expected {token!r} in table output"

    # The CVE table block is byte-identical to the standalone formatter render
    # (guards against accidental drift in the table output).
    assert _normalize(baseline_table) in _normalize(result.stdout)


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
