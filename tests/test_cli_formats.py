"""Native pytest tests for JSON-EVERYWHERE + CSV/MD/SARIF CLI wiring (offline).

Exercises the ``--format`` plumbing added to the read commands ``labs``,
``bugbounty``, ``cpes``, ``cpe2cve``, ``latest`` and ``discover``:

  * ``--format json`` -> the whole of stdout parses as a single JSON document;
  * ``--format csv``  -> stdout parses via :class:`csv.DictReader` with rows;
  * ``--format md``   -> stdout contains a GitHub-flavored Markdown table;
  * ``latest --format sarif`` -> a valid SARIF 2.1.0 log (CVE-list command);
  * a not-applicable ``sarif`` request (e.g. ``cpe2cve --format sarif``) exits
    ``INVALID_INPUT`` (4);
  * an empty result set exits ``NO_RESULTS`` (2);
  * the default (table) output stays byte-identical to the standalone formatter.

Everything is fully offline: each service *method* is monkeypatched (the service
objects themselves construct only in-memory HTTP clients), so no network or DNS
call is ever made. Mirrors the mocking style of ``tests/test_output.py``.
"""

from __future__ import annotations

import csv
import io
import json

import pytest
from rich.console import Console
from typer.testing import CliRunner

from pocmap.cli import app
from pocmap.models import (
    BugBountyReport,
    BugBountySource,
    CPEInfo,
    CVEInfo,
    CVEState,
    CVSSScore,
    CVSSVersion,
    ExploitSource,
    LabEnvironment,
    LabPlatform,
    ProductDiscoveryResult,
    RecentExploitResult,
    Severity,
    VersionConstraint,
)
from pocmap.services.bb_service import BugBountyService
from pocmap.services.cve_service import CVEService
from pocmap.services.lab_service import LabService
from pocmap.services.product_service import ProductDiscoveryService
from pocmap.services.recent_service import RecentService
from pocmap.utils.exit_codes import ExitCode
from pocmap.utils.formatters import format_bb_table

runner = CliRunner()

CVE = "CVE-2021-44228"


# ---------------------------------------------------------------------------
# Fixtures (deterministic in-memory model objects)
# ---------------------------------------------------------------------------

LABS = [
    LabEnvironment(
        platform=LabPlatform.VULHUB,
        name="log4j/CVE-2021-44228",
        url="https://github.com/vulhub/vulhub/tree/master/log4j/CVE-2021-44228",
        setup_instructions="docker compose up -d",
    ),
    LabEnvironment(
        platform=LabPlatform.TRYHACKME,
        name="Solar, exploiting log4j",
        url="https://tryhackme.com/room/solar",
    ),
]

REPORTS = [
    BugBountyReport(
        source=BugBountySource.HACKERONE,
        url="https://hackerone.com/reports/1",
        has_poc=True,
        title="Log4j RCE on Example Corp",
    ),
    BugBountyReport(
        source=BugBountySource.PENTESTERLAND,
        url="https://pentester.land/writeup",
        has_poc=False,
        title="Log4Shell writeup",
    ),
]

CPES = [
    CPEInfo.parse("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"),
    CPEInfo.parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"),
]

CVE_IDS = ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"]


def _cve(cid: str, *, severity: Severity, score: float, epss: float, kev: bool) -> CVEInfo:
    return CVEInfo(
        id=cid,
        description=f"{cid} test description",
        cvss=CVSSScore(
            version=CVSSVersion.V3_1,
            base_score=score,
            severity=severity,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        ),
        epss=epss,
        kev_status=kev,
        cwes=["CWE-502"],
        vendor="Apache",
        product="Log4j",
        publication_date="2021-12-10",
        state=CVEState.PUBLISHED,
    )


RECENT = [
    RecentExploitResult(
        cve_info=_cve(CVE, severity=Severity.CRITICAL, score=10.0, epss=97.53, kev=True),
        has_poc=True,
        poc_sources=[ExploitSource.GITHUB, ExploitSource.NUCLEI],
    ),
    RecentExploitResult(
        cve_info=_cve("CVE-2021-45046", severity=Severity.HIGH, score=9.0, epss=41.2, kev=True),
        has_poc=False,
        poc_sources=[],
    ),
]

DISCOVERY = ProductDiscoveryResult(
    query="Apache Log4j",
    normalized_vendor="apache",
    normalized_product="log4j",
    version_constraint=VersionConstraint(major=2, minor="x", raw="2.x", is_wildcard=True),
    total_found=2,
    confirmed_affected=[_cve(CVE, severity=Severity.CRITICAL, score=10.0, epss=97.53, kev=True)],
    possibly_affected=[_cve("CVE-2021-45046", severity=Severity.HIGH, score=9.0, epss=41.2, kev=True)],
    not_enough_data=[],
)


@pytest.fixture
def stub_services(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutralize every network-bound service method used by the read commands."""
    monkeypatch.setattr(LabService, "find_labs", lambda self, cve: list(LABS))
    monkeypatch.setattr(BugBountyService, "find_reports", lambda self, cve: list(REPORTS))
    monkeypatch.setattr(CVEService, "get_cpes", lambda self, cve: list(CPES))
    monkeypatch.setattr(CVEService, "cpe_to_cves", lambda self, cpe: list(CVE_IDS))
    monkeypatch.setattr(RecentService, "find_recent_cves", lambda self, **kw: list(RECENT))
    monkeypatch.setattr(
        ProductDiscoveryService, "discover_by_product", lambda self, **kw: DISCOVERY
    )


# Each entry: (argv-prefix, key that must exist in the JSON view model).
_COMMANDS = [
    (["labs", CVE], "labs"),
    (["bugbounty", CVE], "reports"),
    (["cpes", CVE], "cpes"),
    (["cpe2cve", "cpe:2.3:a:apache:log4j:2.0"], "cve_ids"),
    (["latest"], "cves"),
    (["discover", "Apache Log4j"], "confirmed_affected"),
]


# ---------------------------------------------------------------------------
# --format json  ->  stdout parses as a single JSON document
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("argv, json_key", _COMMANDS)
def test_json_output_parses(stub_services: None, argv: list[str], json_key: str) -> None:
    result = runner.invoke(app, [*argv, "--format", "json"])
    assert result.exit_code == ExitCode.OK, result.stdout
    data = json.loads(result.stdout)
    assert isinstance(data, dict)
    assert json_key in data


# ---------------------------------------------------------------------------
# --format csv  ->  stdout parses via csv.DictReader with rows
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("argv, _json_key", _COMMANDS)
def test_csv_output_parses(stub_services: None, argv: list[str], _json_key: str) -> None:
    result = runner.invoke(app, [*argv, "--format", "csv"])
    assert result.exit_code == ExitCode.OK, result.stdout
    reader = csv.DictReader(io.StringIO(result.stdout))
    assert reader.fieldnames  # a real header row was emitted
    rows = list(reader)
    assert rows, "expected at least one CSV data row"


# ---------------------------------------------------------------------------
# --format md  ->  stdout contains a GitHub-flavored Markdown table
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("argv, _json_key", _COMMANDS)
def test_markdown_output_has_table(stub_services: None, argv: list[str], _json_key: str) -> None:
    result = runner.invoke(app, [*argv, "--format", "md"])
    assert result.exit_code == ExitCode.OK, result.stdout
    out = result.stdout
    # A GFM table has a header row and a `---` separator row.
    assert "| " in out
    assert "---" in out
    header_line = next(ln for ln in out.splitlines() if ln.startswith("| ") and "---" not in ln)
    sep_line = next(ln for ln in out.splitlines() if set(ln.replace("|", "").split()) == {"---"})
    assert header_line.count("|") == sep_line.count("|")


# ---------------------------------------------------------------------------
# SARIF — allowed for the CVE-list commands, rejected elsewhere
# ---------------------------------------------------------------------------

def test_latest_sarif_is_valid_2_1_0(stub_services: None) -> None:
    result = runner.invoke(app, ["latest", "--format", "sarif"])
    assert result.exit_code == ExitCode.OK, result.stdout
    log = json.loads(result.stdout)
    assert log["version"] == "2.1.0"
    assert "$schema" in log and log["$schema"]
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "pocmap"
    results = log["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == [CVE, "CVE-2021-45046"]
    # CRITICAL -> error; exploit_count comes from the PoC-source count.
    props = {r["ruleId"]: r["properties"] for r in results}
    assert props[CVE]["kev"] is True
    assert props[CVE]["exploit_count"] == 2


def test_discover_sarif_is_valid_2_1_0(stub_services: None) -> None:
    result = runner.invoke(app, ["discover", "Apache Log4j", "--format", "sarif"])
    assert result.exit_code == ExitCode.OK, result.stdout
    log = json.loads(result.stdout)
    assert log["version"] == "2.1.0"
    rule_ids = {r["ruleId"] for r in log["runs"][0]["results"]}
    assert rule_ids == {CVE, "CVE-2021-45046"}


@pytest.mark.parametrize(
    "argv",
    [
        ["labs", CVE],
        ["bugbounty", CVE],
        ["cpes", CVE],
        ["cpe2cve", "cpe:2.3:a:apache:log4j:2.0"],
    ],
)
def test_sarif_not_applicable_exits_invalid_input(
    stub_services: None, argv: list[str]
) -> None:
    result = runner.invoke(app, [*argv, "--format", "sarif"])
    assert result.exit_code == ExitCode.INVALID_INPUT  # 4
    assert "SARIF" in result.stdout


# ---------------------------------------------------------------------------
# Empty result set  ->  NO_RESULTS (2)
# ---------------------------------------------------------------------------

def test_empty_labs_exits_no_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(LabService, "find_labs", lambda self, cve: [])
    result = runner.invoke(app, ["labs", CVE])
    assert result.exit_code == ExitCode.NO_RESULTS  # 2
    assert f"No labs found for {CVE}" in result.stdout


def test_empty_latest_exits_no_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(RecentService, "find_recent_cves", lambda self, **kw: [])
    result = runner.invoke(app, ["latest"])
    assert result.exit_code == ExitCode.NO_RESULTS  # 2


def test_empty_latest_json_still_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty machine-readable result is still a well-formed document (exit 2)."""
    monkeypatch.setattr(RecentService, "find_recent_cves", lambda self, **kw: [])
    result = runner.invoke(app, ["latest", "--format", "json"])
    assert result.exit_code == ExitCode.NO_RESULTS
    assert json.loads(result.stdout) == {"total": 0, "cves": []}


def test_empty_discover_exits_no_results(monkeypatch: pytest.MonkeyPatch) -> None:
    empty = ProductDiscoveryResult(query="Nothing", total_found=0)
    monkeypatch.setattr(ProductDiscoveryService, "discover_by_product", lambda self, **kw: empty)
    result = runner.invoke(app, ["discover", "Nothing"])
    assert result.exit_code == ExitCode.NO_RESULTS  # 2


# ---------------------------------------------------------------------------
# Invalid input  ->  INVALID_INPUT (4)
# ---------------------------------------------------------------------------

def test_labs_invalid_cve_exits_invalid_input() -> None:
    # Real validation rejects the id before any (mocked) network call.
    result = runner.invoke(app, ["labs", "NOTACVE"])
    assert result.exit_code == ExitCode.INVALID_INPUT  # 4


# ---------------------------------------------------------------------------
# Default (table) output stays byte-identical to the standalone formatter
# ---------------------------------------------------------------------------

def _normalize(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.strip().splitlines())


def test_bugbounty_table_default_unchanged(
    stub_services: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("COLUMNS", "200")

    baseline = Console(width=200, file=io.StringIO())
    baseline.print(format_bb_table(REPORTS))
    baseline_table = baseline.file.getvalue()

    result = runner.invoke(app, ["bugbounty", CVE])
    assert result.exit_code == ExitCode.OK
    assert f"Bug Bounty Reports for {CVE}" in result.stdout
    # The rendered table block is byte-identical to the standalone formatter.
    assert _normalize(baseline_table) in _normalize(result.stdout)


def test_labs_table_default_unchanged(stub_services: None) -> None:
    """Default labs output is the pre-existing plain rendering (no format flag)."""
    result = runner.invoke(app, ["labs", CVE])
    assert result.exit_code == ExitCode.OK
    assert f"Lab Environments for {CVE}" in result.stdout
    assert "vulhub" in result.stdout
    assert "docker compose up -d" in result.stdout
    # No CSV/JSON leakage into the default human view.
    assert "{" not in result.stdout
