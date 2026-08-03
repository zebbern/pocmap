"""Native offline tests for the ``pocmap package`` command and its MCP twin.

Covers the ``package`` command in ``src/pocmap/cli.py``, its renderers, and the
``discover_package_cves`` MCP tool.

Fully offline: ``PackageService.discover_package`` is monkeypatched, so the
service builds only in-memory clients and no network or DNS call is made.

Invariants locked in here:

  * ``--format json`` owns stdout entirely — the whole stream parses as one
    document, with no banner, spinner or stray print.
  * The exit-code contract: OK (0), NO_RESULTS (2), INVALID_INPUT (4) for a bad
    ecosystem, UPSTREAM_ERROR (5) offline.
  * A rejected query exits 4, never 2 — "you spelled PyPI wrong" and "this
    package is clean" must not produce the same result.
  * SARIF rows for a non-CVE advisory point at OSV, not at a nonexistent NVD
    page.
"""

from __future__ import annotations

import csv
import io
import json

import pytest
from typer.testing import CliRunner

from pocmap.cli import app
from pocmap.models import PackageDiscoveryResult, PackageVulnerability, Severity
from pocmap.services.package_service import PackageService
from pocmap.utils.exit_codes import ExitCode
from pocmap.utils.http import OfflineError, ValidationError

runner = CliRunner()


def _vuln(
    vuln_id: str = "GHSA-jfh8-c2jp-5v3q",
    *,
    cve: str | None = "CVE-2021-44228",
    severity: Severity = Severity.CRITICAL,
    score: float | None = 10.0,
    fixed: list[str] | None = None,
    kev: bool = True,
    epss: float | None = 99.99,
) -> PackageVulnerability:
    return PackageVulnerability(
        id=vuln_id,
        cve_ids=[cve] if cve else [],
        summary="Remote code injection in Log4j",
        severity=severity,
        cvss_score=score,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" if score else None,
        epss=epss,
        kev_status=kev,
        fixed_versions=fixed if fixed is not None else ["2.15.0", "2.12.2"],
        url=f"https://osv.dev/vulnerability/{vuln_id}",
    )


def _result(*vulns: PackageVulnerability) -> PackageDiscoveryResult:
    return PackageDiscoveryResult(
        ecosystem="Maven",
        package="org.apache.logging.log4j:log4j-core",
        version="2.14.1",
        vulnerabilities=list(vulns),
        total_found=len(vulns),
        fixable_count=sum(1 for v in vulns if v.has_fix),
        unfixed_count=sum(1 for v in vulns if not v.has_fix),
        search_sources=["osv", "epss", "cisa_kev"],
    )


@pytest.fixture
def stub_service(monkeypatch: pytest.MonkeyPatch) -> None:
    """Return one Log4Shell advisory for any query."""
    monkeypatch.setattr(
        PackageService, "discover_package", lambda self, **kw: _result(_vuln())
    )


ARGS = ["package", "Maven", "org.apache.logging.log4j:log4j-core", "--version", "2.14.1"]


# ---------------------------------------------------------------------------
# Machine-readable formats
# ---------------------------------------------------------------------------

def test_json_output_is_the_whole_of_stdout(stub_service: None) -> None:
    result = runner.invoke(app, [*ARGS, "--format", "json"])
    assert result.exit_code == ExitCode.OK, result.stdout
    data = json.loads(result.stdout)
    assert data["ecosystem"] == "Maven"
    assert data["total_found"] == 1
    assert data["vulnerabilities"][0]["fixed_versions"] == ["2.15.0", "2.12.2"]


def test_csv_output_parses_and_joins_fixed_versions(stub_service: None) -> None:
    result = runner.invoke(app, [*ARGS, "--format", "csv"])
    assert result.exit_code == ExitCode.OK, result.stdout
    rows = list(csv.DictReader(io.StringIO(result.stdout)))
    assert len(rows) == 1
    # Joined, not a JSON list: the cell is meant to be readable in a spreadsheet.
    assert rows[0]["fixed_versions"] == "2.15.0, 2.12.2"
    assert rows[0]["severity"] == "CRITICAL"


def test_markdown_output_is_a_table(stub_service: None) -> None:
    result = runner.invoke(app, [*ARGS, "--format", "md"])
    assert result.exit_code == ExitCode.OK, result.stdout
    assert "|" in result.stdout and "---" in result.stdout


def test_sarif_output_is_a_valid_log(stub_service: None) -> None:
    result = runner.invoke(app, [*ARGS, "--format", "sarif"])
    assert result.exit_code == ExitCode.OK, result.stdout
    log = json.loads(result.stdout)
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    assert run["results"][0]["level"] == "error"  # CRITICAL -> error
    assert "2.15.0" in run["results"][0]["message"]["text"]


def test_sarif_help_uri_points_at_osv_for_a_non_cve_advisory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A RUSTSEC/GHSA-only advisory has no NVD page; the default would 404."""
    advisory = _vuln("RUSTSEC-2021-0001", cve=None, kev=False, epss=None)
    monkeypatch.setattr(
        PackageService, "discover_package", lambda self, **kw: _result(advisory)
    )
    result = runner.invoke(app, [*ARGS, "--format", "sarif"])
    assert result.exit_code == ExitCode.OK, result.stdout
    rules = json.loads(result.stdout)["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["helpUri"] == "https://osv.dev/vulnerability/RUSTSEC-2021-0001"


def test_sarif_help_uri_stays_nvd_for_a_cve_advisory(stub_service: None) -> None:
    result = runner.invoke(app, [*ARGS, "--format", "sarif"])
    rules = json.loads(result.stdout)["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["helpUri"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"


# ---------------------------------------------------------------------------
# Table output
# ---------------------------------------------------------------------------

def test_table_output_shows_the_fix_and_no_json(stub_service: None) -> None:
    result = runner.invoke(
        app, ARGS, env={"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"}
    )
    assert result.exit_code == ExitCode.OK, result.stdout
    assert "2.15.0" in result.stdout
    assert "CVE-2021-44228" in result.stdout
    assert "{" not in result.stdout


def test_table_flags_an_advisory_with_no_published_fix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """'no fix published' is a distinct, actionable state — not a blank cell."""
    monkeypatch.setattr(
        PackageService,
        "discover_package",
        lambda self, **kw: _result(_vuln("GHSA-nofix", fixed=[])),
    )
    result = runner.invoke(
        app, ARGS, env={"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"}
    )
    assert "none published" in result.stdout


# ---------------------------------------------------------------------------
# Exit-code contract
# ---------------------------------------------------------------------------

def test_no_results_exits_two(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(PackageService, "discover_package", lambda self, **kw: _result())
    result = runner.invoke(app, [*ARGS, "--format", "json"])
    assert result.exit_code == ExitCode.NO_RESULTS, result.stdout
    assert json.loads(result.stdout)["total_found"] == 0


def test_rejected_ecosystem_exits_invalid_input_not_no_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole point of the 400 plumbing: a typo must not read as 'clean'."""
    def _boom(self: PackageService, **kw: object) -> PackageDiscoveryResult:
        raise ValidationError("OSV rejected ecosystem 'pypi'. Did you mean 'PyPI'?")

    monkeypatch.setattr(PackageService, "discover_package", _boom)
    result = runner.invoke(app, ["package", "pypi", "django", "--format", "json"])
    assert result.exit_code == ExitCode.INVALID_INPUT, result.stdout
    assert json.loads(result.stdout)["category"] == "invalid_input"


def test_offline_exits_upstream_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(self: PackageService, **kw: object) -> PackageDiscoveryResult:
        raise OfflineError("offline: no cached response")

    monkeypatch.setattr(PackageService, "discover_package", _boom)
    result = runner.invoke(app, [*ARGS, "--format", "json"])
    assert result.exit_code == ExitCode.UPSTREAM_ERROR, result.stdout


def test_fixable_only_filters_and_can_empty_the_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        PackageService,
        "discover_package",
        lambda self, **kw: _result(_vuln("GHSA-nofix", fixed=[])),
    )
    result = runner.invoke(app, [*ARGS, "--fixable-only", "--format", "json"])
    assert result.exit_code == ExitCode.NO_RESULTS, result.stdout
    data = json.loads(result.stdout)
    assert data["vulnerabilities"] == []
    # The document must still say something was FOUND, or a consumer reads the
    # empty list as "clean" when the package has an unfixable vulnerability.
    assert data["total_found"] == 1
    assert data["filtered_out"] == 1
    assert data["fixable_only"] is True


def test_fixable_only_table_does_not_claim_the_package_is_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--fixable-only emptying the list is the opposite of "no vulnerabilities"."""
    monkeypatch.setattr(
        PackageService,
        "discover_package",
        lambda self, **kw: _result(_vuln("GHSA-nofix", fixed=[])),
    )
    result = runner.invoke(
        app, [*ARGS, "--fixable-only"], env={"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"}
    )
    assert "No known vulnerabilities" not in result.stdout
    assert "No advisories with a published fix" in result.stdout


def test_upstream_failure_in_json_mode_stays_parseable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Rich error line on stdout would break json.loads and lose the reason."""
    def _boom(self: PackageService, **kw: object) -> PackageDiscoveryResult:
        raise RuntimeError("upstream exploded")

    monkeypatch.setattr(PackageService, "discover_package", _boom)
    result = runner.invoke(app, [*ARGS, "--format", "json"])
    assert result.exit_code == ExitCode.UPSTREAM_ERROR, result.stdout
    payload = json.loads(result.stdout)
    assert payload["category"] == "upstream_error"


def test_unsafe_output_path_fails_before_anything_reaches_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validating after rendering leaves a complete document on a failed run."""
    monkeypatch.setattr(
        PackageService, "discover_package", lambda self, **kw: _result(_vuln())
    )
    result = runner.invoke(
        app, [*ARGS, "--format", "json", "--output", "../../escape.json"]
    )
    assert result.exit_code == ExitCode.INVALID_INPUT, result.stdout
    assert "vulnerabilities" not in result.stdout


def test_truncation_is_reported_rather_than_hidden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _truncated(self: PackageService, **kw: object) -> PackageDiscoveryResult:
        res = _result(_vuln())
        res.total_found = 400
        res.truncated = True
        return res

    monkeypatch.setattr(PackageService, "discover_package", _truncated)
    result = runner.invoke(app, [*ARGS, "--format", "json"])
    data = json.loads(result.stdout)
    assert data["total_found"] == 400
    assert data["returned"] == 1
    assert data["truncated"] is True


def test_package_appears_in_help() -> None:
    result = runner.invoke(app, ["--help"], env={"COLUMNS": "400", "NO_COLOR": "1"})
    assert "package" in result.stdout


# ---------------------------------------------------------------------------
# MCP tool
# ---------------------------------------------------------------------------

def test_mcp_tool_returns_the_documented_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    from pocmap.mcp_server import discover_package_cves

    monkeypatch.setattr(
        PackageService, "discover_package", lambda self, **kw: _result(_vuln())
    )
    data = discover_package_cves("Maven", "org.apache.logging.log4j:log4j-core")
    assert data["ecosystem"] == "Maven"
    vuln = data["vulnerabilities"][0]
    for key in ("id", "canonical_cve", "cve_ids", "severity", "cvss_score", "epss_score",
                "kev_status", "fixed_versions", "has_fix", "url"):
        assert key in vuln, key
    assert vuln["canonical_cve"] == vuln["cve_ids"][0]
    # epss_score is 0.0-1.0 on the wire to match every other MCP tool.
    assert vuln["epss_score"] == pytest.approx(0.9999)
    assert vuln["fixed_versions"] == ["2.15.0", "2.12.2"]


def test_mcp_tool_reports_a_rejected_query_as_invalid_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pocmap.mcp_server import discover_package_cves

    def _boom(self: PackageService, **kw: object) -> PackageDiscoveryResult:
        raise ValidationError("OSV rejected ecosystem 'nope'.")

    monkeypatch.setattr(PackageService, "discover_package", _boom)
    data = discover_package_cves("nope", "django")
    assert data["category"] == "invalid_input"
    assert data["retryable"] is False
    # The success key must be ABSENT so an agent cannot read a failure as empty.
    assert "total_found" not in data
