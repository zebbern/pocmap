"""Regression test for HTML report column alignment (ReportService).

The rendered table must stay rectangular: every ``<td>`` count in the body
must equal the ``<th>`` count in the header. A row is built per CVE by
``_render_body_rows``; the header is fixed by the report template. One entry
deliberately has ``cvss=None`` to exercise the severity/score None-guards --
that path previously risked emitting a different number of cells.

Fully offline: the report is built from in-memory pydantic models and rendered
via ``_render_html`` (no service lookups, no network).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from pocmap.models import (
    BugBountyReport,
    BugBountySource,
    CVEInfo,
    CVSSScore,
    CVSSVersion,
    Exploit,
    ExploitSource,
    LabEnvironment,
    LabPlatform,
    MultiReport,
    ReportEntry,
    Severity,
)
from pocmap.services.report_service import ReportService, _safe_href


def _build_multireport() -> MultiReport:
    entry_full = ReportEntry(
        cve_info=CVEInfo(
            id="CVE-2021-44228",
            description="Apache Log4j2 JNDI RCE",
            cvss=CVSSScore(
                version=CVSSVersion.V3_1,
                base_score=10.0,
                severity=Severity.CRITICAL,
            ),
            epss=97.53,
            kev_status=True,
            references={"NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
        ),
        exploits=[
            Exploit(source=ExploitSource.GITHUB, url="https://github.com/x/y", title="poc"),
        ],
    )
    # cvss=None + epss=None + no exploits/labs/reports exercises every guard.
    entry_no_cvss = ReportEntry(
        cve_info=CVEInfo(
            id="CVE-2023-38408",
            description="OpenSSH ssh-agent RCE",
            cvss=None,
            epss=None,
            kev_status=False,
        ),
    )
    return MultiReport(
        entries={
            "CVE-2021-44228": entry_full,
            "CVE-2023-38408": entry_no_cvss,
        }
    )


def _count(pattern: str, text: str) -> int:
    return len(re.findall(pattern, text))


def test_html_body_td_matches_header_th():
    report = _build_multireport()
    html = ReportService()._render_html(report)

    thead = re.search(r"<thead>(.*?)</thead>", html, re.S)
    assert thead is not None, "rendered report is missing a <thead>"
    th_count = _count(r"<th\b", thead.group(1))
    assert th_count == 13, f"expected the documented 13-column header, got {th_count}"

    tbody = re.search(r"<tbody>(.*?)</tbody>", html, re.S)
    assert tbody is not None, "rendered report is missing a <tbody>"
    rows = re.findall(r"<tr>(.*?)</tr>", tbody.group(1), re.S)
    assert len(rows) == 2, f"expected one row per CVE (2), got {len(rows)}"

    for i, row in enumerate(rows):
        td_count = _count(r"<td\b", row)
        assert td_count == th_count, (
            f"row {i} has {td_count} <td> cells but the header has {th_count} <th>"
        )


def test_html_neutralizes_javascript_href():
    """A javascript:/data: URL in any externally-sourced field must not stay
    clickable: _safe_href replaces the scheme with '#'. A normal https URL is
    left intact."""
    report = MultiReport(
        entries={
            "CVE-2021-44228": ReportEntry(
                cve_info=CVEInfo(
                    id="CVE-2021-44228",
                    description="Apache Log4j2 JNDI RCE",
                    references={
                        "Advisory": "javascript:alert(document.domain)",
                        "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                    },
                ),
                labs=[
                    LabEnvironment(
                        platform=LabPlatform.VULHUB,
                        name="log4j-lab",
                        url="javascript:alert(1)",
                    ),
                ],
                bb_reports=[
                    BugBountyReport(
                        source=BugBountySource.HACKERONE,
                        url="javascript:alert(2)",
                        title="log4j report",
                    ),
                ],
            ),
        }
    )
    html = ReportService()._render_html(report)

    # No anchor may carry a javascript: (or data:) scheme in its href.
    assert "href='javascript:" not in html
    assert "href='data:" not in html
    # The neutralized value collapses to '#'.
    assert "href='#'" in html
    # A genuine https reference still renders untouched.
    assert "href='https://nvd.nist.gov/vuln/detail/CVE-2021-44228'" in html


def test_bulk_report_from_file_reads_utf8_bom(tmp_path: Path, monkeypatch) -> None:
    """A UTF-8-with-BOM CVE list must not drop the BOM-prefixed first CVE.

    Under an unencoded read on a cp1252-default Windows host the leading BOM
    would corrupt the first line; the utf-8-sig pin strips it cleanly.
    """
    cve_file = tmp_path / "cves.txt"
    cve_file.write_text(
        "CVE-2021-44228\nCVE-2023-38408\n",
        encoding="utf-8-sig",
    )

    def _stub_generate_report(self: ReportService, cve_id: str) -> ReportEntry:
        return ReportEntry(cve_info=CVEInfo(id=cve_id.upper()))

    monkeypatch.setattr(ReportService, "generate_report", _stub_generate_report)

    report = ReportService().generate_bulk_report_from_file(cve_file)

    assert "CVE-2021-44228" in report.entries
    assert "CVE-2023-38408" in report.entries


def test_safe_href_fails_closed_on_dangerous_or_malformed_urls() -> None:
    """_safe_href only lets http(s) URLs through; everything else -> '#'.

    ``http://[::1`` trips urlparse's 'Invalid IPv6 URL' ValueError, exercising
    the fail-closed except branch; script-execution and non-web schemes are
    rejected outright.
    """
    # Malformed URL -> urlparse raises ValueError -> fail closed.
    assert _safe_href("http://[::1") == "#"
    # Script-execution / non-web schemes are neutralized.
    assert _safe_href("javascript:alert(1)") == "#"
    assert _safe_href("data:text/html,<script>") == "#"
    assert _safe_href("mailto:x@y") == "#"
    # Genuine http(s) URLs pass through untouched.
    passthrough = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    assert _safe_href(passthrough) == passthrough
    assert _safe_href("http://example.com") == "http://example.com"


def test_save_json_report_round_trips_report_entry(tmp_path: Path) -> None:
    """save_json_report(ReportEntry) writes the entry's to_dict() verbatim."""
    entry = ReportEntry(cve_info=CVEInfo(id="CVE-2021-44228"))
    filepath = ReportService().save_json_report(entry, tmp_path)

    loaded = json.loads(filepath.read_text(encoding="utf-8"))
    assert loaded, "round-tripped ReportEntry JSON must be non-empty"
    assert loaded == entry.to_dict()
    assert loaded["cve_info"]["id"] == "CVE-2021-44228"


def test_save_json_report_round_trips_multi_report(tmp_path: Path) -> None:
    """save_json_report(MultiReport) writes the multi-report's to_dict() verbatim."""
    multi = MultiReport(
        entries={
            "CVE-2021-44228": ReportEntry(cve_info=CVEInfo(id="CVE-2021-44228")),
        }
    )
    filepath = ReportService().save_json_report(multi, tmp_path)

    loaded = json.loads(filepath.read_text(encoding="utf-8"))
    assert loaded, "round-tripped MultiReport JSON must be non-empty"
    assert loaded == multi.to_dict()
    assert "CVE-2021-44228" in loaded["entries"]
