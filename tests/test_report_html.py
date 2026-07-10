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

import re

from pocmap.models import (
    CVEInfo,
    CVSSScore,
    CVSSVersion,
    Exploit,
    ExploitSource,
    MultiReport,
    ReportEntry,
    Severity,
)
from pocmap.services.report_service import ReportService


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
