"""Report generation service.

Generates JSON and HTML reports from CVE analysis results. Supports both
single-CVE and bulk (multi-CVE) report generation with a self-contained,
styled HTML table (no external assets or JavaScript) in HTML output.

Example::

    from pocmap.services.report_service import ReportService
    service = ReportService()

    # Single CVE report
    entry = service.generate_report("CVE-2021-44228")
    print(entry.to_json())

    # Bulk report from file
    report = service.generate_bulk_report(["CVE-2021-44228", "CVE-2023-38408"])
    service.save_json_report(report, "./output")
    service.save_html_report(report, "./output")
"""

from __future__ import annotations

import html
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from pocmap.models import (
    ExploitSource,
    MultiReport,
    ReportEntry,
)
from pocmap.services.bb_service import BugBountyService
from pocmap.services.cve_service import CVEService
from pocmap.services.exploit_service import ExploitService
from pocmap.services.lab_service import LabService
from pocmap.utils.http import NotFoundError, ValidationError, is_programming_error
from pocmap.utils.validators import validate_cve_id

# ---------------------------------------------------------------------------
# Template loading
# ---------------------------------------------------------------------------

_DEFAULT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PocMap Report</title>
<style>*{{box-sizing:border-box;}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:2rem;background:#f8f9fa;color:#1a1a2e;}}
h1{{color:#1a1a2e;border-bottom:3px solid #e94560;padding-bottom:.5rem;}}
.meta{{color:#666;font-size:.9rem;margin-bottom:1.5rem;}}
.table-wrap{{overflow-x:auto;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);}}
table{{border-collapse:collapse;width:100%;background:white;}}
thead th{{background:#1a1a2e;color:white;text-align:left;padding:.75rem 1rem;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;white-space:nowrap;position:sticky;top:0;}}
tbody td{{padding:.65rem 1rem;border-bottom:1px solid #eaecef;font-size:.88rem;vertical-align:top;}}
tbody tr:nth-child(even){{background:#fbfbfc;}}
tbody tr:hover{{background:#fff5f7;}}
tbody tr:last-child td{{border-bottom:none;}}
.badge{{padding:.25rem .75rem;border-radius:999px;font-size:.85rem;font-weight:600;display:inline-block;white-space:nowrap;}}
.badge.yes{{background:#d4edda;color:#155724;}}.badge.no{{background:#f8d7da;color:#721c24;}}
.severity-critical{{background:#dc3545;color:white;}}.severity-high{{background:#fd7e14;color:white;}}
.severity-medium{{background:#ffc107;color:#212529;}}.severity-low{{background:#28a745;color:white;}}
.severity-unknown{{background:#6c757d;color:white;}}
a{{color:#e94560;text-decoration:none;}}a:hover{{text-decoration:underline;}}</style>
</head><body><h1>PocMap Report</h1><p class="meta">Generated on {report_date} at {report_time}</p>
<div class="table-wrap"><table id="report"><thead><tr>
<th>CVE ID</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Description</th>
<th>GitHub PoC</th><th>ExploitDB</th><th>Metasploit</th><th>Nuclei</th><th>Labs</th><th>Bug Bounty</th><th>References</th>
</tr></thead><tbody>{body_rows}</tbody></table></div>
</body></html>"""


def _load_report_template() -> str:
    """Load the HTML report template from the templates package.

    Falls back to a built-in default template if the external file is
    not available (e.g. when running from a single-file bundle).
    """
    template_path = Path(__file__).parent.parent / "templates" / "report.html"
    if template_path.exists():
        return template_path.read_text(encoding="utf-8")
    logger.warning("External report template not found at %s — using built-in default", template_path)
    return _DEFAULT_HTML_TEMPLATE


# Load once at import time for performance
_REPORT_TEMPLATE = _load_report_template()

logger = logging.getLogger(__name__)


def _escape_html(text: object) -> str:
    """Escape HTML special characters in user-controlled text.

    Accepts any value (``str``, numbers, ``None``, …); non-string inputs are
    stringified before escaping.
    """
    if text is None:
        return ""
    return html.escape(str(text))


class ReportService:
    """Service for generating comprehensive CVE analysis reports.

    Combines all other services to produce a complete :class:`ReportEntry`
    or :class:`MultiReport` with CVE info, exploits, labs, and bug bounty data.

    Args:
        cve_service: Optional CVEService instance.
        exploit_service: Optional ExploitService instance.
        lab_service: Optional LabService instance.
        bb_service: Optional BugBountyService instance.

    Example::

        service = ReportService()

        # Generate single report
        entry = service.generate_report("CVE-2021-44228")
        print(entry.to_dict())

        # Generate bulk report
        multi = service.generate_bulk_report(["CVE-2021-44228", "CVE-2023-38408"])

        # Save reports
        service.save_json_report(multi, "./reports")
        service.save_html_report(multi, "./reports")
    """

    def __init__(
        self,
        cve_service: CVEService | None = None,
        exploit_service: ExploitService | None = None,
        lab_service: LabService | None = None,
        bb_service: BugBountyService | None = None,
    ) -> None:
        self._cve = cve_service or CVEService()
        self._exploit = exploit_service or ExploitService()
        self._lab = lab_service or LabService()
        self._bb = bb_service or BugBountyService()

    def generate_report(self, cve_id: str) -> ReportEntry:
        """Generate a complete report for a single CVE.

        Args:
            cve_id: The CVE identifier.

        Returns:
            A populated :class:`ReportEntry`.

        Raises:
            ValidationError: If the CVE ID format is invalid.
            NotFoundError: If no record exists for the CVE.
        """
        cve_id = validate_cve_id(cve_id)
        logger.info("Generating report for %s", cve_id)

        # Get CVE info
        cve_info = self._cve.get_cve_info(cve_id)

        # Find exploits
        exploits = self._exploit.find_exploits(cve_id)

        # Find labs
        labs = self._lab.find_labs(cve_id)

        # Find bug bounty reports
        bb_reports = self._bb.find_reports(cve_id)

        return ReportEntry(
            cve_info=cve_info,
            exploits=exploits,
            labs=labs,
            bb_reports=bb_reports,
        )

    def generate_bulk_report(self, cve_ids: list[str]) -> MultiReport:
        """Generate a combined report for multiple CVEs.

        Args:
            cve_ids: List of CVE identifiers.

        Returns:
            A :class:`MultiReport` containing entries for each CVE.
        """
        entries: dict[str, ReportEntry] = {}
        for cve_id in cve_ids:
            try:
                entry = self.generate_report(cve_id)
                entries[cve_id.upper()] = entry
            except (NotFoundError, ValidationError) as exc:
                logger.warning("Skipping %s: %s", cve_id, exc)
                continue
            except Exception as exc:
                if is_programming_error(exc):
                    raise
                logger.error("Error processing %s: %s", cve_id, exc)
                continue

        return MultiReport(entries=entries)

    def generate_bulk_report_from_file(self, file_path: str | Path) -> MultiReport:
        """Generate a bulk report from a file containing CVE IDs (one per line).

        Args:
            file_path: Path to the file containing CVE IDs.

        Returns:
            A :class:`MultiReport`.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"CVE ID file not found: {path}")

        cve_ids = [
            line.strip()
            for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        return self.generate_bulk_report(cve_ids)

    def save_json_report(
        self, report: MultiReport | ReportEntry, output_dir: str | Path
    ) -> Path:
        """Save a report as JSON.

        Args:
            report: The report to save.
            output_dir: Directory to write the JSON file.

        Returns:
            Path to the written file.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        filename = f"pocmap_report_{timestamp}.json"
        filepath = out / filename

        data = report.to_dict() if isinstance(report, ReportEntry) else report.to_dict()
        filepath.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info("JSON report saved to %s", filepath)
        return filepath

    def save_html_report(
        self, report: MultiReport, output_dir: str | Path
    ) -> Path:
        """Save a multi-report as a self-contained, styled HTML file.

        Args:
            report: The multi-report to save.
            output_dir: Directory to write the HTML file.

        Returns:
            Path to the written file.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        filename = f"pocmap_report_{timestamp}.html"
        filepath = out / filename

        html = self._render_html(report)
        filepath.write_text(html, encoding="utf-8")
        logger.info("HTML report saved to %s", filepath)
        return filepath

    def _render_html(self, report: MultiReport) -> str:
        """Render a MultiReport as an interactive HTML document."""
        report_date = datetime.now().date()
        report_time = datetime.now().strftime("%H:%M:%S")
        body_rows = self._render_body_rows(report)
        return _REPORT_TEMPLATE.format(
            report_date=report_date,
            report_time=report_time,
            body_rows=body_rows,
        )

    def _render_body_rows(self, report: MultiReport) -> str:
        """Generate the HTML table body rows for a MultiReport."""
        rows = ""
        for cve_id, entry in report.entries.items():
            cve = entry.cve_info

            # GitHub cell
            gh_exploits = [e for e in entry.exploits if e.source == ExploitSource.GITHUB]
            if gh_exploits:
                gh_td = (
                    f"<td><span class='badge yes'>"
                    f"<a href='https://poc-in-github.motikan2010.net/api/v1/?cve_id={_escape_html(cve_id)}' "
                    f"target='_blank'>Yes ({len(gh_exploits)})</a></span></td>"
                )
            else:
                gh_td = "<td><span class='badge no'>No</span></td>"

            # ExploitDB cell
            edb = [e for e in entry.exploits if e.source == ExploitSource.EXPLOITDB]
            if edb:
                edb_td = (
                    f"<td><span class='badge yes'>"
                    f"<a href='{_escape_html(edb[0].url)}' target='_blank'>Yes</a></span></td>"
                )
            else:
                edb_td = "<td><span class='badge no'>No</span></td>"

            # Metasploit cell
            msf = [e for e in entry.exploits if e.source == ExploitSource.METASPLOIT]
            if msf:
                msf_td = (
                    f"<td><span class='badge yes'>"
                    f"<a href='{_escape_html(msf[0].url)}' target='_blank'>Yes</a></span></td>"
                )
            else:
                msf_td = "<td><span class='badge no'>No</span></td>"

            # Nuclei cell
            nuc = [e for e in entry.exploits if e.source == ExploitSource.NUCLEI]
            if nuc:
                nuc_td = (
                    f"<td><span class='badge yes'>"
                    f"<a href='{_escape_html(nuc[0].url)}' target='_blank'>Yes</a></span></td>"
                )
            else:
                nuc_td = "<td><span class='badge no'>No</span></td>"

            # Severity cell (colored badge)
            severity = cve.cvss.severity.value if cve.cvss else "UNKNOWN"
            severity_class = f"severity-{severity.lower()}"
            severity_td = (
                f"<td><span class='badge {severity_class}'>"
                f"{_escape_html(severity)}</span></td>"
            )

            # Description cell (truncated for readability)
            description = cve.description or "N/A"
            if len(description) > 200:
                description = description[:197] + "..."
            desc_td = f"<td>{_escape_html(description)}</td>"

            # Labs cell
            if entry.labs:
                lab_links = ", ".join(
                    f"<a href='{_escape_html(lab.url)}' target='_blank'>"
                    f"{_escape_html(lab.name or lab.platform.value)}</a>"
                    for lab in entry.labs[:5]
                )
                labs_td = f"<td>{lab_links}</td>"
            else:
                labs_td = "<td><span class='badge no'>No</span></td>"

            # Bug Bounty cell
            if entry.bb_reports:
                bb_links = ", ".join(
                    f"<a href='{_escape_html(rep.url)}' target='_blank'>"
                    f"{_escape_html(rep.title or rep.source.value)}</a>"
                    for rep in entry.bb_reports[:5]
                )
                bb_td = f"<td>{bb_links}</td>"
            else:
                bb_td = "<td><span class='badge no'>No</span></td>"

            # References cell
            if cve.references:
                ref_links = ", ".join(
                    f"<a href='{_escape_html(url)}' target='_blank'>{_escape_html(name)}</a>"
                    for name, url in list(cve.references.items())[:5]
                )
                ref_td = f"<td>{ref_links}</td>"
            else:
                ref_td = "<td>N/A</td>"

            base_score = (
                cve.cvss.base_score
                if cve.cvss and cve.cvss.base_score is not None
                else "N/A"
            )
            epss_val = cve.epss if cve.epss is not None else "N/A"
            kev_class = "yes" if cve.kev_status else "no"
            kev_val = "Yes" if cve.kev_status else "No"

            # Emit exactly the 13 header columns in order:
            # CVE ID, Severity, CVSS, EPSS, KEV, Description, GitHub PoC,
            # ExploitDB, Metasploit, Nuclei, Labs, Bug Bounty, References
            rows += f"""
            <tr>
                <td><a href='https://nvd.nist.gov/vuln/detail/{_escape_html(cve_id)}' target='_blank'>{_escape_html(cve_id)}</a></td>
                {severity_td}
                <td>{_escape_html(base_score)}</td>
                <td>{_escape_html(epss_val)}</td>
                <td><span class='badge {kev_class}'>{_escape_html(kev_val)}</span></td>
                {desc_td}
                {gh_td}
                {edb_td}
                {msf_td}
                {nuc_td}
                {labs_td}
                {bb_td}
                {ref_td}
            </tr>
            """
        return rows

    def close(self) -> None:
        """Release all underlying services."""
        self._cve.close()
        self._exploit.close()
        self._lab.close()
        self._bb.close()

    def __enter__(self) -> ReportService:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

