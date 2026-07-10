#!/usr/bin/env python3
"""PocMap AI - MCP Server for CVE lookup and exploit discovery.

This server provides AI agents with tools to:
- Look up CVE details from NVD, CVE.org, EPSS, and CISA KEV sources
- Find exploits and PoCs from GitHub, Metasploit, ExploitDB, and Nuclei
- Discover bug bounty reports from HackerOne, PentesterLand
- Find CTF labs on Vulhub, HackTheBox, TryHackMe
- Convert between CVEs and CPEs
- Generate structured vulnerability reports

Usage:
    python mcp_server.py                    # Run with STDIO transport (default)
    python mcp_server.py --transport sse    # Run with SSE transport on port 8000
    python mcp_server.py --transport http   # Run with Streamable HTTP transport
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Package path setup - ensure the src/ package is importable
# ---------------------------------------------------------------------------

# Add src/ to path so `pocmap` imports work
_SRC_DIR = Path(__file__).resolve().parent / "src"
if _SRC_DIR.exists() and str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

# NOTE: every import below sits *after* the sys.path shim above, so E402
# (module import not at top of file) is intentional and suppressed per-line.
from mcp.server.fastmcp import FastMCP  # noqa: E402

# ---------------------------------------------------------------------------
# Import the real pocmap package (the src/ shim above puts it on sys.path).
#
# There is intentionally NO mock fallback: pocmap is the single source of
# truth. If it cannot be imported the server must fail loudly rather than
# silently serve fabricated data.
# ---------------------------------------------------------------------------
from pocmap.models import ExploitSource, LabPlatform  # noqa: E402
from pocmap.services.bb_service import BugBountyService  # noqa: E402
from pocmap.services.cve_service import CVEService  # noqa: E402
from pocmap.services.exploit_service import ExploitService  # noqa: E402
from pocmap.services.lab_service import LabService  # noqa: E402
from pocmap.services.product_service import ProductDiscoveryService  # noqa: E402
from pocmap.services.recent_service import RecentService  # noqa: E402
from pocmap.utils.http import is_programming_error  # noqa: E402

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pocmap-mcp")

# Maximum number of CVEs allowed in bulk report operations
MAX_CVE_BULK = 100

# ---------------------------------------------------------------------------
# Service adapter - normalizes pocmap service results into plain dicts
# ---------------------------------------------------------------------------

class ServiceAdapter:
    """Adapter that wraps the pocmap services and normalizes their results
    into plain, JSON-serializable dicts for the MCP tool layer."""

    def __init__(self) -> None:
        self._cve: Any = CVEService()
        self._exploit: Any = ExploitService()
        self._bb: Any = BugBountyService()
        self._lab: Any = LabService()
        self._recent: Any = RecentService()
        self._product: Any = ProductDiscoveryService()

    def close(self) -> None:
        """Close all services to release resources."""
        for svc_name in ("_recent", "_product", "_cve", "_exploit", "_bb", "_lab"):
            svc = getattr(self, svc_name, None)
            if svc is not None and hasattr(svc, "close"):
                with suppress(Exception):
                    svc.close()

    # -- CVE Service --

    def lookup_cve(self, cve_id: str) -> dict[str, Any]:
        """Look up CVE details. Returns normalized dict."""
        cve_id = cve_id.upper().strip()
        try:
            info = self._cve.get_cve_info(cve_id)
            return self._normalize_cve_info(info)
        except Exception as e:
            if is_programming_error(e):
                raise
            logger.warning(f"CVE lookup failed for {cve_id}: {e}")
            return {"error": f"CVE lookup failed ({type(e).__name__})", "cve_id": cve_id}

    def get_epss(self, cve_id: str) -> float | None:
        """Get EPSS score. Returns 0-1 range."""
        try:
            info = self._cve.get_cve_info(cve_id)
            epss = info.epss
            # CVEInfo.epss is on a 0-100 scale; normalize to a 0-1 probability.
            return epss / 100.0 if epss is not None else None
        except Exception as e:
            if is_programming_error(e):
                raise
            return None

    def check_kev(self, cve_id: str) -> bool:
        """Check KEV status. Returns bool."""
        try:
            info = self._cve.get_cve_info(cve_id)
            return bool(info.kev_status)
        except Exception as e:
            if is_programming_error(e):
                raise
            return False

    # -- Exploit Service --

    def find_github_pocs(self, cve_id: str, limit: int = 10) -> list[dict[str, Any]]:
        """Find GitHub PoCs. Returns list of normalized dicts."""
        try:
            exploits = self._exploit.find_github_pocs(cve_id, limit=limit)
            return [self._normalize_exploit(e) for e in exploits[:limit]]
        except Exception as e:
            if is_programming_error(e):
                raise
            logger.warning(f"GitHub PoC search failed: {e}")
            return []

    def find_github_pocs_with_sources(
        self, cve_id: str, limit: int = 10
    ) -> dict[str, Any]:
        """Find GitHub PoCs and report per-source health (ERR-RESULT).

        Returns ``{"pocs": [...], "sources": [...]}`` where ``sources`` records
        whether GitHub was ``ok``/``empty``/``rate_limited``/``error`` — so a
        throttled or down GitHub can never masquerade as "no PoCs found".
        Programming bugs propagate (they are not masked as empty).
        """
        result = self._exploit.find_github_pocs_with_status(cve_id, limit=limit)
        return {
            "pocs": [self._normalize_exploit(e) for e in result.exploits],
            "sources": [s.to_dict() for s in result.sources],
        }

    def find_metasploit_module(self, cve_id: str, limit: int = 1) -> dict[str, Any] | None:
        """Find Metasploit module."""
        try:
            exploits = self._exploit.find_db_exploits(cve_id)
            for e in exploits[:limit]:
                if e.source == ExploitSource.METASPLOIT:
                    return self._normalize_exploit(e)
            return None
        except Exception as e:
            if is_programming_error(e):
                raise
            logger.warning(f"Metasploit search failed: {e}")
            return None

    def find_exploitdb_entry(self, cve_id: str, limit: int = 1) -> dict[str, Any] | None:
        """Find ExploitDB entry."""
        try:
            exploits = self._exploit.find_db_exploits(cve_id)
            for e in exploits[:limit]:
                if e.source == ExploitSource.EXPLOITDB:
                    return self._normalize_exploit(e)
            return None
        except Exception as e:
            if is_programming_error(e):
                raise
            logger.warning(f"ExploitDB search failed: {e}")
            return None

    def find_nuclei_template(self, cve_id: str, limit: int = 1) -> dict[str, Any] | None:
        """Find Nuclei template."""
        try:
            exploits = self._exploit.find_db_exploits(cve_id)
            for e in exploits[:limit]:
                if e.source == ExploitSource.NUCLEI:
                    return self._normalize_exploit(e)
            return None
        except Exception as e:
            if is_programming_error(e):
                raise
            logger.warning(f"Nuclei search failed: {e}")
            return None

    # -- Bug Bounty Service --

    def find_bug_bounty_reports(self, cve_id: str) -> list[dict[str, Any]]:
        """Find bug bounty reports."""
        try:
            reports = self._bb.find_reports(cve_id)
            return [self._normalize_bb_report(r) for r in reports]
        except Exception as e:
            if is_programming_error(e):
                raise
            logger.warning(f"Bug bounty search failed: {e}")
            return []

    # -- Lab Service --

    def find_labs(self, cve_id: str) -> list[dict[str, Any]]:
        """Find practice labs."""
        try:
            labs = self._lab.find_labs(cve_id)
            return [self._normalize_lab(lab) for lab in labs]
        except Exception as e:
            if is_programming_error(e):
                raise
            logger.warning(f"Lab search failed: {e}")
            return []

    def find_docker_env(self, cve_id: str) -> str | None:
        """Find Vulhub Docker environment URL."""
        try:
            labs = self._lab.find_labs(cve_id)
            for lab in labs:
                if lab.platform == LabPlatform.VULHUB:
                    return lab.url
            return None
        except Exception as e:
            if is_programming_error(e):
                raise
            return None

    # -- CPE Service --

    def cve_to_cpe(self, cve_id: str) -> list[dict[str, Any]]:
        """Convert CVE to CPEs."""
        try:
            cpes = self._cve.get_cpes(cve_id)
            return [self._normalize_cpe(c) for c in cpes]
        except Exception as e:
            if is_programming_error(e):
                raise
            logger.warning(f"CPE lookup failed: {e}")
            return []

    def cpe_to_cve(self, cpe: str) -> list[str]:
        """Convert CPE to CVEs."""
        try:
            return self._cve.cpe_to_cves(cpe)
        except Exception as e:
            if is_programming_error(e):
                raise
            logger.warning(f"CPE->CVE lookup failed: {e}")
            return []

    # -- Recent CVE Discovery --

    def find_recent_exploits(
        self,
        since: str = "24h",
        from_date: str = "",
        to_date: str = "",
        only_with_poc: bool = False,
        kev_only: bool = False,
        min_epss: float = 0.0,
        severity: str = "",
        sort: str = "cve_date",
        limit: int = 50,
    ) -> dict[str, Any]:
        """Find recently published CVEs with exploit/PoC intelligence.

        Args:
            since: Relative time string (1h, 24h, 7d, 30d).
            from_date: Explicit start date (YYYY-MM-DD), overrides *since*.
            to_date: Explicit end date (YYYY-MM-DD).
            only_with_poc: Only return CVEs with known PoCs.
            kev_only: Only return CISA KEV entries.
            min_epss: Minimum EPSS score (0--100).
            severity: Comma-separated severity levels.
            sort: Sort mode (cve_date, severity, epss).
            limit: Maximum results.

        Returns:
            Structured dict with query parameters and CVE results.
        """
        from datetime import date
        parsed_from = date.fromisoformat(from_date) if from_date else None
        parsed_to = date.fromisoformat(to_date) if to_date else None
        severity_list = [s.strip() for s in severity.split(",") if s.strip()] if severity else None
        try:
            results = self._recent.find_recent_cves(
                since=since if not parsed_from else None,
                from_date=parsed_from,
                to_date=parsed_to,
                severity=severity_list,
                kev_only=kev_only,
                min_epss=min_epss if min_epss > 0 else None,
                only_with_poc=only_with_poc,
                sort=sort,
                limit=limit,
            )
            return {
                "success": True,
                "total": len(results),
                "query": {
                    "since": since,
                    "from_date": from_date or None,
                    "to_date": to_date or None,
                    "only_with_poc": only_with_poc,
                    "kev_only": kev_only,
                    "min_epss": min_epss if min_epss > 0 else None,
                    "severity": severity_list,
                    "sort": sort,
                    "limit": limit,
                },
                "cves": [self._normalize_recent_result(r) for r in results],
            }
        except Exception as e:
            if is_programming_error(e):
                raise
            logger.warning(f"Recent exploit discovery failed: {e}")
            return {"success": False, "error": f"Recent exploit discovery failed ({type(e).__name__})"}

    # -- Report Generation --

    def generate_json_report(self, cve_ids: list[str]) -> str:
        """Generate JSON report for CVE IDs."""
        if len(cve_ids) > MAX_CVE_BULK:
            return json.dumps({
                "error": f"Too many CVEs requested: {len(cve_ids)} (max {MAX_CVE_BULK})",
                "category": "invalid_input",
            })
        entries: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for cve_id in cve_ids:
            cve_info = self.lookup_cve(cve_id)
            if "error" in cve_info:
                errors.append({
                    "cve_id": cve_info.get("cve_id", cve_id),
                    "error": cve_info["error"],
                })
                continue
            github = self.find_github_pocs(cve_id)
            msf = self.find_metasploit_module(cve_id)
            edb = self.find_exploitdb_entry(cve_id)
            nuc = self.find_nuclei_template(cve_id)
            exploits = github
            for e in [msf, edb, nuc]:
                if e:
                    exploits.append(e)
            bb_reports = self.find_bug_bounty_reports(cve_id)
            labs = self.find_labs(cve_id)
            entries.append({
                "cve_info": cve_info,
                "exploits": exploits,
                "labs": labs,
                "bb_reports": bb_reports,
            })

        report = {
            "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            "total_requested": len(cve_ids),
            "total_entries": len(entries),
            "total_errors": len(errors),
            "entries": entries,
            "errors": errors,
        }
        return json.dumps(report, indent=2, default=str)

    def generate_html_report(self, cve_ids: list[str]) -> str:
        """Generate HTML report for CVE IDs."""
        if len(cve_ids) > MAX_CVE_BULK:
            return json.dumps({
                "error": f"Too many CVEs requested: {len(cve_ids)} (max {MAX_CVE_BULK})",
                "category": "invalid_input",
            })
        now = datetime.now(timezone.utc)

        # Gather all data
        entries: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for cve_id in cve_ids:
            cve_info = self.lookup_cve(cve_id)
            if "error" in cve_info:
                errors.append({
                    "cve_id": cve_info.get("cve_id", cve_id),
                    "error": cve_info["error"],
                })
                continue
            github = self.find_github_pocs(cve_id)
            msf = self.find_metasploit_module(cve_id)
            edb = self.find_exploitdb_entry(cve_id)
            nuc = self.find_nuclei_template(cve_id)
            exploits = github
            for e in [msf, edb, nuc]:
                if e:
                    exploits.append(e)
            bb_reports = self.find_bug_bounty_reports(cve_id)
            labs = self.find_labs(cve_id)
            entries.append({
                "cve_info": cve_info,
                "exploits": exploits,
                "labs": labs,
                "bb_reports": bb_reports,
            })

        # Build HTML
        parts = [
            "<!DOCTYPE html>",
            '<html lang="en">',
            "<head>",
            '  <meta charset="UTF-8">',
            '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
            "  <title>PocMap Vulnerability Report</title>",
            "  <style>",
            "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2em; background: #f5f5f5; }",
            "    .container { max-width: 1200px; margin: 0 auto; }",
            "    h1 { color: #d32f2f; border-bottom: 2px solid #d32f2f; padding-bottom: 0.3em; }",
            "    .entry { background: white; border-radius: 8px; padding: 1.5em; margin-bottom: 1.5em; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }",
            "    .cve-header { background: #fff3f3; border-left: 4px solid #d32f2f; padding: 1em; margin-bottom: 1em; }",
            "    .cve-id { font-size: 1.5em; font-weight: bold; color: #d32f2f; }",
            "    .severity-CRITICAL { color: #d32f2f; font-weight: bold; }",
            "    .severity-HIGH { color: #f57c00; font-weight: bold; }",
            "    .severity-MEDIUM { color: #fbc02d; font-weight: bold; }",
            "    .severity-LOW { color: #388e3c; font-weight: bold; }",
            "    .section { margin-top: 1em; }",
            "    .section h3 { color: #333; border-bottom: 1px solid #ddd; padding-bottom: 0.2em; }",
            "    .exploit-item { background: #f9f9f9; padding: 0.8em; margin: 0.5em 0; border-radius: 4px; }",
            "    .source-badge { display: inline-block; padding: 0.2em 0.6em; border-radius: 4px; font-size: 0.85em; font-weight: bold; margin-right: 0.5em; }",
            "    .source-github { background: #333; color: white; }",
            "    .source-metasploit { background: #1565c0; color: white; }",
            "    .source-exploitdb { background: #d32f2f; color: white; }",
            "    .source-nuclei { background: #e65100; color: white; }",
            "    .metadata { color: #666; font-size: 0.9em; }",
            "    a { color: #1565c0; text-decoration: none; }",
            "    a:hover { text-decoration: underline; }",
            "    .score-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1em; margin: 1em 0; }",
            "    .score-card { background: #fafafa; padding: 1em; border-radius: 4px; text-align: center; }",
            "    .score-value { font-size: 1.5em; font-weight: bold; }",
            "    .poc-badge { background: #4caf50; color: white; padding: 0.1em 0.4em; border-radius: 3px; font-size: 0.8em; }",
            "    .lab-box { background: #e3f2fd; padding: 0.5em 1em; border-radius: 4px; margin: 0.3em 0; }",
            "  </style>",
            "</head>",
            "<body>",
            '  <div class="container">',
            "    <h1>PocMap Vulnerability Report</h1>",
            f"    <p class=\"metadata\">Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}</p>",
            f"    <p class=\"metadata\">Total CVEs: {len(cve_ids)} | Successful: {len(entries)} | Errors: {len(errors)}</p>",
        ]

        for entry in entries:
            cve = entry["cve_info"]
            cvss = cve.get("cvss", {})
            sev = (cvss.get("severity") or "UNKNOWN").upper()
            parts.append('    <div class="entry">')
            parts.append('      <div class="cve-header">')
            parts.append(f'        <div class="cve-id">{cve.get("id", "N/A")}</div>')
            parts.append(f'        <p>{cve.get("description", "No description")}</p>')
            parts.append('      </div>')

            # Score grid
            parts.append('      <div class="score-grid">')
            if cvss.get("score") is not None:
                parts.append('        <div class="score-card">')
                parts.append(f'          <div>CVSS v{cvss.get("version", "?")}</div>')
                parts.append(f'          <div class="score-value severity-{sev}">{cvss["score"]}</div>')
                parts.append(f'          <div class="severity-{sev}">{sev}</div>')
                parts.append('        </div>')
            epss = cve.get("epss_score")
            if epss is not None:
                parts.append('        <div class="score-card">')
                parts.append('          <div>EPSS</div>')
                parts.append(f'          <div class="score-value">{epss:.4f}</div>')
                parts.append('        </div>')
            parts.append('        <div class="score-card">')
            parts.append('          <div>KEV Status</div>')
            kev = "IN KEV" if cve.get("kev_status") else "Not in KEV"
            parts.append(f'          <div class="score-value">{kev}</div>')
            parts.append('        </div>')
            parts.append('      </div>')

            # Exploits
            if entry["exploits"]:
                parts.append('      <div class="section">')
                parts.append(f'        <h3>Exploits & PoCs ({len(entry["exploits"])})</h3>')
                for ex in entry["exploits"]:
                    src = ex.get("source", "unknown").lower()
                    parts.append('        <div class="exploit-item">')
                    parts.append(f'          <span class="source-badge source-{src}">{src.upper()}</span>')
                    parts.append(f'          <strong>{ex.get("title", "Untitled")}</strong>')
                    if ex.get("language"):
                        parts.append(f'          <span class="metadata"> | {ex["language"]}</span>')
                    if ex.get("stars"):
                        parts.append(f'          <span class="metadata"> | Stars: {ex["stars"]}</span>')
                    parts.append(f'          <br><a href="{ex.get("url", "#")}" target="_blank">{ex.get("url", "")}</a>')
                    parts.append('        </div>')
                parts.append('      </div>')

            # Labs
            if entry["labs"]:
                parts.append('      <div class="section">')
                parts.append(f'        <h3>Practice Labs ({len(entry["labs"])})</h3>')
                for lab in entry["labs"]:
                    parts.append(f'        <div class="lab-box"><strong>[{lab.get("platform", "?").upper()}]</strong> <a href="{lab.get("url", "#")}">{lab.get("name", "Unknown")}</a></div>')
                parts.append('      </div>')

            # BB Reports
            if entry["bb_reports"]:
                parts.append('      <div class="section">')
                parts.append(f'        <h3>Bug Bounty Reports ({len(entry["bb_reports"])})</h3>')
                for r in entry["bb_reports"]:
                    poc = ' <span class="poc-badge">PoC</span>' if r.get("has_poc") else ""
                    parts.append(f'        <p><strong>[{r.get("source", "?").upper()}]</strong>{poc} <a href="{r.get("url", "#")}">{r.get("title", "Untitled")}</a></p>')
                parts.append('      </div>')

            parts.append('    </div>')

        # Errors section
        if errors:
            parts.append('    <div class="entry" style="background: #fff8e1; border-left: 4px solid #f57c00;">')
            parts.append(f'      <h3>Errors ({len(errors)})</h3>')
            parts.append('      <p class="metadata">The following CVEs could not be processed:</p>')
            parts.append('      <ul>')
            for err in errors:
                parts.append(f'        <li><strong>{err["cve_id"]}</strong>: {err["error"]}</li>')
            parts.append('      </ul>')
            parts.append('    </div>')

        parts.extend(["  </div>", "</body>", "</html>"])
        html_output = "\n".join(parts)
        return json.dumps({"format": "html", "content": html_output, "cve_count": len(cve_ids), "status": "ok"})

    # -- Product Discovery --

    def discover_product_cves(
        self,
        product: str,
        version: str = "",
        vendor: str = "",
        limit: int = 50,
    ) -> dict[str, Any]:
        """Discover CVEs affecting a product by name and version.

        Args:
            product: Product name (e.g., 'Apache Struts', 'Log4j').
            version: Version string (e.g., '2.x', '2.14.1').
            vendor: Optional vendor name (e.g., 'Apache').
            limit: Maximum number of CVEs to analyze.

        Returns:
            Normalized dict with confirmed_affected, possibly_affected,
            and not_enough_data CVE lists.
        """
        try:
            result = self._product.discover_by_product(
                product=product,
                version=version or None,
                vendor=vendor or None,
                limit=limit,
            )
            return self._normalize_discovery_result(result)
        except Exception as e:
            if is_programming_error(e):
                raise
            logger.warning(f"Product discovery failed: {e}")
            return {"error": f"Product discovery failed ({type(e).__name__})", "product": product}

    # -- Normalizers --

    @staticmethod
    def _enum_val(value: Any, default: str = "") -> str:
        """Safely extract string value from an enum or plain string."""
        if value is None:
            return default
        if isinstance(value, Enum):
            return value.value
        return str(value)

    @staticmethod
    def _normalize_cve_info(info: Any) -> dict[str, Any]:
        """Normalize CVEInfo to a plain dict with consistent field names."""
        if isinstance(info, dict):
            return info
        cvss = info.cvss if hasattr(info, "cvss") else None
        if cvss is not None and hasattr(cvss, "base_score"):
            cvss_data = {
                "version": ServiceAdapter._enum_val(cvss.version, "unknown") if hasattr(cvss, "version") else "unknown",
                "score": cvss.base_score,
                "severity": ServiceAdapter._enum_val(cvss.severity, "UNKNOWN") if hasattr(cvss, "severity") else "UNKNOWN",
                "vector_string": cvss.vector_string,
            }
        else:
            cvss_data = {"version": "unknown", "score": None, "severity": "UNKNOWN", "vector_string": None}

        cve_id = getattr(info, "id", "UNKNOWN")
        # CVEInfo.epss is on a 0-100 scale; normalize to a 0-1 probability.
        epss_raw = getattr(info, "epss", None)
        epss = epss_raw / 100.0 if epss_raw is not None else None

        kev = bool(getattr(info, "kev_status", False))

        refs = getattr(info, "references", {})
        if isinstance(refs, dict):
            ref_list = []
            for v in refs.values():
                if isinstance(v, str):
                    ref_list.extend(v.split("\n"))
                else:
                    ref_list.append(str(v))
        else:
            ref_list = list(refs) if refs else []

        return {
            "id": cve_id,
            "description": getattr(info, "description", None),
            "cvss": cvss_data,
            "epss_score": epss,
            "kev_status": kev,
            "cwes": list(getattr(info, "cwes", [])),
            "references": ref_list,
            "vendor": getattr(info, "vendor", None),
            "product": getattr(info, "product", None),
            "publication_date": getattr(info, "publication_date", None),
            "state": ServiceAdapter._enum_val(getattr(info, "state", "UNKNOWN"), "UNKNOWN"),
        }

    @staticmethod
    def _normalize_exploit(e: Any) -> dict[str, Any]:
        """Normalize Exploit to dict."""
        if e is None:
            return {}
        if isinstance(e, dict):
            return e
        return {
            "source": ServiceAdapter._enum_val(getattr(e, "source", "unknown"), "unknown"),
            "url": getattr(e, "url", ""),
            "title": getattr(e, "title", "Untitled"),
            "language": getattr(e, "language", None),
            "stars": getattr(e, "stars", None),
            "forks": getattr(e, "forks", None),
            "rank": ServiceAdapter._enum_val(getattr(e, "rank", None)) if getattr(e, "rank", None) is not None else None,
        }

    @staticmethod
    def _normalize_bb_report(r: Any) -> dict[str, Any]:
        """Normalize BugBountyReport to dict."""
        if isinstance(r, dict):
            return r
        return {
            "source": ServiceAdapter._enum_val(getattr(r, "source", "unknown"), "unknown"),
            "url": getattr(r, "url", ""),
            "has_poc": getattr(r, "has_poc", None),
            "title": getattr(r, "title", "Untitled"),
        }

    @staticmethod
    def _normalize_lab(lab: Any) -> dict[str, Any]:
        """Normalize LabEnvironment to dict."""
        if isinstance(lab, dict):
            return lab
        return {
            "platform": ServiceAdapter._enum_val(getattr(lab, "platform", "unknown"), "unknown"),
            "name": getattr(lab, "name", "Unknown"),
            "url": getattr(lab, "url", ""),
        }

    @staticmethod
    def _normalize_cpe(c: Any) -> dict[str, Any]:
        """Normalize CPEInfo to dict."""
        if isinstance(c, dict):
            return c
        return {
            "cpe": getattr(c, "cpe_string", getattr(c, "cpe", "")),
            "vendor": getattr(c, "vendor", None),
            "product": getattr(c, "product", None),
            "version": getattr(c, "version", None),
        }

    @staticmethod
    def _normalize_recent_result(r: Any) -> dict[str, Any]:
        """Convert a RecentExploitResult to a JSON-serializable dict."""
        if hasattr(r, "model_dump"):
            return r.model_dump(mode="json")
        if hasattr(r, "to_dict"):
            return r.to_dict()
        if isinstance(r, dict):
            return r
        return dict(r)

    @staticmethod
    def _normalize_discovery_result(r: Any) -> dict[str, Any]:
        """Normalize ProductDiscoveryResult to dict."""
        if isinstance(r, dict):
            return r

        vc = getattr(r, "version_constraint", None)
        vc_dict = None
        if vc is not None:
            if hasattr(vc, "model_dump"):
                vc_dict = vc.model_dump(mode="json")
            else:
                vc_dict = {
                    "major": getattr(vc, "major", None),
                    "minor": getattr(vc, "minor", None),
                    "patch": getattr(vc, "patch", None),
                    "range_op": getattr(vc, "range_op", None),
                    "raw": getattr(vc, "raw", ""),
                    "is_wildcard": getattr(vc, "is_wildcard", False),
                }

        confirmed = [
            ServiceAdapter._normalize_cve_info(c)
            for c in getattr(r, "confirmed_affected", [])
        ]
        possibly = [
            ServiceAdapter._normalize_cve_info(c)
            for c in getattr(r, "possibly_affected", [])
        ]
        unknown = [
            ServiceAdapter._normalize_cve_info(c)
            for c in getattr(r, "not_enough_data", [])
        ]

        return {
            "query": getattr(r, "query", ""),
            "normalized_vendor": getattr(r, "normalized_vendor", None),
            "normalized_product": getattr(r, "normalized_product", None),
            "version_constraint": vc_dict,
            "total_found": getattr(r, "total_found", 0),
            "search_sources": list(getattr(r, "search_sources", [])),
            "confirmed_affected": confirmed,
            "possibly_affected": possibly,
            "not_enough_data": unknown,
            "summary": {
                "confirmed_count": len(confirmed),
                "possibly_count": len(possibly),
                "unknown_count": len(unknown),
            },
        }


# ---------------------------------------------------------------------------
# Global service adapter instance
# ---------------------------------------------------------------------------

_svc = ServiceAdapter()

# ---------------------------------------------------------------------------
# Lifespan context
# ---------------------------------------------------------------------------

@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    """Manage application lifecycle."""
    logger.info("PocMap MCP Server starting up...")
    yield {"services": _svc}
    logger.info("PocMap MCP Server shutting down...")
    _svc.close()


# ---------------------------------------------------------------------------
# FastMCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "PocMap",
    instructions=(
        "You are an AI security assistant with access to the PocMap toolkit. "
        "You can look up CVE details from NVD, CVE.org, CISA KEV, and EPSS sources; "
        "find exploits and PoCs from GitHub, Metasploit, ExploitDB, and Nuclei; "
        "discover bug bounty reports from HackerOne and PentesterLand; "
        "find practice labs on Vulhub, HackTheBox, and TryHackMe; "
        "convert between CVEs and CPEs; and generate vulnerability reports. "
        "Always verify CVE IDs are in the correct format (CVE-YYYY-NNNN+) before querying. "
        "When a user asks about a vulnerability, provide comprehensive context including "
        "CVSS scores, EPSS scores, KEV status, available exploits, and practice environments."
    ),
    lifespan=app_lifespan,
    host="127.0.0.1",
    port=8000,
)


# ===========================================================================
# TOOLS
# ===========================================================================

def _format_cve_text(data: dict[str, Any]) -> str:
    """Format normalized CVE dict as human-readable text."""
    lines = [f"CVE: {data.get('id', 'N/A')}"]
    if data.get("description"):
        lines.append(f"Description: {data['description']}")
    cvss = data.get("cvss", {})
    if cvss.get("score") is not None:
        lines.append(f"CVSS: {cvss['score']} ({cvss.get('severity', 'N/A')}) - v{cvss.get('version', '?')}")
        if cvss.get("vector_string"):
            lines.append(f"Vector: {cvss['vector_string']}")
    epss = data.get("epss_score")
    if epss is not None:
        lines.append(f"EPSS: {epss:.4f}")
    kev = data.get("kev_status")
    lines.append(f"KEV: {'in_kev' if kev else 'not_in_kev'}")
    cwes = data.get("cwes", [])
    if cwes:
        lines.append(f"CWEs: {', '.join(cwes)}")
    vendor = data.get("vendor")
    product = data.get("product")
    if vendor or product:
        v = vendor or "N/A"
        p = product or "N/A"
        lines.append(f"Affected: {v} - {p}")
    if data.get("publication_date"):
        lines.append(f"Published: {data['publication_date']}")
    lines.append(f"State: {data.get('state', 'UNKNOWN')}")
    refs = data.get("references", [])
    if refs:
        lines.append(f"References ({len(refs)}):")
        for ref in refs[:10]:
            lines.append(f"  - {ref}")
    return "\n".join(lines)


def _format_error_json(e: Exception, context: str = "") -> str:
    """Format an exception as a structured JSON error response.

    Categorizes the error for programmatic handling by AI agents.
    Returns generic error messages without raw exception details.
    """
    error_type = type(e).__name__
    category = "unknown"
    retryable = False

    if isinstance(e, (TimeoutError, ConnectionError, OSError)):
        category = "network_error"
        retryable = True
    elif isinstance(e, ValueError):
        category = "invalid_input"
    elif isinstance(e, PermissionError):
        category = "permission_error"

    return json.dumps({
        "error": f"An error occurred ({error_type})",
        "error_type": error_type,
        "category": category,
        "retryable": retryable,
        "context": context,
    })


def _tool_error(e: Exception, context: str) -> str:
    """Log a tool failure and return the structured JSON error response.

    Consolidates the ``logger.error(...); return _format_error_json(...)`` tail
    every ``@mcp.tool`` ``except`` block repeated; *context* is passed straight
    through, so the client-visible error payload is unchanged.
    """
    logger.error("%s: %s", context, e)
    return _format_error_json(e, context)


def _ok(data: Any) -> str:
    """Serialize a successful tool result (``json.dumps(..., indent=2, default=str)``).

    Single home for the serialization contract shared by the CVE/exploit/report
    tools; output is identical to the inline calls it replaces.
    """
    return json.dumps(data, indent=2, default=str)


# ---------------------------------------------------------------------------
# CVE Tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="lookup_cve",
    description=(
        "Look up detailed information about a CVE (Common Vulnerabilities and Exposures) identifier. "
        "Returns the CVE description, CVSS scores, EPSS probability, KEV status, CWE identifiers, "
        "affected vendor/product, publication date, and reference links. "
        "Use this tool when the user provides a CVE ID and wants to understand what the vulnerability is about. "
        "The CVE ID must be in the format CVE-YYYY-NNNN+ (e.g. CVE-2021-44228). "
        "Data sources: NVD, CVE.org, CISA KEV catalog, EPSS."
    ),
)
def lookup_cve(cve_id: str) -> str:
    """Look up detailed CVE information.

    Args:
        cve_id: The CVE identifier (e.g. 'CVE-2021-44228')

    Returns:
        JSON string with structured CVE information including id (the CVE
        identifier), description, cvss (score, severity, version,
        vector_string), epss_score, kev_status, cwes, references, vendor,
        product, publication_date, and state.
    """
    try:
        data = _svc.lookup_cve(cve_id)
        if "error" in data:
            return json.dumps({
                "error": data["error"],
                "category": "not_found" if "not found" in str(data["error"]).lower() else "unknown",
                "cve_id": data.get("cve_id", cve_id.upper().strip()),
            })
        return _ok(data)
    except Exception as e:
        return _tool_error(e, f"lookup_cve({cve_id})")


@mcp.tool(
    name="get_epss_score",
    description=(
        "Get the EPSS (Exploit Prediction Scoring System) score for a CVE. "
        "EPSS is a probability score that predicts the likelihood a vulnerability "
        "will be exploited in the wild within the next 30 days. The returned score "
        "is on a 0.0--1.0 scale (e.g. 0.85 means 85%% probability). Higher scores mean greater risk. "
        "Use this tool when prioritizing vulnerability remediation - CVEs with EPSS > 0.5 should "
        "be patched urgently. EPSS complements CVSS by adding threat intelligence context."
    ),
)
def get_epss_score(cve_id: str) -> str:
    """Get the EPSS probability score for a CVE.

    Args:
        cve_id: The CVE identifier

    Returns:
        JSON string with cve_id, epss_score (0.0-1.0), risk_level
        (LOW/MEDIUM/HIGH/CRITICAL), and interpretation guidance.
    """
    try:
        score = _svc.get_epss(cve_id)
        cve_clean = cve_id.upper().strip()
        if score is not None:
            risk = "CRITICAL" if score > 0.9 else "HIGH" if score > 0.5 else "MEDIUM" if score > 0.2 else "LOW"
            return json.dumps({
                "cve_id": cve_clean,
                "epss_score": score,
                "risk_level": risk,
                "available": True,
                "interpretation": (
                    "EPSS > 0.9: patch immediately. "
                    "EPSS > 0.5: high priority. "
                    "EPSS > 0.2: medium priority. "
                    "EPSS <= 0.2: lower priority."
                ),
            })
        return json.dumps({
            "cve_id": cve_clean,
            "epss_score": None,
            "risk_level": "UNKNOWN",
            "available": False,
            "interpretation": "No EPSS data available for this CVE.",
        })
    except Exception as e:
        return _tool_error(e, f"get_epss_score({cve_id})")


@mcp.tool(
    name="check_kev_status",
    description=(
        "Check if a CVE is listed in the CISA Known Exploited Vulnerabilities (KEV) catalog. "
        "The KEV catalog contains vulnerabilities that have been actively exploited in the wild. "
        "CVEs in the KEV catalog are mandated for patching by US federal agencies within specific timeframes. "
        "Use this tool to determine if a vulnerability is being actively exploited - KEV entries "
        "should be prioritized for immediate remediation regardless of CVSS score."
    ),
)
def check_kev_status(cve_id: str) -> str:
    """Check if a CVE is in the CISA KEV catalog.

    Args:
        cve_id: The CVE identifier

    Returns:
        JSON string with cve_id, kev_status (bool), description of what
        KEV means, and recommended action based on the result.
    """
    try:
        is_kev = _svc.check_kev(cve_id)
        cve_clean = cve_id.upper().strip()
        return json.dumps({
            "cve_id": cve_clean,
            "kev_status": is_kev,
            "in_kev_catalog": is_kev,
            "description": (
                "CISA Known Exploited Vulnerabilities (KEV) catalog lists "
                "vulnerabilities that have been actively exploited in the wild."
            ),
            "recommendation": (
                "PRIORITIZE FOR IMMEDIATE PATCHING - this CVE is actively exploited."
                if is_kev else
                "Not in KEV catalog - prioritize based on CVSS and EPSS scores."
            ),
        })
    except Exception as e:
        return _tool_error(e, f"check_kev_status({cve_id})")


# ---------------------------------------------------------------------------
# Exploit Tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="find_github_pocs",
    description=(
        "Find GitHub repositories containing Proof-of-Concept (PoC) exploits for a CVE. "
        "Returns a list of GitHub repos with titles, URLs, programming languages, star counts, "
        "fork counts, and relevance rankings. These repos often contain working exploit code, "
        "vulnerable applications for testing, detection scripts, and educational materials. "
        "Use this tool when the user wants to find exploit code, understand how a vulnerability "
        "is exploited, or find detection/remediation scripts on GitHub. Results are sorted by stars."
    ),
)
def find_github_pocs(cve_id: str, limit: int = 10) -> str:
    """Find GitHub PoC repositories for a CVE.

    Args:
        cve_id: The CVE identifier
        limit: Maximum number of results (1-50, default: 10)

    Returns:
        JSON string with cve_id, total_count, a list of PoC objects
        (source, url, title, language, stars, forks), and a ``sources`` block
        reporting per-source health (status ``ok``/``empty``/``rate_limited``/
        ``error``, plus category/retryable) so a throttled or down GitHub is
        never reported as "no PoCs found".
    """
    try:
        limit = max(1, min(50, limit))
        data = _svc.find_github_pocs_with_sources(cve_id, limit)
        cve_clean = cve_id.upper().strip()
        return _ok({
            "cve_id": cve_clean,
            "total_count": len(data["pocs"]),
            "pocs": data["pocs"],
            "sources": data["sources"],
        })
    except Exception as e:
        return _tool_error(e, f"find_github_pocs({cve_id})")


@mcp.tool(
    name="find_metasploit_module",
    description=(
        "Find a Metasploit Framework module for a CVE. "
        "Metasploit is a widely-used penetration testing framework. If a module exists, "
        "it means the vulnerability can be reliably exploited using Metasploit's standardized interface. "
        "Returns the module title, source URL, and msfconsole command. "
        "Use this tool when assessing whether automated exploitation is possible, or when "
        "planning penetration tests. The existence of a Metasploit module indicates mature exploit code."
    ),
)
def find_metasploit_module(cve_id: str, limit: int = 1) -> str:
    """Find a Metasploit module for a CVE.

    Args:
        cve_id: The CVE identifier
        limit: Maximum number of results (1-10, default: 1)

    Returns:
        JSON string with cve_id, found (bool), and module details
        (source, title, url) when available.
    """
    try:
        limit = max(1, min(10, limit))
        exploit = _svc.find_metasploit_module(cve_id, limit=limit)
        cve_clean = cve_id.upper().strip()
        return _ok({
            "cve_id": cve_clean,
            "found": exploit is not None and bool(exploit),
            "module": exploit if exploit else None,
            "note": (
                "Metasploit module available - indicates mature, reliable exploit code."
                if exploit else
                "No Metasploit module found - may still have other exploit sources."
            ),
        })
    except Exception as e:
        return _tool_error(e, f"find_metasploit_module({cve_id})")


@mcp.tool(
    name="find_exploitdb_entry",
    description=(
        "Find an ExploitDB entry for a CVE. "
        "ExploitDB is the ultimate archive of exploit code and proof-of-concepts. "
        "An entry typically contains working exploit code that can be downloaded and used directly. "
        "Returns the entry title, source URL on exploit-db.com, and searchsploit command. "
        "Use this tool when looking for standalone exploit scripts that can be run independently "
        "of frameworks like Metasploit. ExploitDB entries are often the first exploits published."
    ),
)
def find_exploitdb_entry(cve_id: str, limit: int = 1) -> str:
    """Find an ExploitDB entry for a CVE.

    Args:
        cve_id: The CVE identifier
        limit: Maximum number of results (1-10, default: 1)

    Returns:
        JSON string with cve_id, found (bool), and entry details
        (source, title, url) when available.
    """
    try:
        limit = max(1, min(10, limit))
        exploit = _svc.find_exploitdb_entry(cve_id, limit=limit)
        cve_clean = cve_id.upper().strip()
        return _ok({
            "cve_id": cve_clean,
            "found": exploit is not None and bool(exploit),
            "entry": exploit if exploit else None,
            "note": (
                "ExploitDB entry available - often the first standalone exploit published."
                if exploit else
                "No ExploitDB entry found - may still have other exploit sources."
            ),
        })
    except Exception as e:
        return _tool_error(e, f"find_exploitdb_entry({cve_id})")


@mcp.tool(
    name="find_nuclei_template",
    description=(
        "Find a Nuclei vulnerability scanner template for a CVE. "
        "Nuclei is a fast, community-powered vulnerability scanner that uses YAML templates "
        "to detect security issues. If a template exists, you can use Nuclei to quickly scan "
        "for the vulnerability across your infrastructure. "
        "Returns the template title and source URL on GitHub. "
        "Use this tool when you need to detect or verify the presence of a vulnerability "
        "in your environment. Nuclei templates provide standardized, reliable detection."
    ),
)
def find_nuclei_template(cve_id: str, limit: int = 1) -> str:
    """Find a Nuclei template for a CVE.

    Args:
        cve_id: The CVE identifier
        limit: Maximum number of results (1-10, default: 1)

    Returns:
        JSON string with cve_id, found (bool), and template details
        (source, title, url) when available.
    """
    try:
        limit = max(1, min(10, limit))
        exploit = _svc.find_nuclei_template(cve_id, limit=limit)
        cve_clean = cve_id.upper().strip()
        return _ok({
            "cve_id": cve_clean,
            "found": exploit is not None and bool(exploit),
            "template": exploit if exploit else None,
            "note": (
                "Nuclei template available - can be used for rapid detection/verification."
                if exploit else
                "No Nuclei template found - may still have other exploit sources."
            ),
        })
    except Exception as e:
        return _tool_error(e, f"find_nuclei_template({cve_id})")


# ---------------------------------------------------------------------------
# Bug Bounty Tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="find_bug_bounty_reports",
    description=(
        "Find bug bounty reports and write-ups for a CVE. "
        "Bug bounty reports provide real-world exploitation techniques, impact assessments, "
        "and detailed write-ups from security researchers who found the vulnerability in production. "
        "Returns reports from platforms like HackerOne, PentesterLand, and Bug Bounty Hunting "
        "with titles, URLs, and indicators of whether a Proof-of-Concept is included. "
        "Use this tool when you want to understand how a vulnerability is exploited in real-world "
        "scenarios, learn from security researchers' methodologies, or find detailed technical write-ups."
    ),
)
def find_bug_bounty_reports(cve_id: str) -> str:
    """Find bug bounty reports for a CVE.

    Args:
        cve_id: The CVE identifier

    Returns:
        JSON string with cve_id, total_count, and a list of report objects
        (source, url, title, has_poc).
    """
    try:
        reports = _svc.find_bug_bounty_reports(cve_id)
        cve_clean = cve_id.upper().strip()
        return _ok({
            "cve_id": cve_clean,
            "total_count": len(reports),
            "reports": reports,
        })
    except Exception as e:
        return _tool_error(e, f"find_bug_bounty_reports({cve_id})")


# ---------------------------------------------------------------------------
# Lab Tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="find_practice_labs",
    description=(
        "Find CTF (Capture The Flag) labs, vulnerable machines, and practice environments "
        "for a CVE. These labs provide safe, legal environments to practice exploiting the vulnerability. "
        "Returns labs from platforms like Vulhub (Docker-based), TryHackMe, and HackTheBox. "
        "Each lab includes the platform name, challenge name, URL, and setup instructions. "
        "Use this tool when you want hands-on practice with a vulnerability, need to demonstrate "
        "exploitation safely, or want to build detection rules in a controlled environment."
    ),
)
def find_practice_labs(cve_id: str) -> str:
    """Find CTF labs and practice environments for a CVE.

    Args:
        cve_id: The CVE identifier

    Returns:
        JSON string with cve_id, total_count, and a list of lab objects
        (platform, name, url).
    """
    try:
        labs = _svc.find_labs(cve_id)
        cve_clean = cve_id.upper().strip()
        return _ok({
            "cve_id": cve_clean,
            "total_count": len(labs),
            "labs": labs,
        })
    except Exception as e:
        return _tool_error(e, f"find_practice_labs({cve_id})")


@mcp.tool(
    name="find_vulhub_docker",
    description=(
        "Find a Vulhub Docker environment for a CVE. "
        "Vulhub provides pre-built Docker Compose environments for vulnerable applications, "
        "making it trivial to spin up a practice lab with 'docker compose up'. "
        "Returns the GitHub URL to the Vulhub directory containing the Docker files and setup instructions. "
        "Use this tool when you want the quickest way to set up a local practice environment "
        "for a vulnerability. Docker environments are isolated, reproducible, and easy to clean up."
    ),
)
def find_vulhub_docker(cve_id: str) -> str:
    """Find a Vulhub Docker environment for a CVE.

    Args:
        cve_id: The CVE identifier

    Returns:
        JSON string with cve_id, found (bool), url, and setup instructions
        when a Vulhub environment is available.
    """
    try:
        url = _svc.find_docker_env(cve_id)
        cve_clean = cve_id.upper().strip()
        if url:
            parts = url.rstrip("/").split("/")
            path_suffix = "/".join(parts[-2:]) if len(parts) >= 2 else ""
            return json.dumps({
                "cve_id": cve_clean,
                "found": True,
                "url": url,
                "setup_instructions": {
                    "clone": "git clone --depth 1 https://github.com/vulhub/vulhub.git",
                    "navigate": f"cd vulhub/{path_suffix}",
                    "start": "docker compose up -d",
                    "stop": "docker compose down",
                },
            })
        return json.dumps({
            "cve_id": cve_clean,
            "found": False,
            "url": None,
            "note": "No Vulhub Docker environment found. Try find_practice_labs for other platforms.",
        })
    except Exception as e:
        return _tool_error(e, f"find_vulhub_docker({cve_id})")


# ---------------------------------------------------------------------------
# CPE Tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="cve_to_cpe",
    description=(
        "Convert a CVE ID to its associated CPE (Common Platform Enumeration) identifiers. "
        "CPEs are standardized identifiers for software and hardware products. "
        "This conversion helps identify the exact software versions and configurations "
        "that are affected by a vulnerability. "
        "Returns CPE 2.3 URIs with vendor, product, and version information. "
        "Use this tool for asset inventory correlation - map CVEs to actual products in your "
        "environment to determine exposure."
    ),
)
def cve_to_cpe(cve_id: str) -> str:
    """Convert a CVE to its associated CPEs.

    Args:
        cve_id: The CVE identifier

    Returns:
        JSON string with cve_id, total_count, and a list of CPE objects
        (cpe, vendor, product, version).
    """
    try:
        cpes = _svc.cve_to_cpe(cve_id)
        cve_clean = cve_id.upper().strip()
        return _ok({
            "cve_id": cve_clean,
            "total_count": len(cpes),
            "cpes": cpes,
        })
    except Exception as e:
        return _tool_error(e, f"cve_to_cpe({cve_id})")


@mcp.tool(
    name="cpe_to_cve",
    description=(
        "Convert a CPE (Common Platform Enumeration) identifier to its associated CVEs. "
        "Given a software/hardware product identifier, this finds all known vulnerabilities "
        "affecting that product. "
        "Returns a list of CVE identifiers. "
        "Use this tool for vulnerability assessment of specific products - provide a CPE or "
        "product name to discover all CVEs that affect it. This is essential for asset-based "
        "vulnerability management."
    ),
)
def cpe_to_cve(cpe: str) -> str:
    """Convert a CPE to its associated CVEs.

    Args:
        cpe: CPE 2.3 URI or simplified product identifier

    Returns:
        JSON string with cpe, total_count, and a list of CVE identifiers.
    """
    try:
        cves = _svc.cpe_to_cve(cpe)
        return _ok({
            "cpe": cpe,
            "total_count": len(cves),
            "cve_ids": cves,
        })
    except Exception as e:
        return _tool_error(e, f"cpe_to_cve({cpe})")


# ---------------------------------------------------------------------------
# Product Discovery Tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="discover_product_cves",
    description=(
        "Discover CVEs affecting a product by name and version. "
        "Use when the user provides a product name but not a specific CVE ID. "
        "Supports version wildcards like '2.x' and product aliases (e.g., 'struts' matches 'Apache Struts'). "
        "Results are grouped by confidence: confirmed_affected (vendor+product+version match), "
        "possibly_affected (vendor or product match but version unclear), and "
        "not_enough_data (insufficient product/version info). "
        "This tool searches the NVD database using keyword search and applies "
        "fuzzy product name matching and version constraint parsing for accurate results."
    ),
)
def discover_product_cves(
    product: str,
    version: str = "",
    vendor: str = "",
    limit: int = 50,
) -> str:
    """Discover CVEs affecting a product by name and version.

    Args:
        product: Product name (e.g., 'Apache Struts', 'Log4j', 'nginx')
        version: Version string (e.g., '2.x', '2.14.1', '1.20.1').
                 Supports wildcards (2.x), exact versions, and range operators.
        vendor: Optional vendor name (e.g., 'Apache', 'Microsoft').
        limit: Maximum number of CVEs to analyze (1-100, default: 50).

    Returns:
        JSON string with query details, normalized vendor/product,
        version constraint, and CVEs grouped by confidence level:
        confirmed_affected, possibly_affected, not_enough_data.
        Each CVE includes id, description, cvss, vendor, product, etc.
    """
    try:
        limit = max(1, min(100, limit))
        result = _svc.discover_product_cves(
            product=product,
            version=version,
            vendor=vendor,
            limit=limit,
        )
        if "error" in result:
            return json.dumps({
                "error": result["error"],
                "category": "discovery_failed",
                "product": product,
            })
        return _ok(result)
    except Exception as e:
        return _tool_error(e, f"discover_product_cves({product})")


# ---------------------------------------------------------------------------
# Report Tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="generate_json_report",
    description=(
        "Generate a comprehensive JSON vulnerability report for one or more CVEs. "
        "The report includes CVE details (description, CVSS, EPSS, KEV status), all discovered "
        "exploits and PoCs, available practice labs, and bug bounty reports. "
        "The JSON format is suitable for programmatic processing, CI/CD pipelines, and "
        "integration with other security tools. "
        "Use this tool when you need structured data for automation, vulnerability management "
        "platforms, or security dashboards."
    ),
)
def generate_json_report(cve_ids: str) -> str:
    """Generate a JSON report for one or more CVEs.

    Args:
        cve_ids: Comma-separated list of CVE identifiers
            (e.g. 'CVE-2021-44228' for a single CVE,
            or 'CVE-2021-44228,CVE-2023-44487,CVE-2024-21413'
            for multiple CVEs). Whitespace around commas is trimmed.

    Returns:
        JSON-formatted vulnerability report containing for each CVE:
        cve_info (description, CVSS, EPSS, KEV), exploits (GitHub PoCs,
        Metasploit, ExploitDB, Nuclei), labs, and bug bounty reports.
        The top-level object also includes generated_at timestamp,
        total_requested, total_entries, and any errors encountered.
    """
    try:
        ids = [c.strip().upper() for c in cve_ids.split(",") if c.strip()]
        if not ids:
            return json.dumps({
                "error": "No valid CVE IDs provided.",
                "category": "invalid_input",
                "hint": "Provide one or more comma-separated CVE IDs, e.g. 'CVE-2021-44228,CVE-2023-44487'",
            })
        return _svc.generate_json_report(ids)
    except Exception as e:
        return _tool_error(e, f"generate_json_report({cve_ids})")


@mcp.tool(
    name="generate_html_report",
    description=(
        "Generate a comprehensive HTML vulnerability report for one or more CVEs. "
        "The report includes styled cards with CVE details (description, CVSS, EPSS, KEV status), "
        "all discovered exploits and PoCs with source badges, available practice labs, "
        "and bug bounty reports. The HTML is self-contained with embedded CSS for immediate viewing. "
        "Use this tool when creating human-readable reports for stakeholders, security teams, "
        "or documentation. The HTML report can be saved to a file and opened in any browser."
    ),
)
def generate_html_report(cve_ids: str) -> str:
    """Generate an HTML report for one or more CVEs.

    Args:
        cve_ids: Comma-separated list of CVE identifiers
            (e.g. 'CVE-2021-44228' or 'CVE-2021-44228,CVE-2023-44487').
            Whitespace around commas is trimmed.

    Returns:
        Self-contained HTML vulnerability report with embedded CSS.
        The HTML includes styled cards for each CVE with CVSS/EPSS/KEV
        summaries, exploit lists with source badges, lab links, and
        bug bounty report references. Save the output to a .html file
        and open in any browser.
    """
    try:
        ids = [c.strip().upper() for c in cve_ids.split(",") if c.strip()]
        if not ids:
            return json.dumps({
                "error": "No valid CVE IDs provided.",
                "category": "invalid_input",
                "hint": "Provide one or more comma-separated CVE IDs, e.g. 'CVE-2021-44228,CVE-2023-44487'",
            })
        result = _svc.generate_html_report(ids)
        # ServiceAdapter always returns JSON (either error or success envelope)
        return result
    except Exception as e:
        return _tool_error(e, f"generate_html_report({cve_ids})")


# ---------------------------------------------------------------------------
# Recent CVE Discovery Tools
# ---------------------------------------------------------------------------

@mcp.tool(
    name="find_recent_exploits",
    description=(
        "Find recently published CVEs with exploit and PoC intelligence. "
        "Scans the NVD for newly published vulnerabilities within a configurable time window, "
        "then enriches each CVE with CVSS scoring, CISA KEV status, and PoC availability from GitHub. "
        "Results can be filtered by severity, KEV status, minimum EPSS score, and PoC availability. "
        "Use this tool to stay on top of emerging threats, monitor vulnerability disclosures, "
        "or build daily/weekly security briefings. Time window can be specified as a relative "
        "string (e.g., '24h', '7d') or as explicit date range."
    ),
)
def find_recent_exploits(
    since: str = "24h",
    from_date: str = "",
    to_date: str = "",
    only_with_poc: bool = False,
    kev_only: bool = False,
    min_epss: float = 0.0,
    severity: str = "",
    sort: str = "cve_date",
    limit: int = 50,
) -> str:
    """Find recently published CVEs with exploit/PoC intelligence.

    Args:
        since: Relative time window (e.g., '1h', '24h', '7d', '30d').
            Ignored if from_date is provided.
        from_date: Explicit start date (YYYY-MM-DD). Overrides *since*.
        to_date: Explicit end date (YYYY-MM-DD). Defaults to today.
        only_with_poc: Only return CVEs with known PoCs on GitHub.
        kev_only: Only return CISA KEV entries.
        min_epss: Minimum EPSS score, expressed on the 0--100
            percentage scale (e.g. 50.0 means EPSS >= 50%%). EPSS is
            the Exploit Prediction Scoring System probability
            (0 = no filter, 100 = only the most likely to be
            exploited). Higher values filter for CVEs more likely
            to be exploited in the wild within 30 days. Note: this
            input uses the 0--100 scale, not the 0.0--1.0 scale.
        severity: Comma-separated severity levels
            (e.g., 'CRITICAL,HIGH' or 'critical,high').
        sort: Sort results by 'cve_date' (newest first), 'severity'
            (highest first), or 'epss' (highest first).
        limit: Maximum number of results (1--100, default: 50).

    Returns:
        JSON string with query parameters and a list of CVE objects,
        each containing cve_id, description, severity, base_score,
        epss, kev_status, vendor, product, publication_date, has_poc,
        and poc_sources.
    """
    try:
        limit = max(1, min(100, limit))
        result = _svc.find_recent_exploits(
            since=since,
            from_date=from_date,
            to_date=to_date,
            only_with_poc=only_with_poc,
            kev_only=kev_only,
            min_epss=min_epss,
            severity=severity,
            sort=sort,
            limit=limit,
        )
        return _ok(result)
    except Exception as e:
        return _tool_error(e, "find_recent_exploits()")


# ---------------------------------------------------------------------------
# Playbook Tools - expose structured JSON playbooks to AI agents
# ---------------------------------------------------------------------------

# Base directory for playbooks, resolved relative to this file
_PLAYBOOKS_DIR = Path(__file__).resolve().parent / "src" / "pocmap" / "bugbounty" / "playbooks"


def _load_playbook(filename: str) -> str:
    """Load a playbook JSON file and return its contents as a JSON string.

    Falls back to an error JSON if the file is missing or unreadable.
    """
    if ".." in filename or os.path.sep in filename:
        return json.dumps({"error": "Invalid filename"})
    path = _PLAYBOOKS_DIR / filename
    try:
        if not path.exists():
            return json.dumps({
                "error": f"Playbook file not found: {filename}",
                "category": "not_found",
            })
        with open(path, encoding="utf-8") as f:
            content = json.load(f)
        return json.dumps(content, indent=2)
    except json.JSONDecodeError:
        return json.dumps({
            "error": f"Invalid JSON in playbook {filename}",
            "category": "invalid_input",
        })
    except Exception as e:
        return json.dumps({"error": f"Failed to load playbook ({type(e).__name__})"})


@mcp.tool(
    name="get_cve_assessment_playbook",
    description=(
        "Get the complete CVE assessment playbook with detailed step-by-step workflow. "
        "This playbook guides AI agents through systematic evaluation of CVEs including "
        "context gathering, exploit landscape analysis, real-world impact assessment, "
        "risk prioritization, and actionable remediation recommendations. "
        "Use this tool when starting a comprehensive vulnerability assessment workflow."
    ),
)
def get_cve_assessment_playbook() -> str:
    """Get the complete CVE assessment playbook with detailed step-by-step workflow.

    Returns:
        JSON string containing the full CVE assessment playbook with phases,
        decision trees, and structured guidance for evaluating vulnerabilities.
    """
    return _load_playbook("cve-assessment-playbook.json")


@mcp.tool(
    name="get_rapid_response_playbook",
    description=(
        "Get the rapid response playbook for emergency critical CVE handling. "
        "This playbook provides a fast-track workflow for CVEs with CRITICAL severity, "
        "high EPSS scores, or active KEV status. It includes immediate containment steps, "
        "rapid detection, emergency patching procedures, and stakeholder communication templates. "
        "Use this tool when dealing with an actively exploited or high-impact vulnerability."
    ),
)
def get_rapid_response_playbook() -> str:
    """Get the rapid response playbook for emergency critical CVE handling.

    Returns:
        JSON string containing the rapid response playbook with emergency
        procedures, decision trees, and time-bounded action items.
    """
    return _load_playbook("rapid-response-playbook.json")


@mcp.tool(
    name="get_bug_bounty_playbook",
    description=(
        "Get the bug bounty submission playbook from finding to report submission. "
        "This playbook guides researchers through the complete bug bounty workflow: "
        "reconnaissance, vulnerability identification, PoC development, report writing, "
        "submission formatting, and follow-up communication. "
        "Use this tool when preparing a bug bounty report or learning the submission process."
    ),
)
def get_bug_bounty_playbook() -> str:
    """Get the bug bounty submission playbook from finding to report submission.

    Returns:
        JSON string containing the bug bounty submission playbook with
        phases, templates, checklists, and best practices for successful submissions.
    """
    return _load_playbook("bb-submission-playbook.json")


# ===========================================================================
# RESOURCES
# ===========================================================================

@mcp.resource(
    uri="cve://{cve_id}",
    name="cve_info",
    description="Full CVE information including description, CVSS scores, EPSS, KEV status, CWEs, references, and affected vendor/product.",
    mime_type="text/plain",
)
def get_cve_resource(cve_id: str) -> str:
    """Resource: Full CVE information. URI template: cve://{cve_id}"""
    try:
        data = _svc.lookup_cve(cve_id)
        if "error" in data:
            return f"Error: {data['error']}"
        return _format_cve_text(data)
    except Exception as e:
        return f"Error retrieving CVE resource ({type(e).__name__})"


@mcp.resource(
    uri="exploits://{cve_id}",
    name="cve_exploits",
    description="Complete list of available exploits and PoCs for a CVE from all sources (GitHub, Metasploit, ExploitDB, Nuclei).",
    mime_type="text/plain",
)
def get_exploits_resource(cve_id: str) -> str:
    """Resource: Exploit list for a CVE. URI template: exploits://{cve_id}"""
    try:
        exploits: list[dict[str, Any]] = []
        exploits.extend(_svc.find_github_pocs(cve_id))
        msf = _svc.find_metasploit_module(cve_id)
        if msf:
            exploits.append(msf)
        edb = _svc.find_exploitdb_entry(cve_id)
        if edb:
            exploits.append(edb)
        nuc = _svc.find_nuclei_template(cve_id)
        if nuc:
            exploits.append(nuc)

        if not exploits:
            return f"No exploits found for {cve_id.upper().strip()}."

        lines = [f"Exploits for {cve_id.upper().strip()} ({len(exploits)} total):", ""]
        for i, e in enumerate(exploits, 1):
            lines.append(f"{i}. [{e.get('source', 'UNKNOWN').upper()}] {e.get('title', 'Untitled')}")
            lines.append(f"   URL: {e.get('url', 'N/A')}")
            if e.get("language"):
                lines.append(f"   Language: {e['language']}")
            if e.get("stars"):
                lines.append(f"   Stars: {e['stars']}")
            lines.append("")
        return "\n".join(lines)
    except Exception as e:
        return f"Error retrieving exploits resource ({type(e).__name__})"


@mcp.resource(
    uri="report://{cve_id}",
    name="cve_report",
    description="Generated vulnerability report for a CVE including CVE info, exploits, labs, and bug bounty reports (JSON format).",
    mime_type="application/json",
)
def get_report_resource(cve_id: str) -> str:
    """Resource: Full vulnerability report. URI template: report://{cve_id}"""
    try:
        return _svc.generate_json_report([cve_id.upper().strip()])
    except Exception as e:
        return json.dumps({"error": f"Report generation failed ({type(e).__name__})"})


# ===========================================================================
# PROMPTS
# ===========================================================================

@mcp.prompt(
    name="vulnerability_assessment",
    description="Structured vulnerability assessment workflow for analyzing CVEs. Guides through systematic evaluation of threat context, exploitability, and remediation priorities.",
)
def vulnerability_assessment_prompt(cve_id: str) -> str:
    """Prompt: Vulnerability assessment workflow.

    Args:
        cve_id: The CVE identifier to assess
    """
    return f"""You are performing a comprehensive vulnerability assessment for {cve_id.upper().strip()}. Follow this structured workflow:

## Phase 1: Context Gathering
- Look up the CVE details to understand what the vulnerability is
- Check the CVSS score and severity to understand technical impact
- Get the EPSS score to assess exploitation probability
- Check KEV status to determine if it's actively exploited

## Phase 2: Exploit Landscape Analysis
- Find all available GitHub PoCs and examine their quality and recency
- Check for Metasploit modules (indicates reliable, weaponized exploits)
- Look for ExploitDB entries (often the first exploits available)
- Find Nuclei templates (for detection and verification)

## Phase 3: Real-World Impact
- Search for bug bounty reports showing real-world exploitation
- Identify practice labs for hands-on understanding

## Phase 4: Risk Assessment & Prioritization
- Combine CVSS severity + EPSS probability + KEV status for a holistic risk score
- If EPSS > 0.5 OR KEV=true: CRITICAL priority for patching
- If CVSS >= 9.0: HIGH priority regardless of other factors
- If CVSS >= 7.0 and EPSS > 0.2: MEDIUM-HIGH priority
- Consider available exploits as an indicator of ease of exploitation

## Phase 5: Recommendations
Provide actionable remediation advice including:
- Immediate containment steps
- Patch availability and timeline
- Detection rules or monitoring recommendations
- Compensating controls if patching is delayed

Execute this workflow for {cve_id.upper().strip()} and provide a comprehensive assessment."""


@mcp.prompt(
    name="exploit_research",
    description="Deep exploit research prompt for analyzing available exploit code, understanding exploitation techniques, and building detection rules.",
)
def exploit_research_prompt(cve_id: str, focus_area: str = "all") -> str:
    """Prompt: Exploit research workflow.

    Args:
        cve_id: The CVE identifier to research
        focus_area: Specific focus - 'all', 'detection', 'exploitation', 'remediation', or 'analysis'
    """
    focus_map = {
        "all": "comprehensive analysis covering all aspects",
        "detection": "building detection rules and indicators of compromise",
        "exploitation": "understanding exploitation techniques and attack vectors",
        "remediation": "finding patches, workarounds, and compensating controls",
        "analysis": "deep technical analysis of the vulnerability root cause",
    }
    focus_desc = focus_map.get(focus_area.lower(), focus_map["all"])

    return f"""You are conducting exploit research for {cve_id.upper().strip()} with a focus on {focus_desc}.

## Research Objectives
1. **Find all available exploits** - GitHub PoCs, Metasploit modules, ExploitDB entries, Nuclei templates
2. **Analyze exploitation techniques** - Understand the attack vector, prerequisites, and impact
3. **Assess exploit maturity** - Check if exploits are reliable, weaponized, or proof-of-concept only
4. **Build detection capability** - Identify IOCs, network signatures, and behavioral patterns

## Research Questions to Answer
- What is the vulnerability type and root cause?
- What are the prerequisites for exploitation?
- What is the attack vector (network, local, adjacent, physical)?
- Does the exploit require authentication?
- What is the blast radius if exploited?
- Are there public reports of in-the-wild exploitation?
- What detection methods are available?

## Deliverables
Provide a research brief with:
1. Executive summary (2-3 sentences)
2. Available exploits inventory with quality ratings
3. Exploitation technique analysis
4. Detection recommendations (signatures, behavioral rules, log analysis)
5. Remediation guidance

Begin by looking up the CVE details and finding all available exploits for {cve_id.upper().strip()}."""


@mcp.prompt(
    name="bug_bounty_analysis",
    description="Analyze bug bounty reports to extract exploitation techniques, real-world impact assessments, and security lessons learned.",
)
def bug_bounty_analysis_prompt(cve_id: str) -> str:
    """Prompt: Bug bounty report analysis.

    Args:
        cve_id: The CVE identifier to analyze
    """
    return f"""You are analyzing bug bounty reports for {cve_id.upper().strip()} to extract real-world security insights.

## Analysis Framework

### 1. Report Collection
- Find all bug bounty reports and write-ups for this CVE
- Note which platforms (HackerOne, Bugcrowd, Intigriti) have reports
- Identify reports that include PoCs (Proof-of-Concept demonstrations)

### 2. Impact Analysis
For each report found, analyze:
- **Affected scope**: Which companies/services were impacted?
- **Bounty amount**: What was the reward (if disclosed)?
- **Severity**: How did the platform classify it?
- **Exploitation path**: How did the researcher exploit it?
- **Business impact**: What was the real-world consequence?

### 3. Technique Extraction
- Document the specific exploitation techniques used
- Identify any novel or creative attack vectors discovered
- Note any bypasses of existing mitigations
- Catalog tools and methodologies used by researchers

### 4. Lessons Learned
- What does this teach about the vulnerability class?
- What detection/prevention gaps were exposed?
- How can organizations better protect against this?
- What secure coding practices would have prevented this?

### 5. Actionable Recommendations
Provide:
- Security testing guidance for this vulnerability class
- Detection engineering recommendations
- Secure development practices
- Defensive architecture suggestions

Search for bug bounty reports on {cve_id.upper().strip()} and provide a comprehensive analysis."""


# ===========================================================================
# Main entry point
# ===========================================================================

def main():
    """Run the MCP server with the specified transport."""
    parser = argparse.ArgumentParser(
        description="PocMap AI MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python mcp_server.py                           # STDIO transport (default)
  python mcp_server.py --transport sse           # SSE transport on port 8000
  python mcp_server.py --transport http          # Streamable HTTP transport
  python mcp_server.py --host 0.0.0.0 --port 9000 --transport sse
        """,
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "http"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to for SSE/HTTP transports (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to for SSE/HTTP transports (default: 8000)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("Starting PocMap MCP Server with %s transport", args.transport)

    mcp.host = args.host
    mcp.port = args.port
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
