"""Service adapter — normalizes pocmap service results into plain dicts."""

from __future__ import annotations

import logging
from contextlib import suppress
from datetime import datetime, timezone
from enum import Enum
from typing import Any, cast

from pocmap.mcp.html_report import _build_html_report
from pocmap.models import ExploitSource, LabPlatform
from pocmap.services.bb_service import BugBountyService
from pocmap.services.cve_service import CVEService
from pocmap.services.exploit_service import ExploitService
from pocmap.services.lab_service import LabService
from pocmap.services.package_service import PackageService
from pocmap.services.product_service import ProductDiscoveryService
from pocmap.services.recent_service import RecentService
from pocmap.utils.http import (
    HTTPError,
    NotFoundError,
    categorize_exception,
    is_programming_error,
)

logger = logging.getLogger("pocmap-mcp")

# Maximum number of CVEs allowed in bulk report operations
MAX_CVE_BULK = 100

# EPSS is published to 5 decimal places, so rounding the 0-100 -> 0-1
# conversion there is lossless and keeps float noise out of the payload.
_EPSS_DP = 5


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
        self._package: Any = PackageService()

    def close(self) -> None:
        """Close all services to release resources."""
        for svc_name in ("_recent", "_product", "_package", "_cve", "_exploit", "_bb", "_lab"):
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
            category, retryable = categorize_exception(e)
            if isinstance(e, NotFoundError):
                category, retryable = "not_found", False
            return {
                "error": f"CVE lookup failed ({type(e).__name__})",
                "cve_id": cve_id,
                "category": category,
                "error_type": type(e).__name__,
                "retryable": retryable,
            }

    def get_epss(self, cve_id: str) -> float | None:
        """Get EPSS score. Returns 0-1 range."""
        try:
            info = self._cve.get_cve_info(cve_id)
            epss = info.epss
            # CVEInfo.epss is on a 0-100 scale; normalize to a 0-1 probability.
            # Rounded to 5 dp — EPSS publishes 5, and a bare divide leaks float
            # noise (99.99 / 100 -> 0.9998999999999999) into the payload.
            return round(epss / 100.0, _EPSS_DP) if epss is not None else None
        except Exception as e:
            if is_programming_error(e):
                raise
            if isinstance(e, HTTPError):  # RateLimitError/OfflineError/network are real errors, not 'empty'
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
            if isinstance(e, HTTPError):  # RateLimitError/OfflineError/network are real errors, not 'empty'
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

    def verify_github_pocs(self, cve_id: str, limit: int = 5) -> list[dict[str, Any]]:
        """Fetch and score the top PoCs' source (opt-in; see the tool docs).

        Rows are already plain dicts, so no normalizer is needed. Failures are
        deliberately NOT swallowed here: the common one is the operator not
        having opted in, which the agent must report rather than read as
        "no PoCs could be verified".
        """
        return cast("list[dict[str, Any]]", self._exploit.verify_github_pocs(cve_id, limit=limit))

    def get_attack_techniques(self, cve_id: str) -> dict[str, Any]:
        """Curated MITRE ATT&CK techniques for a CVE, split by mapping type."""
        techniques = self._cve.get_attack_techniques(cve_id)
        return {
            "techniques": [
                {
                    "technique_id": t.technique_id,
                    "name": t.name,
                    "mapping_type": self._enum_val(t.mapping_type, "unknown"),
                    "comment": t.comment,
                    "url": t.url,
                    "references": list(t.references),
                }
                for t in techniques
            ],
        }

    def _find_db_exploit(
        self, cve_id: str, source: ExploitSource, limit: int
    ) -> dict[str, Any] | None:
        """First exploit from *source*, or *None*.

        ``limit`` bounds how many entries **of that source** are considered.
        It used to slice the combined db-exploit list before filtering, and
        because that list is ordered [metasploit, exploitdb, nuclei], the
        default ``limit=1`` made ``find_exploitdb_entry`` and
        ``find_nuclei_template`` return ``None`` for every CVE that happened to
        have a Metasploit module.
        """
        exploits = self._exploit.find_db_exploits(cve_id)
        matching = [e for e in exploits if e.source == source]
        for e in matching[: max(limit, 1)]:
            return self._normalize_exploit(e)
        return None

    def find_metasploit_module(self, cve_id: str, limit: int = 1) -> dict[str, Any] | None:
        """Find Metasploit module."""
        try:
            return self._find_db_exploit(cve_id, ExploitSource.METASPLOIT, limit)
        except Exception as e:
            if is_programming_error(e):
                raise
            logger.warning(f"Metasploit search failed: {e}")
            return None

    def find_exploitdb_entry(self, cve_id: str, limit: int = 1) -> dict[str, Any] | None:
        """Find ExploitDB entry."""
        try:
            return self._find_db_exploit(cve_id, ExploitSource.EXPLOITDB, limit)
        except Exception as e:
            if is_programming_error(e):
                raise
            logger.warning(f"ExploitDB search failed: {e}")
            return None

    def find_nuclei_template(self, cve_id: str, limit: int = 1) -> dict[str, Any] | None:
        """Find Nuclei template."""
        try:
            return self._find_db_exploit(cve_id, ExploitSource.NUCLEI, limit)
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
                    return cast("str | None", lab.url)
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
            if isinstance(e, HTTPError):  # RateLimitError/OfflineError/network are real errors, not 'empty'
                raise
            logger.warning(f"CPE lookup failed: {e}")
            return []

    def cpe_to_cve(self, cpe: str) -> list[str]:
        """Convert CPE to CVEs."""
        try:
            return cast("list[str]", self._cve.cpe_to_cves(cpe))
        except Exception as e:
            if is_programming_error(e):
                raise
            if isinstance(e, HTTPError):  # RateLimitError/OfflineError/network are real errors, not 'empty'
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

    def _collect_report_entry(
        self, cve_id: str
    ) -> tuple[dict[str, Any] | None, dict[str, str] | None]:
        """Build one report entry using the same exploit collection as ReportService.

        Uses :meth:`ExploitService.find_exploits_with_status` so third-party
        plugins appear and per-source health is never a silent empty. Returns
        ``(entry, None)`` on success or ``(None, error)`` when CVE lookup fails.
        """
        cve_info = self.lookup_cve(cve_id)
        if "error" in cve_info:
            return None, {
                "cve_id": str(cve_info.get("cve_id", cve_id)),
                "error": str(cve_info["error"]),
            }

        # Same aggregation path as ReportService.generate_report (find_exploits),
        # but with per-source status so agents can tell empty from rate-limited.
        try:
            exploit_result = self._exploit.find_exploits_with_status(cve_id)
            exploits = [self._normalize_exploit(e) for e in exploit_result.exploits]
            sources = [s.to_dict() for s in exploit_result.sources]
        except Exception as e:
            if is_programming_error(e):
                raise
            if isinstance(e, HTTPError):
                raise
            logger.warning("Exploit collection failed for %s: %s", cve_id, e)
            exploits = []
            sources = [{
                "source": "all",
                "status": "error",
                "count": 0,
                "retryable": False,
                "category": "unknown",
                "detail": f"Exploit collection failed ({type(e).__name__})",
            }]

        return {
            "cve_info": cve_info,
            "exploits": exploits,
            "labs": self.find_labs(cve_id),
            "bb_reports": self.find_bug_bounty_reports(cve_id),
            "sources": sources,
        }, None

    def generate_json_report(self, cve_ids: list[str]) -> dict[str, Any]:
        """Generate JSON report for CVE IDs."""
        if len(cve_ids) > MAX_CVE_BULK:
            return {
                "error": f"Too many CVEs requested: {len(cve_ids)} (max {MAX_CVE_BULK})",
                "category": "invalid_input",
            }
        entries: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for cve_id in cve_ids:
            entry, err = self._collect_report_entry(cve_id)
            if err is not None:
                errors.append(err)
                continue
            if entry is not None:
                entries.append(entry)

        return {
            "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            "total_requested": len(cve_ids),
            "total_entries": len(entries),
            "total_errors": len(errors),
            "entries": entries,
            "errors": errors,
        }

    def generate_html_report(self, cve_ids: list[str]) -> dict[str, Any]:
        """Generate HTML report for CVE IDs."""
        if len(cve_ids) > MAX_CVE_BULK:
            return {
                "error": f"Too many CVEs requested: {len(cve_ids)} (max {MAX_CVE_BULK})",
                "category": "invalid_input",
            }
        now = datetime.now(timezone.utc)

        entries: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for cve_id in cve_ids:
            entry, err = self._collect_report_entry(cve_id)
            if err is not None:
                errors.append(err)
                continue
            if entry is not None:
                entries.append(entry)

        html_output = _build_html_report(entries, errors, cve_ids, now)
        return {
            "format": "html",
            "content": html_output,
            "cve_count": len(cve_ids),
            "status": "ok",
        }

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
            category, retryable = categorize_exception(e)
            return {
                "error": f"Product discovery failed ({type(e).__name__})",
                "product": product,
                "category": category,
                "error_type": type(e).__name__,
                "retryable": retryable,
            }

    # -- Package Discovery --

    def discover_package_cves(
        self,
        ecosystem: str,
        name: str,
        version: str = "",
        limit: int = 50,
    ) -> dict[str, Any]:
        """Find vulnerabilities affecting a package coordinate via OSV.

        Args:
            ecosystem: Package ecosystem (``PyPI``, ``npm``, ``Maven``, ...).
            name: Package name as the ecosystem spells it.
            version: Installed version, or "" for every known advisory.
            limit: Maximum advisories to return.

        Returns:
            Normalized dict with the query echo and a ranked vulnerability list.
        """
        try:
            result = self._package.discover_package(
                ecosystem=ecosystem,
                package=name,
                version=version or None,
                limit=limit,
            )
            return self._normalize_package_result(result)
        except Exception as e:
            if is_programming_error(e):
                raise
            logger.warning(f"Package discovery failed: {e}")
            category, retryable = categorize_exception(e)
            return {
                "error": f"Package discovery failed ({type(e).__name__}): {e}",
                "ecosystem": ecosystem,
                "package": name,
                "category": category,
                "error_type": type(e).__name__,
                "retryable": retryable,
            }

    # -- Normalizers --

    @staticmethod
    def _normalize_package_vuln(vuln: Any) -> dict[str, Any]:
        """Flatten a PackageVulnerability for the wire.

        ``epss_score`` is on the 0.0-1.0 scale to match every other MCP tool;
        the model stores 0-100.
        """
        epss = getattr(vuln, "epss", None)
        return {
            "id": vuln.id,
            "cve_ids": list(vuln.cve_ids),
            "aliases": list(vuln.aliases),
            "summary": vuln.summary,
            "severity": ServiceAdapter._enum_val(vuln.severity, "UNKNOWN"),
            "cvss_score": vuln.cvss_score,
            "cvss_vector": vuln.cvss_vector,
            "epss_score": round(epss / 100.0, _EPSS_DP) if epss is not None else None,
            "kev_status": bool(vuln.kev_status),
            "fixed_versions": list(vuln.fixed_versions),
            "introduced_versions": list(vuln.introduced_versions),
            "has_fix": bool(vuln.fixed_versions),
            "withdrawn": vuln.withdrawn,
            "published": vuln.published,
            "url": vuln.url,
        }

    @staticmethod
    def _normalize_package_result(result: Any) -> dict[str, Any]:
        """Flatten a PackageDiscoveryResult for the wire."""
        return {
            "ecosystem": result.ecosystem,
            "package": result.package,
            "version": result.version,
            "total_found": result.total_found,
            "returned": result.returned,
            "truncated": result.truncated,
            "fixable_count": result.fixable_count,
            "unfixed_count": result.unfixed_count,
            "search_sources": list(result.search_sources),
            "vulnerabilities": [
                ServiceAdapter._normalize_package_vuln(v) for v in result.vulnerabilities
            ],
        }

    @staticmethod
    def _enum_val(value: Any, default: str = "") -> str:
        """Safely extract string value from an enum or plain string."""
        if value is None:
            return default
        if isinstance(value, Enum):
            return cast("str", value.value)
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
        epss = round(epss_raw / 100.0, _EPSS_DP) if epss_raw is not None else None

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

        # Every (vendor, product) pair the CVE is filed under. ``vendor``/
        # ``product`` above are only the first of these, so a product-scoped
        # question ("does this affect nginx?") needs the full list: a CVE
        # typically names the vulnerable component plus every distro that
        # shipped it. The verbose ``cpe_matches`` stay Python-API-only.
        affected_products = [
            {"vendor": ap.vendor, "product": ap.product}
            for ap in getattr(info, "affected_products", [])
            if getattr(ap, "vendor", None) or getattr(ap, "product", None)
        ]

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
            "affected_products": affected_products,
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
            # Populated by Exploit.from_metasploit/from_exploitdb/from_nuclei
            # (msfconsole / searchsploit / nuclei invocations); None for GitHub
            # PoCs, which have no canonical run command.
            "command": getattr(e, "command", None),
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
        """Convert a RecentExploitResult to a JSON-serializable dict.

        ``cve_info`` goes through :meth:`_normalize_cve_info` so agents see the
        same shape as ``lookup_cve`` / ``generate_json_report`` (``cvss.score``,
        ``epss_score`` 0.0–1.0, ``references`` as a list) — not the raw model
        dump (``cvss.base_score``, ``epss`` 0–100).
        """
        if isinstance(r, dict):
            cve_raw = r.get("cve_info")
            poc_sources = r.get("poc_sources") or []
            return {
                "cve_info": (
                    ServiceAdapter._normalize_cve_info(cve_raw)
                    if cve_raw is not None
                    else {}
                ),
                "has_poc": bool(r.get("has_poc", False)),
                "poc_sources": [
                    ServiceAdapter._enum_val(s, str(s)) for s in poc_sources
                ],
                "discovered_at": r.get("discovered_at"),
            }

        cve_raw = getattr(r, "cve_info", None)
        poc_sources = getattr(r, "poc_sources", None) or []
        discovered = getattr(r, "discovered_at", None)
        isoformat = getattr(discovered, "isoformat", None)
        if callable(isoformat):
            discovered = isoformat()

        return {
            "cve_info": (
                ServiceAdapter._normalize_cve_info(cve_raw)
                if cve_raw is not None
                else {}
            ),
            "has_poc": bool(getattr(r, "has_poc", False)),
            "poc_sources": [
                ServiceAdapter._enum_val(s, str(s)) for s in poc_sources
            ],
            "discovered_at": discovered,
        }

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
            # ``nvd_cpe_match`` = resolved to canonical CPEs (authoritative);
            # ``nvd_keyword_search`` = unresolvable product, noisy full-text
            # fallback. Agents should weigh the latter's results accordingly.
            "search_sources": list(getattr(r, "search_sources", [])),
            "matched_cpes": list(getattr(r, "matched_cpes", [])),
            "confirmed_affected": confirmed,
            "possibly_affected": possibly,
            "not_enough_data": unknown,
            "summary": {
                "confirmed_count": len(confirmed),
                "possibly_count": len(possibly),
                "unknown_count": len(unknown),
            },
        }
