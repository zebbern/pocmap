"""Package vulnerability discovery via OSV, enriched with pocmap's CVE intel.

Answers the dependency question the CPE path cannot: *given a package and the
version we actually ship, what is wrong with it and what do we upgrade to?*

The combination is the point. OSV knows package coordinates and fixed releases
but publishes no exploitation signal; pocmap already carries EPSS and CISA KEV
as **whole-catalogue bulk feeds**, so cross-referencing every advisory's CVE
aliases against them costs two cached downloads regardless of how many
advisories came back — no per-CVE API calls, and no NVD budget at all. The
result is a remediation list ordered by real-world exploitation risk rather than
by CVSS alone.

Example::

    from pocmap.services.package_service import PackageService

    with PackageService() as svc:
        result = svc.discover_package("PyPI", "django", version="3.2.0")
        for vuln in result.vulnerabilities:
            print(vuln.id, vuln.severity.value, "->", vuln.fixed_versions)
"""

from __future__ import annotations

import logging
from typing import Any

from pocmap.clients.cveorg_client import CVEOrgClient
from pocmap.clients.osv_client import (
    OSVClient,
    cve_ids,
    fixed_versions,
    introduced_versions,
    is_withdrawn,
    normalize_ecosystem,
    qualitative_severity,
    scorable_vector,
    severity_vector,
)
from pocmap.models import PackageDiscoveryResult, PackageVulnerability, Severity
from pocmap.utils.cvss import base_score_from_vector, severity_band
from pocmap.utils.http import (
    OfflineError,
    RateLimitError,
    is_programming_error,
)

logger = logging.getLogger(__name__)

# Upper bound on advisories carried back to the caller. A distro package can
# have thousands; nobody reads that, and each one costs enrichment work.
DEFAULT_LIMIT = 100

_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNKNOWN: 0,
}


class PackageService:
    """Discovery of vulnerabilities affecting a package coordinate.

    Args:
        osv_client: Optional OSV client instance.
        cveorg_client: Optional CVE.org client, used only for EPSS/KEV lookup.

    Example::

        with PackageService() as svc:
            result = svc.discover_package("npm", "lodash", version="4.17.20")
            print(result.fixable_count, "of", result.total_found, "have a fix")
    """

    def __init__(
        self,
        osv_client: OSVClient | None = None,
        cveorg_client: CVEOrgClient | None = None,
    ) -> None:
        self._osv = osv_client or OSVClient()
        self._cveorg = cveorg_client or CVEOrgClient()

    def discover_package(
        self,
        ecosystem: str,
        package: str,
        version: str | None = None,
        limit: int = DEFAULT_LIMIT,
        enrich: bool = True,
    ) -> PackageDiscoveryResult:
        """Find the advisories affecting *package* in *ecosystem*.

        Args:
            ecosystem: Ecosystem name in any casing — normalized to OSV's
                case-sensitive spelling before use.
            package: Package name as the ecosystem spells it. Maven wants the
                full ``groupId:artifactId``; a bare artifact matches nothing and
                would otherwise look like a clean package.
            version: Installed version. When given, OSV evaluates its own
                affected ranges and returns only what actually applies, which is
                more reliable than comparing versions client-side — ecosystem
                version strings such as ``2.4-2ubuntu0.1~esm1`` are explicitly
                not semver-orderable.
            limit: Maximum advisories to return, highest risk first.
            enrich: Cross-reference CVE aliases against EPSS and CISA KEV.

        Returns:
            A :class:`PackageDiscoveryResult`. An empty ``vulnerabilities`` list
            means OSV knows of nothing affecting this coordinate — note it
            cannot distinguish that from an unknown package, since both return
            HTTP 200 with an empty body.

        Raises:
            ValueError: Ecosystem or package name is blank.
            ValidationError: OSV rejected the query (unknown ecosystem).
            OfflineError: Offline mode with no cached response.
            RateLimitError: OSV throttled the request.
        """
        if not ecosystem or not ecosystem.strip():
            raise ValueError("Ecosystem cannot be empty or whitespace-only")
        if not package or not package.strip():
            raise ValueError("Package name cannot be empty or whitespace-only")

        package = package.strip()
        requested = ecosystem.strip()
        canonical = normalize_ecosystem(requested)
        if canonical is None:
            # Unrecognized here is not necessarily invalid — OSV adds ecosystems
            # over time — so forward it verbatim and let the API be the judge.
            logger.debug("Unrecognized ecosystem %r; forwarding as-is", requested)
            canonical = requested

        raw = self._osv.query(canonical, package, version=version or None)
        sources = ["osv"]

        records = [e for e in raw if isinstance(e, dict) and e.get("id")]
        # A retracted advisory is not a vulnerability, and rendering one beside
        # live findings is a false positive. ``/v1/query`` already omits them,
        # so this only fires on a record reached another way — but it is logged
        # rather than dropped silently, because a disappearing row is confusing.
        live = [e for e in records if not is_withdrawn(e)]
        if len(live) != len(records):
            logger.info(
                "Excluded %d withdrawn advisory/advisories for %s/%s",
                len(records) - len(live),
                canonical,
                package,
            )
        vulns = [self._to_model(entry, canonical, package) for entry in live]
        vulns = self._merge_duplicates(vulns)
        if enrich and vulns:
            sources.extend(self._enrich(vulns))

        vulns.sort(key=self._risk_key, reverse=True)
        discovered = len(vulns)
        if limit > 0 and discovered > limit:
            logger.info(
                "OSV returned %d advisories for %s/%s; showing the %d highest-risk",
                discovered,
                canonical,
                package,
                limit,
            )
            vulns = vulns[:limit]

        # ``total_found`` counts what was FOUND, not what survived ``limit`` --
        # reporting the truncated length would silently understate exposure,
        # and "12 vulnerabilities" reading as the whole picture when there are
        # 400 is exactly the wrong answer for a security tool. ``truncated``
        # says so explicitly rather than leaving the caller to compare lengths.
        return PackageDiscoveryResult(
            ecosystem=canonical,
            package=package,
            version=version or None,
            vulnerabilities=vulns,
            total_found=discovered,
            returned=len(vulns),
            truncated=discovered > len(vulns),
            fixable_count=sum(1 for v in vulns if v.has_fix),
            unfixed_count=sum(1 for v in vulns if not v.has_fix),
            search_sources=sources,
        )

    @staticmethod
    def _to_model(
        entry: dict[str, Any], ecosystem: str, package: str
    ) -> PackageVulnerability:
        """Convert one raw OSV record into a scoped :class:`PackageVulnerability`."""
        vuln_id = str(entry["id"])
        scoreable = scorable_vector(entry)
        score = base_score_from_vector(scoreable) if scoreable else None
        # Show the vector the number was derived from. Reporting a 4.0 vector
        # beside a score computed from a different (3.x) one invites a reader to
        # "check the maths" against a string that cannot produce it.
        vector = scoreable if score is not None else severity_vector(entry)

        severity = Severity.UNKNOWN
        if score is not None and score > 0:
            band = severity_band(score)
            severity = Severity(band) if band in Severity.__members__ else Severity.UNKNOWN
        else:
            # No 3.x vector to score (a 4.0-only advisory, or none at all) —
            # fall back to whatever rating the publisher assigned.
            label = qualitative_severity(entry)
            if label:
                severity = Severity(label)

        aliases = [a for a in (entry.get("aliases") or []) if isinstance(a, str)]
        return PackageVulnerability(
            id=vuln_id,
            aliases=aliases,
            cve_ids=cve_ids(entry),
            summary=entry.get("summary"),
            severity=severity,
            cvss_score=score,
            cvss_vector=vector,
            fixed_versions=fixed_versions(entry, ecosystem, package),
            introduced_versions=introduced_versions(entry, ecosystem, package),
            withdrawn=entry.get("withdrawn") if is_withdrawn(entry) else None,
            published=entry.get("published"),
            modified=entry.get("modified"),
            url=f"https://osv.dev/vulnerability/{vuln_id}",
        )

    @staticmethod
    def _richness(vuln: PackageVulnerability) -> tuple[int, int, int]:
        """How much usable detail a record carries, for choosing a survivor."""
        return (
            1 if vuln.cvss_score is not None else 0,
            1 if vuln.severity is not Severity.UNKNOWN else 0,
            len(vuln.summary or ""),
        )

    @classmethod
    def _merge_duplicates(
        cls, vulns: list[PackageVulnerability]
    ) -> list[PackageVulnerability]:
        """Collapse records that describe the same underlying vulnerability.

        Several databases feed OSV, so one CVE routinely arrives more than once
        — Django 3.2.0 returns 56 records for 30 distinct CVEs, and ``requests``
        16 for 8. Showing both is not just noisy: the duplicate is usually the
        *poorer* record (PYSEC entries carry no CVSS), so a reader who happens
        to look at that row sees severity "UNKNOWN" for a vulnerability whose
        sibling row is scored CRITICAL.

        The richest record survives; identifiers and version lists from the
        others are folded in so nothing is lost. Advisories with no CVE alias
        are keyed on their own id and never merge.
        """
        merged: dict[str, PackageVulnerability] = {}
        order: list[str] = []
        for vuln in vulns:
            key = vuln.cve_ids[0] if vuln.cve_ids else vuln.id
            existing = merged.get(key)
            if existing is None:
                merged[key] = vuln
                order.append(key)
                continue
            keep, drop = (
                (existing, vuln)
                if cls._richness(existing) >= cls._richness(vuln)
                else (vuln, existing)
            )
            for value in [drop.id, *drop.aliases]:
                if value != keep.id and value not in keep.aliases:
                    keep.aliases.append(value)
            for cve in drop.cve_ids:
                if cve not in keep.cve_ids:
                    keep.cve_ids.append(cve)
            for version in drop.fixed_versions:
                if version not in keep.fixed_versions:
                    keep.fixed_versions.append(version)
            for version in drop.introduced_versions:
                if version not in keep.introduced_versions:
                    keep.introduced_versions.append(version)
            merged[key] = keep
        return [merged[key] for key in order]

    def _enrich(self, vulns: list[PackageVulnerability]) -> list[str]:
        """Attach EPSS and KEV status from the bulk catalogues.

        Both feeds are whole-catalogue downloads that pocmap already caches, so
        this is two fetches for the entire result set rather than two per CVE.
        A failure degrades the ranking signal but must never fail the lookup —
        except offline/throttled, which are real upstream failures.
        """
        used: list[str] = []
        try:
            # Bulk, not per-CVE: one cached download each, then dict lookups.
            epss = self._cveorg.epss_scores()
            kev = self._cveorg.kev_ids()
            for vuln in vulns:
                for cve in vuln.cve_ids:
                    if vuln.epss is None:
                        vuln.epss = epss.get(cve.upper())
                    if not vuln.kev_status:
                        vuln.kev_status = cve.upper() in kev
            # Only claim a source that actually produced data. An empty
            # catalogue means the feed failed, and silently reporting
            # ``kev_status: false`` off that would understate the risk of every
            # CVE in the result.
            if epss:
                used.append("epss")
            if kev:
                used.append("cisa_kev")
            else:
                logger.warning("CISA KEV catalogue unavailable; kev_status is not authoritative")
        except (OfflineError, RateLimitError):
            raise
        except Exception as exc:
            if is_programming_error(exc):
                raise
            logger.warning("EPSS/KEV enrichment unavailable: %s", exc)
        return used

    @staticmethod
    def _epss_bucket(epss: float | None) -> int:
        """Coarsen EPSS into bands so small differences do not outrank severity.

        Compared raw, EPSS dominates: a MEDIUM with EPSS 0.1%% would sort above a
        CRITICAL with no score at all, even though 0.1%% and "unknown" both mean
        *no evidence of exploitation*. Banding lets CVSS decide inside a band and
        reserves precedence for an EPSS that is genuinely elevated.
        """
        if epss is None:
            return 0
        if epss >= 50.0:
            return 3
        if epss >= 10.0:
            return 2
        if epss >= 1.0:
            return 1
        return 0

    @classmethod
    def _risk_key(cls, vuln: PackageVulnerability) -> tuple[int, int, float, int, float]:
        """Order by real-world exploitation risk, not CVSS alone.

        KEV first (it is being exploited *now*), then the EPSS band (how likely
        it is to be), then CVSS, then the qualitative band for advisories with no
        numeric score, and finally raw EPSS as a stable last tiebreak.
        """
        return (
            1 if vuln.kev_status else 0,
            cls._epss_bucket(vuln.epss),
            vuln.cvss_score if vuln.cvss_score is not None else -1.0,
            _SEVERITY_ORDER.get(vuln.severity, 0),
            vuln.epss if vuln.epss is not None else 0.0,
        )

    def close(self) -> None:
        """Release the underlying clients."""
        self._osv.close()
        self._cveorg.close()

    def __enter__(self) -> PackageService:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
