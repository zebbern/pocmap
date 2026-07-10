"""Recent CVE exploit discovery service.

Discovers recently published CVEs from the NVD API and enriches them
with exploit/PoC intelligence from multiple sources.

Example::

    from pocmap.services.recent_service import RecentService
    with RecentService() as service:
        # Find CVEs from the last 24 hours
        results = service.find_recent_cves(since="24h")

        # Find high/critical CVEs from the last 7 days with PoCs
        results = service.find_recent_cves(
            since="7d",
            severity=["HIGH", "CRITICAL"],
            only_with_poc=True,
        )
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timedelta, timezone
from itertools import zip_longest
from typing import Any

from pocmap.clients.cveorg_client import CVEOrgClient
from pocmap.clients.github_client import GitHubClient
from pocmap.clients.nvd_client import NVDClient
from pocmap.config import NVD_API_BASE, settings
from pocmap.models import (
    CVEInfo,
    CVEState,
    ExploitSource,
    RecentExploitResult,
    Severity,
)
from pocmap.utils.http import HTTPClient, HTTPError, is_programming_error

logger = logging.getLogger(__name__)

# NVD API pagination parameters
# NVD allows resultsPerPage=100 with an API key, but only 20 without.
_NVD_RESULTS_PER_PAGE_NO_KEY: int = 20
_NVD_RESULTS_PER_PAGE_WITH_KEY: int = 100

# Severity mapping from CLI-friendly strings to NVD API values
_SEVERITY_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


class RecentService:
    """Service for discovering recent CVEs with exploit intelligence.

    Fetches recently published CVEs from the NVD API, then enriches them
    with CVSS scoring, EPSS filtering, and PoC discovery from GitHub.

    Args:
        nvd_client: Optional NVDClient instance.
        github_client: Optional GitHubClient instance.
        http_client: Optional HTTPClient instance for direct NVD API calls.
        cveorg_client: Optional CVEOrgClient instance (used for EPSS enrichment).

    Example::

        with RecentService() as service:
            results = service.find_recent_cves(since="24h")
            for r in results:
                print(f"{r.cve_info.id}: {r.cve_info.cvss.severity}")
    """

    def __init__(
        self,
        nvd_client: NVDClient | None = None,
        github_client: GitHubClient | None = None,
        http_client: HTTPClient | None = None,
        cveorg_client: CVEOrgClient | None = None,
    ) -> None:
        self._nvd = nvd_client or NVDClient()
        self._github = github_client or GitHubClient()
        self._client = http_client or HTTPClient(headers=settings.nvd_headers)
        self._cveorg = cveorg_client or CVEOrgClient()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def find_recent_cves(
        self,
        since: str | None = None,
        from_date: date | None = None,
        to_date: date | None = None,
        severity: list[str] | None = None,
        kev_only: bool = False,
        min_epss: float | None = None,
        only_with_poc: bool = False,
        sort: str = "cve_date",
        limit: int = 50,
    ) -> list[RecentExploitResult]:
        """Find recently published CVEs with exploit intelligence.

        Time window resolution (in order of precedence):
            1. ``since`` -- relative time string (e.g., ``"24h"``, ``"7d"``).
            2. ``from_date`` / ``to_date`` -- explicit date range.
            3. Neither -- defaults to last 24 hours.

        Args:
            since: Relative time string: ``"1h"``, ``"24h"``, ``"7d"``, ``"30d"``,
                or any ``"<int>h"`` / ``"<int>d"`` pattern.
            from_date: Explicit start date (inclusive).
            to_date: Explicit end date (inclusive). Defaults to today.
            severity: Filter by CVSS severity levels
                (e.g., ``["CRITICAL", "HIGH"]``).
            kev_only: Only include CISA KEV entries.
            min_epss: Minimum EPSS score (0--100).
            only_with_poc: Only include CVEs with known PoCs on GitHub.
            sort: Sort order -- ``"cve_date"``, ``"severity"``, or ``"epss"``.
            limit: Maximum number of results to return (1--100).

        Returns:
            List of :class:`RecentExploitResult` objects, sorted according
            to the *sort* parameter.

        Raises:
            ValueError: If *since* format is invalid or *limit* is out of range.
        """
        # Resolve time window
        if since:
            pub_end = datetime.now(timezone.utc).replace(tzinfo=None)
            pub_start = self._parse_since(since)
        elif from_date:
            if to_date and from_date > to_date:
                raise ValueError(
                    f"Invalid date range: from_date ({from_date}) "
                    f"cannot be after to_date ({to_date})."
                )
            pub_end = (
                datetime.combine(to_date, datetime.max.time())
                if to_date
                else datetime.now(timezone.utc).replace(tzinfo=None)
            )
            pub_start = datetime.combine(from_date, datetime.min.time())
        else:
            # Default: last 24 hours
            pub_end = datetime.now(timezone.utc).replace(tzinfo=None)
            pub_start = pub_end - timedelta(hours=24)

        # Normalize severity filter
        nvd_severities: list[str] | None = None
        if severity:
            nvd_severities = []
            for sev in severity:
                sev_upper = sev.strip().upper()
                if sev_upper in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                    nvd_severities.append(sev_upper)
                elif sev.lower() in _SEVERITY_MAP:
                    nvd_severities.append(_SEVERITY_MAP[sev.lower()])
            if not nvd_severities:
                raise ValueError(
                    f"Invalid severity values: {severity!r}. "
                    "Expected one or more of: CRITICAL, HIGH, MEDIUM, LOW."
                )

        # Clamp limit
        limit = max(1, min(100, limit))

        logger.info(
            "Fetching recent CVEs from %s to %s (severity=%s, kev_only=%s)",
            pub_start.isoformat(),
            pub_end.isoformat(),
            nvd_severities,
            kev_only,
        )

        # Fetch raw CVEs from NVD
        raw_vulns = self._fetch_recent_from_nvd(
            pub_start=pub_start,
            pub_end=pub_end,
            severity=nvd_severities,
            kev_only=kev_only,
            limit=limit,
        )

        if not raw_vulns:
            logger.info("No CVEs found in the specified time window")
            return []

        # Convert raw NVD data to CVEInfo models, dropping failed conversions.
        converted = [self._convert_raw_cve(v) for v in raw_vulns]
        cve_infos: list[CVEInfo] = [c for c in converted if c is not None]

        # Apply EPSS filter. NVD does not expose EPSS, so the score is
        # enriched from the EPSS dataset first (only when a filter is set).
        if min_epss is not None and min_epss > 0:
            cve_infos = self._enrich_epss(cve_infos)
            cve_infos = self._filter_by_epss(cve_infos, min_epss)

        # Apply PoC filter
        if only_with_poc:
            cve_infos = self._filter_by_poc(cve_infos)

        # Sort results
        cve_infos = self._sort_results(cve_infos, sort)

        # Build final results with PoC discovery
        results: list[RecentExploitResult] = []
        for cve_info in cve_infos[:limit]:
            has_poc, poc_sources = self._check_poc_sources(cve_info.id)
            results.append(
                RecentExploitResult(
                    cve_info=cve_info,
                    has_poc=has_poc,
                    poc_sources=poc_sources,
                )
            )

        logger.info("Returning %d recent CVE results", len(results))
        return results

    # ------------------------------------------------------------------
    # Time parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_since(since_str: str) -> datetime:
        """Parse a relative time string into an absolute datetime.

        Supports patterns like ``"1h"``, ``"24h"``, ``"7d"``, ``"30d"``.

        Args:
            since_str: Relative time string ending with ``"h"`` (hours)
                or ``"d"`` (days).

        Returns:
            Datetime in the past corresponding to the relative time.

        Raises:
            ValueError: If the format is invalid or the numeric value
                is not a positive integer.
        """
        since_str = since_str.strip().lower()
        match = re.match(r"^(\d+)([hd])$", since_str)
        if not match:
            raise ValueError(
                f"Invalid 'since' format: {since_str!r}. "
                "Expected: '<int>h' or '<int>d' (e.g., '24h', '7d')"
            )
        value = int(match.group(1))
        unit = match.group(2)

        # Validate bounds: minimum 1 hour, maximum 365 days
        max_hours = 365 * 24
        requested_hours = value if unit == "h" else value * 24
        if requested_hours < 1:
            raise ValueError(
                f"Invalid 'since' value: {since_str!r}. "
                "Minimum allowed is 1 hour (\"1h\")."
            )
        if requested_hours > max_hours:
            raise ValueError(
                f"Invalid 'since' value: {since_str!r}. "
                "Maximum allowed is 365 days (\"365d\")."
            )

        delta = timedelta(hours=value) if unit == "h" else timedelta(days=value)
        return datetime.now(timezone.utc).replace(tzinfo=None) - delta

    # ------------------------------------------------------------------
    # NVD API fetching
    # ------------------------------------------------------------------

    def _fetch_recent_from_nvd(
        self,
        pub_start: datetime,
        pub_end: datetime,
        severity: list[str] | None = None,
        kev_only: bool = False,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch recent CVEs from the NVD API.

        Handles pagination to retrieve all results within the time window.

        Args:
            pub_start: Start of publication date range (UTC).
            pub_end: End of publication date range (UTC).
            severity: Optional list of CVSS severity filters.
            kev_only: Only include CISA KEV entries.
            limit: Maximum number of CVEs to return.

        Returns:
            List of raw vulnerability dictionaries from the NVD API.
        """
        # NVD expects ISO-8601 format with timezone
        pub_start_str = pub_start.strftime("%Y-%m-%dT%H:%M:%S.000") + "+00:00"
        pub_end_str = pub_end.strftime("%Y-%m-%dT%H:%M:%S.000") + "+00:00"

        # Choose safe page size based on API key availability
        results_per_page = (
            _NVD_RESULTS_PER_PAGE_WITH_KEY
            if settings.nvd_api_key
            else _NVD_RESULTS_PER_PAGE_NO_KEY
        )

        # NVD's cvssV3Severity parameter only accepts a SINGLE severity per
        # request. To honor every requested severity we issue one query per
        # severity and merge the results (de-duplicated by CVE id). A single
        # severity (or none) behaves exactly as a single paginated fetch.
        queries: list[str | None] = list(severity) if severity else [None]

        per_severity: list[list[dict[str, Any]]] = [
            self._fetch_nvd_window(
                pub_start_str,
                pub_end_str,
                sev,
                kev_only,
                results_per_page,
                limit,
            )
            for sev in queries
        ]

        if len(per_severity) == 1:
            return per_severity[0][:limit]

        # Interleave per-severity results so each requested severity is
        # fairly represented, de-duplicating by CVE id and capping at *limit*.
        merged: dict[str, dict[str, Any]] = {}
        for group in zip_longest(*per_severity):
            for cve_data in group:
                if not cve_data:
                    continue
                cve_id = cve_data.get("id")
                if cve_id and cve_id not in merged:
                    merged[cve_id] = cve_data
            if len(merged) >= limit:
                break

        return list(merged.values())[:limit]

    def _fetch_nvd_window(
        self,
        pub_start_str: str,
        pub_end_str: str,
        severity: str | None,
        kev_only: bool,
        results_per_page: int,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Fetch a single paginated NVD window, optionally filtered by one severity.

        Args:
            pub_start_str: ISO-8601 start of the publication window.
            pub_end_str: ISO-8601 end of the publication window.
            severity: A single CVSS v3 severity (``CRITICAL``/``HIGH``/...),
                or *None* for no severity filter.
            kev_only: Only include CISA KEV entries.
            results_per_page: NVD page size.
            limit: Maximum number of CVEs to return.

        Returns:
            List of raw CVE dictionaries (at most *limit*).
        """
        all_vulns: list[dict[str, Any]] = []
        start_index = 0

        while len(all_vulns) < limit:
            params: dict[str, str] = {
                "pubStartDate": pub_start_str,
                "pubEndDate": pub_end_str,
                "resultsPerPage": str(results_per_page),
                "startIndex": str(start_index),
            }

            # Add severity filter if provided (NVD uses cvssV3Severity)
            if severity:
                params["cvssV3Severity"] = severity

            # Add KEV filter
            if kev_only:
                params["hasKev"] = "true"

            try:
                headers = {**(settings.nvd_headers or {})}
                if settings.nvd_api_key:
                    headers["apiKey"] = settings.nvd_api_key

                data = self._client.get_json(
                    NVD_API_BASE,
                    headers=headers,
                    params=params,
                    default={},
                )

                if not data:
                    break

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                # Extract the raw CVE data from each vulnerability wrapper
                for v in vulnerabilities:
                    cve_data = v.get("cve", {})
                    if cve_data:
                        all_vulns.append(cve_data)

                total_results = data.get("totalResults", 0)
                if start_index + len(vulnerabilities) >= total_results:
                    break
                if len(vulnerabilities) < results_per_page:
                    break

                start_index += len(vulnerabilities)

            except HTTPError as exc:
                logger.warning(
                    "NVD API request failed (startIndex=%d): %s",
                    start_index,
                    exc,
                )
                break
            except Exception as exc:
                if is_programming_error(exc):
                    raise
                logger.error(
                    "Unexpected error fetching from NVD: %s",
                    exc,
                )
                break

        return all_vulns[:limit]

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def _enrich_epss(self, cves: list[CVEInfo]) -> list[CVEInfo]:
        """Populate the EPSS score on each CVE from the EPSS dataset.

        The NVD API does not return EPSS data, so scores are looked up via
        :meth:`CVEOrgClient.get_epss`, which is backed by a single cached
        bulk EPSS dataset (one download shared across all lookups). This is
        only invoked when an EPSS filter is actually requested, so the extra
        fetch is not paid on the common no-filter path.

        Args:
            cves: List of CVEInfo objects (mutated in place).

        Returns:
            The same list, with ``epss`` populated where available.
        """
        for cve in cves:
            if cve.epss is not None:
                continue
            try:
                cve.epss = self._cveorg.get_epss(cve.id)
            except Exception as exc:  # pragma: no cover - defensive
                if is_programming_error(exc):
                    raise
                logger.debug("EPSS lookup failed for %s: %s", cve.id, exc)
        return cves

    @staticmethod
    def _filter_by_epss(
        cves: list[CVEInfo],
        min_epss: float,
    ) -> list[CVEInfo]:
        """Filter CVEs by minimum EPSS score.

        Note: EPSS data is not directly available from the NVD API, so
        :meth:`_enrich_epss` must be called first to populate ``epss`` on
        the CVEInfo objects. CVEs with no EPSS score are excluded.

        Args:
            cves: List of CVEInfo objects.
            min_epss: Minimum EPSS score (0--100).

        Returns:
            Filtered list of CVEs with EPSS >= *min_epss*.
        """
        if not min_epss or min_epss <= 0:
            return cves
        result = [c for c in cves if c.epss is not None and c.epss >= min_epss]
        logger.debug("EPSS filter: %d/%d CVEs retained (min_epss=%.2f)",
                     len(result), len(cves), min_epss)
        return result

    def _filter_by_poc(self, cves: list[CVEInfo]) -> list[CVEInfo]:
        """Filter CVEs to only those with known PoCs on GitHub.

        Performs a lightweight GitHub search for each CVE concurrently
        using a thread pool.

        Args:
            cves: List of CVEInfo objects.

        Returns:
            Filtered list of CVEs that have at least one GitHub PoC.
        """
        result: list[CVEInfo] = []

        def _check(cve: CVEInfo) -> CVEInfo | None:
            try:
                pocs = self._github.search_pocs(cve.id)
                return cve if pocs else None
            except Exception as exc:
                if is_programming_error(exc):
                    raise
                logger.debug("PoC check failed for %s: %s", cve.id, exc)
                return None

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(_check, cve): cve for cve in cves}
            for future in as_completed(futures):
                cve_result = future.result()
                if cve_result is not None:
                    result.append(cve_result)

        logger.debug("PoC filter: %d/%d CVEs have PoCs", len(result), len(cves))
        return result

    # ------------------------------------------------------------------
    # Sorting
    # ------------------------------------------------------------------

    @staticmethod
    def _sort_results(cves: list[CVEInfo], sort: str) -> list[CVEInfo]:
        """Sort CVE results by the specified criterion.

        Args:
            cves: List of CVEInfo objects.
            sort: Sort mode -- ``"cve_date"``, ``"severity"``, or ``"epss"``.

        Returns:
            Sorted list of CVEs (newest/highest first).
        """
        sort_key = sort.lower().strip()

        if sort_key == "severity":
            severity_order = {
                Severity.CRITICAL: 4,
                Severity.HIGH: 3,
                Severity.MEDIUM: 2,
                Severity.LOW: 1,
                Severity.UNKNOWN: 0,
            }
            return sorted(
                cves,
                key=lambda c: (
                    c.cvss.base_score if c.cvss and c.cvss.base_score is not None else 0,
                    severity_order.get(c.cvss.severity, 0) if c.cvss else 0,
                ),
                reverse=True,
            )

        if sort_key == "epss":
            return sorted(
                cves,
                key=lambda c: c.epss if c.epss is not None else -1.0,
                reverse=True,
            )

        # Default: sort by publication date (newest first)
        def _date_key(cve: CVEInfo) -> datetime:
            if cve.publication_date and cve.publication_date != "N/A":
                try:
                    # Try ISO format
                    dt = datetime.fromisoformat(cve.publication_date.replace("Z", "+00:00"))
                    return dt
                except (ValueError, AttributeError):
                    pass
                try:
                    # Try "DD Mon YYYY" format
                    dt = datetime.strptime(cve.publication_date, "%d %b %Y")
                    return dt
                except (ValueError, AttributeError):
                    pass
            return datetime.min

        return sorted(cves, key=_date_key, reverse=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_poc_sources(self, cve_id: str) -> tuple[bool, list[ExploitSource]]:
        """Check if a CVE has known PoCs and identify the sources.

        Args:
            cve_id: The CVE identifier.

        Returns:
            Tuple of (has_poc, list of ExploitSource values).
        """
        sources: list[ExploitSource] = []

        try:
            github_pocs = self._github.search_pocs(cve_id)
            if github_pocs:
                sources.append(ExploitSource.GITHUB)
        except Exception as exc:
            if is_programming_error(exc):
                raise
            logger.debug("GitHub PoC check failed for %s: %s", cve_id, exc)

        # Note: Additional source checks (ExploitDB, Metasploit, Nuclei)
        # can be added here by leveraging the ExploitService

        return bool(sources), sources

    def _convert_raw_cve(self, raw_cve: dict[str, Any]) -> CVEInfo | None:
        """Convert a raw NVD CVE dictionary into a :class:`CVEInfo` model.

        Args:
            raw_cve: Raw CVE data from the NVD API.

        Returns:
            Populated :class:`CVEInfo` instance, or *None* if conversion fails.
        """
        try:
            cve_id = raw_cve.get("id", "")
            if not cve_id:
                return None

            # Extract description
            descriptions = raw_cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # Extract CVSS using the NVD client's logic
            cvss = self._nvd.extract_cvss(raw_cve)

            # Extract CWEs
            cwes = self._nvd.extract_cwes(raw_cve)

            # Extract references
            references: dict[str, str] = {}
            refs = raw_cve.get("references", [])
            for i, ref in enumerate(refs):
                url = ref.get("url", "")
                if url:
                    source = ref.get("source", f"ref_{i}")
                    references[source] = url

            # Extract vendor/product from CPEs
            vendor: str | None = None
            product: str | None = None
            configs = raw_cve.get("configurations", [])
            for conf in configs:
                for node in conf.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria", "")
                        if criteria:
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3] or vendor
                                product = parts[4] or product
                                break
                    if vendor and product:
                        break
                if vendor and product:
                    break

            # Publication date
            pub_date = raw_cve.get("published")

            return CVEInfo(
                id=cve_id,
                description=description or None,
                cvss=cvss,
                epss=None,  # EPSS not available from NVD directly
                kev_status=False,  # KEV status requires separate lookup
                cwes=cwes,
                references=references,
                vendor=vendor or "N/A",
                product=product or "N/A",
                publication_date=pub_date,
                state=CVEState.PUBLISHED,
            )

        except Exception as exc:
            if is_programming_error(exc):
                raise
            cve_id = raw_cve.get("id", "UNKNOWN")
            logger.warning("Failed to convert raw CVE %s: %s", cve_id, exc)
            return None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Release all underlying clients."""
        self._nvd.close()
        self._github.close()
        self._client.close()
        self._cveorg.close()

    def __enter__(self) -> RecentService:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
