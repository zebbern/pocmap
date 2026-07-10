"""Bug bounty report discovery service.

Searches bug bounty write-up platforms for reports related to CVE identifiers.
Supports HackerOne, PentesterLand, and Bug Bounty Hunting Search Engine.

Example::

    from pocmap.services.bb_service import BugBountyService
    service = BugBountyService()
    reports = service.find_reports("CVE-2021-44228")
    for report in reports:
        print(f"{report.source}: {report.url} (PoC: {report.has_poc})")
"""

from __future__ import annotations

import csv
import logging
import re
from typing import Any

from pocmap.config import (
    BB_HUNTING_URL,
    H1_POC_FLAGS_URL,
    H1_REPORTS_URL,
    PENTESTERLAND_URL,
    settings,
)
from pocmap.models import BugBountyReport, BugBountySource
from pocmap.utils.http import (
    HTTPClient,
    OfflineError,
    fetch_json,
    fetch_text,
    is_programming_error,
)
from pocmap.utils.validators import validate_cve_id

logger = logging.getLogger(__name__)


class BugBountyService:
    """Service for discovering bug bounty reports related to CVEs.

    Searches multiple bug bounty platforms for write-ups that mention
    a specific CVE identifier.

    Example::

        service = BugBountyService()
        reports = service.find_reports("CVE-2021-44228")

        # Search individual platforms
        h1 = service.search_hackerone("CVE-2021-44228")
        pl = service.search_pentesterland("CVE-2021-44228")
    """

    def __init__(self, http_client: HTTPClient | None = None) -> None:
        self._client = http_client or HTTPClient(headers=settings.default_headers)

    def find_reports(self, cve_id: str) -> list[BugBountyReport]:
        """Search all bug bounty platforms for reports.

        Args:
            cve_id: The CVE identifier.

        Returns:
            List of :class:`BugBountyReport` objects.
        """
        cve_id = validate_cve_id(cve_id)

        results: list[BugBountyReport] = []

        h1_reports = self.search_hackerone(cve_id)
        if h1_reports:
            results.extend(h1_reports)

        pl = self.search_pentesterland(cve_id)
        if pl:
            results.append(pl)

        # Only search Bug Bounty Hunting if PentesterLand had no results
        if not pl:
            bbh = self.search_bugbounty_hunting(cve_id)
            if bbh:
                results.append(bbh)

        logger.info("Found %d bug bounty reports for %s", len(results), cve_id)
        return results

    def search_hackerone(self, cve_id: str) -> list[BugBountyReport]:
        """Search HackerOne reports for a CVE.

        Args:
            cve_id: The CVE identifier.

        Returns:
            List of :class:`BugBountyReport` objects matching the CVE.
        """
        matches: list[BugBountyReport] = []
        try:
            # Fetch PoC flags and reports data in parallel (sync)
            poc_flags_data = fetch_json(
                H1_POC_FLAGS_URL, headers=settings.default_headers
            )
            reports_text = fetch_text(
                H1_REPORTS_URL, headers=settings.default_headers
            )

            if not reports_text:
                return matches

            reports = list(csv.DictReader(reports_text.splitlines()))
            for report in reports:
                if re.search(cve_id, report.get("title", ""), re.I):
                    report_link = f"https://{report['link']}"
                    report_id = report_link.split("/")[-1]

                    has_poc: bool | None = None
                    if isinstance(poc_flags_data, dict):
                        poc_val = poc_flags_data.get(report_id)
                        if poc_val is not None:
                            has_poc = bool(poc_val)

                    matches.append(
                        BugBountyReport(
                            source=BugBountySource.HACKERONE,
                            url=report_link,
                            has_poc=has_poc,
                            title=report.get("title"),
                        )
                    )
        except Exception as exc:
            if is_programming_error(exc) or isinstance(exc, OfflineError):
                raise
            logger.debug("HackerOne search failed for %s: %s", cve_id, exc)

        return matches

    def search_pentesterland(self, cve_id: str) -> BugBountyReport | None:
        """Search PentesterLand write-ups for a CVE.

        Args:
            cve_id: The CVE identifier.

        Returns:
            A :class:`BugBountyReport`, or *None* if not found.
        """
        try:
            data = fetch_json(PENTESTERLAND_URL, headers=settings.default_headers)
            if not data or "data" not in data:
                return None

            for writeup in data["data"]:
                links = writeup.get("Links", [])
                if links:
                    title = links[0].get("Title", "")
                    if re.search(cve_id, title, re.I):
                        return BugBountyReport(
                            source=BugBountySource.PENTESTERLAND,
                            url=links[0].get("Link", ""),
                            has_poc=None,  # Not determinable from this source
                            title=title,
                        )
        except Exception as exc:
            if is_programming_error(exc) or isinstance(exc, OfflineError):
                raise
            logger.debug("PentesterLand search failed for %s: %s", cve_id, exc)

        return None

    def search_bugbounty_hunting(self, cve_id: str) -> BugBountyReport | None:
        """Search Bug Bounty Hunting Search Engine for a CVE.

        Args:
            cve_id: The CVE identifier.

        Returns:
            A :class:`BugBountyReport`, or *None* if not found.
        """
        try:
            text = fetch_text(BB_HUNTING_URL, headers=settings.default_headers)
            if text and re.search(cve_id, text, re.I):
                return BugBountyReport(
                    source=BugBountySource.BUGBOUNTY_HUNTING,
                    url=f"https://www.bugbountyhunting.com/?q={cve_id.upper()}",
                    has_poc=None,
                )
        except Exception as exc:
            if is_programming_error(exc) or isinstance(exc, OfflineError):
                raise
            logger.debug("BugBountyHunting search failed for %s: %s", cve_id, exc)

        return None

    def close(self) -> None:
        """Release the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> BugBountyService:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
