"""CVE lookup and enrichment service.

Provides high-level methods for retrieving comprehensive CVE information
by combining data from CVE.org, NVD, CISA KEV, and EPSS sources.

Example::

    from pocmap.services.cve_service import CVEService
    service = CVEService()
    info = service.get_cve_info("CVE-2021-44228")
    print(info.cvss.severity, info.epss, info.kev_status)
"""

from __future__ import annotations

import logging
from typing import Any

from pocmap.clients.cveorg_client import CVEOrgClient
from pocmap.clients.nvd_client import NVDClient
from pocmap.models import CPEInfo, CVEInfo, CVEState, CVSSScore
from pocmap.utils.http import ValidationError
from pocmap.utils.validators import validate_cve_id as _validate_cve_id

logger = logging.getLogger(__name__)


class CVEService:
    """Service for CVE information retrieval and enrichment.

    Combines data from multiple sources (CVE.org, NVD, CISA KEV, EPSS)
    into a single, comprehensive :class:`CVEInfo` model.

    Args:
        cveorg_client: Optional CVEOrgClient instance.
        nvd_client: Optional NVDClient instance.

    Example::

        service = CVEService()

        # Get full CVE info
        info = service.get_cve_info("CVE-2021-44228")

        # Get CPEs
        cpes = service.get_cpes("CVE-2021-44228")

        # Resolve CPE to CVEs
        cves = service.cpe_to_cves("cpe:2.3:o:microsoft:windows_10:1607")
    """

    def __init__(
        self,
        cveorg_client: CVEOrgClient | None = None,
        nvd_client: NVDClient | None = None,
    ) -> None:
        self._cveorg = cveorg_client or CVEOrgClient()
        self._nvd = nvd_client or NVDClient()

    @classmethod
    def validate_cve_id(cls, cve_id: str) -> str:
        """Validate and normalize a CVE identifier.

        Delegates to the shared :func:`~pocmap.utils.validators.validate_cve_id`
        to keep a single source of truth while maintaining backward compatibility.

        Args:
            cve_id: The CVE ID string to validate.

        Returns:
            Uppercase normalized CVE ID.

        Raises:
            ValidationError: If the format is invalid.
        """
        try:
            return _validate_cve_id(cve_id)
        except ValueError as exc:
            raise ValidationError(
                f"Invalid CVE ID format: {cve_id!r}. Expected: CVE-YYYY-NNNN+"
            ) from exc

    def get_cve_info(self, cve_id: str) -> CVEInfo:
        """Retrieve comprehensive information about a CVE.

        Combines data from CVE.org (primary) and NVD (fallback) to build
        a complete :class:`CVEInfo` model including CVSS scores, EPSS,
        KEV status, CWEs, references, and vendor/product info.

        Args:
            cve_id: The CVE identifier (e.g., ``CVE-2021-44228``).

        Returns:
            A fully populated :class:`CVEInfo` instance.

        Raises:
            ValidationError: If the CVE ID format is invalid.
            NotFoundError: If no record exists for the CVE.
        """
        cve_id = self.validate_cve_id(cve_id)

        # Fetch primary record from CVE.org
        record = self._cveorg.get_cve_record(cve_id)
        if record is None:
            from pocmap.utils.http import NotFoundError
            raise NotFoundError(f"No CVE record found for {cve_id}")

        # Handle non-published states
        state = str(record.get("state", "UNKNOWN")).upper()
        if state == "RESERVED":
            return CVEInfo(
                id=cve_id,
                state=CVEState.RESERVED,
                publication_date=None,
                vendor=None,
                product=None,
            )
        if state == "REJECTED":
            return CVEInfo(
                id=cve_id,
                state=CVEState.REJECTED,
                rejected_reason=record.get("rejectedReasons"),
                publication_date=None,
                vendor=None,
                product=None,
            )

        # Build CVSS from CVE.org record
        cvss = self._build_cvss(record)

        # Fallback to NVD if CVE.org had no CVSS
        if cvss.base_score is None:
            cvss = self._fetch_nvd_cvss(cve_id)

        # Get EPSS score
        epss = self._cveorg.get_epss(cve_id)

        # Check KEV status
        is_kev, kev_record = self._cveorg.is_kev(cve_id)

        # Get references
        references = self._cveorg.get_references(cve_id, kev_record if is_kev else None)

        # Check ransomware usage
        ransomware = self._cveorg.get_ransomware_usage(cve_id)

        # Get description
        description = self._cveorg.get_description(cve_id)

        # Build and return the model
        cve_info = CVEInfo(
            id=cve_id,
            description=description,
            cvss=cvss,
            epss=epss,
            kev_status=is_kev,
            cwes=record.get("cwe", []),
            references=references,
            vendor=record.get("vendor") or "N/A",
            product=record.get("affected_product") or "N/A",
            publication_date=self._format_date(record.get("publication_date")),
            state=CVEState.PUBLISHED,
            ransomware_usage=ransomware if ransomware != "N/A" else None,
        )

        # Attach KEV references if available
        if is_kev and kev_record:
            notes = kev_record.get("notes", "")
            if notes:
                import re
                kev_refs = re.findall(
                    r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}"
                    r"\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)",
                    notes,
                )
                if kev_refs:
                    cve_info.references["KEV_Advisories"] = "\n".join(kev_refs)

        return cve_info

    def get_cpes(self, cve_id: str) -> list[CPEInfo]:
        """Retrieve affected CPE identifiers for a CVE.

        Args:
            cve_id: The CVE identifier.

        Returns:
            List of parsed :class:`CPEInfo` objects.
        """
        cve_id = self.validate_cve_id(cve_id)
        cpe_strings = self._nvd.get_cpe_affected(cve_id)
        return [CPEInfo.parse(cpe) for cpe in cpe_strings]

    def get_description(self, cve_id: str) -> str | None:
        """Get the human-readable description for a CVE.

        Args:
            cve_id: The CVE identifier.

        Returns:
            Description text, or *None* if not found.
        """
        cve_id = self.validate_cve_id(cve_id)
        return self._cveorg.get_description(cve_id)

    def cpe_to_cves(self, cpe_string: str) -> list[str]:
        """Find all CVE IDs associated with a CPE identifier.

        Args:
            cpe_string: A CPE 2.3 string (e.g., ``cpe:2.3:o:microsoft:windows_10:1607``).

        Returns:
            List of CVE IDs.

        Raises:
            ValidationError: If the CPE format is invalid.
        """
        if not cpe_string.startswith("cpe:"):
            raise ValidationError(
                f"Invalid CPE format: {cpe_string!r}. Expected: cpe:2.3:..."
            )

        from pocmap.config import NVD_API_BASE, settings
        from pocmap.utils.http import fetch_json

        try:
            data = fetch_json(
                NVD_API_BASE,
                headers=settings.nvd_headers,
                params={"cpeName": cpe_string},
            )
            if data and data.get("vulnerabilities"):
                return [
                    v.get("cve", {}).get("id")
                    for v in data["vulnerabilities"]
                    if v.get("cve", {}).get("id")
                ]
        except Exception as exc:
            logger.warning("CPE-to-CVE lookup failed for %s: %s", cpe_string, exc)

        return []

    def _build_cvss(self, record: dict[str, Any]) -> CVSSScore:
        """Build a CVSSScore from a CVE.org record."""
        return CVSSScore.from_raw(
            version=record.get("cvss_version", "unknown"),
            base_score=record.get("base_score"),
            severity=record.get("severity", "UNKNOWN"),
            vector_string=record.get("vector_string"),
        )

    def _fetch_nvd_cvss(self, cve_id: str) -> CVSSScore:
        """Fetch CVSS data from NVD as a fallback."""
        try:
            cve_data = self._nvd.get_cve(cve_id)
            if cve_data:
                return self._nvd.extract_cvss(cve_data)
        except Exception as exc:
            logger.debug("NVD CVSS fallback failed for %s: %s", cve_id, exc)
        return CVSSScore()

    @staticmethod
    def _format_date(date_value: Any) -> str | None:
        """Format a date value to a human-readable string."""
        if date_value is None:
            return None
        from datetime import datetime
        if isinstance(date_value, str):
            try:
                dt = datetime.fromisoformat(date_value.replace("Z", "+00:00"))
                return dt.strftime("%d %b %Y")
            except ValueError:
                return date_value
        return str(date_value)

    def close(self) -> None:
        """Release all underlying clients."""
        self._cveorg.close()
        self._nvd.close()

    def __enter__(self) -> CVEService:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
