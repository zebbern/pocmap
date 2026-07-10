"""NVD (National Vulnerability Database) API client.

Provides typed access to the NVD REST API for retrieving CVE metadata,
CVSS scores, vector strings, and CWE identifiers.

Reference: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import logging
from typing import Any

from pocmap.config import NVD_API_BASE, settings
from pocmap.models import CVSSScore, CVSSVersion
from pocmap.utils.http import HTTPClient, HTTPError, OfflineError

logger = logging.getLogger(__name__)


class NVDClient:
    """Client for the National Vulnerability Database REST API.

    Args:
        api_key: Optional NVD API key for higher rate limits.
        http_client: Optional HTTP client instance.

    Example::

        client = NVDClient()
        cve_data = client.get_cve("CVE-2021-44228")
        cvss = client.extract_cvss(cve_data)
        print(cvss.base_score, cvss.severity)
    """

    def __init__(
        self,
        api_key: str | None = None,
        http_client: HTTPClient | None = None,
    ) -> None:
        self.api_key = api_key or settings.nvd_api_key
        self._client = http_client or HTTPClient(headers=settings.nvd_headers)
        self._base_url = NVD_API_BASE

    def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Retrieve raw CVE data from the NVD API.

        Args:
            cve_id: The CVE identifier (e.g., ``CVE-2021-44228``).

        Returns:
            Raw CVE data dictionary, or *None* if not found.
        """
        params: dict[str, str] = {"cveId": cve_id.upper()}
        # Use a copy of headers so we can add the API key without mutating defaults
        headers = {**(settings.nvd_headers or {})}
        if self.api_key:
            # SECURITY: send API key in header instead of query string
            headers["apiKey"] = self.api_key

        try:
            data = self._client.get_json(
                self._base_url,
                headers=headers,
                params=params,
            )
            if data and data.get("totalResults", 0) > 0:
                cve = data["vulnerabilities"][0]["cve"]
                return cve if isinstance(cve, dict) else None
        except OfflineError:
            # Offline cache-miss must surface, not degrade to None ("no data").
            raise
        except HTTPError:
            # SECURITY: strip apiKey from any logged URL before logging
            safe_cve_id = cve_id.upper()
            logger.warning("NVD API request failed for %s", safe_cve_id)
        return None

    def extract_cvss(self, cve_data: dict[str, Any]) -> CVSSScore:
        """Extract CVSS scoring information from NVD CVE data.

        Tries CVSS versions in order: v4.0, v3.1, v3.0, v2.0.

        Args:
            cve_data: Raw CVE data from :meth:`get_cve`.

        Returns:
            A populated :class:`CVSSScore` instance.
        """
        metrics = cve_data.get("metrics", {})

        # Try each CVSS version in descending order
        for version_key, cvss_key, version_enum in [
            ("cvssMetricV40", "cvssData", CVSSVersion.V4_0),
            ("cvssMetricV31", "cvssData", CVSSVersion.V3_1),
            ("cvssMetricV30", "cvssData", CVSSVersion.V3_0),
            ("cvssMetricV2", "cvssData", CVSSVersion.V2_0),
        ]:
            metric_list = metrics.get(version_key)
            if metric_list and len(metric_list) > 0:
                cvss_data = metric_list[0].get(cvss_key, {})
                return CVSSScore.from_raw(
                    version=version_enum.value,
                    base_score=cvss_data.get("baseScore"),
                    severity=cvss_data.get("baseSeverity", "UNKNOWN"),
                    vector_string=cvss_data.get("vectorString"),
                )

        return CVSSScore()

    def extract_cwes(self, cve_data: dict[str, Any]) -> list[str]:
        """Extract CWE identifiers from NVD CVE data.

        Args:
            cve_data: Raw CVE data from :meth:`get_cve`.

        Returns:
            List of CWE strings (e.g., ``["CWE-79", "CWE-89"]``).
        """
        cwes: list[str] = []
        weaknesses = cve_data.get("weaknesses", [])
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    cwes.append(value)
        return list(set(cwes))

    def get_cpe_affected(self, cve_id: str) -> list[str]:
        """Retrieve affected CPE strings for a CVE.

        Args:
            cve_id: The CVE identifier.

        Returns:
            List of CPE 2.3 strings.
        """
        data = self.get_cve(cve_id)
        if not data:
            return []
        cpes: list[str] = []
        for conf in data.get("configurations", []):
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria")
                    if criteria:
                        cpes.append(criteria)
        return cpes

    def close(self) -> None:
        """Release the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> NVDClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
