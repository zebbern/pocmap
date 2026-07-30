"""CVE.org and CISA KEV data client.

Retrieves canonical CVE records from the CVEProject cvelistV5 repository
and Known Exploited Vulnerabilities data from CISA.
"""

from __future__ import annotations

import csv
import logging
import math
import re
from collections.abc import Iterable, Mapping
from typing import Any

from pocmap.config import (
    CISA_KEV_URL,
    CVE_ORG_GIT_RAW,
    EPSS_API_URL,
    EPSS_CSV_URL,
    SHODAN_CVEDB_URL,
    settings,
)
from pocmap.utils.http import (
    HTTPClient,
    HTTPError,
    OfflineError,
    RateLimitError,
    fetch_json,
    fetch_text,
    is_programming_error,
)

logger = logging.getLogger(__name__)


class CVEOrgClient:
    """Client for CVE.org data sources.

    Retrieves canonical CVE records, EPSS scores, and KEV status.

    Example::

        client = CVEOrgClient()
        record = client.get_cve_record("CVE-2021-44228")
        print(record.get("state"))
        epss = client.get_epss("CVE-2021-44228")
        print(epss)
    """

    def __init__(self, http_client: HTTPClient | None = None) -> None:
        self._client = http_client or HTTPClient(headers=settings.default_headers)
        self._kev_cache: list[dict[str, Any]] | None = None
        self._epss_cache: list[dict[str, str]] | None = None
        # CVE-keyed lookup indexes over the two bulk datasets above. Both feeds
        # are whole-catalogue downloads, so scoring N CVEs must not cost N scans.
        self._epss_index: dict[str, float] | None = None
        self._kev_index: dict[str, dict[str, Any]] | None = None
        # Distinguishes "loaded, and the feed was empty" from "not yet loaded",
        # since the parsed rows are released once the index exists.
        self._epss_loaded = False

    def get_cve_record(self, cve_id: str) -> dict[str, Any] | None:
        """Fetch a CVE record from the CVEProject cvelistV5 GitHub repo.

        Args:
            cve_id: The CVE identifier.

        Returns:
            Parsed CVE record dictionary, or *None* if not found.
        """
        parts = cve_id.upper().split("-")
        if len(parts) != 3:
            return None

        year = parts[1]
        seq = parts[2]
        batch = seq[:-3] + "xxx" if len(seq) >= 3 else "xxx"

        url = f"{CVE_ORG_GIT_RAW}/{year}/{batch}/{cve_id.upper()}.json"
        try:
            data = self._client.get_json(url, headers=settings.github_headers)
            if isinstance(data, dict):
                return self._parse_record(data)
        except OfflineError:
            # Offline cache-miss must surface, not degrade to "not found".
            raise
        except RateLimitError:
            # A throttled upstream is not a 404 — surface it, don't swallow.
            raise
        except HTTPError:
            logger.debug("CVE.org record not found for %s", cve_id)

        # Fallback: try the CVE AWG API for reserved/rejected states
        return self._get_cve_state_from_api(cve_id)

    def _parse_record(self, data: dict[str, Any]) -> dict[str, Any]:
        """Parse raw cvelistV5 JSON into a normalized record."""
        metadata = data.get("cveMetadata", {})
        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        affected = cna.get("affected", [{}])[0] if cna.get("affected") else {}

        record: dict[str, Any] = {
            "cve_id": metadata.get("cveID", ""),
            "state": metadata.get("state", "UNKNOWN"),
            "publication_date": metadata.get("datePublished"),
            "vendor": affected.get("vendor") if affected else None,
            "affected_product": affected.get("product") if affected else None,
        }

        # Handle rejected CVEs
        if record["state"] == "REJECTED":
            rejected_reasons = cna.get("rejectedReasons", [{}])
            record["rejectedReasons"] = (
                rejected_reasons[0].get("value", "") if rejected_reasons else ""
            )
            return record

        # Extract CVSS from CNA metrics
        metrics = cna.get("metrics", [])
        if metrics:
            self._extract_cvss_from_metrics(record, metrics[0])

        # Extract CVSS from ADP if CNA doesn't have it
        if record.get("base_score") is None:
            adps = containers.get("adp", [])
            for adp in adps:
                adp_metrics = adp.get("metrics", [])
                if adp_metrics:
                    self._extract_cvss_from_metrics(record, adp_metrics[0])
                    if record.get("base_score") is not None:
                        break

        # Extract CWEs
        record["cwe"] = self._extract_cwes(cna, containers.get("adp", []))

        # Extract description
        descriptions = cna.get("descriptions", [])
        if descriptions:
            record["description"] = descriptions[0].get("value", "")

        return record

    def _extract_cvss_from_metrics(
        self, record: dict[str, Any], metric: dict[str, Any]
    ) -> None:
        """Extract CVSS data from a single metrics entry."""
        for key, prefix in [
            ("cvssV4_0", "4.0"),
            ("cvssV3_1", "3.1"),
            ("cvssV3_0", "3.0"),
            ("cvssV2_0", "2.0"),
        ]:
            if key in metric:
                record["cvss_version"] = prefix
                record["vector_string"] = metric[key].get("vectorString")
                record["base_score"] = metric[key].get("baseScore")
                record["severity"] = metric[key].get("baseSeverity")
                if key == "cvssV2_0" and record.get("base_score") is not None:
                    score = float(record["base_score"])
                    if score < 4.0:
                        record["severity"] = "LOW"
                    elif score < 7.0:
                        record["severity"] = "MEDIUM"
                    else:
                        record["severity"] = "HIGH"
                return

    def _extract_cwes(
        self, cna: dict[str, Any], adps: list[dict[str, Any]]
    ) -> list[str]:
        """Extract CWE identifiers from CNA and ADP containers."""
        cwes: list[str] = []

        # Try CNA problemTypes first
        problem_types = cna.get("problemTypes", [])
        for pt in problem_types:
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId")
                if cwe_id:
                    cwes.append(cwe_id)
                else:
                    desc_text = desc.get("description", "")
                    found = re.findall(r"CWE-\d+", desc_text, re.I)
                    cwes.extend(found)

        # Fallback to ADP problemTypes
        if not cwes:
            for adp in adps:
                pt = adp.get("problemTypes", [])
                for entry in pt:
                    for desc in entry.get("descriptions", []):
                        cwe_id = desc.get("cweId")
                        if cwe_id:
                            cwes.append(cwe_id)
                        else:
                            desc_text = desc.get("description", "")
                            found = re.findall(r"CWE-\d+", desc_text, re.I)
                            cwes.extend(found)

        return list(dict.fromkeys(cwes))

    def _get_cve_state_from_api(self, cve_id: str) -> dict[str, Any] | None:
        """Query the CVE AWG API to check for reserved/rejected states."""
        url = f"https://cveawg.mitre.org/api/cve-id/{cve_id.upper()}"
        try:
            data = self._client.get_json(url, headers=settings.default_headers)
            if isinstance(data, dict) and "state" in data:
                return {
                    "cve_id": cve_id.upper(),
                    "state": data["state"],
                    "publication_date": None,
                    "vendor": None,
                    "affected_product": None,
                }
        except OfflineError:
            raise
        except RateLimitError:
            # A throttled upstream is not a 404 — surface it, don't swallow.
            raise
        except HTTPError:
            pass
        return None

    def get_epss(self, cve_id: str) -> float | None:
        """Retrieve the EPSS score for a CVE.

        First tries the cached CSV dataset, then falls back to the FIRST API.

        Args:
            cve_id: The CVE identifier.

        Returns:
            EPSS score as a percentage (0-100), or *None* if unavailable.
        """
        index = self._ensure_epss_index()
        if index:
            score = index.get(cve_id.upper())
            if score is not None:
                return score

        # Fallback to FIRST API
        return self._get_epss_from_api(cve_id)

    def epss_scores(self) -> dict[str, float]:
        """Return the whole EPSS catalogue as ``{CVE-ID: score 0-100}``.

        For callers scoring a *set* of CVEs. :meth:`get_epss` falls back to a
        per-CVE API request on a miss, which is right for a single lookup and
        wrong for a hundred — it is N network calls, and it fails in offline
        mode. This is one cached bulk download and then pure dict lookups.

        An empty mapping means the feed did not load, which is distinguishable
        from "this CVE has no score".
        """
        return dict(self._ensure_epss_index())

    def kev_ids(self) -> set[str]:
        """Return every CVE ID in the CISA KEV catalogue, uppercased.

        Empty means the catalogue did not load — *not* that nothing is known to
        be exploited. Callers must not report `kev_status: false` off an empty
        catalogue without saying the source was unavailable.
        """
        self.is_kev("CVE-0000-0000")  # forces load + index build
        return set(self._kev_index or {})

    @staticmethod
    def _build_epss_index(rows: Iterable[Mapping[str, str]]) -> dict[str, float]:
        """Fold EPSS rows into a ``{CVE-ID: score 0-100}`` mapping."""
        index: dict[str, float] = {}
        for row in rows:
            cve = str(row.get("cve", "")).upper()
            if not cve:
                continue
            try:
                index[cve] = math.trunc(float(row["epss"]) * 10000) / 100
            except (ValueError, KeyError, TypeError):
                continue
        return index

    def _ensure_epss_index(self) -> dict[str, float]:
        """Return the CVE-keyed EPSS index, building it on first use.

        Indexed rather than scanned: the dataset carries ~354k rows, and callers
        that score a whole result set (a package's vulnerabilities, a bulk
        report) would otherwise pay a full linear scan *per CVE*.

        Only the index is retained. Keeping the parsed rows as well costs ~120 MB
        per client for no benefit, and the MCP server holds three clients for the
        lifetime of the process, so the list is released once folded in.
        """
        if self._epss_index is None:
            if self._epss_cache:
                # Seeded directly (tests); fold it in without refetching.
                self._epss_index = self._build_epss_index(self._epss_cache)
            elif not self._epss_loaded:
                self._load_epss_cache()
        return self._epss_index if self._epss_index is not None else {}

    def _load_epss_cache(self) -> None:
        """Load EPSS data from the cached CSV straight into the index."""
        rows: list[dict[str, str]] = []
        try:
            text = fetch_text(EPSS_CSV_URL, headers=settings.default_headers)
            if text:
                # The feed opens with a metadata comment
                # ("#model_version:...,score_date:..."), which DictReader would
                # otherwise consume as the header row and yield garbage keys.
                lines = [ln for ln in text.splitlines() if not ln.startswith("#")]
                rows = list(csv.DictReader(lines))
        except Exception as exc:
            if is_programming_error(exc) or isinstance(exc, OfflineError):
                raise
            logger.warning("Failed to load EPSS cache: %s", exc)
        self._epss_index = self._build_epss_index(rows)
        # Release the parsed rows: the index is the only thing read afterwards.
        self._epss_cache = []
        self._epss_loaded = True

    def _get_epss_from_api(self, cve_id: str) -> float | None:
        """Query the FIRST EPSS API directly."""
        url = f"{EPSS_API_URL}?cve={cve_id.upper()}"
        try:
            data = fetch_json(url, headers=settings.default_headers)
            if data and data.get("data"):
                epss_value = float(data["data"][0]["epss"])
                return math.trunc(epss_value * 10000) / 100
        except OfflineError:
            raise
        except (HTTPError, KeyError, ValueError, TypeError, IndexError) as exc:
            logger.debug("FIRST EPSS API failed for %s: %s", cve_id, exc)
        return None

    def load_kev(self) -> list[dict[str, Any]]:
        """Load and cache CISA's Known Exploited Vulnerabilities catalog.

        Returns:
            List of KEV vulnerability records.
        """
        if self._kev_cache is not None:
            return self._kev_cache

        try:
            data = fetch_json(CISA_KEV_URL, headers=settings.default_headers)
            if data and "vulnerabilities" in data:
                self._kev_cache = data["vulnerabilities"]
                return self._kev_cache
        except OfflineError:
            raise
        except HTTPError as exc:
            logger.warning("Failed to load CISA KEV: %s", exc)

        self._kev_cache = []
        return self._kev_cache

    def is_kev(self, cve_id: str) -> tuple[bool, dict[str, Any] | None]:
        """Check whether a CVE is in the CISA KEV catalog.

        Args:
            cve_id: The CVE identifier.

        Returns:
            Tuple of (is_kev, kev_record_or_none).
        """
        kevs = self.load_kev()
        if self._kev_index is None:
            self._kev_index = {
                str(k.get("cveID", "")).upper(): k for k in kevs if k.get("cveID")
            }
        record = self._kev_index.get(cve_id.upper())
        return (True, record) if record is not None else (False, None)

    def get_ransomware_usage(self, cve_id: str) -> str:
        """Check if a CVE is known to be used in ransomware campaigns.

        Args:
            cve_id: The CVE identifier.

        Returns:
            ``"Known"``, ``"Unknown"``, or ``"N/A"``.
        """
        try:
            data = fetch_json(
                f"{SHODAN_CVEDB_URL}/{cve_id}",
                headers=settings.default_headers,
            )
            if data and "ransomware_campaign" in data:
                campaign = data["ransomware_campaign"]
                return str(campaign) if campaign else "N/A"
        except OfflineError:
            raise
        except HTTPError:
            pass
        return "N/A"

    def get_references(
        self, cve_id: str, kev_record: dict[str, Any] | None = None
    ) -> dict[str, str]:
        """Build a dictionary of reference URLs for a CVE.

        Args:
            cve_id: The CVE identifier.
            kev_record: Optional KEV record with additional references.

        Returns:
            Mapping of reference names to URLs.
        """
        from bs4 import BeautifulSoup

        refs: dict[str, str] = {
            "NVD": f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}",
            "CVEdetails": f"https://www.cvedetails.com/cve/{cve_id.upper()}",
        }

        # GitHub Security Advisory
        try:
            ghsa_url = f"https://github.com/advisories?query={cve_id.upper()}"
            resp_text = fetch_text(ghsa_url, headers=settings.default_headers)
            if resp_text:
                soup = BeautifulSoup(resp_text, "html.parser")
                ghsa_links: list[str] = []
                for row in soup.select("div.Box-row"):
                    cve_span = row.select_one("span.text-bold")
                    if cve_span and cve_span.text.strip().upper() == cve_id.upper():
                        link = row.select_one("a[href]")
                        if link:
                            ghsa_links.append("https://github.com" + str(link["href"]))
                if ghsa_links:
                    refs["GHSA"] = "\n".join(ghsa_links)
        except Exception as exc:
            if is_programming_error(exc) or isinstance(exc, OfflineError):
                raise
            logger.debug("GHSA reference lookup failed for %s: %s", cve_id, exc)

        # KEV references
        if kev_record:
            notes = kev_record.get("notes", "")
            if notes:
                found = re.findall(
                    r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}"
                    r"\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)",
                    notes,
                )
                if found:
                    # Remove NVD duplicates
                    found = [r for r in found if "nvd.nist.gov" not in r]
                    if found:
                        refs["Advisories"] = "\n".join(found)

        # CVE.org references fallback
        if len(refs) < 3:
            self._add_cve_org_references(cve_id, refs)

        return refs

    def _add_cve_org_references(
        self, cve_id: str, refs: dict[str, str]
    ) -> None:
        """Add references from CVE.org CNA container."""
        parts = cve_id.upper().split("-")
        if len(parts) != 3:
            return
        year, seq = parts[1], parts[2]
        batch = seq[:-3] + "xxx" if len(seq) >= 3 else "xxx"
        url = f"{CVE_ORG_GIT_RAW}/{year}/{batch}/{cve_id.upper()}.json"
        try:
            data = self._client.get_json(url, headers=settings.github_headers)
            if isinstance(data, dict):
                cna = data.get("containers", {}).get("cna", {})
                cna_refs = cna.get("references", [])
                if cna_refs:
                    urls = [ref["url"] for ref in cna_refs if "url" in ref]
                    if urls:
                        refs["Advisories"] = "\n".join(urls)
        except OfflineError:
            raise
        except HTTPError:
            pass

    def get_description(self, cve_id: str) -> str | None:
        """Fetch the human-readable description for a CVE.

        Args:
            cve_id: The CVE identifier.

        Returns:
            Description text, or *None* if not found.
        """
        # Try CVE.org first
        parts = cve_id.upper().split("-")
        if len(parts) == 3:
            year, seq = parts[1], parts[2]
            batch = seq[:-3] + "xxx" if len(seq) >= 3 else "xxx"
            url = f"{CVE_ORG_GIT_RAW}/{year}/{batch}/{cve_id.upper()}.json"
            try:
                data = self._client.get_json(url, headers=settings.github_headers)
                if isinstance(data, dict):
                    cna = data.get("containers", {}).get("cna", {})
                    descriptions = cna.get("descriptions", [])
                    if descriptions:
                        value = descriptions[0].get("value")
                        return value if isinstance(value, str) else None
            except OfflineError:
                raise
            except HTTPError:
                pass

        # Fallback to NVD
        try:
            data = fetch_json(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}",
                headers=settings.nvd_headers,
            )
            if data and data.get("vulnerabilities"):
                vuln = data["vulnerabilities"][0]["cve"]
                for desc in vuln.get("descriptions", []):
                    if desc.get("lang") == "en":
                        value = desc.get("value")
                        return value if isinstance(value, str) else None
        except OfflineError:
            raise
        except HTTPError:
            pass

        return None

    def close(self) -> None:
        """Release the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> CVEOrgClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
