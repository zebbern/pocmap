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
from urllib.parse import urlparse

from pocmap.clients.attack_client import ATTACKClient
from pocmap.clients.cveorg_client import CVEOrgClient
from pocmap.clients.nvd_client import NVDClient
from pocmap.models import (
    AffectedProduct,
    ATTACKTechnique,
    CPEInfo,
    CVEInfo,
    CVEState,
    CVSSScore,
)
from pocmap.utils.http import (
    OfflineError,
    RateLimitError,
    ValidationError,
    is_programming_error,
)
from pocmap.utils.product_fallback import infer_vendor_product
from pocmap.utils.validators import validate_cve_id as _validate_cve_id

logger = logging.getLogger(__name__)


# Placeholders CNAs file when they will not name a product. Treated as absent
# rather than shown verbatim: "n/a" in a vendor column tells a reader nothing,
# and it hides the fact that NVD often does know the answer.
_PLACEHOLDER_NAMES = frozenset({"n/a", "na", "unknown", "not applicable", "-"})


def _blank_to_none(value: object) -> str | None:
    """Normalize a CNA-supplied name, collapsing placeholders to ``None``."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    return None if not text or text.lower() in _PLACEHOLDER_NAMES else text


def _affected_from_nvd(nvd_record: dict[str, Any]) -> list[AffectedProduct]:
    """Derive ``(vendor, product)`` pairs from an NVD record's CPE matches.

    Order is preserved and duplicates dropped. Callers that need a single
    "primary" pair should use :func:`_pick_primary_affected` — NVD often lists
    downstream vendor firmware before the component named in the description
    (Log4Shell: Siemens SKUs before ``apache:log4j``).
    """
    seen: set[tuple[str, str]] = set()
    pairs: list[AffectedProduct] = []
    for config in nvd_record.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                parts = str(match.get("criteria", "")).split(":")
                if len(parts) < 5:
                    continue
                pair = (parts[3], parts[4])
                if not all(pair) or "*" in pair or pair in seen:
                    continue
                seen.add(pair)
                pairs.append(AffectedProduct(vendor=pair[0], product=pair[1]))
    return pairs


def _pick_primary_affected(
    products: list[AffectedProduct],
    description: str | None = None,
) -> tuple[str | None, str | None]:
    """Choose the scalar vendor/product that best matches the CVE description.

    NVD CPE order is not authoritative for "what is this CVE about" — downstream
    integrators often appear first. Prefer pairs whose vendor/product tokens
    appear in the description, and demote ``*_firmware`` SKUs.
    """
    if not products:
        return None, None

    desc = (description or "").lower()

    def _score(ap: AffectedProduct) -> tuple[int, int, int]:
        vendor = (ap.vendor or "").lower()
        product = (ap.product or "").lower()
        product_spaced = product.replace("_", " ")
        vendor_spaced = vendor.replace("_", " ")
        hit = 0
        if product and (product in desc or product_spaced in desc):
            hit += 2
        elif product:
            # Partial token match: "log4j" inside "Apache Log4j2 ..."
            for token in product.split("_"):
                if len(token) >= 4 and token in desc:
                    hit += 1
                    break
        if vendor and (vendor in desc or vendor_spaced in desc):
            hit += 1
        firmware_penalty = 1 if "firmware" in product else 0
        # Prefer shorter product slugs when scores tie (log4j over long SKUs).
        return (hit, -firmware_penalty, -len(product))

    best = max(products, key=_score)
    return best.vendor, best.product


def _prioritize_affected(
    products: list[AffectedProduct],
    vendor: str | None,
    product: str | None,
) -> list[AffectedProduct]:
    """Move the primary ``(vendor, product)`` pair to the front of the list."""
    if not products or not vendor or not product:
        return products
    primary = [
        ap
        for ap in products
        if ap.vendor == vendor and ap.product == product
    ]
    if not primary:
        return products
    rest = [
        ap
        for ap in products
        if not (ap.vendor == vendor and ap.product == product)
    ]
    return primary + rest


def _cna_references(raw_refs: list[dict[str, Any]]) -> dict[str, str]:
    """Label the CNA's own reference URLs for display.

    These are the links the advisory actually cites — the vendor bulletin, the
    patch commit, the vulnerable file — and they were being dropped in favour of
    synthesized NVD/CVEdetails URLs. Labels come from the reference's ``tags``
    (``patch``, ``vendor-advisory``, ``exploit``) or its ``name``, falling back
    to the host, so a reader can tell a patch from a writeup without opening it.
    """
    labelled: dict[str, str] = {}
    for ref in raw_refs:
        url = str(ref.get("url") or "").strip()
        if not url:
            continue
        tags = [t for t in ref.get("tags") or [] if t and not t.startswith("x_refsource")]
        label = (tags[0] if tags else "") or str(ref.get("name") or "").strip()
        if label:
            # "vendor-advisory" -> "Vendor Advisory"
            label = label.replace("-", " ").replace("_", " ").title()
        else:
            # Fall back to the host, kept lowercase — "Www.Npmjs.Com" reads as a
            # bug, and the bare domain is what a reader recognizes.
            label = (urlparse(url).netloc or "reference").removeprefix("www.")
        # Keep every URL: same-label references (two patch commits) would
        # otherwise silently overwrite each other.
        key, n = label, 2
        while key in labelled and labelled[key] != url:
            key, n = f"{label} ({n})", n + 1
        labelled[key] = url
    return labelled


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
        attack_client: ATTACKClient | None = None,
    ) -> None:
        self._cveorg = cveorg_client or CVEOrgClient()
        self._nvd = nvd_client or NVDClient()
        self._attack = attack_client or ATTACKClient()

    def get_attack_techniques(self, cve_id: str) -> list[ATTACKTechnique]:
        """Return curated MITRE ATT&CK techniques for a CVE.

        Answers "how would this be exploited, and what would the attacker do
        next" — the operational question a CWE cannot. Techniques come back
        exploitation-first, then primary and secondary impact.

        Coverage is the CISA KEV catalogue (the actively-exploited CVEs), so an
        empty list is the common case and means *no curated mapping exists*, not
        that the CVE is harmless. Nothing is inferred: see
        :mod:`pocmap.clients.attack_client` for why the CWE-derived alternative
        was measured and rejected.

        Args:
            cve_id: The CVE identifier.

        Returns:
            List of :class:`~pocmap.models.ATTACKTechnique`, possibly empty.

        Raises:
            ValidationError: If the CVE ID format is invalid.
        """
        cve_id = _validate_cve_id(cve_id)
        return self._attack.get_techniques(cve_id)

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

        # NVD fills whatever CVE.org left blank. Fetched at most once and only
        # when something is actually missing, because NVD allows 5 requests /
        # 30s unauthenticated and most CVEs need no fallback at all.
        vendor = _blank_to_none(record.get("vendor"))
        product = _blank_to_none(record.get("affected_product"))
        cwes: list[str] = list(record.get("cwe") or [])
        # CVE.org already listed every affected entry — use it before spending an
        # NVD request. NVD only supplements when this comes back empty.
        affected: list[AffectedProduct] = []
        for raw_vendor, raw_product in record.get("affected_products") or []:
            named_product = _blank_to_none(raw_product)
            if named_product is None:
                continue
            affected.append(
                AffectedProduct(
                    vendor=_blank_to_none(raw_vendor) or "N/A", product=named_product
                )
            )

        if cvss.base_score is None or not cwes or (vendor is None and product is None):
            nvd_record = self._safe_nvd_record(cve_id)
            if nvd_record is not None:
                if cvss.base_score is None:
                    cvss = self._nvd.extract_cvss(nvd_record)
                if not cwes:
                    cwes = self._nvd.extract_cwes(nvd_record)
                # A CNA may file literal "n/a" placeholders (12% of a 180-CVE
                # sample). NVD's CPE data usually names the real product —
                # CVE-2026-26832 is "n/a / n/a" at CVE.org and
                # zapolnoch:tesseract_ocr at NVD.
                #
                # Supplement, never overwrite: CVE.org is the authoritative CNA
                # record, and its names are the ones the advisory actually uses
                # ("Apache Software Foundation / Apache Log4j2"), where NVD
                # carries the CPE slug ("apache / log4j2").
                if not affected:
                    affected = _affected_from_nvd(nvd_record)

        # Description is needed both for the response and to rank NVD CPE pairs
        # when CVE.org left vendor/product blank.
        description = self._cveorg.get_description(cve_id)

        if vendor is None and product is None and affected:
            vendor, product = _pick_primary_affected(affected, description)
            affected = _prioritize_affected(affected, vendor, product)

        # Fresh / thin advisories often lack CPE and CNA product names. Infer
        # from description (and reference name/tags already on the record)
        # without inventing CPE strings or calling GHSA/WPScan.
        if vendor is None and product is None:
            ref_titles: list[str] = []
            for item in record.get("references") or []:
                if not isinstance(item, dict):
                    continue
                for key in ("name", "title"):
                    value = item.get(key)
                    if isinstance(value, str) and value.strip():
                        ref_titles.append(value)
                tags = item.get("tags")
                if isinstance(tags, list):
                    ref_titles.extend(str(t) for t in tags if t)
            inferred_v, inferred_p = infer_vendor_product(
                description, reference_titles=ref_titles
            )
            vendor = inferred_v
            product = inferred_p

        # Get EPSS score
        epss = self._cveorg.get_epss(cve_id)

        # Check KEV status
        is_kev, kev_record = self._cveorg.is_kev(cve_id)

        # Get references
        references = self._cveorg.get_references(cve_id, kev_record if is_kev else None)
        references.update(_cna_references(record.get("references") or []))

        # Check ransomware usage
        ransomware = self._cveorg.get_ransomware_usage(cve_id)

        # Build and return the model
        cve_info = CVEInfo(
            id=cve_id,
            description=description,
            cvss=cvss,
            epss=epss,
            kev_status=is_kev,
            cwes=cwes,
            references=references,
            vendor=vendor or "N/A",
            product=product or "N/A",
            affected_products=affected,
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
            if is_programming_error(exc) or isinstance(exc, (OfflineError, RateLimitError)):
                raise
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

    def _safe_nvd_record(self, cve_id: str) -> dict[str, Any] | None:
        """Fetch the NVD record for gap-filling, degrading to ``None``.

        NVD is a *supplement* here — CVE.org already answered. A throttled or
        unavailable NVD must therefore leave the CVE.org data intact rather than
        fail the whole lookup, which is why this swallows HTTP errors that the
        primary path would re-raise.
        """
        try:
            return self._nvd.get_cve(cve_id)
        except Exception as exc:
            logger.debug("NVD fallback unavailable for %s: %s", cve_id, exc)
            return None

    def _fetch_nvd_cvss(self, cve_id: str) -> CVSSScore:
        """Fetch CVSS data from NVD as a fallback."""
        try:
            cve_data = self._nvd.get_cve(cve_id)
            if cve_data:
                return self._nvd.extract_cvss(cve_data)
        except Exception as exc:
            if is_programming_error(exc) or isinstance(exc, OfflineError):
                raise
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
        self._attack.close()

    def __enter__(self) -> CVEService:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
