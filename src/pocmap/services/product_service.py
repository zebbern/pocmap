"""Product and version discovery service.

Provides fuzzy product name matching, version constraint parsing, and
CVE discovery by product name using the NVD API keyword search.

Example::

    from pocmap.services.product_service import ProductDiscoveryService
    service = ProductDiscoveryService()
    result = service.discover_by_product("Apache Struts", version="2.x")
    print(f"Confirmed: {len(result.confirmed_affected)}")
    print(f"Possibly: {len(result.possibly_affected)}")
"""

from __future__ import annotations

import logging
import re
from typing import Any

from pocmap.clients.nvd_client import NVDClient
from pocmap.config import NVD_API_BASE, settings
from pocmap.data.product_aliases import PRODUCT_ALIASES, VENDOR_PRODUCT_MAP
from pocmap.models import (
    CPEInfo,
    CVEInfo,
    ProductDiscoveryResult,
    VersionConstraint,
)
from pocmap.utils.http import HTTPClient, HTTPError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

_RE_RANGE_OP = re.compile(
    r"^(?P<op>>=|<=|>|<|=)?\s*(?P<ver>[^\s]+)$"
)
_RE_VERSION_PARTS = re.compile(
    r"^(?P<major>\d+|[x*])(?:\.(?P<minor>\d+|[x*]))?(?:\.(?P<patch>\d+|[x*]))?$"
)

# Build reverse lookup: alias -> (canonical_vendor, canonical_product)
# This is computed once at module import time.
_ALIAS_REVERSE_MAP: dict[str, tuple[str | None, str]] = {}


def _build_reverse_map() -> dict[str, tuple[str | None, str]]:
    """Build a reverse mapping from alias -> (vendor, canonical_product)."""
    reverse_map: dict[str, tuple[str | None, str]] = {}

    for canonical, aliases in PRODUCT_ALIASES.items():
        vendor: str | None = None
        # Determine vendor from VENDOR_PRODUCT_MAP
        for v, products in VENDOR_PRODUCT_MAP.items():
            if any(canonical.startswith(vp) for vp in products):
                vendor = v
                break
            # Check if canonical name contains the vendor
            if canonical.startswith(v):
                vendor = v
                break

        # Map the canonical name itself
        reverse_map[canonical.lower()] = (vendor, canonical)
        # Map all aliases
        for alias in aliases:
            reverse_map[alias.lower()] = (vendor, canonical)

    return reverse_map


_ALIAS_REVERSE_MAP = _build_reverse_map()


class ProductDiscoveryService:
    """Service for discovering CVEs by product name and version.

    Combines fuzzy product name matching via aliases, version constraint
    parsing (including wildcards like ``2.x``), and NVD API keyword search
    to categorize CVEs by confidence level.

    Args:
        http_client: Optional :class:`HTTPClient` instance.
        http_client: Optional :class:`HTTPClient` instance.

    Example::

        service = ProductDiscoveryService()
        result = service.discover_by_product("Log4j", version="2.14.1")
        for cve in result.confirmed_affected:
            print(cve.id, cve.cvss.severity)
    """

    def __init__(
        self,
        http_client: HTTPClient | None = None,
    ) -> None:
        self._client = http_client or HTTPClient(headers=settings.nvd_headers)
        self._nvd_client = NVDClient(http_client=self._client)

    # -- Public API --

    def discover_by_product(
        self,
        product: str,
        version: str | None = None,
        vendor: str | None = None,
        limit: int = 50,
    ) -> ProductDiscoveryResult:
        """Discover CVEs affecting a product.

        The discovery pipeline:
        1. Normalize the product name via alias lookup.
        2. Parse the version string into a :class:`VersionConstraint`.
        3. Search NVD by keyword for candidate CVEs.
        4. Categorize each CVE as *confirmed*, *possibly*, or *not enough data*.

        Args:
            product: Product name (e.g., ``"Apache Struts"``, ``"Log4j"``).
            version: Version string (e.g., ``"2.x"``, ``"2.14.1"``, ``None``).
            vendor: Optional vendor name (e.g., ``"Apache"``).
            limit: Maximum number of CVEs to analyze.

        Returns:
            A :class:`ProductDiscoveryResult` with CVEs grouped by confidence.
        """
        # Validate product input
        if not product or not product.strip():
            raise ValueError("Product name cannot be empty or whitespace-only")

        # Step 1: Normalize
        norm_vendor, norm_product = self.normalize_product(product)
        if vendor:
            norm_vendor = vendor.lower().strip()

        # Step 2: Parse version
        v_constraint = self.parse_version(version)

        # Step 3: Search NVD
        keyword = norm_product or product
        candidate_cves = self.search_nvd_by_keyword(keyword, limit=limit)

        # Also try with vendor prefix if available
        if norm_vendor and len(candidate_cves) < limit:
            vendor_keyword = f"{norm_vendor} {keyword}"
            additional = self.search_nvd_by_keyword(
                vendor_keyword, limit=limit - len(candidate_cves)
            )
            # Merge without duplicates
            seen_ids = {c.id for c in candidate_cves}
            for cve in additional:
                if cve.id not in seen_ids:
                    candidate_cves.append(cve)
                    seen_ids.add(cve.id)

        # Step 4: Categorize
        result = self.match_cves_to_product(
            candidate_cves,
            norm_product or product,
            v_constraint,
            norm_vendor,
        )
        result.query = product
        result.normalized_vendor = norm_vendor
        result.normalized_product = norm_product
        result.version_constraint = v_constraint
        result.total_found = len(candidate_cves)
        result.search_sources = ["nvd_keyword_search"]

        return result

    def normalize_product(self, product: str) -> tuple[str | None, str | None]:
        """Normalize a product name to *(vendor, canonical_product)*.

        Handles aliases such as:

        - ``"struts"`` -> *(``"apache"``, ``"struts"``)*
        - ``"log4j"`` -> *(``"apache"``, ``"log4j"``)*
        - ``"apache struts"`` -> *(``"apache"``, ``"struts"``)*

        Args:
            product: Raw product name from user input.

        Returns:
            Tuple of *(vendor, canonical_product)* or *(None, None)* if no match.
        """
        normalized = product.lower().strip()

        # Direct alias lookup
        if normalized in _ALIAS_REVERSE_MAP:
            return _ALIAS_REVERSE_MAP[normalized]

        # Try partial/fuzzy matching
        best_match: tuple[str | None, str] | None = None
        best_score = 0

        for alias, (vendor, canonical) in _ALIAS_REVERSE_MAP.items():
            # Exact match already handled above
            # Check if the normalized input contains the alias
            if alias in normalized or normalized in alias:
                score = len(alias) if alias in normalized else len(normalized)
                if score > best_score:
                    best_score = score
                    best_match = (vendor, canonical)

        if best_match:
            return best_match

        # Try extracting vendor from the product string itself
        parts = normalized.split()
        for part in parts:
            if part in VENDOR_PRODUCT_MAP:
                # The rest is the product
                remaining = " ".join(p for p in parts if p != part).strip()
                return (part, remaining if remaining else None)

        # No match found -- return the input as-is
        return (None, normalized)

    def parse_version(self, version: str | None) -> VersionConstraint | None:
        """Parse a version string into a :class:`VersionConstraint`.

        Handles:

        - ``"2.x"`` -> wildcard major=2
        - ``"2.14.1"`` -> exact version
        - ``"2.14"`` -> major.minor
        - ``">= 2.0"`` -> range operator
        - ``None`` -> any version

        Args:
            version: Raw version string.

        Returns:
            Parsed :class:`VersionConstraint` or *None*.
        """
        if version is None or version.strip() == "":
            return None

        raw = version.strip()
        vc = VersionConstraint(raw=raw)

        # Strip common "v" / "V" prefix (e.g., "v2.14.1" -> "2.14.1")
        raw_stripped = raw.lstrip("vV")
        if raw_stripped != raw:
            vc.raw = raw_stripped

        # Check for range operator
        m = _RE_RANGE_OP.match(raw_stripped)
        if m:
            op = m.group("op")
            ver_str = m.group("ver")
            if op:
                vc.range_op = op
            # Parse version parts
            vm = _RE_VERSION_PARTS.match(ver_str)
            if vm:
                vc.major = _parse_version_part(vm.group("major"))
                vc.minor = _parse_version_part(vm.group("minor"))
                vc.patch = _parse_version_part(vm.group("patch"))
                vc.is_wildcard = any(
                    isinstance(v, str) and v == "x"
                    for v in (vc.major, vc.minor, vc.patch)
                )

        # If no version parts or range operator could be parsed, the string
        # is unparseable (e.g., "latest", "unknown") -- return None meaning
        # no version constraint.
        if (
            vc.major is None
            and vc.minor is None
            and vc.patch is None
            and vc.range_op is None
        ):
            return None

        return vc

    def search_nvd_by_keyword(
        self, keyword: str, limit: int = 50
    ) -> list[CVEInfo]:
        """Search the NVD API by keyword.

        Uses the ``keywordSearch`` parameter to find CVEs related to the
        given product keyword.  Handles pagination to retrieve up to *limit*
        results.

        Args:
            keyword: Search keyword (e.g., product name).
            limit: Maximum results to return.

        Returns:
            List of :class:`CVEInfo` objects from matching CVEs.
        """
        headers = {**(settings.nvd_headers or {})}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        # HIGH-4: NVD limit is 20 for unauthenticated, 100 with API key.
        results_per_page = 100 if settings.nvd_api_key else 20

        all_cves: list[CVEInfo] = []
        start_index = 0

        while len(all_cves) < limit:
            params: dict[str, str | int] = {
                "keywordSearch": keyword,
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
            }

            try:
                data = self._client.get_json(
                    NVD_API_BASE,
                    headers=headers,
                    params=params,
                )
            except HTTPError as exc:
                logger.warning(
                    "NVD keyword search failed for %r (startIndex=%d): %s",
                    keyword,
                    start_index,
                    exc,
                )
                break

            if not data or not data.get("vulnerabilities"):
                break

            for vuln in data["vulnerabilities"]:
                cve_data = vuln.get("cve", {})
                cve_info = self._parse_nvd_cve(cve_data)
                if cve_info:
                    all_cves.append(cve_info)

            # Pagination: check if we've fetched all results.
            total_results = data.get("totalResults", 0)
            if start_index + len(data["vulnerabilities"]) >= total_results:
                break
            if len(data["vulnerabilities"]) < results_per_page:
                break

            start_index += len(data["vulnerabilities"])

        return all_cves[:limit]

    def match_cves_to_product(
        self,
        cves: list[CVEInfo],
        product: str,
        version_constraint: VersionConstraint | None = None,
        vendor: str | None = None,
    ) -> ProductDiscoveryResult:
        """Categorize CVEs by confidence level against a product/version query.

        Categorization rules:

        - **confirmed_affected**: Vendor AND product match AND version
          constraint is met (or no constraint provided).
        - **possibly_affected**: Vendor OR product matches but version info
          is unclear or cannot be verified.
        - **not_enough_data**: CVE has no vendor/product information at all.

        Args:
            cves: List of candidate :class:`CVEInfo` objects.
            product: Canonical product name to match against.
            version_constraint: Parsed version constraint (optional).
            vendor: Canonical vendor name (optional).

        Returns:
            A :class:`ProductDiscoveryResult` with categorized CVEs.
        """
        result = ProductDiscoveryResult(query=product)

        for cve in cves:
            confidence = self._classify_cve(cve, product, version_constraint, vendor)
            if confidence == "confirmed":
                result.confirmed_affected.append(cve)
            elif confidence == "possible":
                result.possibly_affected.append(cve)
            else:
                result.not_enough_data.append(cve)

        return result

    # -- Internal helpers --

    def _classify_cve(
        self,
        cve: CVEInfo,
        product: str,
        version_constraint: VersionConstraint | None,
        vendor: str | None,
    ) -> str:
        """Classify a single CVE's match confidence.

        Returns:
            ``"confirmed"``, ``"possible"``, or ``"unknown"``.
        """
        cve_vendor = (cve.vendor or "").lower().strip()
        cve_product = (cve.product or "").lower().strip()

        # Check if there's any vendor/product info at all
        if not cve_vendor and not cve_product:
            return "unknown"

        # Determine if vendor matches
        vendor_match = False
        if vendor and cve_vendor:
            vendor_match = vendor in cve_vendor or cve_vendor in vendor
        # Also check vendor from the product string (e.g., "apache struts")
        if not vendor_match and vendor:
            product_words = product.lower().split()
            for word in product_words:
                if word in cve_vendor or cve_vendor in word:
                    vendor_match = True
                    break

        # Determine if product matches
        product_match = False
        product_lower = product.lower()
        if cve_product:
            # Direct match
            product_match = (
                product_lower in cve_product
                or cve_product in product_lower
                or cve_product == product_lower
            )
            # Check aliases
            if not product_match:
                for canonical, aliases in PRODUCT_ALIASES.items():
                    if canonical.lower() == product_lower and any(
                        alias in cve_product for alias in aliases
                    ):
                        product_match = True
                        break
                    if product_lower in aliases and (
                        canonical.lower() in cve_product or cve_product in canonical.lower()
                    ):
                        product_match = True
                        break

        # Classification logic
        if vendor_match and product_match:
            # Both match -- check version
            if version_constraint is None:
                return "confirmed"
            if self._version_matches(cve, version_constraint):
                return "confirmed"
            # Version unclear but vendor+product match
            return "possible"

        if vendor_match or product_match:
            return "possible"

        return "unknown"

    def _version_matches(
        self, cve: CVEInfo, constraint: VersionConstraint
    ) -> bool:
        """Check if a CVE's affected versions match the constraint.

        This is a best-effort check. Uses CPE information already extracted
        from the NVD response (no additional API calls).

        Args:
            cve: The CVE to check.
            constraint: The version constraint.

        Returns:
            *True* if the CVE likely affects the constrained version.
        """
        # If constraint has no specific version parts, match everything
        if constraint.major is None and constraint.range_op is None:
            return True

        # MEDIUM-4: Use CPE info extracted during NVD parsing (no extra API calls)
        if cve.affected_cpes:
            return any(
                self._cpe_version_matches(CPEInfo.parse(cpe), constraint)
                for cpe in cve.affected_cpes
            )

        # No CPE info -- be permissive and consider it a match
        return True

    @staticmethod
    def _cpe_version_matches(cpe: CPEInfo, constraint: VersionConstraint) -> bool:
        """Check if a single CPE's version matches the constraint.

        Args:
            cpe: Parsed CPE info.
            constraint: Version constraint.

        Returns:
            *True* if the CPE version matches the constraint.
        """
        cpe_version = cpe.version
        if not cpe_version or cpe_version in ("*", "-"):
            return True  # Wildcard CPE version matches anything

        # Parse CPE version
        cpe_parts = cpe_version.split(".")
        try:
            cpe_major = int(cpe_parts[0]) if cpe_parts[0].isdigit() else None
            cpe_minor = int(cpe_parts[1]) if len(cpe_parts) > 1 and cpe_parts[1].isdigit() else None
            cpe_patch = int(cpe_parts[2]) if len(cpe_parts) > 2 and cpe_parts[2].isdigit() else None
        except (ValueError, IndexError):
            return True  # Can't parse, be permissive

        # Compare based on constraint
        if constraint.is_wildcard:
            if (
                constraint.major is not None
                and constraint.major != "x"
                and cpe_major is not None
                and cpe_major != constraint.major
            ):
                return False
            return not (
                constraint.minor is not None
                and constraint.minor != "x"
                and cpe_minor is not None
                and cpe_minor != constraint.minor
            )

        if constraint.range_op:
            # Build comparable integer tuples. Non-numeric parts (``"x"`` or
            # ``None``) collapse to 0 so tuple comparison never mixes str/int.
            def _v_tuple(
                major: int | str | None,
                minor: int | str | None,
                patch: int | str | None,
            ) -> tuple[int, int, int]:
                def _n(value: int | str | None) -> int:
                    return value if isinstance(value, int) else 0

                return (_n(major), _n(minor), _n(patch))

            c_v = _v_tuple(cpe_major, cpe_minor, cpe_patch)
            cn_v = _v_tuple(constraint.major, constraint.minor, constraint.patch)

            op = constraint.range_op
            if op == ">=":
                return c_v >= cn_v
            if op == "<=":
                return c_v <= cn_v
            if op == ">":
                return c_v > cn_v
            if op == "<":
                return c_v < cn_v
            if op == "=":
                return c_v == cn_v

        # Exact version match (no range op, no wildcard)
        if (
            constraint.major is not None
            and constraint.major != "x"
            and cpe_major is not None
            and cpe_major != constraint.major
        ):
            return False
        if (
            constraint.minor is not None
            and constraint.minor != "x"
            and cpe_minor is not None
            and cpe_minor != constraint.minor
        ):
            return False
        return not (
            constraint.patch is not None
            and constraint.patch != "x"
            and cpe_patch is not None
            and cpe_patch != constraint.patch
        )

    def _parse_nvd_cve(self, cve_data: dict[str, Any]) -> CVEInfo | None:
        """Parse raw NVD CVE data into a :class:`CVEInfo` model.

        Args:
            cve_data: Raw CVE dictionary from NVD API.

        Returns:
            A :class:`CVEInfo` instance, or *None* if parsing fails.
        """
        try:
            cve_id = cve_data.get("id", "")
            if not cve_id.startswith("CVE-"):
                return None

            # Description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # CVSS & CWEs via cached NVDClient (CRITICAL-2)
            cvss = self._nvd_client.extract_cvss(cve_data)
            cwes = self._nvd_client.extract_cwes(cve_data)

            # Vendor/product from configurations + CPE extraction (MEDIUM-4)
            vendor: str | None = None
            product: str | None = None
            affected_cpes: list[str] = []
            configurations = cve_data.get("configurations", [])
            for conf in configurations:
                for node in conf.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria", "")
                        if criteria.startswith("cpe:"):
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3] or vendor
                                product = parts[4] or product
                            # Collect all CPE strings for version checking
                            affected_cpes.append(criteria)
                # Continue collecting CPEs from all nodes/configs

            # Remove duplicate CPEs while preserving order
            seen_cpes: set[str] = set()
            affected_cpes = [
                cpe for cpe in affected_cpes
                if not (cpe in seen_cpes or seen_cpes.add(cpe))  # type: ignore[func-returns-value]
            ]

            # References
            references: dict[str, str] = {}
            refs = cve_data.get("references", [])
            for ref in refs:
                url = ref.get("url", "")
                source = ref.get("source", "reference")
                if url:
                    references[source] = url

            return CVEInfo(
                id=cve_id,
                description=description or None,
                cvss=cvss,
                cwes=cwes,
                references=references,
                vendor=vendor,
                product=product,
                publication_date=cve_data.get("published") or None,
                affected_cpes=affected_cpes,
            )
        except Exception as exc:
            logger.debug("Failed to parse NVD CVE data: %s", exc)
            return None

    def close(self) -> None:
        """Release the underlying HTTP client and CVE service."""
        self._client.close()

        self._nvd_client.close()

    def __enter__(self) -> ProductDiscoveryService:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_version_part(part: str | None) -> int | str | None:
    """Parse a version part string into an int, 'x', or None."""
    if part is None:
        return None
    part = part.strip().lower()
    if part == "x" or part == "*":
        return "x"
    try:
        return int(part)
    except ValueError:
        return None
