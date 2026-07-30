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

from pocmap.clients.cpe_client import CPEDictionaryClient
from pocmap.clients.nvd_client import NVDClient
from pocmap.config import NVD_API_BASE, settings
from pocmap.data.product_aliases import PRODUCT_ALIASES, VENDOR_PRODUCT_MAP
from pocmap.models import (
    AffectedProduct,
    CPEInfo,
    CPEMatch,
    CVEInfo,
    ProductDiscoveryResult,
    VersionConstraint,
)
from pocmap.utils.http import (
    HTTPClient,
    HTTPError,
    OfflineError,
    RateLimitError,
    is_programming_error,
)

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

# Separator-insensitive view of the same table, so "apache_struts",
# "apache struts" and "Apache-Struts" all hit the same entry.
_ALIAS_SLUG_MAP: dict[str, tuple[str | None, str]] = {
    re.sub(r"[^a-z0-9]+", "", alias): value for alias, value in _ALIAS_REVERSE_MAP.items()
}

# Longest first so "palo alto" is tried before any single-token vendor.
_VENDOR_NAMES_BY_LENGTH: list[str] = sorted(VENDOR_PRODUCT_MAP, key=len, reverse=True)


def _lookup_alias(value: str) -> tuple[str | None, str] | None:
    """Look up *value* in the alias table, ignoring separators and case."""
    return _ALIAS_SLUG_MAP.get(re.sub(r"[^a-z0-9]+", "", value.lower()))


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
        self._cpe_client = CPEDictionaryClient(http_client=self._client)

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
        1. Normalize the product name via alias lookup (a fast-path hint).
        2. Parse the version string into a :class:`VersionConstraint`.
        3. Resolve the product to canonical ``vendor:product`` CPE pairs and
           search NVD by CPE, pushing the version constraint upstream. Falls
           back to keyword search only when the product cannot be resolved.
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

        # Step 3: Resolve to CPE pairs, then search by CPE.
        keyword = norm_product or product
        pairs = self._resolve_cpe_pairs(keyword, norm_vendor)
        if pairs:
            candidate_cves = self.search_nvd_by_cpe(pairs, v_constraint, limit=limit)
            sources = ["nvd_cpe_match"]
            # An explicit CPE vendor beats the alias table's inference.
            if not vendor:
                norm_vendor = pairs[0][0]
            matched_cpes = [f"{CPE_PREFIX}{v}:{p}" for v, p in pairs]
        else:
            # Unresolvable product: fall back to noisy full-text search rather
            # than returning nothing, and say so in ``search_sources``.
            candidate_cves = self.search_nvd_by_keyword(keyword, limit=limit)
            sources = ["nvd_keyword_search"]
            matched_cpes = []

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
        result.search_sources = sources
        result.matched_cpes = matched_cpes

        return result

    def _resolve_cpe_pairs(
        self, keyword: str, vendor_hint: str | None
    ) -> list[tuple[str, str]]:
        """Resolve *keyword* to CPE pairs, degrading to ``[]`` on soft failure.

        ``OfflineError`` and ``RateLimitError`` propagate: they mean "could not
        look up", not "no such product", and swallowing them here would silently
        drop the caller into the noisier keyword path.
        """
        try:
            return self._cpe_client.resolve(keyword, vendor_hint=vendor_hint)
        except (OfflineError, RateLimitError):
            raise
        except HTTPError as exc:
            logger.warning("CPE resolution failed for %r: %s", keyword, exc)
            return []

    def normalize_product(self, product: str) -> tuple[str | None, str | None]:
        """Normalize a product name to *(vendor, canonical_product)*.

        Handles aliases such as:

        - ``"struts"`` -> *(``"apache"``, ``"struts"``)*
        - ``"log4j"`` -> *(``"apache"``, ``"log4j"``)*
        - ``"apache struts"`` -> *(``"apache"``, ``"struts"``)*

        The alias table is a curated *fast path*, not the authority: a hit skips
        the CPE-dictionary round trip, a miss simply defers to it. Matching is
        therefore deliberately strict — the previous bare-substring search
        resolved ``"Fortinet FortiOS"`` to ``("apple", "ios")`` because ``"ios"``
        occurs inside ``"fortios"``, and a confidently wrong hint is worse than
        no hint now that a miss is cheap.

        Args:
            product: Raw product name from user input.

        Returns:
            Tuple of *(vendor, canonical_product)* or *(None, None)* if no match.
        """
        normalized = product.lower().strip()

        # Whole-string alias lookup (separator-insensitive: "apache_struts",
        # "apache struts" and "Apache-Struts" all resolve).
        hit = _lookup_alias(normalized)
        if hit:
            return hit

        # Peel off a known vendor phrase ("palo alto", "f5", ...) and retry the
        # remainder. Word-boundary anchored so "f5" does not match inside "f50".
        for vendor_name in _VENDOR_NAMES_BY_LENGTH:
            m = re.search(
                rf"(?<![a-z0-9]){re.escape(vendor_name)}(?![a-z0-9])", normalized
            )
            if not m:
                continue
            remainder = f"{normalized[: m.start()]} {normalized[m.end() :]}".strip()
            if not remainder:
                return (vendor_name, None)
            nested = _lookup_alias(remainder)
            # An explicit vendor token beats whatever vendor the table inferred.
            return (vendor_name, nested[1] if nested else remainder)

        # Unknown to the table -- hand the raw name to the CPE dictionary.
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

        Full-text search over CVE *descriptions*, so results are both noisy
        (``nginx`` matches 363 CVEs, of which 41 actually carry an nginx CPE)
        and incomplete (a CVE that never names the product in prose is
        invisible). Kept as the fallback for products the CPE dictionary cannot
        resolve; prefer :meth:`search_nvd_by_cpe`.

        Args:
            keyword: Search keyword (e.g., product name).
            limit: Maximum results to return.

        Returns:
            List of :class:`CVEInfo` objects from matching CVEs.
        """
        return self._paged_nvd_query(
            {"keywordSearch": keyword}, limit=limit, label=f"keyword {keyword!r}"
        )

    def search_nvd_by_cpe(
        self,
        pairs: list[tuple[str, str]],
        version_constraint: VersionConstraint | None = None,
        limit: int = 50,
    ) -> list[CVEInfo]:
        """Search the NVD API by CPE, unioning results across *pairs*.

        Uses ``virtualMatchString`` so NVD performs the applicability match
        itself, and pushes the version constraint upstream via
        ``versionStart``/``versionEnd``. NVD applies its own range-boundary
        logic there, which is more faithful than any client-side comparison
        against ``versionStartIncluding``/``versionEndExcluding``.

        Args:
            pairs: ``(vendor, product)`` pairs from the CPE dictionary.
            version_constraint: Optional parsed constraint to push upstream.
            limit: Maximum results to return in total.

        Returns:
            CVEs affecting any of *pairs*, deduped by ID and newest first.
        """
        collected: dict[str, CVEInfo] = {}
        for vendor, product in pairs:
            if len(collected) >= limit:
                break
            params = _cpe_search_params(vendor, product, version_constraint)
            found = self._paged_nvd_query(
                params,
                # Over-fetch per pair: the union is deduped and re-sorted below,
                # so a per-pair cut would bias the result toward the first pair.
                limit=limit,
                label=f"cpe {vendor}:{product}",
            )
            for cve in found:
                collected.setdefault(cve.id, cve)

        ordered = sorted(
            collected.values(), key=lambda c: c.publication_date or "", reverse=True
        )
        return ordered[:limit]

    def _paged_nvd_query(
        self, params: dict[str, str | int], limit: int, label: str
    ) -> list[CVEInfo]:
        """Run a paginated NVD CVE query, parsing each page into models.

        Shared by the keyword and CPE search paths so both inherit the same
        offline / throttling semantics.

        NVD returns results **oldest first** and offers no ``sortBy``, so when
        the result set is larger than *limit* this seeks to the tail rather than
        taking the head — otherwise a product with more CVEs than ``--limit``
        could never surface a recent one (``fortinet:fortios`` has 278; the
        first 100 stop in 2015).

        Raises:
            OfflineError: Offline mode with no cached response.
            RateLimitError: Throttled before any result was collected.
        """
        headers = {**(settings.nvd_headers or {})}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        # HIGH-4: NVD limit is 20 for unauthenticated, 100 with API key.
        results_per_page = 100 if settings.nvd_api_key else 20

        all_cves: list[CVEInfo] = []
        start_index = 0
        seeked_to_tail = False

        while len(all_cves) < limit:
            page_params: dict[str, str | int] = {
                **params,
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
            }

            try:
                data = self._client.get_json(
                    NVD_API_BASE,
                    headers=headers,
                    params=page_params,
                )
            except OfflineError:
                # Offline cache-miss must surface, not degrade to an empty result
                # set (which would read as "no CVEs for this product").
                raise
            except RateLimitError as exc:
                # A throttled upstream must surface as UPSTREAM_ERROR rather than
                # masquerade as "no CVEs for this product". Only re-raise when
                # nothing has been collected yet; otherwise degrade gracefully.
                if not all_cves:
                    raise
                logger.warning(
                    "NVD search throttled after partial fetch "
                    "for %s (startIndex=%d): %s",
                    label,
                    start_index,
                    exc,
                )
                break
            except HTTPError as exc:
                logger.warning(
                    "NVD search failed for %s (startIndex=%d): %s",
                    label,
                    start_index,
                    exc,
                )
                break

            if not data or not data.get("vulnerabilities"):
                break

            total_results = int(data.get("totalResults", 0) or 0)

            # More matches than we can return: restart from the newest end.
            # Costs one extra request, and only on the first page of an
            # oversized result set.
            if not seeked_to_tail:
                seeked_to_tail = True
                if total_results > limit:
                    logger.info(
                        "NVD returned %d results for %s; taking the %d most "
                        "recent (oldest %d not analysed)",
                        total_results,
                        label,
                        limit,
                        total_results - limit,
                    )
                    start_index = total_results - limit
                    continue

            for vuln in data["vulnerabilities"]:
                cve_data = vuln.get("cve", {})
                cve_info = self._parse_nvd_cve(cve_data)
                if cve_info:
                    all_cves.append(cve_info)

            # Pagination: check if we've fetched all results.
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
        # Consider EVERY (vendor, product) pair the CVE is recorded against, not
        # just the scalar ``vendor``/``product``. A CVE routinely names the
        # vulnerable component *and* every distro that shipped it, so judging it
        # by one pair misses the component the CVE is actually about.
        pairs = self._candidate_pairs(cve)
        if not pairs:
            return "unknown"

        vendor_match = False
        product_match = False
        for cve_vendor, cve_product in pairs:
            if self._vendor_matches(cve_vendor, vendor, product):
                vendor_match = True
            if self._product_matches(cve_product, product):
                product_match = True
            # A single CPE satisfying both is a stronger signal than two CPEs
            # each satisfying one, so stop as soon as one pair does.
            if vendor_match and product_match:
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

    @staticmethod
    def _candidate_pairs(cve: CVEInfo) -> list[tuple[str, str]]:
        """Every ``(vendor, product)`` pair to consider for *cve*, lowercased.

        Prefers the full :attr:`CVEInfo.affected_products` list, falling back to
        the scalar ``vendor``/``product`` so hand-built :class:`CVEInfo` objects
        (and CVEs from sources other than the NVD parser) still classify.
        """
        pairs: list[tuple[str, str]] = [
            ((ap.vendor or "").lower().strip(), (ap.product or "").lower().strip())
            for ap in cve.affected_products
        ]
        scalar = ((cve.vendor or "").lower().strip(), (cve.product or "").lower().strip())
        if scalar != ("", "") and scalar not in pairs:
            pairs.append(scalar)
        return [p for p in pairs if p != ("", "")]

    @staticmethod
    def _vendor_matches(cve_vendor: str, vendor: str | None, product: str) -> bool:
        """Whether *cve_vendor* satisfies the requested vendor."""
        if not vendor or not cve_vendor:
            return False
        if vendor == cve_vendor or vendor in cve_vendor or cve_vendor in vendor:
            return True
        # The vendor is often embedded in the product phrase ("apache struts").
        return any(word == cve_vendor for word in product.lower().split())

    @staticmethod
    def _product_matches(cve_product: str, product: str) -> bool:
        """Whether *cve_product* satisfies the requested product."""
        if not cve_product:
            return False
        product_lower = product.lower().strip()
        if not product_lower:
            return False
        # NVD products use underscores where queries use spaces/hyphens.
        normalized = _slug(product_lower)
        cve_slug = _slug(cve_product)
        if normalized == cve_slug or normalized in cve_slug or cve_slug in normalized:
            return True
        # Fall back to the curated aliases in either direction.
        for canonical, aliases in PRODUCT_ALIASES.items():
            canonical_slug = _slug(canonical)
            alias_slugs = {_slug(a) for a in aliases}
            if canonical_slug == normalized and cve_slug in alias_slugs:
                return True
            if normalized in alias_slugs and cve_slug == canonical_slug:
                return True
        return False

    def _version_matches(
        self, cve: CVEInfo, constraint: VersionConstraint
    ) -> bool:
        """Check whether a CVE's affected versions overlap the constraint.

        Uses CPE information already extracted from the NVD response (no extra
        API calls). Prefers :attr:`CVEInfo.cpe_matches`, which carries the
        out-of-band ``versionStart*``/``versionEnd*`` bounds — the literal
        version field in the CPE ``criteria`` is ``*`` for most modern entries,
        so matching on it alone accepts every constraint.

        Args:
            cve: The CVE to check.
            constraint: The version constraint.

        Returns:
            *True* if the CVE's affected range overlaps the constrained version.
        """
        # If constraint has no specific version parts, match everything
        if constraint.major is None and constraint.range_op is None:
            return True

        if cve.cpe_matches:
            return any(
                _intervals_overlap(_constraint_interval(constraint), _match_interval(m))
                for m in cve.cpe_matches
            )

        # Older/hand-built records only carry the criteria strings.
        if cve.affected_cpes:
            return any(
                self._cpe_version_matches(CPEInfo.parse(cpe), constraint)
                for cpe in cve.affected_cpes
            )

        # No CPE info -- be permissive and consider it a match
        return True

    @staticmethod
    def _cpe_version_matches(cpe: CPEInfo, constraint: VersionConstraint) -> bool:
        """Check if a single CPE's literal version satisfies the constraint.

        Only sees the version field embedded in the CPE string, so a ``*`` or
        ``-`` version is permissive. Prefer :func:`_match_interval` via
        :class:`~pocmap.models.CPEMatch` when the out-of-band range bounds are
        available — this remains for CPE strings parsed in isolation.

        Args:
            cpe: Parsed CPE info.
            constraint: Version constraint.

        Returns:
            *True* if the CPE version matches the constraint.
        """
        cpe_version = cpe.version
        if not cpe_version or cpe_version in ("*", "-"):
            return True  # Wildcard CPE version matches anything

        point = _version_key(cpe_version)
        if point is None:
            return True  # Can't parse, be permissive

        return _intervals_overlap(
            _constraint_interval(constraint), (point, True, point, True)
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

            # Vendor/product/version data from every CPE in every node.
            #
            # A CVE names many CPEs: the vulnerable component plus each distro
            # that shipped it. Collapsing them to one scalar pair (as this used
            # to, by overwriting on each iteration and keeping the *last*) makes
            # e.g. CVE-2009-2629 — first CPEs ``f5:nginx``, last
            # ``o:fedoraproject:fedora:12`` — look like a Fedora CVE. Every pair
            # is kept so matching can consider all of them.
            affected_cpes: list[str] = []
            cpe_matches: list[CPEMatch] = []
            affected_products: list[AffectedProduct] = []
            seen_pairs: set[tuple[str, str]] = set()
            configurations = cve_data.get("configurations", [])
            for conf in configurations:
                for node in conf.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria", "")
                        if not criteria.startswith("cpe:"):
                            continue
                        affected_cpes.append(criteria)
                        cpe_matches.append(CPEMatch.from_nvd(match))
                        parts = criteria.split(":")
                        if len(parts) >= 5 and parts[3] and parts[4]:
                            pair = (parts[3], parts[4])
                            if pair not in seen_pairs:
                                seen_pairs.add(pair)
                                affected_products.append(
                                    AffectedProduct(vendor=pair[0], product=pair[1])
                                )

            # Remove duplicate CPEs while preserving first-appearance order
            affected_cpes = list(dict.fromkeys(affected_cpes))
            cpe_matches = _dedupe_matches(cpe_matches)

            # Scalar vendor/product stay populated for backward compatibility.
            # Prefer the first pair NVD marks *vulnerable* — platform-only CPEs
            # (``vulnerable: false``) describe where the software ran, not what
            # was broken.
            vendor, product = _primary_pair(cpe_matches, affected_products)

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
                affected_products=affected_products,
                cpe_matches=cpe_matches,
            )
        except Exception as exc:
            if is_programming_error(exc):
                raise
            logger.debug("Failed to parse NVD CVE data: %s", exc)
            return None

    def close(self) -> None:
        """Release the underlying HTTP client and CVE service."""
        self._client.close()

        self._nvd_client.close()
        self._cpe_client.close()

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


# CPE match-string prefix. The part is wildcarded so applications (``a``),
# operating systems (``o``) and hardware (``h``) are all matched — NVD unions
# them for ``*``.
CPE_PREFIX = "cpe:2.3:*:"


def _version_text(constraint: VersionConstraint) -> str | None:
    """Render a constraint's numeric parts as a dotted version string."""
    parts = [
        str(p)
        for p in (constraint.major, constraint.minor, constraint.patch)
        if isinstance(p, int)
    ]
    return ".".join(parts) if parts else None


def _cpe_search_params(
    vendor: str, product: str, constraint: VersionConstraint | None
) -> dict[str, str | int]:
    """Build NVD CVE-search params for one ``vendor:product`` pair.

    The version constraint is pushed upstream so NVD evaluates it against the
    real applicability ranges. The mapping mirrors the documented constraint
    syntax:

    * ``2.14.1`` -> embedded in the match string (an exact CPE version)
    * ``>= 2.0`` / ``> 1.0`` -> ``versionStart`` including / excluding
    * ``<= 1.20`` / ``< 3.0`` -> ``versionEnd`` including / excluding
    * ``2.x`` -> ``[2, 3)``, expressed as both bounds

    The CPE *part* is wildcarded rather than assumed to be ``a`` (application):
    plenty of targets are operating systems or hardware. Hardcoding ``a`` found
    1 CVE for ``fortinet:fortios`` where the ``o`` part has 277.
    """
    base = f"{CPE_PREFIX}{vendor}:{product}"
    params: dict[str, str | int] = {"virtualMatchString": base}
    if constraint is None:
        return params

    version = _version_text(constraint)
    if version is None:
        return params

    op = constraint.range_op
    if op in (">=", ">"):
        params["versionStart"] = version
        params["versionStartType"] = "including" if op == ">=" else "excluding"
        return params
    if op in ("<=", "<"):
        params["versionEnd"] = version
        params["versionEndType"] = "including" if op == "<=" else "excluding"
        return params

    numeric = [
        p for p in (constraint.major, constraint.minor, constraint.patch) if isinstance(p, int)
    ]
    if constraint.is_wildcard or len(numeric) < 3:
        # A truncated or wildcarded version is a prefix range: "2.x" and "2"
        # both mean [2, 3), "2.14" means [2.14, 2.15).
        upper = ".".join(str(p) for p in numeric[:-1] + [numeric[-1] + 1])
        params["versionStart"] = version
        params["versionStartType"] = "including"
        params["versionEnd"] = upper
        params["versionEndType"] = "excluding"
        return params

    # Fully specified: ask NVD for that exact CPE version.
    params["virtualMatchString"] = f"{base}:{version}"
    return params


def _slug(value: str) -> str:
    """Normalize a vendor/product name for comparison.

    NVD writes products with underscores (``apache_http_server``) where callers
    write spaces or hyphens, so both sides collapse to a single separator-free
    form before matching.
    """
    return re.sub(r"[^a-z0-9]+", "", value.lower())


# ---------------------------------------------------------------------------
# Version intervals
#
# Both a parsed constraint ("2.x", ">= 2.0") and an NVD applicability statement
# (``versionStartIncluding`` .. ``versionEndExcluding``) describe a *range* of
# versions. Asking whether a CVE affects the queried version is therefore an
# interval-overlap test, not a component-wise equality test.
# ---------------------------------------------------------------------------

# (lower bound, lower inclusive, upper bound, upper inclusive); None == unbounded
_Interval = tuple["tuple[int, ...] | None", bool, "tuple[int, ...] | None", bool]

_UNBOUNDED: _Interval = (None, True, None, True)


def _version_key(value: str | None) -> tuple[int, ...] | None:
    """Convert a version string to a comparable integer tuple.

    Stops at the first non-numeric component, so ``9.4.0.M1`` becomes
    ``(9, 4, 0)``. Returns *None* when nothing numeric can be extracted.
    """
    if not value:
        return None
    parts: list[int] = []
    for chunk in re.split(r"[.\-_+]", value.strip()):
        m = re.match(r"^(\d+)", chunk)
        if not m:
            break
        parts.append(int(m.group(1)))
    return tuple(parts) or None


def _cmp_versions(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Three-way compare two version tuples, zero-padding to equal length."""
    width = max(len(a), len(b))
    left = a + (0,) * (width - len(a))
    right = b + (0,) * (width - len(b))
    return (left > right) - (left < right)


def _constraint_interval(constraint: VersionConstraint) -> _Interval:
    """Convert a parsed :class:`VersionConstraint` into a version interval."""
    parts = [p for p in (constraint.major, constraint.minor, constraint.patch) if p is not None]
    numeric = tuple(p for p in parts if isinstance(p, int))

    # A leading wildcard ("x.y") pins nothing.
    if not numeric:
        return _UNBOUNDED

    op = constraint.range_op
    if op == ">=":
        return (numeric, True, None, True)
    if op == ">":
        return (numeric, False, None, True)
    if op == "<=":
        return (None, True, numeric, True)
    if op == "<":
        return (None, True, numeric, False)

    # No operator: the version is a *prefix*. "2" and "2.x" both mean [2, 3),
    # "2.14" means [2.14, 2.15) — matching the documented Major.Minor semantics —
    # and a fully-specified "2.14.1" is the single point [2.14.1, 2.14.1].
    truncated = constraint.is_wildcard or len(numeric) < 3
    if truncated:
        upper = numeric[:-1] + (numeric[-1] + 1,)
        return (numeric, True, upper, False)
    return (numeric, True, numeric, True)


def _match_interval(match: CPEMatch) -> _Interval:
    """Convert an NVD applicability statement into a version interval."""
    lower = _version_key(match.version_start_including)
    lower_inc = True
    if lower is None:
        lower = _version_key(match.version_start_excluding)
        lower_inc = lower is None  # an exclusive bound, when one was found

    upper = _version_key(match.version_end_including)
    upper_inc = True
    if upper is None:
        upper = _version_key(match.version_end_excluding)
        upper_inc = upper is None

    if lower is None and upper is None:
        # No out-of-band bounds: fall back to the literal version in the CPE.
        version = CPEInfo.parse(match.criteria).version
        if not version or version in ("*", "-"):
            return _UNBOUNDED
        point = _version_key(version)
        if point is None:
            return _UNBOUNDED
        return (point, True, point, True)

    return (lower, lower_inc, upper, upper_inc)


def _intervals_overlap(a: _Interval, b: _Interval) -> bool:
    """Whether two version intervals share at least one version."""
    a_lo, a_lo_inc, a_hi, a_hi_inc = a
    b_lo, b_lo_inc, b_hi, b_hi_inc = b

    if a_lo is not None and b_hi is not None:
        cmp = _cmp_versions(a_lo, b_hi)
        if cmp > 0 or (cmp == 0 and not (a_lo_inc and b_hi_inc)):
            return False
    if b_lo is not None and a_hi is not None:
        cmp = _cmp_versions(b_lo, a_hi)
        if cmp > 0 or (cmp == 0 and not (b_lo_inc and a_hi_inc)):
            return False
    return True


def _dedupe_matches(matches: list[CPEMatch]) -> list[CPEMatch]:
    """Drop duplicate applicability statements, preserving order."""
    seen: set[tuple[Any, ...]] = set()
    unique: list[CPEMatch] = []
    for m in matches:
        key = (
            m.criteria,
            m.version_start_including,
            m.version_start_excluding,
            m.version_end_including,
            m.version_end_excluding,
            m.vulnerable,
        )
        if key not in seen:
            seen.add(key)
            unique.append(m)
    return unique


def _primary_pair(
    matches: list[CPEMatch], products: list[AffectedProduct]
) -> tuple[str | None, str | None]:
    """Pick the scalar ``(vendor, product)`` to expose for compatibility.

    Prefers the first CPE NVD marks vulnerable; a ``vulnerable: false`` CPE
    describes the platform the software ran on, not the broken component.
    """
    for match in matches:
        if not match.vulnerable:
            continue
        parts = match.criteria.split(":")
        if len(parts) >= 5 and parts[3] and parts[4]:
            return parts[3], parts[4]
    if products:
        return products[0].vendor, products[0].product
    return None, None
