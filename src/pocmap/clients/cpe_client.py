"""NVD CPE dictionary client.

Resolves a human-written product name ("nginx", "Fortinet FortiOS") to the
canonical ``vendor:product`` pairs NVD actually files CVEs under, so discovery
can query by CPE instead of full-text keyword search.

Two properties of the dictionary drive the design:

* A product routinely has **several** pairs, usually because it changed hands.
  ``nginx`` resolves to ``igor_sysoev:nginx`` (0 CVEs), ``nginx:nginx`` (2) and
  ``f5:nginx`` (41) — taking only the top-ranked hit would return almost
  nothing, so every pair is searched and the results unioned.
* Keyword hits include neighbours (``nginx`` also matches
  ``nginx_ingress_controller``), so exact product-token matches are preferred
  and looser matches are only used when there is no exact hit.

Reference: https://nvd.nist.gov/developers/products
"""

from __future__ import annotations

import logging
import re
from typing import Any

from pocmap.config import NVD_CPE_API_BASE, settings
from pocmap.utils.http import HTTPClient, HTTPError, OfflineError, RateLimitError

logger = logging.getLogger(__name__)

# Bounds the fan-out of the follow-up CVE queries: each resolved pair costs one
# more NVD request, and unauthenticated NVD allows only 5 requests / 30s.
DEFAULT_MAX_PAIRS = 5

# One dictionary page. NVD caps this endpoint at 10,000; a single page is enough
# to see every vendor spelling of a product without paginating.
_RESULTS_PER_PAGE = 2000


def _slug(value: str) -> str:
    """Collapse a name to a separator-free comparison key."""
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _is_exact_product(cpe_product: str, target: str) -> bool:
    """Whether *cpe_product* names the queried product rather than a neighbour.

    The query often still carries the vendor ("Fortinet FortiOS" -> target
    ``fortinetfortios``), so a trailing match counts as exact. Prefix matches
    deliberately do not: ``nginx_ingress_controller`` is a different product
    from ``nginx``.
    """
    product_slug = _slug(cpe_product)
    if not product_slug:
        return False
    return product_slug == target or target.endswith(product_slug)


class CPEDictionaryClient:
    """Client for the NVD CPE dictionary.

    Args:
        api_key: Optional NVD API key for higher rate limits.
        http_client: Optional HTTP client instance.

    Example::

        client = CPEDictionaryClient()
        client.resolve("nginx")
        # [('f5', 'nginx'), ('nginx', 'nginx'), ('igor_sysoev', 'nginx')]
    """

    def __init__(
        self,
        api_key: str | None = None,
        http_client: HTTPClient | None = None,
    ) -> None:
        self.api_key = api_key or settings.nvd_api_key
        self._client = http_client or HTTPClient(headers=settings.nvd_headers)

    def resolve(
        self,
        product: str,
        vendor_hint: str | None = None,
        max_pairs: int = DEFAULT_MAX_PAIRS,
    ) -> list[tuple[str, str]]:
        """Resolve *product* to canonical ``(vendor, product)`` CPE pairs.

        Args:
            product: Product name as written by the caller.
            vendor_hint: Optional vendor to prefer. Applied as a *soft* filter:
                if it matches nothing, it is ignored rather than emptying the
                result, since the hint may come from the alias table's guess.
            max_pairs: Cap on returned pairs.

        Returns:
            Pairs ordered by relevance (exact product matches first, then by how
            many CPE entries back them). Empty if the product is unknown.

        Raises:
            OfflineError: Offline mode with no cached response.
            RateLimitError: NVD throttled the request.
        """
        product = product.strip()
        if not product:
            return []

        products = self._fetch(product)
        if not products:
            return []

        target = _slug(product)
        # Rank by CPE-entry count: the vendor with the most catalogued versions
        # is the one the product is actually filed under.
        counts: dict[tuple[str, str], int] = {}
        for entry in products:
            cpe_name = (entry.get("cpe") or {}).get("cpeName", "")
            parts = cpe_name.split(":")
            if len(parts) < 5 or not parts[3] or not parts[4]:
                continue
            pair = (parts[3], parts[4])
            counts[pair] = counts.get(pair, 0) + 1

        if not counts:
            return []

        exact = {p: c for p, c in counts.items() if _is_exact_product(p[1], target)}
        # Only fall back to neighbours ("nginx_ingress_controller") when nothing
        # matches the product name outright.
        candidates = exact or counts

        if vendor_hint:
            hint = _slug(vendor_hint)
            narrowed = {p: c for p, c in candidates.items() if hint in _slug(p[0])}
            if narrowed:
                candidates = narrowed
            else:
                logger.debug(
                    "Vendor hint %r matched no CPE vendor for %r; ignoring it",
                    vendor_hint,
                    product,
                )

        ranked = sorted(candidates.items(), key=lambda kv: (-kv[1], kv[0]))
        pairs = [pair for pair, _count in ranked]
        if len(pairs) > max_pairs:
            logger.info(
                "CPE dictionary returned %d vendor:product pairs for %r; "
                "querying the top %d (%s) and dropping %s",
                len(pairs),
                product,
                max_pairs,
                ", ".join(f"{v}:{p}" for v, p in pairs[:max_pairs]),
                ", ".join(f"{v}:{p}" for v, p in pairs[max_pairs:]),
            )
            pairs = pairs[:max_pairs]
        return pairs

    def _fetch(self, keyword: str) -> list[dict[str, Any]]:
        """Fetch one page of dictionary entries for *keyword*."""
        headers = {**(settings.nvd_headers or {})}
        if self.api_key:
            # SECURITY: send API key in header instead of query string
            headers["apiKey"] = self.api_key

        params: dict[str, str | int] = {
            "keywordSearch": keyword,
            "resultsPerPage": _RESULTS_PER_PAGE,
        }
        try:
            data = self._client.get_json(NVD_CPE_API_BASE, headers=headers, params=params)
        except (OfflineError, RateLimitError):
            # An offline cache-miss or a throttled upstream must surface as an
            # upstream failure, never as "this product has no CPEs".
            raise
        except HTTPError as exc:
            logger.warning("CPE dictionary lookup failed for %r: %s", keyword, exc)
            return []

        if not isinstance(data, dict):
            return []
        products = data.get("products")
        return products if isinstance(products, list) else []

    def close(self) -> None:
        """Release the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> CPEDictionaryClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
