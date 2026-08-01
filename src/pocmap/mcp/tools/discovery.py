"""Product and package discovery MCP tools."""

from __future__ import annotations

from typing import Any

from pocmap.mcp.errors import _ok, _tool_error
from pocmap.mcp.registration import _tool
from pocmap.mcp.server import _svc


@_tool(
    name="discover_product_cves",
    description=(
        "Discover CVEs affecting a product by name and version. "
        "Use when the user provides a product name but not a specific CVE ID. "
        "Supports version wildcards like '2.x' and product aliases (e.g., 'struts' matches 'Apache Struts'). "
        "Results are grouped by confidence: confirmed_affected (vendor+product+version match), "
        "possibly_affected (vendor or product match but version unclear), and "
        "not_enough_data (insufficient product/version info). "
        "This tool searches the NVD database using keyword search and applies "
        "fuzzy product name matching and version constraint parsing for accurate results."
    ),
)
def discover_product_cves(
    product: str,
    version: str = "",
    vendor: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """Discover CVEs affecting a product by name and version.

    Args:
        product: Product name (e.g., 'Apache Struts', 'Log4j', 'nginx')
        version: Version string (e.g., '2.x', '2.14.1', '1.20.1').
                 Supports wildcards (2.x), exact versions, and range operators.
        vendor: Optional vendor name (e.g., 'Apache', 'Microsoft').
        limit: Maximum number of CVEs to analyze (1-100, default: 50).

    Returns:
        JSON string with query details, normalized vendor/product,
        version constraint, and CVEs grouped by confidence level:
        confirmed_affected, possibly_affected, not_enough_data.
        Each CVE includes id, description, cvss, vendor, product, etc.
    """
    try:
        limit = max(1, min(100, limit))
        result = _svc.discover_product_cves(
            product=product,
            version=version,
            vendor=vendor,
            limit=limit,
        )
        if "error" in result:
            return _ok({
                "error": result["error"],
                "error_type": result.get("error_type", "unknown"),
                "category": result.get("category", "unknown"),
                "retryable": result.get("retryable", False),
                "context": f"discover_product_cves({product})",
                "product": product,
            })
        return _ok(result)
    except Exception as e:
        return _tool_error(e, f"discover_product_cves({product})")


@_tool(
    name="discover_package_cves",
    description=(
        "Find vulnerabilities in a software PACKAGE (a dependency) and the exact releases "
        "that fix them. Use this whenever the user asks about a library, a dependency, a "
        "lockfile, an SBOM, or 'what should I upgrade to' — e.g. requirements.txt, "
        "package.json, pom.xml, go.mod, Gemfile, Cargo.toml. "
        "This is the ONLY pocmap tool that returns fixed versions; lookup_cve and "
        "discover_product_cves are keyed on CPE products and cannot answer 'what do I "
        "upgrade to'. Conversely this tool CANNOT answer questions about deployed products "
        "like nginx, Confluence or FortiOS — use discover_product_cves for those. "
        "Backed by OSV.dev (no API key, no NVD rate limit) and enriched with EPSS and CISA "
        "KEV, so results are ranked by real-world exploitation risk: KEV first, then EPSS, "
        "then CVSS. "
        "Always pass 'version' when the user knows it — OSV then returns only advisories "
        "that genuinely apply to that release instead of every one ever filed. "
        "Ecosystem is case-insensitive here ('pypi' works) and Maven names need the full "
        "'groupId:artifactId'. "
        "Note fixed_versions often lists SEVERAL releases: maintainers backport a fix to "
        "each supported branch, so pick the one on the user's major version."
    ),
)
def discover_package_cves(
    ecosystem: str,
    name: str,
    version: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """Find vulnerabilities affecting a package and the releases that fix them.

    Args:
        ecosystem: Package ecosystem — PyPI, npm, Go, Maven, crates.io, RubyGems,
                   Packagist, NuGet, Hex, Pub, or a distro (Debian:12, Ubuntu:22.04,
                   Alpine:v3.19, Red Hat, Rocky Linux, SUSE, Bitnami).
        name: Package name as that ecosystem spells it. Maven requires the full
              'groupId:artifactId' (e.g. 'org.apache.logging.log4j:log4j-core');
              a bare artifact name matches nothing and looks falsely clean.
        version: Installed version (e.g. '3.2.0'). Strongly recommended.
        limit: Maximum advisories to return (1-500, default: 50).

    Returns:
        JSON string with ecosystem, package, version, total_found, fixable_count,
        unfixed_count, search_sources, and a 'vulnerabilities' list ranked
        highest-risk first. Each entry has id, cve_ids, aliases, summary,
        severity, cvss_score, cvss_vector, epss_score (0.0-1.0), kev_status,
        fixed_versions, introduced_versions, has_fix, withdrawn, published, url.
        An empty list means OSV knows of nothing affecting this coordinate — it
        cannot distinguish that from an unknown package, so check the spelling
        before reporting a dependency as clean.
    """
    try:
        limit = max(1, min(500, limit))
        result = _svc.discover_package_cves(
            ecosystem=ecosystem,
            name=name,
            version=version,
            limit=limit,
        )
        if "error" in result:
            return _ok({
                "error": result["error"],
                "error_type": result.get("error_type", "unknown"),
                "category": result.get("category", "unknown"),
                "retryable": result.get("retryable", False),
                "context": f"discover_package_cves({ecosystem}/{name})",
                "ecosystem": ecosystem,
                "package": name,
            })
        return _ok(result)
    except Exception as e:
        return _tool_error(e, f"discover_package_cves({ecosystem}/{name})")
