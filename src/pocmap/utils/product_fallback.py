"""Infer vendor/product from CVE description text when CPE/CNA names are thin.

Does not invent CPE strings or call external APIs — only extracts tokens that
already appear in the advisory prose (and optionally reference titles).
"""

from __future__ import annotations

import re

# Common advisory openers: "X vulnerability in Product", "Y in Apache Foo ..."
_IN_PRODUCT_RE = re.compile(
    r"(?i)\b(?:vulnerability|flaw|issue|bug|weakness)\s+in\s+"
    r"(?:the\s+)?([A-Za-z0-9][\w .+\-/]{1,80?}?)(?:\s+(?:before|prior|through|allows|that|which|,|\.|$))"
)
_PRODUCT_ALLOWS_RE = re.compile(
    r"(?i)^([A-Za-z0-9][\w .+\-/]{1,60}?)\s+allows\b"
)
# "Apache Log4j2 ..." / "Microsoft Exchange Server ..." at sentence start
_VENDOR_PRODUCT_RE = re.compile(
    r"(?i)^((?:Apache|Microsoft|Google|Oracle|Cisco|IBM|Red Hat|VMware|Adobe|"
    r"Mozilla|Linux|Samsung|Apple|Amazon|GitLab|Jenkins|WordPress)\b"
    r"[\w .+\-/]{0,60}?)"
    r"(?:\s+(?:before|prior|through|allows|is|are|contains|has|versions?|,|\.|$))"
)

# Fresh NVD blurbs often open with the product, then a version gate / verb:
# "FreeRDP before 3.30.0 contains…", "PyAthena prior to 3.35.4 contains…",
# "sentence-transformers contains…", "ComfyUI v0.23.0 contains…",
# "ArcadeDB versions before…", "@better-auth/scim (…) versions…".
_PRODUCT_LEAD_RE = re.compile(
    r"(?i)^"
    r"("
    r"@[A-Za-z0-9._\-]+/[A-Za-z0-9._\-]+"  # npm scoped package
    r"|[A-Za-z][\w.+/\-]{1,70}?"  # FreeRDP, PyAthena, GitPython, …
    r")"
    r"(?:\s*\([^)]{0,80}\))?"  # optional parenthetical qualifier
    r"\s+"
    r"(?:"
    r"v?\d[\w.\-]*\s+(?:contains|fails|allows|is|does)\b"
    r"|(?:before|prior\s+to)\b"
    r"|versions?\b"
    r"|contains\b"
    r"|fails\s+to\b"
    r"|allows\b"
    r"|is\s+vulnerable\b"
    r")"
)

# WPScan-style: "The Foo plugin for WordPress is vulnerable…"
_WP_PLUGIN_RE = re.compile(
    r"(?i)^The\s+(.+?)\s+plugin\s+for\s+WordPress\s+is\s+vulnerable\b"
)

_MAX_NAME = 80


def infer_vendor_product(
    description: str | None,
    *,
    reference_titles: list[str] | None = None,
) -> tuple[str | None, str | None]:
    """Best-effort ``(vendor, product)`` from description / reference titles.

    Returns ``(None, None)`` when nothing confident can be extracted. Product
    may be set without a separate vendor (caller may store product only).
    """
    texts: list[str] = []
    if description and description.strip():
        texts.append(description.strip())
    for title in reference_titles or []:
        if isinstance(title, str) and title.strip():
            texts.append(title.strip())

    for text in texts:
        first = text.split(". ", 1)[0].strip()
        candidate = _match_name(first) or _match_name(text[:240])
        if candidate:
            return _split_vendor_product(candidate)
    return None, None


def _match_name(text: str) -> str | None:
    wp = _WP_PLUGIN_RE.search(text)
    if wp:
        name = _clean(wp.group(1))
        if name:
            # Keep WordPress as vendor so agents can group plugin CVEs.
            return f"WordPress {name}"

    for pattern in (
        _IN_PRODUCT_RE,
        _PRODUCT_LEAD_RE,
        _PRODUCT_ALLOWS_RE,
        _VENDOR_PRODUCT_RE,
    ):
        m = pattern.search(text)
        if not m:
            continue
        name = _clean(m.group(1))
        if name:
            return name
    return None


def _clean(raw: str) -> str | None:
    name = re.sub(r"\s+", " ", raw).strip(" .,;:-")
    if len(name) < 2 or len(name) > _MAX_NAME:
        return None
    # Reject pure severity / generic filler.
    lowered = name.lower()
    if lowered in {
        "software",
        "the product",
        "a product",
        "multiple products",
        "vulnerability",
        "a vulnerability",
        "an vulnerability",
    }:
        return None
    return name


def _split_vendor_product(name: str) -> tuple[str | None, str | None]:
    """Split a multi-word name into rough vendor + product when obvious."""
    known_vendors = (
        "Apache Software Foundation",
        "Red Hat",
        "Apache",
        "Microsoft",
        "Google",
        "Oracle",
        "Cisco",
        "IBM",
        "VMware",
        "Adobe",
        "Mozilla",
        "Samsung",
        "Apple",
        "Amazon",
        "GitLab",
        "Jenkins",
        "WordPress",
        "Linux",
    )
    for vendor in known_vendors:
        if name.lower().startswith(vendor.lower()):
            rest = name[len(vendor) :].strip(" -/")
            if rest:
                return vendor, rest
            return vendor, name
    # Scoped npm packages: keep the whole coordinate as the product.
    if name.startswith("@"):
        return None, name
    # Single token → product only; multi-word → first token vendor, rest product.
    parts = name.split()
    if len(parts) >= 2 and parts[0][0].isupper():
        return parts[0], " ".join(parts[1:])
    return None, name
