"""Validation utilities for PocMap.

Shared validation functions used across multiple services to avoid
cross-service coupling (e.g., importing CVEService just for CVE ID validation).
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Single source of truth for CVE ID validation.
#
# This module owns the canonical CVE-ID regex and length bound. Other modules
# (``pocmap.models``, ``pocmap.services.cve_service``) reference these instead
# of redefining their own copies, so the validation rules cannot drift apart.
# ---------------------------------------------------------------------------

# Maximum length for a well-formed CVE ID. Real IDs (CVE-YYYY-NNNNNNN) top out
# far below this; the bound just rejects pathologically long / crafted input
# before it reaches downstream systems.
MAX_CVE_ID_LENGTH: int = 20

# Compiled regex for CVE ID validation (case-insensitive; IDs are normalized
# to uppercase before matching).
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


def validate_cve_id(cve_id: str) -> str:
    """Validate and normalize a CVE identifier.

    Guards are applied in order: empty, null byte, length, then format. The
    null-byte and length checks protect the live lookup path (CLI + services)
    from crafted input that could truncate or overrun downstream systems.

    Args:
        cve_id: The CVE ID string to validate.

    Returns:
        Uppercase normalized CVE ID.

    Raises:
        ValueError: If the value is empty, contains a null byte, exceeds
            :data:`MAX_CVE_ID_LENGTH`, or is not a well-formed CVE ID.
    """
    if not cve_id:
        raise ValueError("CVE ID cannot be empty")
    cve_id = cve_id.upper().strip()
    # Reject null bytes that could cause truncation in downstream systems.
    if "\x00" in cve_id:
        raise ValueError("CVE ID contains null byte")
    if len(cve_id) > MAX_CVE_ID_LENGTH:
        raise ValueError(f"CVE ID too long (max {MAX_CVE_ID_LENGTH}): {cve_id}")
    if not _CVE_PATTERN.match(cve_id):
        raise ValueError(f"Invalid CVE ID format: {cve_id}")
    return cve_id


def validate_cve_ids(cve_ids: list[str]) -> list[str]:
    """Validate multiple CVE identifiers.

    Args:
        cve_ids: List of CVE ID strings to validate.

    Returns:
        List of uppercase normalized CVE IDs.

    Raises:
        ValueError: If any CVE ID format is invalid.
    """
    return [validate_cve_id(c) for c in cve_ids]
