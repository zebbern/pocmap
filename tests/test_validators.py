"""Native pytest tests for CVE-ID validation (``pocmap.utils.validators``).

Locks in the canonical normalize/validate contract: case-folding, whitespace
trimming, the null-byte and length guards, and the strict CVE-YYYY-NNNN format.
These are the input-sanitization invariant for the live lookup path, so they
must fail CI if weakened.
"""

from __future__ import annotations

import pytest

from pocmap.utils.validators import (
    MAX_CVE_ID_LENGTH,
    validate_cve_id,
    validate_cve_ids,
)


def test_lowercase_is_normalized() -> None:
    assert validate_cve_id("cve-2021-44228") == "CVE-2021-44228"


def test_surrounding_whitespace_is_trimmed() -> None:
    assert validate_cve_id("  CVE-2021-44228  ") == "CVE-2021-44228"


@pytest.mark.parametrize(
    "bad",
    [
        "",              # empty
        "CVE-2021-",     # missing sequence number
        "CVE202144228",  # missing hyphens
        "CVE-21-44228",  # year is not 4 digits
    ],
)
def test_malformed_ids_raise(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_cve_id(bad)


def test_null_byte_raises_with_message() -> None:
    with pytest.raises(ValueError, match="null byte"):
        validate_cve_id("CVE-2021-44228\x00")


def test_too_long_raises_with_message() -> None:
    # Format-valid but longer than MAX_CVE_ID_LENGTH -> the length guard trips
    # before the format check.
    overlong = "CVE-2021-" + "4" * (MAX_CVE_ID_LENGTH + 5)
    assert len(overlong) > MAX_CVE_ID_LENGTH
    with pytest.raises(ValueError, match="too long"):
        validate_cve_id(overlong)


def test_validate_cve_ids_maps_over_list() -> None:
    out = validate_cve_ids(["cve-2021-44228", "  CVE-2023-38408 "])
    assert out == ["CVE-2021-44228", "CVE-2023-38408"]


def test_validate_cve_ids_propagates_error() -> None:
    with pytest.raises(ValueError):
        validate_cve_ids(["CVE-2021-44228", "bogus"])
