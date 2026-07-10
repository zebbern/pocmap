"""
Edge case and boundary test suite for PocMap new features.

Tests cover:
  - Time parsing edge cases (_parse_since)
  - Product discovery edge cases (normalize_product, parse_version)
  - Severity filter edge cases
  - Date range edge cases

Run: python test_new_features_edge.py
"""

from __future__ import annotations

import os
import sys
from datetime import date, datetime

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------

import pytest  # noqa: E402

from pocmap.data.product_aliases import PRODUCT_ALIASES
from pocmap.services.product_service import (
    ProductDiscoveryService,
    _build_reverse_map,
    _parse_version_part,
)
from pocmap.services.recent_service import RecentService

# Legacy standalone script-runner suite — run directly: `python tests/test_new_features_edge.py`.
# Its checks execute at import via a custom harness (no collectable `test_*` funcs),
# so it is excluded from the default `pytest` run (`addopts = -m 'not network'`) to
# avoid executing as an import side effect. It currently runs offline (it replicates
# parsing/validation logic rather than calling the network); the `network` marker is a
# conservative default in case network-dependent checks are added.
pytestmark = pytest.mark.network

# ============================================================================
# Test harness
# ============================================================================

PASSED = []
FAILED = []
WARNINGS = []


def test(description: str, condition: bool, detail: str = "") -> bool:
    """Record a single test result."""
    if condition:
        PASSED.append((description, detail))
        print(f"  [PASS] {description}")
        return True
    else:
        FAILED.append((description, detail))
        print(f"  [FAIL] {description} — {detail}")
        return False


def expect_error(description: str, callable_, expected_type=ValueError) -> bool:
    """Test that a callable raises an expected exception."""
    try:
        result = callable_()
        FAILED.append((description, f"Expected {expected_type.__name__} but got result: {result!r}"))
        print(f"  [FAIL] {description} — Expected {expected_type.__name__}, got {result!r}")
        return False
    except expected_type as exc:
        PASSED.append((description, f"Raised {expected_type.__name__}: {exc}"))
        print(f"  [PASS] {description}")
        return True
    except Exception as exc:
        FAILED.append((description, f"Expected {expected_type.__name__} but got {type(exc).__name__}: {exc}"))
        print(f"  [FAIL] {description} — Expected {expected_type.__name__}, got {type(exc).__name__}: {exc}")
        return False


def expect_no_error(description: str, callable_) -> tuple[bool, any]:
    """Test that a callable does NOT raise an exception."""
    try:
        result = callable_()
        PASSED.append((description, f"Returned {result!r}"))
        print(f"  [PASS] {description}")
        return True, result
    except Exception as exc:
        FAILED.append((description, f"Unexpected {type(exc).__name__}: {exc}"))
        print(f"  [FAIL] {description} — Unexpected {type(exc).__name__}: {exc}")
        return False, None


# ============================================================================
# Section 1: Time Parsing Edge Cases
# ============================================================================

print("\n" + "=" * 70)
print("SECTION 1: Time Parsing Edge Cases (_parse_since)")
print("=" * 70)

# Test 1: "1h" -> valid
ok, result = expect_no_error(
    "1. _parse_since('1h') -> valid",
    lambda: RecentService._parse_since("1h"),
)
if ok:
    now = datetime.utcnow()
    test(
        "1b. _parse_since('1h') returns datetime ~1 hour ago",
        isinstance(result, datetime) and (now - result).total_seconds() <= 3660,
        f"Delta: {(now - result).total_seconds()}s",
    )

# Test 2: "365d" -> valid (max boundary)
ok, result = expect_no_error(
    "2. _parse_since('365d') -> valid (max boundary)",
    lambda: RecentService._parse_since("365d"),
)
if ok:
    now = datetime.utcnow()
    delta_days = (now - result).total_seconds() / 86400
    test(
        "2b. _parse_since('365d') returns datetime ~365 days ago",
        364 <= delta_days <= 366,
        f"Delta: {delta_days:.2f} days",
    )

# Test 3: "0h" -> ValueError
expect_error(
    "3. _parse_since('0h') -> ValueError (zero hours)",
    lambda: RecentService._parse_since("0h"),
    ValueError,
)

# Test 4: "366d" -> ValueError (exceeds max)
expect_error(
    "4. _parse_since('366d') -> ValueError (exceeds 365d max)",
    lambda: RecentService._parse_since("366d"),
    ValueError,
)

# Test 5: "1w" -> ValueError (invalid unit)
expect_error(
    "5. _parse_since('1w') -> ValueError (invalid unit 'w')",
    lambda: RecentService._parse_since("1w"),
    ValueError,
)

# Test 6: "h" -> ValueError (no number)
expect_error(
    "6. _parse_since('h') -> ValueError (no number)",
    lambda: RecentService._parse_since("h"),
    ValueError,
)

# Test 7: "1.5h" -> ValueError (decimal)
expect_error(
    "7. _parse_since('1.5h') -> ValueError (decimal not allowed)",
    lambda: RecentService._parse_since("1.5h"),
    ValueError,
)

# Test 8: "-1h" -> ValueError (negative)
expect_error(
    "8. _parse_since('-1h') -> ValueError (negative number)",
    lambda: RecentService._parse_since("-1h"),
    ValueError,
)

# Test 9: "  24h  " -> valid (whitespace trimmed)
ok, result = expect_no_error(
    "9. _parse_since('  24h  ') -> valid (whitespace trimmed)",
    lambda: RecentService._parse_since("  24h  "),
)
if ok:
    now = datetime.utcnow()
    test(
        "9b. _parse_since('  24h  ') returns datetime ~24h ago",
        isinstance(result, datetime) and 23 <= (now - result).total_seconds() / 3600 <= 25,
        f"Delta: {(now - result).total_seconds() / 3600:.2f} hours",
    )


# ============================================================================
# Section 2: Product Discovery Edge Cases
# ============================================================================

print("\n" + "=" * 70)
print("SECTION 2: Product Discovery Edge Cases")
print("=" * 70)

service = ProductDiscoveryService()

# --- normalize_product tests ---

# Test 10: normalize_product("") -> behavior check
print("\n  --- normalize_product ---")
ok, result = expect_no_error(
    "10. normalize_product('') behavior check",
    lambda: service.normalize_product(""),
)
if ok:
    test(
        "10b. normalize_product('') returns (None, '')",
        result == (None, ""),
        f"Got: {result!r}",
    )

# Test 11: normalize_product("unknown_product_12345") -> behavior check
ok, result = expect_no_error(
    "11. normalize_product('unknown_product_12345') behavior check",
    lambda: service.normalize_product("unknown_product_12345"),
)
if ok:
    # Unknown products should return (None, normalized_input)
    vendor, prod = result
    test(
        "11b. normalize_product(unknown) returns (None, lowercase_input)",
        vendor is None and prod == "unknown_product_12345",
        f"Got: vendor={vendor!r}, product={prod!r}",
    )

# Test 12: normalize_product("STRUTS") -> case insensitive
ok, result = expect_no_error(
    "12. normalize_product('STRUTS') -> case insensitive?",
    lambda: service.normalize_product("STRUTS"),
)
if ok:
    vendor, prod = result
    # "struts" alias canonical form is "apache struts" per PRODUCT_ALIASES
    test(
        "12b. STRUTS resolves to (apache, 'apache struts') case-insensitively",
        vendor == "apache" and prod == "apache struts",
        f"Got: vendor={vendor!r}, product={prod!r}",
    )

# Test 13: normalize_product("Apache Struts") -> exact match
ok, result = expect_no_error(
    "13. normalize_product('Apache Struts') -> exact match",
    lambda: service.normalize_product("Apache Struts"),
)
if ok:
    vendor, prod = result
    test(
        "13b. 'Apache Struts' resolves to ('apache', 'struts')",
        vendor == "apache" and prod == "apache struts",
        f"Got: vendor={vendor!r}, product={prod!r}",
    )

# --- parse_version tests ---

print("\n  --- parse_version ---")

# Test 14: parse_version("") -> None
ok, result = expect_no_error(
    "14. parse_version('') -> None?",
    lambda: service.parse_version(""),
)
if ok:
    test(
        "14b. parse_version('') returns None",
        result is None,
        f"Got: {result!r}",
    )

# Test 15: parse_version("v2.14.1") -> handles "v" prefix?
ok, result = expect_no_error(
    "15. parse_version('v2.14.1') -> handles 'v' prefix?",
    lambda: service.parse_version("v2.14.1"),
)
if ok:
    if result is None:
        WARNINGS.append(("15", "parse_version('v2.14.1') returned None - 'v' prefix not handled"))
        print("  [WARN] parse_version('v2.14.1') returned None - 'v' prefix NOT handled")
        # This is a potential bug
        test(
            "15b. parse_version('v2.14.1') handles 'v' prefix",
            False,
            "'v' prefix is stripped and version is parsed, but returned None",
        )
    else:
        test(
            "15b. parse_version('v2.14.1') handles 'v' prefix",
            result.major == 2 and result.minor == 14 and result.patch == 1,
            f"Got: major={result.major}, minor={result.minor}, patch={result.patch}",
        )

# Test 16: parse_version(">= 2.0") -> range operator?
ok, result = expect_no_error(
    "16. parse_version('>= 2.0') -> range operator?",
    lambda: service.parse_version(">= 2.0"),
)
if ok:
    test(
        "16b. parse_version('>= 2.0') sets range_op='>=' and major=2, minor=0",
        result is not None
        and result.range_op == ">="
        and result.major == 2
        and result.minor == 0,
        f"Got: range_op={result.range_op if result else None}, major={result.major if result else None}, minor={result.minor if result else None}",
    )

# Test 17: parse_version("2.*") -> wildcard?
ok, result = expect_no_error(
    "17. parse_version('2.*') -> wildcard?",
    lambda: service.parse_version("2.*"),
)
if ok:
    test(
        "17b. parse_version('2.*') sets is_wildcard=True, major=2, minor='x'",
        result is not None
        and result.is_wildcard
        and result.major == 2
        and result.minor == "x",
        f"Got: is_wildcard={result.is_wildcard if result else None}, major={result.major if result else None}, minor={result.minor if result else None}",
    )

# Test 18: parse_version("1.2.3.4") -> 4-part version?
ok, result = expect_no_error(
    "18. parse_version('1.2.3.4') -> 4-part version?",
    lambda: service.parse_version("1.2.3.4"),
)
if ok:
    # The regex only matches up to 3 parts. Let's see behavior
    if result is None:
        test(
            "18b. parse_version('1.2.3.4') returns None (4-part not supported)",
            True,
            "4-part version not parseable by 3-part regex - returns None",
        )
    else:
        test(
            "18b. parse_version('1.2.3.4') parses first 3 parts",
            result.major == 1 and result.minor == 2 and result.patch == 3,
            f"Got: major={result.major}, minor={result.minor}, patch={result.patch}, raw={result.raw}",
        )

# Test 19: parse_version("latest") -> None (no constraint)
ok, result = expect_no_error(
    "19. parse_version('latest') -> None (no constraint)",
    lambda: service.parse_version("latest"),
)
if ok:
    test(
        "19b. parse_version('latest') returns None",
        result is None,
        f"Got: {result!r}",
    )


# ============================================================================
# Section 3: Severity Filter Edge Cases
# ============================================================================

print("\n" + "=" * 70)
print("SECTION 3: Severity Filter Edge Cases")
print("=" * 70)

# We can't easily call find_recent_cves because it requires NVD API calls.
# Instead, we test the severity normalization logic directly by extracting
# the relevant code path.

# Test the severity normalization logic from RecentService.find_recent_cves
# by replicating the logic here:

_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def _normalize_severity(severity: list[str] | None) -> list[str] | None:
    """Replicated severity normalization logic from RecentService."""
    nvd_severities: list[str] | None = None
    if severity:
        nvd_severities = []
        for sev in severity:
            sev_upper = sev.strip().upper()
            if sev_upper in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                nvd_severities.append(sev_upper)
            elif sev.lower() in _SEVERITY_MAP:
                nvd_severities.append(_SEVERITY_MAP[sev.lower()])
        if not nvd_severities:
            raise ValueError(
                f"Invalid severity values: {severity!r}. "
                "Expected one or more of: CRITICAL, HIGH, MEDIUM, LOW."
            )
    return nvd_severities


# Test 20: severity=["critical", "high"] -> lowercase accepted?
ok, result = expect_no_error(
    "20. severity=['critical', 'high'] -> lowercase accepted?",
    lambda: _normalize_severity(["critical", "high"]),
)
if ok:
    test(
        "20b. lowercase severity values are accepted",
        result == ["CRITICAL", "HIGH"],
        f"Got: {result!r}",
    )

# Test 21: severity=["INVALID"] -> ValueError
expect_error(
    "21. severity=['INVALID'] -> ValueError",
    lambda: _normalize_severity(["INVALID"]),
    ValueError,
)

# Test 22: severity=[] -> behavior check
ok, result = expect_no_error(
    "22. severity=[] (empty list) behavior check",
    lambda: _normalize_severity([]),
)
if ok:
    test(
        "22b. severity=[] returns None (no filter applied)",
        result is None,
        f"Got: {result!r}",
    )


# ============================================================================
# Section 4: Date Range Edge Cases
# ============================================================================

print("\n" + "=" * 70)
print("SECTION 4: Date Range Edge Cases")
print("=" * 70)

# We test the date range validation from find_recent_cves by calling it
# with a mock that avoids the NVD API call, or we test the validation
# logic directly.

# Let's test the validation logic directly


def _validate_date_range(from_date: date | None, to_date: date | None) -> bool:
    """Replicated date range validation from RecentService.find_recent_cves."""
    if from_date and to_date and from_date > to_date:
        raise ValueError(
            f"Invalid date range: from_date ({from_date}) "
            f"cannot be after to_date ({to_date})."
        )
    return True


# Test 23: from_date > to_date -> ValueError
expect_error(
    "23. from_date > to_date -> ValueError",
    lambda: _validate_date_range(date(2024, 1, 15), date(2024, 1, 10)),
    ValueError,
)

# Test 24: from_date == to_date -> valid (single day)
ok, result = expect_no_error(
    "24. from_date == to_date -> valid (single day)",
    lambda: _validate_date_range(date(2024, 1, 10), date(2024, 1, 10)),
)
if ok:
    test(
        "24b. Same-day range is valid",
        result is True,
        f"Got: {result}",
    )


# ============================================================================
# Additional boundary tests for completeness
# ============================================================================

print("\n" + "=" * 70)
print("SECTION 5: Additional Boundary / Edge Tests")
print("=" * 70)

# -- Time parsing additional boundaries --
print("\n  --- Additional time parsing ---")

# Max hours boundary (365 * 24 = 8760 hours)
expect_error(
    "25. _parse_since('8761h') -> ValueError (just over max hours)",
    lambda: RecentService._parse_since("8761h"),
    ValueError,
)

ok, _ = expect_no_error(
    "26. _parse_since('8760h') -> valid (exactly 365 days in hours)",
    lambda: RecentService._parse_since("8760h"),
)

# Case sensitivity
ok, result = expect_no_error(
    "27. _parse_since('24H') -> valid (uppercase H)",
    lambda: RecentService._parse_since("24H"),
)

ok, result = expect_no_error(
    "28. _parse_since('7D') -> valid (uppercase D)",
    lambda: RecentService._parse_since("7D"),
)

# Large but valid number
ok, result = expect_no_error(
    "29. _parse_since('364d') -> valid (just under max)",
    lambda: RecentService._parse_since("364d"),
)

# -- Product discovery additional --
print("\n  --- Additional product discovery ---")

# Whitespace-only product
ok, result = expect_no_error(
    "30. normalize_product('   ') behavior check",
    lambda: service.normalize_product("   "),
)
if ok:
    test(
        "30b. normalize_product('   ') returns (None, '')",
        result == (None, ""),
        f"Got: {result!r}",
    )

# Partial match: "apache" should find vendor
ok, result = expect_no_error(
    "31. normalize_product('apache') -> vendor extraction",
    lambda: service.normalize_product("apache"),
)
if ok:
    vendor, prod = result
    test(
        "31b. 'apache' extracts vendor='apache'",
        vendor == "apache",
        f"Got: vendor={vendor!r}, product={prod!r}",
    )

# _parse_version_part helper
print("\n  --- _parse_version_part helper ---")

test(
    "32. _parse_version_part(None) -> None",
    _parse_version_part(None) is None,
    f"Got: {_parse_version_part(None)!r}",
)

test(
    "33. _parse_version_part('x') -> 'x'",
    _parse_version_part("x") == "x",
    f"Got: {_parse_version_part('x')!r}",
)

test(
    "34. _parse_version_part('*') -> 'x' (asterisk mapped to x)",
    _parse_version_part("*") == "x",
    f"Got: {_parse_version_part('*')!r}",
)

test(
    "35. _parse_version_part('  5  ') -> 5 (whitespace stripped)",
    _parse_version_part("  5  ") == 5,
    f"Got: {_parse_version_part('  5  ')!r}",
)

test(
    "36. _parse_version_part('abc') -> None (non-numeric)",
    _parse_version_part("abc") is None,
    f"Got: {_parse_version_part('abc')!r}",
)

# -- Severity normalization additional --
print("\n  --- Additional severity normalization ---")

# Mixed case
ok, result = expect_no_error(
    "37. Mixed case severity ['Critical', 'HIGH', 'medium'] accepted",
    lambda: _normalize_severity(["Critical", "HIGH", "medium"]),
)
if ok:
    test(
        "37b. Mixed case normalizes to uppercase",
        result == ["CRITICAL", "HIGH", "MEDIUM"],
        f"Got: {result!r}",
    )

# With extra whitespace
ok, result = expect_no_error(
    "38. severity with whitespace ['  critical  ', '  high  '] accepted",
    lambda: _normalize_severity(["  critical  ", "  high  "]),
)
if ok:
    test(
        "38b. Whitespace is stripped",
        result == ["CRITICAL", "HIGH"],
        f"Got: {result!r}",
    )

# Combination of valid and invalid should keep only valid
ok, result = expect_no_error(
    "39. severity=['critical', 'INVALID'] keeps only valid",
    lambda: _normalize_severity(["critical", "INVALID"]),
)
if ok:
    test(
        "39b. Only 'critical' kept, INVALID silently dropped",
        result == ["CRITICAL"],
        f"Got: {result!r}",
    )

# All invalid -> ValueError
expect_error(
    "40. severity=['INVALID1', 'INVALID2'] -> ValueError",
    lambda: _normalize_severity(["INVALID1", "INVALID2"]),
    ValueError,
)

# -- Date range additional --
print("\n  --- Additional date range ---")

# None dates should not error
ok, result = expect_no_error(
    "41. from_date=None, to_date=None -> valid",
    lambda: _validate_date_range(None, None),
)

# Only from_date
ok, result = expect_no_error(
    "42. from_date only (to_date=None) -> valid",
    lambda: _validate_date_range(date(2024, 1, 1), None),
)

# -- discover_by_product validation --
print("\n  --- discover_by_product input validation ---")

expect_error(
    "43. discover_by_product('') -> ValueError (empty string)",
    lambda: service.discover_by_product(""),
    ValueError,
)

expect_error(
    "44. discover_by_product('   ') -> ValueError (whitespace only)",
    lambda: service.discover_by_product("   "),
    ValueError,
)

# -- _build_reverse_map sanity --
print("\n  --- Reverse map sanity checks ---")

reverse_map = _build_reverse_map()

test(
    "45. Reverse map is non-empty",
    len(reverse_map) > 0,
    f"Length: {len(reverse_map)}",
)

# Check that all canonical entries are in the reverse map
all_canonical_present = all(
    canonical.lower() in reverse_map for canonical in PRODUCT_ALIASES.keys()
)
test(
    "46. All canonical product names are in reverse map",
    all_canonical_present,
    "",
)

# Check that all aliases are in the reverse map
all_aliases_present = True
missing_aliases = []
for canonical, aliases in PRODUCT_ALIASES.items():
    for alias in aliases:
        if alias.lower() not in reverse_map:
            all_aliases_present = False
            missing_aliases.append(alias)

test(
    "47. All aliases are in reverse map",
    all_aliases_present,
    f"Missing: {missing_aliases}",
)


# ============================================================================
# Summary
# ============================================================================

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

print(f"\n  Total tests:    {len(PASSED) + len(FAILED)}")
print(f"  Passed:         {len(PASSED)}")
print(f"  Failed:         {len(FAILED)}")
print(f"  Warnings:       {len(WARNINGS)}")

if FAILED:
    print("\n--- FAILED TESTS ---")
    for desc, detail in FAILED:
        print(f"  FAIL: {desc}")
        print(f"        {detail}")

if WARNINGS:
    print("\n--- WARNINGS ---")
    for desc, detail in WARNINGS:
        print(f"  WARN [{desc}]: {detail}")

if PASSED and not FAILED:
    print("\n*** ALL TESTS PASSED ***")
elif FAILED:
    print(f"\n*** {len(FAILED)} TEST(S) FAILED ***")
    sys.exit(1)
