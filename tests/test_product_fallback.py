"""Offline tests for description-based vendor/product inference."""

from __future__ import annotations

from pocmap.utils.product_fallback import infer_vendor_product


def test_infer_apache_log4j() -> None:
    vendor, product = infer_vendor_product(
        "Apache Log4j2 allows remote code execution via JNDI."
    )
    assert vendor == "Apache"
    assert product is not None
    assert "log4j" in product.lower()


def test_infer_vulnerability_in_product() -> None:
    vendor, product = infer_vendor_product(
        "A vulnerability in WidgetServer before 2.0 allows XSS."
    )
    assert product is not None
    assert "widget" in product.lower()


def test_infer_product_before_version() -> None:
    vendor, product = infer_vendor_product(
        "FreeRDP before 3.30.0 (<= 3.29.0) contains a heap-based buffer overflow."
    )
    assert product == "FreeRDP"
    assert vendor is None


def test_infer_product_prior_to_contains() -> None:
    _, product = infer_vendor_product(
        "PyAthena prior to 3.35.4 contains a sql injection vulnerability."
    )
    assert product == "PyAthena"


def test_infer_wordpress_plugin() -> None:
    vendor, product = infer_vendor_product(
        "The WooCommerce - Social Login plugin for WordPress is vulnerable to Authentication Bypass."
    )
    assert vendor == "WordPress"
    assert product is not None
    assert "WooCommerce" in product


def test_infer_scoped_npm_package() -> None:
    _, product = infer_vendor_product(
        "@better-auth/scim (a better-auth plugin) versions >= 1.4.0 contain an issue."
    )
    assert product == "@better-auth/scim"


def test_empty_description() -> None:
    assert infer_vendor_product(None) == (None, None)
    assert infer_vendor_product("") == (None, None)
