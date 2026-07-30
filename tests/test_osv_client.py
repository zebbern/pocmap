"""Native offline regression tests for OSVClient.

Covers ``src/pocmap/clients/osv_client.py``. Every test injects a ``MagicMock``
HTTP client into the constructor, so no network or DNS call is ever made.

Invariants locked in here:

  * **Fixed versions are scoped to one package coordinate.** One advisory covers
    every package shipping the vulnerable code and their fix streams differ, so
    a flat scan over ``affected[]`` reports upgrade targets that do not exist
    for the package the caller asked about. This is the defect the whole module
    is shaped around — see the Log4Shell case below.
  * **Ecosystem case is normalized before the call.** OSV is case-sensitive and
    answers ``pypi`` with HTTP 400, which would otherwise read as "unknown
    package" rather than "you typed it wrong".
  * **A rejected request never looks like an empty result.** OSV returns 200
    with an empty body for a clean package and 400 for a bad ecosystem; those
    are opposite answers and must not collapse into the same one.
  * ``RateLimitError`` / ``OfflineError`` PROPAGATE — a throttled or offline
    lookup must never read as "this package has no vulnerabilities".
  * GIT ranges, ``last_affected`` and ``limit`` events are never reported as
    fixed versions: a commit SHA is not an installable release, and
    ``last_affected`` is the last *vulnerable* version, so presenting it as a
    fix tells the user to upgrade to something still exploitable.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from pocmap.clients.osv_client import (
    COMMON_ECOSYSTEMS,
    OSVClient,
    cve_ids,
    fixed_versions,
    introduced_versions,
    is_withdrawn,
    normalize_ecosystem,
    qualitative_severity,
    scorable_vector,
    severity_vector,
)
from pocmap.utils.http import HTTPError, OfflineError, RateLimitError, ValidationError


def _client(*pages: Any) -> tuple[OSVClient, MagicMock]:
    """Build a client whose POST returns *pages* in order."""
    http = MagicMock()
    http.post_json_cached.side_effect = list(pages)
    return OSVClient(http_client=http), http


# The real Log4Shell advisory, trimmed. The pax-logging entry is the reason
# scoping exists: 1.9.2 is a genuine fix for that repackager and a nonsense
# instruction for a log4j-core user.
LOG4SHELL: dict[str, Any] = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "aliases": ["CVE-2021-44228"],
    "summary": "Remote code injection in Log4j",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "database_specific": {"severity": "CRITICAL"},
    "affected": [
        {
            "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0.1"}, {"fixed": "2.12.2"}]}],
        },
        {
            "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]}],
        },
        {
            "package": {"ecosystem": "Maven", "name": "org.ops4j.pax.logging:pax-logging-log4j2"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.9.2"}]}],
        },
    ],
}


# ---------------------------------------------------------------------------
# Per-package scoping — the defect this module exists to avoid
# ---------------------------------------------------------------------------

def test_fixed_versions_are_scoped_to_the_queried_package() -> None:
    assert fixed_versions(LOG4SHELL, "Maven", "org.apache.logging.log4j:log4j-core") == [
        "2.12.2",
        "2.15.0",
    ]


def test_a_sibling_package_gets_its_own_fixes_not_the_others() -> None:
    """1.9.2 belongs to pax-logging alone; log4j-core must never be told to use it."""
    assert fixed_versions(LOG4SHELL, "Maven", "org.ops4j.pax.logging:pax-logging-log4j2") == [
        "1.9.2"
    ]


def test_an_unrelated_package_gets_nothing() -> None:
    assert fixed_versions(LOG4SHELL, "Maven", "com.example:not-in-this-advisory") == []


def test_introduced_versions_skip_the_zero_sentinel() -> None:
    """``introduced: "0"`` means "since the beginning" — a bound, not a release."""
    assert introduced_versions(LOG4SHELL, "Maven", "org.ops4j.pax.logging:pax-logging-log4j2") == []
    assert introduced_versions(LOG4SHELL, "Maven", "org.apache.logging.log4j:log4j-core") == [
        "2.0.1",
        "2.13.0",
    ]


def test_ecosystem_is_matched_on_its_base_name() -> None:
    """A record filed under 'Ubuntu:Pro:16.04:LTS' still matches a query for 'Ubuntu'.

    An exact string compare drops every entry here and yields a silently empty
    (i.e. wrong) result rather than an obviously broken one.
    """
    vuln = {
        "id": "UBUNTU-CVE-2021-44228",
        "affected": [
            {
                "package": {"ecosystem": "Ubuntu:Pro:16.04:LTS", "name": "apache-log4j2"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.17"}]}],
            }
        ],
    }
    assert fixed_versions(vuln, "Ubuntu", "apache-log4j2") == ["2.17"]


# ---------------------------------------------------------------------------
# Event and range kinds that are NOT fixes
# ---------------------------------------------------------------------------

def test_git_commit_ranges_are_not_reported_as_fixed_versions() -> None:
    """A 40-hex SHA is not something a user can upgrade to.

    The CVE-keyed OSV record for Log4Shell carries GIT ranges only, so a naive
    walk would answer "upgrade to 38513a7d..." to "what release fixes this".
    """
    vuln = {
        "id": "CVE-2021-44228",
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/apache/logging-log4j2",
                        "events": [
                            {"introduced": "6b788facd3479dfe9052b3a5e13f6603dce8c16f"},
                            {"fixed": "38513a7d57343881f7bf58f37e67d6a87e0a47c5"},
                            {"limit": "deadbeef" * 5},
                        ],
                    }
                ],
            }
        ],
    }
    assert fixed_versions(vuln, "Maven", "org.apache.logging.log4j:log4j-core") == []


def test_last_affected_is_never_reported_as_a_fix() -> None:
    """``last_affected`` is the last VULNERABLE version and means no fix exists."""
    vuln = {
        "id": "GHSA-nofix",
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "com.guicedee.services:log4j-core"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.0.19.1"}]}
                ],
            }
        ],
    }
    assert fixed_versions(vuln, "Maven", "com.guicedee.services:log4j-core") == []


def test_affected_entry_without_ranges_yields_no_fix() -> None:
    """Some entries enumerate ``versions`` only and carry no fix at all."""
    vuln = {
        "id": "GHSA-versions-only",
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "org.xbib.elasticsearch:log4j"},
                "versions": ["6.3.2.1"],
            }
        ],
    }
    assert fixed_versions(vuln, "Maven", "org.xbib.elasticsearch:log4j") == []


# ---------------------------------------------------------------------------
# Ecosystem normalization
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "written,canonical",
    [
        ("pypi", "PyPI"), ("PYPI", "PyPI"), ("PyPI", "PyPI"), ("python", "PyPI"),
        ("npm", "npm"), ("NPM", "npm"), ("nodejs", "npm"),
        ("golang", "Go"), ("go", "Go"),
        ("cargo", "crates.io"), ("crates.io", "crates.io"), ("CRATES.IO", "crates.io"),
        ("red hat", "Red Hat"), ("redhat", "Red Hat"), ("rhel", "Red Hat"),
        ("composer", "Packagist"), ("nuget", "NuGet"), ("gem", "RubyGems"),
    ],
)
def test_ecosystem_spellings_normalize(written: str, canonical: str) -> None:
    assert normalize_ecosystem(written) == canonical


@pytest.mark.parametrize(
    "written,canonical",
    [
        ("debian:12", "Debian:12"),
        ("alpine:v3.19", "Alpine:v3.19"),
        ("ubuntu:22.04", "Ubuntu:22.04"),
    ],
)
def test_release_qualifier_is_preserved(written: str, canonical: str) -> None:
    """OSV validates only the base name; the ``:release`` suffix rides along."""
    assert normalize_ecosystem(written) == canonical


def test_unrecognized_ecosystem_is_none_not_a_guess() -> None:
    """OSV adds ecosystems over time, so 'unknown here' must not mean 'invalid'."""
    assert normalize_ecosystem("madeup") is None
    assert normalize_ecosystem("") is None
    assert normalize_ecosystem("   ") is None


def test_documented_common_ecosystems_all_normalize() -> None:
    """Anything advertised in help text must actually round-trip."""
    for name in COMMON_ECOSYSTEMS:
        assert normalize_ecosystem(name) == name, name


# ---------------------------------------------------------------------------
# Severity extraction
# ---------------------------------------------------------------------------

def test_severity_is_read_from_the_nested_affected_block() -> None:
    """Some sources (every Bitnami record) put severity ONLY under affected[]."""
    vuln = {
        "id": "BIT-nginx-2021-23017",
        "affected": [
            {
                "package": {"ecosystem": "Bitnami", "name": "nginx"},
                "severity": [
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                ],
            }
        ],
    }
    assert scorable_vector(vuln) == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_non_cvss_ordinal_severity_is_not_mistaken_for_a_vector() -> None:
    """Ubuntu records put {"type": "Ubuntu", "score": "high"} in the same array."""
    vuln = {"id": "UBUNTU-CVE-1", "severity": [{"type": "Ubuntu", "score": "high"}]}
    assert severity_vector(vuln) is None
    assert scorable_vector(vuln) is None


def test_v4_only_advisory_is_not_scoreable_but_still_displayable() -> None:
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    vuln = {"id": "GHSA-v4", "severity": [{"type": "CVSS_V4", "score": v4}]}
    assert severity_vector(vuln) == v4
    assert scorable_vector(vuln) is None


def test_v3_is_preferred_for_scoring_even_when_v4_exists() -> None:
    v3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    vuln = {
        "id": "GHSA-both",
        "severity": [{"type": "CVSS_V4", "score": v4}, {"type": "CVSS_V3", "score": v3}],
    }
    assert severity_vector(vuln) == v4  # newest for display
    assert scorable_vector(vuln) == v3  # scoreable for ranking


def test_qualitative_severity_normalizes_publisher_vocabulary() -> None:
    assert qualitative_severity({"database_specific": {"severity": "MODERATE"}}) == "MEDIUM"
    assert qualitative_severity({"database_specific": {"severity": "Medium"}}) == "MEDIUM"
    assert qualitative_severity({"id": "x"}) is None


# ---------------------------------------------------------------------------
# Identifiers and withdrawal
# ---------------------------------------------------------------------------

def test_cve_ids_come_from_the_id_or_the_aliases() -> None:
    assert cve_ids(LOG4SHELL) == ["CVE-2021-44228"]
    assert cve_ids({"id": "CVE-2020-1", "aliases": ["GHSA-x"]}) == ["CVE-2020-1"]
    assert cve_ids({"id": "RUSTSEC-2021-0001", "aliases": []}) == []


def test_withdrawn_is_detected_by_the_timestamp() -> None:
    assert is_withdrawn({"id": "x", "withdrawn": "2022-06-01T17:40:51Z"}) is True
    assert is_withdrawn({"id": "x"}) is False


# ---------------------------------------------------------------------------
# Query behaviour, paging, and the failure taxonomy
# ---------------------------------------------------------------------------

def test_query_sends_the_package_body_and_returns_records() -> None:
    client, http = _client({"vulns": [LOG4SHELL]})
    out = client.query("Maven", "org.apache.logging.log4j:log4j-core", version="2.14.1")
    assert [v["id"] for v in out] == ["GHSA-jfh8-c2jp-5v3q"]
    _url, payload = http.post_json_cached.call_args[0]
    assert payload == {
        "package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"},
        "version": "2.14.1",
    }


def test_query_omits_version_when_not_given() -> None:
    client, http = _client({"vulns": []})
    client.query("PyPI", "django")
    _url, payload = http.post_json_cached.call_args[0]
    assert "version" not in payload


def test_empty_body_is_a_clean_package_not_a_crash() -> None:
    """A zero-vuln reply is literally ``{}`` — there is no 'vulns' key at all."""
    client, _http = _client({})
    assert client.query("PyPI", "django") == []


def test_paging_follows_the_token_and_dedupes() -> None:
    page1 = {"vulns": [{"id": "A"}, {"id": "B"}], "next_page_token": "tok"}
    page2 = {"vulns": [{"id": "B"}, {"id": "C"}]}
    client, http = _client(page1, page2)
    assert [v["id"] for v in client.query("PyPI", "django")] == ["A", "B", "C"]
    assert http.post_json_cached.call_count == 2
    _url, second = http.post_json_cached.call_args_list[1][0]
    assert second["page_token"] == "tok"


def test_paging_stops_at_max_pages() -> None:
    """A pathological package must not spin forever."""
    endless = [{"vulns": [{"id": f"V{i}"}], "next_page_token": "t"} for i in range(10)]
    client, http = _client(*endless)
    client.query("Debian:12", "linux", max_pages=3)
    assert http.post_json_cached.call_count == 3


def test_bad_ecosystem_raises_instead_of_returning_empty() -> None:
    """HTTP 400 and "no vulnerabilities" are opposite answers."""
    http = MagicMock()
    http.post_json_cached.side_effect = HTTPError(
        'HTTP 400 from osv: {"code":3,"message":"invalid ecosystem"}', status_code=400
    )
    client = OSVClient(http_client=http)
    with pytest.raises(ValidationError, match="PyPI"):
        client.query("pypi", "django")


def test_rate_limit_error_propagates() -> None:
    http = MagicMock()
    http.post_json_cached.side_effect = RateLimitError("429", status_code=429)
    with pytest.raises(RateLimitError):
        OSVClient(http_client=http).query("PyPI", "django")


def test_offline_error_propagates() -> None:
    http = MagicMock()
    http.post_json_cached.side_effect = OfflineError("cache miss")
    with pytest.raises(OfflineError):
        OSVClient(http_client=http).query("PyPI", "django")


def test_generic_http_error_propagates_instead_of_reading_as_clean() -> None:
    """Elsewhere an empty list means "nothing found"; here it means "safe to ship".

    Degrading an unreachable OSV to [] would tell a user their dependency has no
    known vulnerabilities because the lookup failed — the worst answer this tool
    can give, and indistinguishable from a genuine all-clear.
    """
    http = MagicMock()
    http.post_json_cached.side_effect = HTTPError("500", status_code=500)
    with pytest.raises(HTTPError):
        OSVClient(http_client=http).query("PyPI", "django")


def test_blank_input_short_circuits_without_a_request() -> None:
    http = MagicMock()
    client = OSVClient(http_client=http)
    assert client.query("", "django") == []
    assert client.query("PyPI", "  ") == []
    http.post_json_cached.assert_not_called()


def test_a_malformed_vulns_field_yields_no_records() -> None:
    """A dict without a usable 'vulns' list is a genuine empty answer."""
    client, _ = _client({"vulns": "not-a-list"})
    assert client.query("PyPI", "django") == []


def test_a_non_object_response_raises_rather_than_reading_as_clean() -> None:
    """Something is mangling the response; that is not an all-clear."""
    client, _ = _client(None)
    with pytest.raises(HTTPError):
        client.query("PyPI", "django")


def test_get_vuln_returns_none_for_a_missing_id() -> None:
    http = MagicMock()
    http.get_json.return_value = None
    assert OSVClient(http_client=http).get_vuln("GHSA-nope") is None


def test_get_vuln_rejects_a_path_traversing_id() -> None:
    """The id lands in a URL path, so a separator must never reach it."""
    http = MagicMock()
    client = OSVClient(http_client=http)
    assert client.get_vuln("../../etc/passwd") is None
    assert client.get_vuln("a\\b") is None
    http.get_json.assert_not_called()


def test_aliases_bridges_cve_to_ghsa() -> None:
    http = MagicMock()
    http.get_json.return_value = {"id": "CVE-2021-44228", "aliases": ["GHSA-jfh8-c2jp-5v3q"]}
    assert OSVClient(http_client=http).aliases("CVE-2021-44228") == ["GHSA-jfh8-c2jp-5v3q"]


# ---------------------------------------------------------------------------
# Package-name normalization — the "no fix published" false negative
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "written",
    ["django", "Django", "DJANGO", "dJaNgO"],
)
def test_package_name_matching_is_case_insensitive(written: str) -> None:
    """OSV stores the normalized name; the caller types the manifest's name.

    A raw != comparison emptied fixed_versions for `Django` — exactly how it is
    spelled in a requirements.txt — and callers are told an empty list means
    "no fix published".
    """
    vuln = {
        "id": "GHSA-x",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "django"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.2.14"}]}
                ],
            }
        ],
    }
    assert fixed_versions(vuln, "PyPI", written) == ["3.2.14"]


@pytest.mark.parametrize(
    "written,stored",
    [
        ("PyYAML", "pyyaml"),
        ("zope.interface", "zope-interface"),
        ("ruamel_yaml", "ruamel.yaml"),
        ("Flask-Cors", "flask_cors"),
    ],
)
def test_pep503_separators_are_equivalent(written: str, stored: str) -> None:
    """PEP 503: runs of '-', '_' and '.' are the same character for matching."""
    vuln = {
        "id": "GHSA-y",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": stored},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}
                ],
            }
        ],
    }
    assert fixed_versions(vuln, "PyPI", written) == ["1.0"]


def test_a_genuinely_different_package_still_does_not_match() -> None:
    """Folding case must not start matching neighbours."""
    vuln = {
        "id": "GHSA-z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "django-rest-framework"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}
                ],
            }
        ],
    }
    assert fixed_versions(vuln, "PyPI", "django") == []
