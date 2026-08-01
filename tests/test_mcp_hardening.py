"""Hardening regression tests for the MCP server (``pocmap.mcp_server``).

Covers three security/correctness invariants added to the MCP layer:

1. The generated HTML report escapes every externally-sourced value and routes
   every ``href`` through an http(s)-only scheme guard, so a malicious CVE
   description, exploit title, or URL cannot inject markup or a ``javascript:``
   click-to-execute link (XSS).
2. A genuine "CVE not found" is reported with ``category == "not_found"`` rather
   than being mislabeled ``"unknown"``.
3. ``_format_error_json`` derives its ``(category, retryable)`` pair from
   :func:`pocmap.utils.http.categorize_exception`, so rate-limit / offline
   failures are classified with the shared taxonomy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pocmap.mcp_server as mcp_server
from pocmap.models import Exploit, ExploitSource
from pocmap.utils.http import NotFoundError, OfflineError, RateLimitError, categorize_exception


def _entry() -> dict[str, Any]:
    """An entry dict matching the shape produced inside ``generate_html_report``."""
    return {
        "cve_info": {
            "id": "CVE-2021-44228",
            "description": "<script>alert(1)</script>",
            "cvss": {"version": "3.1", "score": 10.0, "severity": "CRITICAL"},
            "epss_score": 0.97,
            "kev_status": True,
        },
        "exploits": [
            {
                "source": "github",
                "title": "<img src=x onerror=alert(1)>",
                "language": "Python",
                "stars": 100,
                "url": "javascript:alert(1)",
            },
            {
                "source": "github",
                "title": "safe repo",
                "language": "Go",
                "stars": 5,
                "url": "https://example.com/safe",
            },
        ],
        "labs": [
            {"platform": "vulhub", "name": "lab", "url": "javascript:alert(1)"},
        ],
        "bb_reports": [
            {"source": "hackerone", "has_poc": True, "title": "report", "url": "javascript:alert(1)"},
        ],
    }


def test_build_html_report_escapes_and_neutralizes_urls() -> None:
    html_out = mcp_server._build_html_report(
        [_entry()], [], ["CVE-2021-44228"], datetime.now(timezone.utc)
    )

    # Raw dangerous markup must not survive verbatim.
    assert "<script>alert(1)</script>" not in html_out
    assert "<img src=x onerror=alert(1)>" not in html_out
    assert "<img" not in html_out

    # javascript: never reaches an href (it is replaced by "#").
    assert 'href="javascript:' not in html_out

    # It was escaped, not silently dropped.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_out

    # A legitimate https URL survives intact.
    assert 'href="https://example.com/safe"' in html_out


def test_build_html_report_escapes_error_rows() -> None:
    errors = [{"cve_id": "<b>x</b>", "error": "<script>boom</script>"}]
    html_out = mcp_server._build_html_report([], errors, ["CVE-0000-0000"], datetime.now(timezone.utc))
    assert "<script>boom</script>" not in html_out
    assert "<b>x</b>" not in html_out
    assert "&lt;script&gt;boom&lt;/script&gt;" in html_out


def test_safe_url_blocks_non_http_schemes() -> None:
    assert mcp_server._safe_url("https://example.com") == "https://example.com"
    assert mcp_server._safe_url("http://example.com") == "http://example.com"
    assert mcp_server._safe_url("javascript:alert(1)") == "#"
    assert mcp_server._safe_url("data:text/html,<script>") == "#"
    assert mcp_server._safe_url("file:///etc/passwd") == "#"


def test_safe_url_malformed_ipv6_does_not_crash() -> None:
    # An unbalanced IPv6 bracket makes urlparse raise ValueError; the guard
    # must degrade to "#" instead of crashing the whole HTML report build.
    assert mcp_server._safe_url("http://[oops") == "#"


def test_lookup_cve_not_found_category(monkeypatch: Any) -> None:
    def _raise_not_found(cve_id: str) -> Any:
        raise NotFoundError(f"no such CVE: {cve_id}")

    monkeypatch.setattr(mcp_server._svc._cve, "get_cve_info", _raise_not_found)

    result = mcp_server.lookup_cve("CVE-2021-44228")
    assert result["category"] == "not_found"
    assert result["cve_id"] == "CVE-2021-44228"
    # Full MCP error envelope: error_type present, retryable False, context set.
    assert result["error_type"] == "NotFoundError"
    assert result["retryable"] is False
    assert result["context"] == "lookup_cve(CVE-2021-44228)"


def test_lookup_cve_rate_limited_envelope(monkeypatch: Any) -> None:
    def _raise_rate_limit(cve_id: str) -> Any:
        raise RateLimitError("throttled")

    monkeypatch.setattr(mcp_server._svc._cve, "get_cve_info", _raise_rate_limit)

    result = mcp_server.lookup_cve("CVE-2021-44228")
    # Full envelope routed through categorize_exception's shared taxonomy.
    assert result["category"] == "rate_limited"
    assert result["retryable"] is True
    assert result["error_type"] == "RateLimitError"
    assert result["context"] == "lookup_cve(CVE-2021-44228)"


def test_lookup_cve_non_notfound_category(monkeypatch: Any) -> None:
    def _raise_value(cve_id: str) -> Any:
        raise ValueError("bad input")

    monkeypatch.setattr(mcp_server._svc._cve, "get_cve_info", _raise_value)

    result = mcp_server.lookup_cve("CVE-2021-44228")
    assert result["category"] == "invalid_input"


def test_format_error_json_uses_shared_taxonomy() -> None:
    rate = mcp_server._format_error_json(RateLimitError("x"), "ctx")
    assert rate["category"] == "rate_limited"
    assert rate["retryable"] is True
    assert (rate["category"], rate["retryable"]) == categorize_exception(RateLimitError("x"))

    offline = mcp_server._format_error_json(OfflineError("x"), "ctx")
    assert offline["category"] == "offline"
    assert offline["retryable"] is False
    assert (offline["category"], offline["retryable"]) == categorize_exception(OfflineError("x"))


# ---------------------------------------------------------------------------
# Upstream-failure vs genuine-empty for cve_to_cpe / cpe_to_cve / KEV / EPSS.
# A throttled/offline NVD must surface the error envelope, never masquerade as
# "no CPEs" / "no CVEs" / "not in KEV" / "no EPSS" (a security false negative).
# ---------------------------------------------------------------------------


def test_cve_to_cpe_rate_limited_envelope(monkeypatch: Any) -> None:
    def _raise(cve_id: str) -> Any:
        raise RateLimitError("throttled")

    monkeypatch.setattr(mcp_server._svc._cve, "get_cpes", _raise)

    result = mcp_server.cve_to_cpe("CVE-2021-44228")
    assert result["category"] == "rate_limited"
    assert result["retryable"] is True
    assert result["error_type"] == "RateLimitError"
    assert "total_count" not in result


def test_cve_to_cpe_offline_envelope(monkeypatch: Any) -> None:
    def _raise(cve_id: str) -> Any:
        raise OfflineError("offline")

    monkeypatch.setattr(mcp_server._svc._cve, "get_cpes", _raise)

    result = mcp_server.cve_to_cpe("CVE-2021-44228")
    assert result["category"] == "offline"
    assert result["retryable"] is False


def test_cve_to_cpe_genuine_empty(monkeypatch: Any) -> None:
    monkeypatch.setattr(mcp_server._svc._cve, "get_cpes", lambda cve_id: [])

    result = mcp_server.cve_to_cpe("CVE-2021-44228")
    assert result["total_count"] == 0
    assert "error" not in result
    assert "category" not in result


def test_cpe_to_cve_rate_limited_envelope(monkeypatch: Any) -> None:
    def _raise(cpe: str) -> Any:
        raise RateLimitError("throttled")

    monkeypatch.setattr(mcp_server._svc._cve, "cpe_to_cves", _raise)

    result = mcp_server.cpe_to_cve("cpe:2.3:a:apache:log4j:2.0")
    assert result["category"] == "rate_limited"
    assert result["retryable"] is True
    assert result["error_type"] == "RateLimitError"
    assert "total_count" not in result


def test_cpe_to_cve_genuine_empty(monkeypatch: Any) -> None:
    monkeypatch.setattr(mcp_server._svc._cve, "cpe_to_cves", lambda cpe: [])

    result = mcp_server.cpe_to_cve("cpe:2.3:a:apache:log4j:2.0")
    assert result["total_count"] == 0
    assert "error" not in result


def test_check_kev_status_rate_limited_envelope(monkeypatch: Any) -> None:
    def _raise(cve_id: str) -> Any:
        raise RateLimitError("throttled")

    monkeypatch.setattr(mcp_server._svc._cve, "get_cve_info", _raise)

    result = mcp_server.check_kev_status("CVE-2021-44228")
    assert result["category"] == "rate_limited"
    assert result["retryable"] is True
    # A throttle must NOT be reported as "not in KEV".
    assert "kev_status" not in result


def test_check_kev_status_offline_envelope(monkeypatch: Any) -> None:
    def _raise(cve_id: str) -> Any:
        raise OfflineError("offline")

    monkeypatch.setattr(mcp_server._svc._cve, "get_cve_info", _raise)

    result = mcp_server.check_kev_status("CVE-2021-44228")
    assert result["category"] == "offline"
    assert "kev_status" not in result


def test_get_epss_score_offline_envelope(monkeypatch: Any) -> None:
    def _raise(cve_id: str) -> Any:
        raise OfflineError("offline")

    monkeypatch.setattr(mcp_server._svc._cve, "get_cve_info", _raise)

    result = mcp_server.get_epss_score("CVE-2021-44228")
    assert result["category"] == "offline"
    assert result["retryable"] is False
    # A cache miss must NOT be reported as "no EPSS data".
    assert "available" not in result


# ---------------------------------------------------------------------------
# db-exploit lookups filter by source BEFORE applying the limit
# ---------------------------------------------------------------------------

def test_db_exploit_tools_are_not_shadowed_by_earlier_sources(
    monkeypatch: Any,
) -> None:
    """``find_db_exploits`` returns [metasploit, exploitdb, nuclei] in order.

    The default ``limit=1`` used to slice that combined list *before* filtering
    by source, so any CVE with a Metasploit module reported "no ExploitDB entry"
    and "no Nuclei template".
    """
    fake = [
        Exploit(source=ExploitSource.METASPLOIT, url="https://msf", title="msf module"),
        Exploit(source=ExploitSource.EXPLOITDB, url="https://edb", title="edb entry"),
        Exploit(source=ExploitSource.NUCLEI, url="https://nuc", title="nuclei tpl"),
    ]
    adapter = mcp_server.ServiceAdapter()
    monkeypatch.setattr(adapter._exploit, "find_db_exploits", lambda cve_id: fake)

    cve = "CVE-2021-44228"
    assert (adapter.find_metasploit_module(cve) or {}).get("title") == "msf module"
    assert (adapter.find_exploitdb_entry(cve) or {}).get("title") == "edb entry"
    assert (adapter.find_nuclei_template(cve) or {}).get("title") == "nuclei tpl"


def test_db_exploit_tools_return_none_when_their_source_is_absent(
    monkeypatch: Any,
) -> None:
    fake = [Exploit(source=ExploitSource.METASPLOIT, url="https://msf", title="msf")]
    adapter = mcp_server.ServiceAdapter()
    monkeypatch.setattr(adapter._exploit, "find_db_exploits", lambda cve_id: fake)

    assert adapter.find_exploitdb_entry("CVE-2021-44228") is None
    assert adapter.find_nuclei_template("CVE-2021-44228") is None
