"""A malformed identifier must be an error, never a negative finding.

Only 3 of the 13 CVE-taking MCP tools validated their input. The other 10
reported a typo as a *result*: ``check_kev_status("CVE202144228")`` returned
``kev_status: false`` — which an agent reads as "not actively exploited" — and
``cve_to_cpe`` / ``cpe_to_cve`` returned ``total_count: 0``, indistinguishable
from a genuine empty answer. AGENTS.md documents ``invalid_input`` as the
contract for exactly this case.

The guard lives in the shared ``_tool`` decorator, so a tool added later
inherits it. These tests are the thing that keeps that true.
"""

from __future__ import annotations

from typing import Any

import anyio
import pytest

mcp_server = pytest.importorskip("pocmap.mcp_server")

MALFORMED_CVE = ["CVE202144228", "2021-44228", "CVE-2021", "not-a-cve", "", "   "]


def _call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    result = anyio.run(lambda: mcp_server.mcp.call_tool(name, args))
    payload = result.structured_content
    assert isinstance(payload, dict)
    return payload


def _cve_tools() -> list[str]:
    tools = anyio.run(mcp_server.mcp.list_tools)
    names = []
    for tool in tools:
        props = (tool.input_schema or {}).get("properties") or {}
        if "cve_id" in props:
            names.append(tool.name)
    return names


def test_every_cve_taking_tool_is_discovered() -> None:
    """Guards the guard: if this shrinks, a tool lost its cve_id parameter."""
    assert len(_cve_tools()) >= 13


@pytest.mark.parametrize("tool_name", _cve_tools())
def test_malformed_cve_id_returns_invalid_input(tool_name: str) -> None:
    payload = _call(tool_name, {"cve_id": "CVE202144228"})

    assert payload.get("category") == "invalid_input", (
        f"{tool_name} reported a malformed CVE id as a result, not an error: {payload}"
    )
    assert payload.get("retryable") is False
    for field in ("error", "error_type", "context"):
        assert field in payload, f"{tool_name} error envelope missing {field!r}"


@pytest.mark.parametrize("bad", MALFORMED_CVE)
def test_check_kev_never_answers_false_for_a_malformed_id(bad: str) -> None:
    """The dangerous case: "not in KEV" must never be the answer to a typo."""
    payload = _call("check_kev_status", {"cve_id": bad})

    assert payload.get("category") == "invalid_input"
    assert "kev_status" not in payload, (
        f"check_kev_status({bad!r}) returned a KEV verdict for an unparseable id"
    )


@pytest.mark.parametrize("bad", ["not-a-cpe", "", "apache:log4j", "cpe:9.9:junk"])
def test_malformed_cpe_returns_invalid_input(bad: str) -> None:
    payload = _call("cpe_to_cve", {"cpe": bad})

    assert payload.get("category") == "invalid_input"
    assert "cve_ids" not in payload, "an empty CVE list is indistinguishable from a real answer"


@pytest.mark.parametrize("good", ["cpe:2.3:a:apache:log4j:2.0", "cpe:/a:apache:log4j"])
def test_well_formed_cpe_is_not_rejected(good: str) -> None:
    """Both CPE 2.3 and the older 2.2 URI form must pass the guard."""
    payload = _call("cpe_to_cve", {"cpe": good})
    assert payload.get("category") != "invalid_input"


def test_lowercase_cve_id_still_accepted() -> None:
    """AGENTS.md documents `cve-2021-44228` as fine — normalized, not rejected."""
    payload = _call("check_kev_status", {"cve_id": "cve-2021-44228"})
    assert payload.get("category") != "invalid_input"
    assert payload.get("cve_id") == "CVE-2021-44228"


def test_guard_does_not_alter_the_advertised_schemas() -> None:
    """The decorator wraps the function — schemas and hints must be unchanged."""
    tools = anyio.run(mcp_server.mcp.list_tools)
    lookup = next(t for t in tools if t.name == "lookup_cve")

    assert sorted((lookup.input_schema or {}).get("properties") or {}) == ["cve_id"]
    assert (lookup.output_schema or {}).get("type") == "object"
    assert lookup.annotations is not None and lookup.annotations.read_only_hint is True
