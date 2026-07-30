"""Protocol-level regression tests for the MCP server (offline).

These drive the real ``mcp`` SDK client against the real ``MCPServer`` instance
in-process, so they catch what unit-testing the adapter functions cannot:
registration failures, decorator/SDK signature drift, and a server that imports
fine but does not actually serve. Everything the agent-facing docs promise about
the *surface* is asserted here.

No network: only the playbook tools (pure local JSON) and an intentionally
invalid CVE id are exercised.
"""

from __future__ import annotations

import json
from typing import Any

import anyio
import pytest

from pocmap import __version__

mcp_sdk = pytest.importorskip("mcp", reason="requires the [server] extra")


def _with_client(fn: Any) -> Any:
    """Run *fn(client)* against an in-process client bound to the server."""

    async def _run() -> Any:
        from mcp import Client

        from pocmap.mcp_server import mcp

        async with Client(mcp) as client:
            return await fn(client)

    return anyio.run(_run)


# ---------------------------------------------------------------------------
# The advertised surface
# ---------------------------------------------------------------------------

def test_server_speaks_the_2026_07_28_protocol() -> None:
    async def probe(c: Any) -> tuple[str, str, str]:
        return c.protocol_version, c.server_info.name, c.server_info.version

    protocol, name, version = _with_client(probe)
    assert protocol == "2026-07-28"
    assert name == "PocMap"
    # Version is reported to clients, so it must track the package.
    assert version == __version__


# The advertised tool count, repeated across README, AGENTS.md, mcp_config.json
# and the pocmap-agent skill. Changing it means updating all of them.
EXPECTED_TOOL_COUNT = 22


def test_advertised_tool_count_is_registered() -> None:
    async def probe(c: Any) -> list[str]:
        return [t.name for t in (await c.list_tools()).tools]

    names = set(_with_client(probe))
    assert len(names) == EXPECTED_TOOL_COUNT
    # Spot-check one from each documented category rather than pinning them all
    # twice (the count above already guards additions/removals).
    for expected in (
        "lookup_cve",
        "find_github_pocs",
        "verify_github_pocs",
        "get_attack_techniques",
        "find_bug_bounty_reports",
        "find_practice_labs",
        "discover_product_cves",
        "cve_to_cpe",
        "generate_json_report",
        "get_rapid_response_playbook",
    ):
        assert expected in names


def test_prompts_and_resource_templates_match_the_docs() -> None:
    async def probe(c: Any) -> tuple[list[str], list[str]]:
        prompts = [p.name for p in (await c.list_prompts()).prompts]
        templates = [
            t.uri_template for t in (await c.list_resource_templates()).resource_templates
        ]
        return prompts, templates

    prompts, templates = _with_client(probe)
    assert len(prompts) == 3
    # Parameterized resources are *templates*; they never appear in
    # ``resources/list``, which is why that call returns an empty list.
    assert sorted(templates) == [
        "cve://{cve_id}",
        "exploits://{cve_id}",
        "report://{cve_id}",
    ]


def test_every_tool_advertises_a_description() -> None:
    """The description is the agent's only documentation for a tool."""
    async def probe(c: Any) -> list[tuple[str, str | None]]:
        return [(t.name, t.description) for t in (await c.list_tools()).tools]

    for name, description in _with_client(probe):
        assert description, f"{name} has no description"
        assert len(description) > 80, f"{name} description is too thin to route on"


# ---------------------------------------------------------------------------
# Dispatch actually works end to end
# ---------------------------------------------------------------------------

def test_call_tool_round_trips_a_local_playbook() -> None:
    async def probe(c: Any) -> str:
        out = await c.call_tool("get_rapid_response_playbook", {})
        return out.content[0].text

    payload = json.loads(_with_client(probe))
    assert payload.get("phases"), "playbook should carry phases"


def test_verify_github_pocs_is_gated_and_says_how_to_enable() -> None:
    """Off by default, and the refusal must be actionable.

    A generic ``category: "unknown"`` would leave the agent unable to tell the
    user what to do, so this asserts the remediation reaches the client.
    """
    async def probe(c: Any) -> str:
        out = await c.call_tool(
            "verify_github_pocs", {"cve_id": "CVE-2021-44228", "limit": 1}
        )
        return out.content[0].text

    payload = json.loads(_with_client(probe))
    assert payload["category"] == "not_enabled"
    assert payload["retryable"] is False
    assert "POCMAP_ALLOW_FETCH_POC_SOURCE" in payload["error"]
    assert "POCMAP_ALLOW_FETCH_POC_SOURCE" in payload["remediation"]


def test_malformed_cve_id_is_categorized_invalid_input() -> None:
    """AGENTS.md promises ``invalid_input`` for a malformed CVE ID.

    Regression: ``ValidationError`` did not subclass ``ValueError``, so
    ``categorize_exception`` fell through to ``unknown`` — a documented-contract
    violation that unit tests missed because they never went through dispatch.
    """
    async def probe(c: Any) -> str:
        out = await c.call_tool("lookup_cve", {"cve_id": "CVE202144228"})
        return out.content[0].text

    payload = json.loads(_with_client(probe))
    assert payload["category"] == "invalid_input"
    assert payload["retryable"] is False
