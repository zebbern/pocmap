"""Every MCP tool must return a dict through the real SDK call path.

Regression for a 2.6.0 defect: ``generate_json_report`` and
``generate_html_report`` were annotated ``-> dict[str, Any]`` while their
``ServiceAdapter`` methods still returned a JSON *string*. The SDK validates a
tool's return against the schema derived from its annotation, so both tools
raised ``ToolError`` on **every** call — including ``generate_json_report``,
which AGENTS.md documents as the primary entry point ("one call instead of
seven"). Nothing caught it: ``pocmap.mcp_server`` was exempt from
``mypy --strict``, and no test invoked the tools through ``mcp.call_tool``.

These tests run with the network hard-blocked, so most tools return an error
envelope. That is the point — an error envelope is still a dict, and a tool
must never blow up the call path regardless of upstream state.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import anyio
import pytest

from pocmap.config import settings
from pocmap.utils import http as http_mod

mcp_server = pytest.importorskip("pocmap.mcp_server")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force offline and make any transport call an outright failure.

    ``POCMAP_OFFLINE=1`` via ``monkeypatch.setenv`` does NOT work here: the
    ``settings`` singleton is built at import time (config.py), so the env var
    is read long before the test runs. Offline has to be switched on by
    replacing the frozen dataclass on the http module, the way
    ``tests/test_offline.py`` does it.
    """
    monkeypatch.setattr(http_mod, "settings", replace(settings, offline=True))

    def _explode(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("contract tests must not touch the network")

    monkeypatch.setattr("requests.Session.get", _explode)
    monkeypatch.setattr("requests.Session.request", _explode)

# One representative argument set per tool.
TOOL_ARGS: dict[str, dict[str, object]] = {
    "lookup_cve": {"cve_id": "CVE-2021-44228"},
    "get_epss_score": {"cve_id": "CVE-2021-44228"},
    "check_kev_status": {"cve_id": "CVE-2021-44228"},
    "get_attack_techniques": {"cve_id": "CVE-2021-44228"},
    "find_github_pocs": {"cve_id": "CVE-2021-44228"},
    "verify_github_pocs": {"cve_id": "CVE-2021-44228"},
    "find_metasploit_module": {"cve_id": "CVE-2021-44228"},
    "find_exploitdb_entry": {"cve_id": "CVE-2021-44228"},
    "find_nuclei_template": {"cve_id": "CVE-2021-44228"},
    "find_bug_bounty_reports": {"cve_id": "CVE-2021-44228"},
    "find_practice_labs": {"cve_id": "CVE-2021-44228"},
    "find_vulhub_docker": {"cve_id": "CVE-2021-44228"},
    "cve_to_cpe": {"cve_id": "CVE-2021-44228"},
    "cpe_to_cve": {"cpe": "cpe:2.3:a:apache:log4j"},
    "discover_product_cves": {"product": "nginx"},
    "discover_package_cves": {"ecosystem": "PyPI", "name": "django"},
    "generate_json_report": {"cve_ids": "CVE-2021-44228"},
    "generate_html_report": {"cve_ids": "CVE-2021-44228"},
    "find_recent_exploits": {"since": "24h"},
    "get_cve_assessment_playbook": {},
    "get_rapid_response_playbook": {},
    "get_bug_bounty_playbook": {},
}


def _registered_tool_names() -> list[str]:
    return [t.name for t in anyio.run(mcp_server.mcp.list_tools)]


def test_every_registered_tool_has_a_contract_case() -> None:
    """A new tool must be added here — otherwise it ships unexercised."""
    assert sorted(_registered_tool_names()) == sorted(TOOL_ARGS)


@pytest.mark.parametrize("tool_name", sorted(TOOL_ARGS))
def test_tool_returns_a_dict_through_the_sdk(tool_name: str) -> None:
    """The SDK validates the return against the annotation-derived schema.

    Calling through ``mcp.call_tool`` is what makes this a real contract test:
    invoking the undecorated function directly bypasses the validation that
    actually broke in 2.6.0.
    """
    result = anyio.run(
        lambda: mcp_server.mcp.call_tool(tool_name, dict(TOOL_ARGS[tool_name]))
    )

    assert isinstance(result.structured_content, dict), (
        f"{tool_name} returned {type(result.structured_content).__name__}, not dict — "
        "the SDK cannot emit it as structuredContent"
    )
    # The text block must stay parseable for clients that read content[0].text.
    assert result.content and result.content[0].type == "text"


@pytest.mark.parametrize("tool_name", sorted(TOOL_ARGS))
def test_tool_declares_an_object_output_schema(tool_name: str) -> None:
    """A ``-> str`` annotation silently yields a vacuous {result: string} schema."""
    tool = next(t for t in anyio.run(mcp_server.mcp.list_tools) if t.name == tool_name)
    schema = tool.output_schema
    assert schema is not None and schema.get("type") == "object"
    assert "result" not in (schema.get("properties") or {}), (
        f"{tool_name} advertises the double-encoded {{result: string}} wrapper"
    )
