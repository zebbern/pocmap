"""Native offline tests for the 2.5.0 upstream-freshness fixes.

Each case here pins a place where the code had drifted from how the outside
world actually behaves. They are grouped by what went stale, and every one
exists because the old behaviour produced a *confident wrong answer* rather
than an error.

Offline by construction: HTML/JSON fixtures are fed to the parsers directly, and
the MCP registration is inspected in-process without a transport.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from pocmap.services.bb_service import BugBountyService
from pocmap.services.lab_service import LabService

# ---------------------------------------------------------------------------
# 0xdf HackTheBox parser — stopped fabricating machine names
# ---------------------------------------------------------------------------

def _tags_html(cve: str, links: list[str]) -> str:
    items = "".join(f'<li><a href="/x">{t}</a></li>' for t in links)
    return f'<html><body><h2 id="{cve}">{cve}</h2><ul>{items}</ul></body></html>'


def _lab_service(html: str, monkeypatch: pytest.MonkeyPatch) -> LabService:
    import pocmap.services.lab_service as mod

    monkeypatch.setattr(mod, "fetch_text", lambda *a, **k: html)
    return LabService(http_client=MagicMock())


def test_htb_machine_is_read_from_a_real_machine_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    svc = _lab_service(_tags_html("CVE-2021-44228", ["HTB: Crafty"]), monkeypatch)
    lab = svc._search_hackthebox("CVE-2021-44228")
    assert lab is not None
    assert lab.name == "Crafty"
    assert lab.url == "https://www.hackthebox.com/machines/crafty"


def test_htb_skips_a_non_machine_first_link(monkeypatch: pytest.MonkeyPatch) -> None:
    """The old code took links[0] blindly and split on whitespace.

    A "Beyond Root" follow-up listed first meant the second token ("Root") was
    reported as the machine name, producing a confident link to a machine page
    that does not exist.
    """
    html = _tags_html("CVE-2021-3156", ["Beyond Root: Sudo", "HTB: RouterSpace"])
    lab = _lab_service(html, monkeypatch)._search_hackthebox("CVE-2021-3156")
    assert lab is not None
    assert lab.name == "RouterSpace"


def test_htb_returns_none_when_no_post_is_a_machine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reporting nothing beats inventing a plausible machine name."""
    html = _tags_html("CVE-2020-1938", ["Ghostcat writeup", "Some other post"])
    assert _lab_service(html, monkeypatch)._search_hackthebox("CVE-2020-1938") is None


def test_htb_survives_a_single_word_link(monkeypatch: pytest.MonkeyPatch) -> None:
    """``.split()[1]`` raised IndexError here, swallowed into a silent None."""
    html = _tags_html("CVE-2021-1234", ["Writeup"])
    assert _lab_service(html, monkeypatch)._search_hackthebox("CVE-2021-1234") is None


# ---------------------------------------------------------------------------
# Bug bounty sources are independent
# ---------------------------------------------------------------------------

def test_a_pentesterland_hit_no_longer_suppresses_bugbounty_hunting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """These are separate indexes; a hit in one says nothing about the other.

    The old gate meant a PentesterLand result hid the Bug Bounty Hunting one —
    and PentesterLand's feed has not moved since 2024, so the suppression was
    effectively permanent for older CVEs.
    """
    from pocmap.models import BugBountyReport, BugBountySource

    svc = BugBountyService(http_client=MagicMock())
    pl = BugBountyReport(source=BugBountySource.PENTESTERLAND, url="https://pl/x")
    bbh = BugBountyReport(source=BugBountySource.BUGBOUNTY_HUNTING, url="https://bbh/y")
    monkeypatch.setattr(BugBountyService, "search_hackerone", lambda self, c: [])
    monkeypatch.setattr(BugBountyService, "search_pentesterland", lambda self, c: pl)
    monkeypatch.setattr(BugBountyService, "search_bugbounty_hunting", lambda self, c: bbh)

    sources = {r.source for r in svc.find_reports("CVE-2021-44228")}
    assert sources == {BugBountySource.PENTESTERLAND, BugBountySource.BUGBOUNTY_HUNTING}


# ---------------------------------------------------------------------------
# MCP tool registration — annotations and no vacuous output schema
# ---------------------------------------------------------------------------

_LIST_TOOLS = """
import anyio, json
from pocmap.mcp_server import mcp
async def main():
    tools = await mcp.list_tools()
    print(json.dumps([
        {"name": t.name,
         "outputSchema": t.output_schema,
         "annotations": t.annotations.model_dump(by_alias=True) if t.annotations else None}
        for t in tools
    ]))
anyio.run(main)
"""


@pytest.fixture(scope="module")
def registered_tools() -> list[dict[str, Any]]:
    """Tool descriptors as the SDK would advertise them."""
    proc = subprocess.run(
        [sys.executable, "-c", _LIST_TOOLS],
        capture_output=True, text=True, timeout=180, cwd=str(Path(__file__).parent.parent),
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    return list(json.loads(proc.stdout))


def test_every_tool_advertises_a_real_object_schema(
    registered_tools: list[dict[str, Any]],
) -> None:
    """Tools return objects, so the schema must describe an object.

    While they were annotated ``-> str`` the SDK derived
    ``{"result": {"type": "string"}}`` and wrapped the already-JSON body as
    ``structuredContent: {"result": "<json string>"}`` — encoded twice, behind a
    schema describing none of it.
    """
    for tool in registered_tools:
        schema = tool["outputSchema"]
        assert schema, f"{tool['name']} advertises no output schema"
        assert schema.get("type") == "object", (tool["name"], schema)


def test_no_tool_still_advertises_the_vacuous_result_wrapper(
    registered_tools: list[dict[str, Any]],
) -> None:
    """The specific regression: a `{"result": {"type": "string"}}` schema."""
    offenders = [
        t["name"]
        for t in registered_tools
        if "result" in ((t["outputSchema"] or {}).get("properties") or {})
    ]
    assert offenders == [], offenders


def test_every_tool_declares_behavioural_annotations(
    registered_tools: list[dict[str, Any]],
) -> None:
    """Without hints a host must assume every tool may be destructive."""
    missing = [t["name"] for t in registered_tools if not t["annotations"]]
    assert missing == []


def test_only_the_disk_writing_tool_is_not_read_only(
    registered_tools: list[dict[str, Any]],
) -> None:
    not_read_only = {
        t["name"] for t in registered_tools if not t["annotations"]["readOnlyHint"]
    }
    # verify_github_pocs downloads and extracts third-party exploit source.
    assert not_read_only == {"verify_github_pocs"}


def test_playbook_tools_are_marked_closed_world(
    registered_tools: list[dict[str, Any]],
) -> None:
    """The playbooks read packaged JSON — they touch no network at all."""
    closed = {
        t["name"] for t in registered_tools if not t["annotations"]["openWorldHint"]
    }
    assert closed == {
        "get_cve_assessment_playbook",
        "get_rapid_response_playbook",
        "get_bug_bounty_playbook",
    }
