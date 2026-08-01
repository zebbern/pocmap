"""Playbook MCP tools (packaged JSON, no network)."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from pocmap.mcp.registration import _LOCAL_ONLY, _tool

logger = logging.getLogger("pocmap-mcp")

# Playbooks ship under ``pocmap/bugbounty/playbooks`` (two levels above tools/).
_PLAYBOOKS_DIR = Path(__file__).resolve().parents[2] / "bugbounty" / "playbooks"


def _load_playbook(filename: str) -> dict[str, Any]:
    """Load a playbook JSON file and return its contents as an object.

    Falls back to an error object if the file is missing or unreadable.
    """
    if ".." in filename or os.path.sep in filename:
        return {"error": "Invalid filename"}
    path = _PLAYBOOKS_DIR / filename
    try:
        if not path.exists():
            return {
                "error": f"Playbook file not found: {filename}",
                "category": "not_found",
            }
        with open(path, encoding="utf-8") as f:
            content: dict[str, Any] = json.load(f)
        return content
    except json.JSONDecodeError:
        return {
            "error": f"Invalid JSON in playbook {filename}",
            "category": "invalid_input",
        }
    except Exception as e:
        return {"error": f"Failed to load playbook ({type(e).__name__})"}


@_tool(
    annotations=_LOCAL_ONLY,
    name="get_cve_assessment_playbook",
    description=(
        "Get the complete CVE assessment playbook with detailed step-by-step workflow. "
        "This playbook guides AI agents through systematic evaluation of CVEs including "
        "context gathering, exploit landscape analysis, real-world impact assessment, "
        "risk prioritization, and actionable remediation recommendations. "
        "Use this tool when starting a comprehensive vulnerability assessment workflow."
    ),
)
def get_cve_assessment_playbook() -> dict[str, Any]:
    """Get the complete CVE assessment playbook with detailed step-by-step workflow.

    Returns:
        JSON string containing the full CVE assessment playbook with phases,
        decision trees, and structured guidance for evaluating vulnerabilities.
    """
    return _load_playbook("cve-assessment-playbook.json")


@_tool(
    annotations=_LOCAL_ONLY,
    name="get_rapid_response_playbook",
    description=(
        "Get the rapid response playbook for emergency critical CVE handling. "
        "This playbook provides a fast-track workflow for CVEs with CRITICAL severity, "
        "high EPSS scores, or active KEV status. It includes immediate containment steps, "
        "rapid detection, emergency patching procedures, and stakeholder communication templates. "
        "Use this tool when dealing with an actively exploited or high-impact vulnerability."
    ),
)
def get_rapid_response_playbook() -> dict[str, Any]:
    """Get the rapid response playbook for emergency critical CVE handling.

    Returns:
        JSON string containing the rapid response playbook with emergency
        procedures, decision trees, and time-bounded action items.
    """
    return _load_playbook("rapid-response-playbook.json")


@_tool(
    annotations=_LOCAL_ONLY,
    name="get_bug_bounty_playbook",
    description=(
        "Get the bug bounty submission playbook from finding to report submission. "
        "This playbook guides researchers through the complete bug bounty workflow: "
        "reconnaissance, vulnerability identification, PoC development, report writing, "
        "submission formatting, and follow-up communication. "
        "Use this tool when preparing a bug bounty report or learning the submission process."
    ),
)
def get_bug_bounty_playbook() -> dict[str, Any]:
    """Get the bug bounty submission playbook from finding to report submission.

    Returns:
        JSON string containing the bug bounty submission playbook with
        phases, templates, checklists, and best practices for successful submissions.
    """
    return _load_playbook("bb-submission-playbook.json")
