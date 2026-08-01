"""PocMap MCP server package.

Implementation lives here; ``pocmap.mcp_server`` remains the public import path
and ``pocmap-mcp`` entry point for compatibility.
"""

from __future__ import annotations

# Register tools / resources / prompts on ``mcp`` (decorator side effects).
from pocmap.mcp import prompts as _prompts
from pocmap.mcp import resources as _resources
from pocmap.mcp.adapter import MAX_CVE_BULK, ServiceAdapter
from pocmap.mcp.errors import _format_cve_text, _format_error_json, _ok, _tool_error
from pocmap.mcp.html_report import _build_html_report, _safe_url
from pocmap.mcp.registration import (
    _LOCAL_ONLY,
    _READ_ONLY,
    _WRITES_TO_DISK,
    _tool,
    _validate_tool_input,
)
from pocmap.mcp.server import _svc, app_lifespan, main, mcp
from pocmap.mcp.tools import (
    check_kev_status,
    cpe_to_cve,
    cve_to_cpe,
    discover_package_cves,
    discover_product_cves,
    find_bug_bounty_reports,
    find_exploitdb_entry,
    find_github_pocs,
    find_metasploit_module,
    find_nuclei_template,
    find_practice_labs,
    find_recent_exploits,
    find_vulhub_docker,
    generate_html_report,
    generate_json_report,
    get_attack_techniques,
    get_bug_bounty_playbook,
    get_cve_assessment_playbook,
    get_epss_score,
    get_rapid_response_playbook,
    lookup_cve,
    verify_github_pocs,
)

# Keep side-effect aliases referenced so ruff does not drop the imports.
_ = (_prompts, _resources)

__all__ = [
    "MAX_CVE_BULK",
    "ServiceAdapter",
    "_LOCAL_ONLY",
    "_READ_ONLY",
    "_WRITES_TO_DISK",
    "_build_html_report",
    "_format_cve_text",
    "_format_error_json",
    "_ok",
    "_safe_url",
    "_svc",
    "_tool",
    "_tool_error",
    "_validate_tool_input",
    "app_lifespan",
    "check_kev_status",
    "cpe_to_cve",
    "cve_to_cpe",
    "discover_package_cves",
    "discover_product_cves",
    "find_bug_bounty_reports",
    "find_exploitdb_entry",
    "find_github_pocs",
    "find_metasploit_module",
    "find_nuclei_template",
    "find_practice_labs",
    "find_recent_exploits",
    "find_vulhub_docker",
    "generate_html_report",
    "generate_json_report",
    "get_attack_techniques",
    "get_bug_bounty_playbook",
    "get_cve_assessment_playbook",
    "get_epss_score",
    "get_rapid_response_playbook",
    "lookup_cve",
    "main",
    "mcp",
    "verify_github_pocs",
]
