"""Register all MCP tools by importing tool modules (side effects)."""

from __future__ import annotations

from pocmap.mcp.tools import bb as bb
from pocmap.mcp.tools import cpe as cpe
from pocmap.mcp.tools import cve as cve
from pocmap.mcp.tools import discovery as discovery
from pocmap.mcp.tools import exploits as exploits
from pocmap.mcp.tools import labs as labs
from pocmap.mcp.tools import playbooks as playbooks
from pocmap.mcp.tools import recent as recent
from pocmap.mcp.tools import reports as reports

# Re-export tool callables for the mcp_server compatibility facade.
from pocmap.mcp.tools.bb import find_bug_bounty_reports
from pocmap.mcp.tools.cpe import cpe_to_cve, cve_to_cpe
from pocmap.mcp.tools.cve import check_kev_status, get_epss_score, lookup_cve
from pocmap.mcp.tools.discovery import discover_package_cves, discover_product_cves
from pocmap.mcp.tools.exploits import (
    find_exploitdb_entry,
    find_github_pocs,
    find_metasploit_module,
    find_nuclei_template,
    get_attack_techniques,
    verify_github_pocs,
)
from pocmap.mcp.tools.labs import find_practice_labs, find_vulhub_docker
from pocmap.mcp.tools.playbooks import (
    get_bug_bounty_playbook,
    get_cve_assessment_playbook,
    get_rapid_response_playbook,
)
from pocmap.mcp.tools.recent import find_recent_exploits
from pocmap.mcp.tools.reports import generate_html_report, generate_json_report

__all__ = [
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
    "verify_github_pocs",
]
