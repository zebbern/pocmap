"""MCP resources (text payloads)."""

from __future__ import annotations

import json
from typing import Any

from pocmap.mcp.errors import _format_cve_text
from pocmap.mcp.server import _svc, mcp


@mcp.resource(
    uri="cve://{cve_id}",
    name="cve_info",
    description="Full CVE information including description, CVSS scores, EPSS, KEV status, CWEs, references, and affected vendor/product.",
    mime_type="text/plain",
)
def get_cve_resource(cve_id: str) -> str:
    """Resource: Full CVE information. URI template: cve://{cve_id}"""
    try:
        data = _svc.lookup_cve(cve_id)
        if "error" in data:
            return f"Error: {data['error']}"
        return _format_cve_text(data)
    except Exception as e:
        return f"Error retrieving CVE resource ({type(e).__name__})"


@mcp.resource(
    uri="exploits://{cve_id}",
    name="cve_exploits",
    description="Complete list of available exploits and PoCs for a CVE from all sources (GitHub, Metasploit, ExploitDB, Nuclei).",
    mime_type="text/plain",
)
def get_exploits_resource(cve_id: str) -> str:
    """Resource: Exploit list for a CVE. URI template: exploits://{cve_id}"""
    try:
        exploits: list[dict[str, Any]] = []
        exploits.extend(_svc.find_github_pocs(cve_id))
        msf = _svc.find_metasploit_module(cve_id)
        if msf:
            exploits.append(msf)
        edb = _svc.find_exploitdb_entry(cve_id)
        if edb:
            exploits.append(edb)
        nuc = _svc.find_nuclei_template(cve_id)
        if nuc:
            exploits.append(nuc)

        if not exploits:
            return f"No exploits found for {cve_id.upper().strip()}."

        lines = [f"Exploits for {cve_id.upper().strip()} ({len(exploits)} total):", ""]
        for i, e in enumerate(exploits, 1):
            lines.append(f"{i}. [{e.get('source', 'UNKNOWN').upper()}] {e.get('title', 'Untitled')}")
            lines.append(f"   URL: {e.get('url', 'N/A')}")
            if e.get("language"):
                lines.append(f"   Language: {e['language']}")
            if e.get("stars"):
                lines.append(f"   Stars: {e['stars']}")
            lines.append("")
        return "\n".join(lines)
    except Exception as e:
        return f"Error retrieving exploits resource ({type(e).__name__})"


@mcp.resource(
    uri="report://{cve_id}",
    name="cve_report",
    description="Generated vulnerability report for a CVE including CVE info, exploits, labs, and bug bounty reports (JSON format).",
    mime_type="application/json",
)
def get_report_resource(cve_id: str) -> str:
    """Resource: Full vulnerability report. URI template: report://{cve_id}"""
    try:
        # Resources are text, unlike tools — serialize the adapter's object.
        return json.dumps(
            _svc.generate_json_report([cve_id.upper().strip()]), indent=2, default=str
        )
    except Exception as e:
        return json.dumps({"error": f"Report generation failed ({type(e).__name__})"})
