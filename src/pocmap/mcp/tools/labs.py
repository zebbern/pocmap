"""Practice lab MCP tools."""

from __future__ import annotations

from typing import Any

from pocmap.mcp.errors import _ok, _tool_error
from pocmap.mcp.registration import _tool
from pocmap.mcp.server import _svc


@_tool(
    name="find_practice_labs",
    description=(
        "Find CTF (Capture The Flag) labs, vulnerable machines, and practice environments "
        "for a CVE. These labs provide safe, legal environments to practice exploiting the vulnerability. "
        "Returns labs from Vulhub (Docker-based) and HackTheBox. "
        "Each lab includes the platform name, challenge name, URL, and setup instructions. "
        "Use this tool when you want hands-on practice with a vulnerability, need to demonstrate "
        "exploitation safely, or want to build detection rules in a controlled environment."
    ),
)
def find_practice_labs(cve_id: str) -> dict[str, Any]:
    """Find CTF labs and practice environments for a CVE.

    Args:
        cve_id: The CVE identifier

    Returns:
        JSON string with cve_id, total_count, and a list of lab objects
        (platform, name, url).
    """
    try:
        labs = _svc.find_labs(cve_id)
        cve_clean = cve_id.upper().strip()
        return _ok({
            "cve_id": cve_clean,
            "total_count": len(labs),
            "labs": labs,
        })
    except Exception as e:
        return _tool_error(e, f"find_practice_labs({cve_id})")


@_tool(
    name="find_vulhub_docker",
    description=(
        "Find a Vulhub Docker environment for a CVE. "
        "Vulhub provides pre-built Docker Compose environments for vulnerable applications, "
        "making it trivial to spin up a practice lab with 'docker compose up'. "
        "Returns the GitHub URL to the Vulhub directory containing the Docker files and setup instructions. "
        "Use this tool when you want the quickest way to set up a local practice environment "
        "for a vulnerability. Docker environments are isolated, reproducible, and easy to clean up."
    ),
)
def find_vulhub_docker(cve_id: str) -> dict[str, Any]:
    """Find a Vulhub Docker environment for a CVE.

    Args:
        cve_id: The CVE identifier

    Returns:
        JSON string with cve_id, found (bool), url, and setup instructions
        when a Vulhub environment is available.
    """
    try:
        url = _svc.find_docker_env(cve_id)
        cve_clean = cve_id.upper().strip()
        if url:
            parts = url.rstrip("/").split("/")
            path_suffix = "/".join(parts[-2:]) if len(parts) >= 2 else ""
            return _ok({
                "cve_id": cve_clean,
                "found": True,
                "url": url,
                "setup_instructions": {
                    "clone": "git clone --depth 1 https://github.com/vulhub/vulhub.git",
                    "navigate": f"cd vulhub/{path_suffix}",
                    "start": "docker compose up -d",
                    "stop": "docker compose down",
                },
            })
        return _ok({
            "cve_id": cve_clean,
            "found": False,
            "url": None,
            "note": "No Vulhub Docker environment found. Try find_practice_labs for other platforms.",
        })
    except Exception as e:
        return _tool_error(e, f"find_vulhub_docker({cve_id})")
