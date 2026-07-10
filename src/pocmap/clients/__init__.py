"""HTTP clients for external APIs and data sources.

Each client encapsulates interaction with a specific external service:
    - NVD API for CVE metadata and CVSS scores
    - GitHub API for PoC repositories
    - CVE.org for canonical CVE records
    - ExploitDB, Metasploit, and Nuclei for exploit code
"""

from pocmap.clients.cveorg_client import CVEOrgClient
from pocmap.clients.exploit_client import ExploitDBClient, MetasploitClient, NucleiClient
from pocmap.clients.github_client import GitHubClient
from pocmap.clients.nvd_client import NVDClient

__all__ = [
    "NVDClient",
    "GitHubClient",
    "CVEOrgClient",
    "ExploitDBClient",
    "MetasploitClient",
    "NucleiClient",
]
