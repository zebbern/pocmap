"""HTTP clients for external APIs and data sources.

Each client encapsulates interaction with a specific external service:
    - NVD API for CVE metadata and CVSS scores
    - NVD CPE dictionary for product-name -> vendor:product resolution
    - GitHub API for PoC repositories
    - CVE.org for canonical CVE records
    - ExploitDB, Metasploit, and Nuclei for exploit code
    - OSV.dev for package-ecosystem vulnerabilities and their fixed versions
"""

from pocmap.clients.attack_client import ATTACKClient
from pocmap.clients.cpe_client import CPEDictionaryClient
from pocmap.clients.cveorg_client import CVEOrgClient
from pocmap.clients.exploit_client import ExploitDBClient, MetasploitClient, NucleiClient
from pocmap.clients.github_client import GitHubClient
from pocmap.clients.nvd_client import NVDClient
from pocmap.clients.osv_client import OSVClient

__all__ = [
    "NVDClient",
    "ATTACKClient",
    "CPEDictionaryClient",
    "GitHubClient",
    "CVEOrgClient",
    "ExploitDBClient",
    "MetasploitClient",
    "NucleiClient",
    "OSVClient",
]
