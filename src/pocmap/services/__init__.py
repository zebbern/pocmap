"""High-level service layer for PocMap.

Each service provides a clear, documented interface for a specific domain:
    - CVE lookup and enrichment
    - Exploit discovery across multiple sources
    - CTF lab environment discovery
    - Report generation (JSON, HTML)
    - Bug bounty report lookup

All services return structured Pydantic models rather than raw dictionaries.

Example::

    from pocmap.services.cve_service import CVEService
    from pocmap.services.exploit_service import ExploitService

    cve_svc = CVEService()
    exploit_svc = ExploitService()

    info = cve_svc.get_cve_info("CVE-2021-44228")
    exploits = exploit_svc.find_exploits("CVE-2021-44228")
"""

from pocmap.services.bb_service import BugBountyService
from pocmap.services.cve_service import CVEService
from pocmap.services.exploit_service import ExploitService
from pocmap.services.lab_service import LabService
from pocmap.services.product_service import ProductDiscoveryService
from pocmap.services.recent_service import RecentService
from pocmap.services.report_service import ReportService

__all__ = [
    "CVEService",
    "ExploitService",
    "LabService",
    "ReportService",
    "BugBountyService",
    "RecentService",
    "ProductDiscoveryService",
]
