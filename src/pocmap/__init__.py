"""PocMap: A modern, AI-friendly CVE PoC discovery tool.

This package provides a structured, type-safe API for discovering
Proof-of-Concept exploits, lab environments, and bug bounty reports
related to CVE identifiers.

Example:
    >>> import asyncio
    >>> from pocmap.services.cve_service import CVEService
    >>> service = CVEService()
    >>> info = asyncio.run(service.get_cve_info("CVE-2021-44228"))
    >>> print(info.cvss.base_score)

Modules:
    models: Pydantic data models for all data types.
    config: Configuration management with environment variable support.
    clients: HTTP clients for NVD, GitHub, CVE.org, and exploit databases.
    services: High-level business logic for CVE enrichment.
    utils: HTTP utilities, formatters, and helper functions.
"""

from pocmap.models import (
    BugBountyReport,
    CPEInfo,
    CVEInfo,
    CVSSScore,
    Exploit,
    LabEnvironment,
    ReportEntry,
)

__version__ = "2.0.0"
__all__ = [
    "CVSSScore",
    "CVEInfo",
    "Exploit",
    "LabEnvironment",
    "BugBountyReport",
    "CPEInfo",
    "ReportEntry",
]
