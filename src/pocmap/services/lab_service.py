"""CTF lab and vulnerable environment discovery service.

Searches for pre-built Docker environments (Vulhub) and CTF platforms
(HackTheBox, TryHackMe) related to CVE identifiers.

Example::

    from pocmap.services.lab_service import LabService
    service = LabService()
    labs = service.find_labs("CVE-2021-44228")
    for lab in labs:
        print(f"{lab.platform}: {lab.url}")
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from bs4 import BeautifulSoup

from pocmap.config import HTB_TAGS_URL, THM_ROOMS_URL, VULHUB_TOML_URL, settings
from pocmap.models import LabEnvironment, LabPlatform
from pocmap.utils.http import HTTPClient, fetch_text
from pocmap.utils.registry import PluginRegistry
from pocmap.utils.validators import validate_cve_id

logger = logging.getLogger(__name__)


class LabService:
    """Service for discovering CTF labs and vulnerable environments.

    Searches Vulhub (Docker), HackTheBox, and TryHackMe for labs
    related to a CVE identifier.

    Example::

        service = LabService()
        labs = service.find_labs("CVE-2021-44228")

        # Search specific platforms
        vulhub = service.search_vulhub("CVE-2021-44228")
        htb = service.search_hackthebox("CVE-2021-44228")
        thm = service.search_tryhackme("CVE-2021-44228")
    """

    def __init__(self, http_client: HTTPClient | None = None) -> None:
        self._client = http_client or HTTPClient(headers=settings.default_headers)

    def find_labs(self, cve_id: str) -> list[LabEnvironment]:
        """Search all registered platforms for labs related to a CVE.

        Iterates over the :data:`_lab_platform_registry` and aggregates
        results from every registered platform.

        Args:
            cve_id: The CVE identifier.

        Returns:
            Combined list of :class:`LabEnvironment` objects from all sources.
        """
        cve_id = validate_cve_id(cve_id)

        results: list[LabEnvironment] = []
        for name in _lab_platform_registry.list():
            fn = _lab_platform_registry.get(name)
            if fn is not None:
                lab = fn(self, cve_id)
                if lab is not None:
                    results.append(lab)

        logger.info("Found %d labs for %s", len(results), cve_id)
        return results

    def search_vulhub(self, cve_id: str) -> LabEnvironment | None:
        """Search Vulhub for a pre-built vulnerable Docker environment.

        Args:
            cve_id: The CVE identifier.

        Returns:
            A :class:`LabEnvironment` with setup instructions, or *None*.
        """
        return self._search_vulhub(cve_id)

    def _search_vulhub(self, cve_id: str) -> LabEnvironment | None:
        """Internal: search Vulhub for a pre-built vulnerable Docker environment."""
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

        try:
            text = fetch_text(VULHUB_TOML_URL, headers=settings.default_headers)
            if not text:
                return None

            config = tomllib.loads(text)
            environments = config.get("environment", [])

            for env in environments:
                env_cves = env.get("cve", [])
                if env_cves and env_cves[0].casefold() == cve_id.casefold():
                    path = env.get("path", "")
                    instructions = (
                        f"1. Clone: git clone --depth 1 https://github.com/vulhub/vulhub.git\n"
                        f"2. Navigate: cd vulhub/{path}\n"
                        f"3. Start: docker compose up -d\n"
                        f"4. Guide: https://github.com/vulhub/vulhub/tree/master/{path}\n"
                        f"5. Cleanup: docker compose down"
                    )
                    return LabEnvironment(
                        platform=LabPlatform.VULHUB,
                        name=path.split("/")[-1] if path else cve_id,
                        url=f"https://github.com/vulhub/vulhub/tree/master/{path}",
                        setup_instructions=instructions,
                    )
        except Exception as exc:
            logger.warning("Vulhub search failed for %s: %s", cve_id, exc)

        return None

    def search_hackthebox(self, cve_id: str) -> LabEnvironment | None:
        """Search HackTheBox for machines related to a CVE.

        Uses the 0xdf GitLab blog tags page to find HTB machines.

        Args:
            cve_id: The CVE identifier.

        Returns:
            A :class:`LabEnvironment`, or *None* if not found.
        """
        return self._search_hackthebox(cve_id)

    def _search_hackthebox(self, cve_id: str) -> LabEnvironment | None:
        """Internal: search HackTheBox for machines related to a CVE."""
        try:
            resp_text = fetch_text(
                HTB_TAGS_URL,
                headers=settings.default_headers,
            )
            if not resp_text:
                return None

            soup = BeautifulSoup(resp_text, "html.parser")
            cve_selector = soup.select(f'h2[id="{cve_id}" i] + ul')
            if cve_selector:
                machine_name = cve_selector[0].select("a")[0].text.split()[1]
                return LabEnvironment(
                    platform=LabPlatform.HACKTHEBOX,
                    name=machine_name,
                    url=f"https://www.hackthebox.com/machines/{machine_name.lower()}",
                )
        except Exception as exc:
            logger.debug("HackTheBox search failed for %s: %s", cve_id, exc)

        return None

    def search_tryhackme(self, cve_id: str) -> LabEnvironment | None:
        """Search TryHackMe for rooms related to a CVE.

        Args:
            cve_id: The CVE identifier.

        Returns:
            A :class:`LabEnvironment`, or *None* if not found.
        """
        return self._search_tryhackme(cve_id)

    def _search_tryhackme(self, cve_id: str) -> LabEnvironment | None:
        """Internal: search TryHackMe for rooms related to a CVE."""
        try:
            text = fetch_text(THM_ROOMS_URL, headers=settings.default_headers)
            if not text:
                return None

            for line in text.splitlines():
                if ":" in line:
                    cve_part, url_part = line.split(":", 1)
                    if cve_part.strip().upper() == cve_id.upper():
                        room_name = url_part.strip().split("/")[-1]
                        return LabEnvironment(
                            platform=LabPlatform.TRYHACKME,
                            name=room_name,
                            url=url_part.strip(),
                        )
        except Exception as exc:
            logger.debug("TryHackMe search failed for %s: %s", cve_id, exc)

        return None

    def close(self) -> None:
        """Release the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> LabService:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Plugin registry
# ---------------------------------------------------------------------------

_lab_platform_registry: PluginRegistry[Callable[[LabService, str], LabEnvironment | None]] = PluginRegistry()


def _register_default_platforms() -> None:
    """Register default lab platform providers at module import time."""
    _lab_platform_registry.register("vulhub", LabService._search_vulhub)
    _lab_platform_registry.register("hackthebox", LabService._search_hackthebox)
    _lab_platform_registry.register("tryhackme", LabService._search_tryhackme)


_register_default_platforms()
