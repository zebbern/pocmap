"""MITRE ATT&CK technique mappings for CVEs.

Why only the curated source
---------------------------
pocmap already returns CWEs, but a CWE describes the *weakness class*, which an
agent cannot act on. An ATT&CK technique answers the operational question:
how would this be exploited, and what should I detect?

The obvious way to cover every CVE is the published chain
``CWE -> CAPEC -> ATT&CK``. That was measured against this curated data and
rejected: it yields **zero** overlap with the expert mappings, and it only
produces output at all when the CWE is too generic to be meaningful. Precise
weaknesses (CWE-502 deserialization, CWE-77/78 command injection, CWE-917 EL
injection) reach no technique whatsoever, while the catch-all CWE-20 "Improper
Input Validation" fans out to seven unrelated ones — so for Log4Shell the chain
suggests "Steal Web Session Cookie". Plausible-looking and wrong is worse than
absent, so a CVE with no curated mapping returns nothing rather than a guess.

Source: Center for Threat-Informed Defense, ``mappings-explorer``, KEV mappings.
Coverage is therefore the CISA KEV catalogue — the actively-exploited CVEs,
which is exactly the set where "how is this used" matters most.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from pocmap.config import (
    ATTACK_KEV_CONTENTS_API,
    ATTACK_KEV_PINNED_URL,
    settings,
)
from pocmap.models import ATTACKTechnique
from pocmap.utils.http import HTTPClient, HTTPError, OfflineError, RateLimitError

logger = logging.getLogger(__name__)

_ATTACK_DIR_RE = re.compile(r"^attack-(\d+)\.(\d+)$")
_SNAPSHOT_DIR_RE = re.compile(r"^kev-(\d{2})\.(\d{2})\.(\d{4})$")


class ATTACKClient:
    """Client for the curated CVE -> ATT&CK technique mappings.

    Args:
        http_client: Optional HTTP client instance.

    Example::

        client = ATTACKClient()
        for t in client.get_techniques("CVE-2021-44228"):
            print(t.technique_id, t.name, t.mapping_type.value)
    """

    def __init__(self, http_client: HTTPClient | None = None) -> None:
        self._client = http_client or HTTPClient(headers=settings.default_headers)
        self._index: dict[str, list[ATTACKTechnique]] | None = None

    def get_techniques(self, cve_id: str) -> list[ATTACKTechnique]:
        """Return curated ATT&CK techniques for *cve_id*.

        Args:
            cve_id: The CVE identifier.

        Returns:
            Techniques ordered exploitation-first, then primary and secondary
            impact. Empty when the CVE has no curated mapping — which is the
            common case, since coverage is the KEV catalogue.

        Raises:
            OfflineError: Offline mode with no cached copy of the feed.
            RateLimitError: The feed host throttled the request.
        """
        index = self._load()
        return index.get(cve_id.upper().strip(), [])

    def coverage(self) -> int:
        """How many CVEs the loaded mapping set covers (0 if unavailable)."""
        return len(self._load())

    # -- Internals --

    def _load(self) -> dict[str, list[ATTACKTechnique]]:
        """Fetch and index the mapping set once per client."""
        if self._index is not None:
            return self._index

        data = self._fetch()
        index: dict[str, list[ATTACKTechnique]] = {}
        for obj in data.get("mapping_objects", []) if isinstance(data, dict) else []:
            if not isinstance(obj, dict):
                continue
            cve = str(obj.get("capability_id") or "").upper().strip()
            technique = ATTACKTechnique.from_ctid(obj)
            if not cve.startswith("CVE-") or not technique.technique_id:
                continue
            index.setdefault(cve, []).append(technique)

        # Exploitation first: "how is it exploited" is the more actionable half,
        # and impacts read as consequences of it.
        order = {"exploitation_technique": 0, "primary_impact": 1, "secondary_impact": 2}
        for entries in index.values():
            entries.sort(
                key=lambda t: (order.get(t.mapping_type.value, 9), t.technique_id)
            )

        self._index = index
        logger.info("Loaded ATT&CK mappings for %d CVEs", len(index))
        return index

    def _fetch(self) -> dict[str, Any]:
        """Fetch the mapping JSON, self-healing if the pinned snapshot moved."""
        try:
            data = self._client.get_json(
                ATTACK_KEV_PINNED_URL, headers=settings.default_headers
            )
            if isinstance(data, dict) and data.get("mapping_objects"):
                return data
        except (OfflineError, RateLimitError):
            # Both mean "could not look up", not "no mappings exist".
            raise
        except HTTPError as exc:
            logger.info(
                "Pinned ATT&CK mapping snapshot unavailable (%s); discovering latest",
                exc,
            )

        discovered = self._discover_latest_url()
        if not discovered:
            logger.warning("No ATT&CK mapping snapshot could be resolved")
            return {}
        try:
            data = self._client.get_json(discovered, headers=settings.default_headers)
        except (OfflineError, RateLimitError):
            raise
        except HTTPError as exc:
            logger.warning("ATT&CK mapping fetch failed for %s: %s", discovered, exc)
            return {}
        return data if isinstance(data, dict) else {}

    def _discover_latest_url(self) -> str | None:
        """Walk the published directory tree to the newest enterprise snapshot.

        Only reached when the pinned URL 404s, so the GitHub API budget is not
        spent on the normal path.
        """
        attack_dirs = self._list_dir(ATTACK_KEV_CONTENTS_API)
        newest_attack = _newest(attack_dirs, _ATTACK_DIR_RE, lambda m: (int(m[1]), int(m[2])))
        if not newest_attack:
            return None

        snaps = self._list_dir(f"{ATTACK_KEV_CONTENTS_API}/{newest_attack}")
        newest_snap = _newest(
            snaps, _SNAPSHOT_DIR_RE, lambda m: (int(m[3]), int(m[1]), int(m[2]))
        )
        if not newest_snap:
            return None

        files = self._list_dir(
            f"{ATTACK_KEV_CONTENTS_API}/{newest_attack}/{newest_snap}/enterprise",
            want="file",
        )
        target = next((f for f in files if f.endswith(".json")), None)
        if not target:
            return None
        from pocmap.config import _CTID_RAW

        return f"{_CTID_RAW}/{newest_attack}/{newest_snap}/enterprise/{target}"

    def _list_dir(self, api_url: str, want: str = "dir") -> list[str]:
        """List entry names of one GitHub contents endpoint."""
        try:
            data = self._client.get_json(api_url, headers=settings.github_headers)
        except (OfflineError, RateLimitError):
            raise
        except HTTPError as exc:
            logger.debug("ATT&CK mapping discovery failed for %s: %s", api_url, exc)
            return []
        if not isinstance(data, list):
            return []
        return [
            str(e.get("name"))
            for e in data
            if isinstance(e, dict) and e.get("type") == want and e.get("name")
        ]

    def close(self) -> None:
        """Release the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> ATTACKClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def _newest(
    names: list[str], pattern: re.Pattern[str], key: Any
) -> str | None:
    """Pick the highest-sorting name matching *pattern*, by *key*.

    Lexical ordering is wrong for both shapes here — ``attack-9.0`` would beat
    ``attack-16.1``, and ``kev-12.01.2024`` would beat ``kev-07.28.2025`` — so
    the components are compared numerically.
    """
    best: tuple[Any, str] | None = None
    for name in names:
        m = pattern.match(name)
        if not m:
            continue
        rank = key(m)
        if best is None or rank > best[0]:
            best = (rank, name)
    return best[1] if best else None
