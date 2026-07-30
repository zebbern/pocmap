"""Offline tests for the CVE -> MITRE ATT&CK mapping client.

The trust-critical property is that an *absent* mapping and a *failed lookup*
are never confused: coverage is the KEV catalogue, so an empty result is normal
and must not be reported as "no techniques" when the feed was simply
unreachable.

Also covered: the self-healing discovery path (the published snapshot URL
carries an ATT&CK version and a date with no "latest" alias, so the pinned URL
eventually 404s), and the numeric ordering that discovery depends on — lexical
sorting would pick attack-9.0 over attack-16.1.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from pocmap.clients.attack_client import ATTACKClient
from pocmap.models import ATTACKMappingType
from pocmap.utils.http import HTTPError, OfflineError, RateLimitError


def _mapping(cve: str, tid: str, mtype: str, name: str = "Some Technique") -> dict[str, Any]:
    return {
        "capability_id": cve,
        "attack_object_id": tid,
        "attack_object_name": name,
        "mapping_type": mtype,
        "comments": f"why {cve} maps to {tid}",
        "references": ["https://example.test/ref"],
    }


def _client(payload: Any) -> ATTACKClient:
    http = MagicMock()
    http.get_json.return_value = payload
    return ATTACKClient(http_client=http)


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------

def test_techniques_are_returned_exploitation_first() -> None:
    """'How is it exploited' is the actionable half; impacts follow from it."""
    client = _client({"mapping_objects": [
        _mapping("CVE-2021-44228", "T1486", "secondary_impact"),
        _mapping("CVE-2021-44228", "T1005", "primary_impact"),
        _mapping("CVE-2021-44228", "T1190", "exploitation_technique"),
    ]})

    got = client.get_techniques("CVE-2021-44228")
    assert [t.technique_id for t in got] == ["T1190", "T1005", "T1486"]
    assert got[0].mapping_type is ATTACKMappingType.EXPLOITATION


def test_lookup_is_case_insensitive_and_trims() -> None:
    client = _client({"mapping_objects": [
        _mapping("CVE-2021-44228", "T1190", "exploitation_technique")
    ]})
    assert client.get_techniques("  cve-2021-44228  ")


def test_sub_technique_url_uses_the_parent_path() -> None:
    """T1505.003 lives at /techniques/T1505/003/, not /T1505.003/."""
    client = _client({"mapping_objects": [
        _mapping("CVE-2021-44228", "T1505.003", "secondary_impact", "Web Shell")
    ]})
    assert client.get_techniques("CVE-2021-44228")[0].url == (
        "https://attack.mitre.org/techniques/T1505/003/"
    )


def test_curator_comment_is_preserved() -> None:
    """The explanation is the point — a bare technique ID is not actionable."""
    client = _client({"mapping_objects": [
        _mapping("CVE-2021-44228", "T1190", "exploitation_technique")
    ]})
    assert client.get_techniques("CVE-2021-44228")[0].comment


def test_uncovered_cve_returns_empty_not_a_guess() -> None:
    """Coverage is KEV; everything else legitimately has no curated mapping."""
    client = _client({"mapping_objects": [
        _mapping("CVE-2021-44228", "T1190", "exploitation_technique")
    ]})
    assert client.get_techniques("CVE-2099-0001") == []


def test_unknown_mapping_type_degrades_rather_than_raising() -> None:
    client = _client({"mapping_objects": [
        _mapping("CVE-2021-44228", "T1190", "some_future_type")
    ]})
    assert client.get_techniques("CVE-2021-44228")[0].mapping_type is (
        ATTACKMappingType.UNKNOWN
    )


@pytest.mark.parametrize(
    "obj",
    [
        {"capability_id": "not-a-cve", "attack_object_id": "T1190"},
        {"capability_id": "CVE-2021-44228", "attack_object_id": ""},
        {"capability_id": "CVE-2021-44228"},
        "not-a-dict",
    ],
)
def test_malformed_entries_are_skipped(obj: Any) -> None:
    client = _client({"mapping_objects": [obj]})
    assert client.coverage() == 0


def test_feed_is_loaded_once_per_client() -> None:
    http = MagicMock()
    http.get_json.return_value = {"mapping_objects": [
        _mapping("CVE-2021-44228", "T1190", "exploitation_technique")
    ]}
    client = ATTACKClient(http_client=http)

    client.get_techniques("CVE-2021-44228")
    client.get_techniques("CVE-2021-44228")
    client.coverage()
    assert http.get_json.call_count == 1


# ---------------------------------------------------------------------------
# A failed lookup must never read as "no techniques"
# ---------------------------------------------------------------------------

def test_offline_error_propagates() -> None:
    http = MagicMock()
    http.get_json.side_effect = OfflineError("cache miss")
    with pytest.raises(OfflineError):
        ATTACKClient(http_client=http).get_techniques("CVE-2021-44228")


def test_rate_limit_error_propagates() -> None:
    http = MagicMock()
    http.get_json.side_effect = RateLimitError("429", status_code=429)
    with pytest.raises(RateLimitError):
        ATTACKClient(http_client=http).get_techniques("CVE-2021-44228")


# ---------------------------------------------------------------------------
# Self-healing discovery when the pinned snapshot moves
# ---------------------------------------------------------------------------

def test_pinned_404_falls_back_to_discovering_the_newest_snapshot() -> None:
    """The published path is version- and date-stamped with no 'latest' alias."""
    http = MagicMock()
    payload = {"mapping_objects": [
        _mapping("CVE-2024-3400", "T1190", "exploitation_technique")
    ]}

    def fake_get_json(url: str, **_: Any) -> Any:
        if url.endswith("kev-07.28.2025_attack-16.1-enterprise.json"):
            raise HTTPError("404", status_code=404)          # pinned snapshot gone
        if url.endswith("/contents/mappings/kev"):
            # Deliberately unsorted, and lexically misleading: "attack-9.0"
            # sorts above "attack-17.2" as a string.
            return [{"name": n, "type": "dir"} for n in ("attack-9.0", "attack-17.2", "attack-16.1")]
        if url.endswith("/attack-17.2"):
            return [{"name": n, "type": "dir"} for n in ("kev-12.01.2024", "kev-01.15.2026")]
        if url.endswith("/enterprise"):
            return [{"name": "kev-01.15.2026_attack-17.2-enterprise.json", "type": "file"}]
        return payload

    http.get_json.side_effect = fake_get_json
    client = ATTACKClient(http_client=http)

    assert client.get_techniques("CVE-2024-3400")
    urls = [c.args[0] for c in http.get_json.call_args_list]
    # Newest by version number and by date, not by string order.
    assert any("attack-17.2/kev-01.15.2026/enterprise" in u for u in urls), urls


def test_discovery_failure_degrades_to_empty_not_a_crash() -> None:
    http = MagicMock()

    def fake_get_json(url: str, **_: Any) -> Any:
        raise HTTPError("500", status_code=500)

    http.get_json.side_effect = fake_get_json
    assert ATTACKClient(http_client=http).get_techniques("CVE-2021-44228") == []
