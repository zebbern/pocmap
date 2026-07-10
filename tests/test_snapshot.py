"""Offline native pytest tests for the snapshot + diff engine (WATCH-DIFF).

Exercises :mod:`pocmap.services.snapshot` end to end with no network:

  * ``save`` -> ``load`` round-trips a result set (models and records).
  * :func:`diff_snapshots` classifies added / removed / changed / unchanged.
  * A KEV flip and a severity escalation are each reported as *changed*.
  * Identical sets produce an ``is_empty`` diff.
  * A corrupt snapshot file is treated as "no previous snapshot".
  * A ``query_key`` cannot escape the snapshot directory (path containment).

Everything runs against a ``tmp_path`` cache dir (or a monkeypatched
``settings.cache_dir``), so no real cache directory is ever touched.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from pocmap.config import settings
from pocmap.models import CVEInfo, CVSSScore, RecentExploitResult, Severity
from pocmap.services import snapshot as snapshot_mod
from pocmap.services.snapshot import (
    ChangeReason,
    SnapshotRecord,
    SnapshotStore,
    diff_snapshots,
    load_snapshot,
    make_query_key,
    save_snapshot,
)

# ---------------------------------------------------------------------------
# Fixtures / builders
# ---------------------------------------------------------------------------


def _cve(
    cve_id: str,
    *,
    severity: Severity = Severity.HIGH,
    base_score: float | None = 7.5,
    epss: float | None = 10.0,
    kev: bool = False,
) -> CVEInfo:
    """Build a minimal CVEInfo for snapshotting."""
    return CVEInfo(
        id=cve_id,
        cvss=CVSSScore(severity=severity, base_score=base_score),
        epss=epss,
        kev_status=kev,
    )


def _rec(
    cve_id: str,
    *,
    severity: str | None = "HIGH",
    base_score: float | None = 7.5,
    epss: float | None = 10.0,
    kev: bool = False,
    has_poc: bool = False,
) -> SnapshotRecord:
    """Build a SnapshotRecord directly (diff fixtures)."""
    return SnapshotRecord(
        cve_id=cve_id,
        severity=severity,
        base_score=base_score,
        epss=epss,
        kev_status=kev,
        has_poc=has_poc,
    )


@pytest.fixture
def store(tmp_path: Path) -> SnapshotStore:
    """A store rooted in an isolated temp cache dir."""
    return SnapshotStore(cache_dir=tmp_path)


# ---------------------------------------------------------------------------
# Persistence: save / load round-trip
# ---------------------------------------------------------------------------


def test_save_then_load_round_trips_result_set(store: SnapshotStore) -> None:
    key = store.make_key("latest", {"since": "24h", "severity": ["CRITICAL"]})
    cves = [
        _cve("CVE-2021-44228", severity=Severity.CRITICAL, base_score=10.0, epss=97.5, kev=True),
        _cve("CVE-2023-38408", severity=Severity.HIGH, base_score=8.1, epss=31.2),
    ]

    path = store.save(key, cves)
    assert path.exists()
    assert path.parent == store.directory

    loaded = store.load(key)
    assert loaded is not None
    by_id = {r.cve_id: r for r in loaded}
    assert set(by_id) == {"CVE-2021-44228", "CVE-2023-38408"}

    log4j = by_id["CVE-2021-44228"]
    assert log4j.severity == "CRITICAL"
    assert log4j.base_score == 10.0
    assert log4j.epss == 97.5
    assert log4j.kev_status is True
    assert log4j.has_poc is False


def test_load_missing_snapshot_returns_none(store: SnapshotStore) -> None:
    assert store.load(store.make_key("latest", {"since": "7d"})) is None


def test_save_preserves_has_poc_from_recent_result(store: SnapshotStore) -> None:
    key = "recent-key"
    result = RecentExploitResult(cve_info=_cve("CVE-2024-0001"), has_poc=True)

    store.save(key, [result])
    loaded = store.load(key)

    assert loaded is not None
    assert loaded[0].cve_id == "CVE-2024-0001"
    assert loaded[0].has_poc is True


def test_save_accepts_records_and_mappings(store: SnapshotStore) -> None:
    key = "mixed-key"
    items = [
        _rec("CVE-2020-0001", severity="LOW"),
        {"cve_id": "CVE-2020-0002", "severity": "medium", "base_score": 5.0, "kev_status": True},
        {"id": "CVE-2020-0003", "epss": 42.0},
    ]

    store.save(key, items)
    loaded = store.load(key)

    assert loaded is not None
    by_id = {r.cve_id: r for r in loaded}
    assert set(by_id) == {"CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"}
    # Mapping severity is normalized to an upper-case label.
    assert by_id["CVE-2020-0002"].severity == "MEDIUM"
    assert by_id["CVE-2020-0002"].kev_status is True


def test_save_dedupes_by_cve_id_last_wins(store: SnapshotStore) -> None:
    key = "dupe-key"
    store.save(
        key,
        [
            _rec("CVE-2019-0001", base_score=1.0),
            _rec("CVE-2019-0001", base_score=9.9),
        ],
    )
    loaded = store.load(key)
    assert loaded is not None
    assert len(loaded) == 1
    assert loaded[0].base_score == 9.9


def test_module_level_functions_use_cache_dir(tmp_path: Path) -> None:
    key = make_query_key("discover", {"product": "struts", "version": "2.x"})
    save_snapshot(key, [_cve("CVE-2017-5638")], cache_dir=tmp_path)

    loaded = load_snapshot(key, cache_dir=tmp_path)
    assert loaded is not None
    assert loaded[0].cve_id == "CVE-2017-5638"


def test_store_defaults_to_settings_cache_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = dataclasses.replace(settings, cache_dir=tmp_path)
    monkeypatch.setattr(snapshot_mod, "settings", fake)

    store = SnapshotStore()
    assert store.directory == tmp_path / "snapshots"

    store.save("k", [_cve("CVE-2022-1234")])
    assert (tmp_path / "snapshots").is_dir()
    loaded = store.load("k")
    assert loaded is not None and loaded[0].cve_id == "CVE-2022-1234"


def test_make_key_is_stable_and_order_independent() -> None:
    a = SnapshotStore.make_key("latest", {"since": "24h", "severity": ["CRITICAL"]})
    b = SnapshotStore.make_key("latest", {"severity": ["CRITICAL"], "since": "24h"})
    c = SnapshotStore.make_key("latest", {"since": "7d"})
    assert a == b
    assert a != c
    assert len(a) == 64


# ---------------------------------------------------------------------------
# Diff: added / removed
# ---------------------------------------------------------------------------


def test_diff_detects_added_and_removed() -> None:
    previous = [_rec("CVE-2000-0001"), _rec("CVE-2000-0002"), _rec("CVE-2000-0003")]
    current = [_rec("CVE-2000-0002"), _rec("CVE-2000-0003"), _rec("CVE-2000-0004")]

    diff = diff_snapshots(previous, current)

    assert diff.added_ids == ("CVE-2000-0004",)
    assert diff.removed_ids == ("CVE-2000-0001",)
    assert diff.changed == ()
    assert diff.unchanged == 2
    assert diff.is_empty is False
    assert diff.total_changes == 2


def test_diff_none_previous_treats_all_as_added() -> None:
    current = [_rec("CVE-2001-0001"), _rec("CVE-2001-0002")]
    diff = diff_snapshots(None, current)
    assert set(diff.added_ids) == {"CVE-2001-0001", "CVE-2001-0002"}
    assert diff.removed == ()
    assert diff.unchanged == 0


def test_first_run_via_load_then_diff(store: SnapshotStore) -> None:
    """The intended CLI flow: load (None) -> diff -> save."""
    key = store.make_key("latest", {"since": "24h"})
    previous = store.load(key)  # first run: no baseline
    assert previous is None

    current = [SnapshotRecord(cve_id="CVE-2024-9999")]
    diff = diff_snapshots(previous, current)
    assert diff.added_ids == ("CVE-2024-9999",)


# ---------------------------------------------------------------------------
# Diff: changed detection rules
# ---------------------------------------------------------------------------


def test_diff_reports_kev_flip_as_changed() -> None:
    previous = [_rec("CVE-2100-0001", kev=False)]
    current = [_rec("CVE-2100-0001", kev=True)]

    diff = diff_snapshots(previous, current)

    assert diff.changed_ids == ("CVE-2100-0001",)
    assert diff.added == ()
    assert diff.removed == ()
    assert diff.unchanged == 0
    assert ChangeReason.KEV_GAINED in diff.changed[0].reasons


def test_diff_reports_severity_escalation_as_changed() -> None:
    previous = [_rec("CVE-2100-0002", severity="MEDIUM", base_score=5.0)]
    current = [_rec("CVE-2100-0002", severity="CRITICAL", base_score=5.0)]

    diff = diff_snapshots(previous, current)

    assert diff.changed_ids == ("CVE-2100-0002",)
    assert ChangeReason.SEVERITY_ESCALATED in diff.changed[0].reasons
    assert ChangeReason.SEVERITY_DEESCALATED not in diff.changed[0].reasons


def test_diff_reports_cvss_and_epss_jumps() -> None:
    previous = [_rec("CVE-2100-0003", base_score=5.0, epss=10.0)]
    current = [_rec("CVE-2100-0003", base_score=8.0, epss=55.0)]

    diff = diff_snapshots(previous, current)

    reasons = diff.changed[0].reasons
    assert ChangeReason.CVSS_INCREASED in reasons
    assert ChangeReason.EPSS_JUMPED in reasons


def test_diff_reports_poc_gained() -> None:
    previous = [_rec("CVE-2100-0004", has_poc=False)]
    current = [_rec("CVE-2100-0004", has_poc=True)]

    diff = diff_snapshots(previous, current)
    assert ChangeReason.POC_GAINED in diff.changed[0].reasons


def test_diff_ignores_sub_threshold_movements() -> None:
    # base_score +0.5 (< 1.0) and epss +5 (< 10) are below the default thresholds.
    previous = [_rec("CVE-2100-0005", base_score=7.0, epss=20.0)]
    current = [_rec("CVE-2100-0005", base_score=7.5, epss=25.0)]

    diff = diff_snapshots(previous, current)
    assert diff.is_empty is True
    assert diff.unchanged == 1


def test_diff_respects_custom_thresholds() -> None:
    previous = [_rec("CVE-2100-0006", base_score=7.0, epss=20.0)]
    current = [_rec("CVE-2100-0006", base_score=7.5, epss=25.0)]

    diff = diff_snapshots(previous, current, cvss_delta=0.4, epss_delta=4.0)
    reasons = diff.changed[0].reasons
    assert ChangeReason.CVSS_INCREASED in reasons
    assert ChangeReason.EPSS_JUMPED in reasons


def test_diff_identical_sets_is_empty() -> None:
    records = [_rec("CVE-2100-0007"), _rec("CVE-2100-0008", kev=True)]
    diff = diff_snapshots(records, list(records))

    assert diff.is_empty is True
    assert diff.added == ()
    assert diff.removed == ()
    assert diff.changed == ()
    assert diff.unchanged == 2
    assert "No changes" in diff.summary()


def test_diff_summary_and_to_dict_shape() -> None:
    previous = [_rec("CVE-2100-0009", kev=False), _rec("CVE-2100-0010")]
    current = [_rec("CVE-2100-0009", kev=True), _rec("CVE-2100-0011")]

    diff = diff_snapshots(previous, current)
    payload = diff.to_dict()

    assert set(payload) == {"added", "removed", "changed", "unchanged", "summary"}
    assert payload["changed"][0]["cve_id"] == "CVE-2100-0009"
    assert "kev_gained" in payload["changed"][0]["reasons"]
    assert "added" in diff.summary()


def test_diff_round_trips_through_saved_snapshots(store: SnapshotStore) -> None:
    """End-to-end: two saved snapshots diffed via loaded records."""
    key_old = "run-old"
    key_new = "run-new"
    store.save(key_old, [_cve("CVE-2100-1000", kev=False), _cve("CVE-2100-1001")])
    store.save(
        key_new,
        [
            _cve("CVE-2100-1000", kev=True),  # KEV gained
            _cve("CVE-2100-1002"),            # added
        ],
    )

    old = store.load(key_old)
    new = store.load(key_new)
    assert old is not None and new is not None

    diff = diff_snapshots(old, new)
    assert diff.added_ids == ("CVE-2100-1002",)
    assert diff.removed_ids == ("CVE-2100-1001",)
    assert diff.changed_ids == ("CVE-2100-1000",)
    assert ChangeReason.KEV_GAINED in diff.changed[0].reasons


# ---------------------------------------------------------------------------
# Corruption handling
# ---------------------------------------------------------------------------


def test_corrupt_snapshot_treated_as_no_previous(store: SnapshotStore) -> None:
    key = "corrupt-key"
    store.save(key, [_cve("CVE-2100-2000")])
    path = store.path_for(key)

    path.write_text("{ this is not valid json ]", encoding="utf-8")
    assert store.load(key) is None


def test_snapshot_with_bad_records_list_is_no_previous(store: SnapshotStore) -> None:
    key = "bad-shape-key"
    store.save(key, [_cve("CVE-2100-2001")])
    path = store.path_for(key)

    # Structurally valid JSON but "records" is not a list.
    path.write_text('{"version": 1, "records": "nope"}', encoding="utf-8")
    assert store.load(key) is None


def test_snapshot_skips_individual_malformed_records(store: SnapshotStore) -> None:
    key = "partial-key"
    path = store.path_for(key)
    store.directory.mkdir(parents=True, exist_ok=True)
    # One good record, one missing its id -> the good one survives.
    path.write_text(
        '{"version": 1, "records": ['
        '{"cve_id": "CVE-2100-2002", "severity": "HIGH"},'
        '{"severity": "LOW"}'
        ']}',
        encoding="utf-8",
    )

    loaded = store.load(key)
    assert loaded is not None
    assert [r.cve_id for r in loaded] == ["CVE-2100-2002"]


# ---------------------------------------------------------------------------
# Path-traversal containment
# ---------------------------------------------------------------------------


def test_path_for_stays_within_snapshot_dir(store: SnapshotStore) -> None:
    key = store.make_key("latest", {"since": "24h"})
    resolved = store.path_for(key)
    assert str(resolved).startswith(str(store.directory))


def test_save_rejects_traversal_query_key(store: SnapshotStore) -> None:
    with pytest.raises(ValueError, match="traversal"):
        store.save("../escape", [_cve("CVE-2100-3000")])

    # Nothing was written outside the snapshot directory.
    escaped = store.directory.parent / "escape.json"
    assert not escaped.exists()


def test_path_for_rejects_traversal_and_null_byte(store: SnapshotStore) -> None:
    with pytest.raises(ValueError):
        store.path_for("../../etc/passwd")
    with pytest.raises(ValueError):
        store.path_for("bad\x00name")


def test_load_traversal_query_key_returns_none(store: SnapshotStore) -> None:
    assert store.load("../escape") is None
