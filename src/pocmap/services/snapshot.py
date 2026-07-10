"""Local snapshot + diff engine for ``latest`` / ``discover`` result sets.

This is the offline persistence half of the **WATCH-DIFF** feature: it lets the
CLI answer "what's new since last time" by snapshotting a query's result set to
disk and diffing the current run against the previous one. It performs **no**
network I/O and knows nothing about the CLI — the CLI layer wires it up as
``load -> run query -> diff -> save``.

Design
------
* **Store** — :class:`SnapshotStore` persists a query's result set as a JSON
  envelope under ``<cache_dir>/snapshots/<query_key>.json``. ``query_key`` is a
  filesystem-safe token; use :meth:`SnapshotStore.make_key` (a stable SHA-256 of
  the ``latest``/``discover`` params) to derive one. Every path is additionally
  run through :func:`pocmap.utils.paths.safe_path` for containment.
* **Record** — only the fields that matter for change detection are stored:
  ``cve_id``, ``severity``, CVSS ``base_score``, ``epss``, ``kev_status`` and
  ``has_poc`` (see :class:`SnapshotRecord`).
* **Atomic writes** — content is written to a temp file in the same directory
  and then :func:`os.replace`\\d into place (atomic, overwrites on Windows).
* **Corruption-safe** — a missing or corrupt snapshot is treated as *no previous
  snapshot* (:meth:`SnapshotStore.load` returns ``None``); the engine never
  raises to its callers on read.
* **Diff** — :func:`diff_snapshots` compares two record sets and reports
  ``added`` / ``removed`` / ``changed`` CVEs plus an ``unchanged`` count, where
  "changed" means a meaningful movement (KEV flip, severity escalation, a CVSS
  or EPSS jump past a threshold, or a newly-available PoC).

Example::

    from pocmap.services.snapshot import (
        diff_snapshots, load_snapshot, make_query_key, save_snapshot,
    )

    key = make_query_key("latest", {"since": "24h", "severity": ["CRITICAL"]})
    previous = load_snapshot(key)            # None on the first ever run
    results = run_latest_query(...)          # list[RecentExploitResult]
    diff = diff_snapshots(previous, [r.cve_info for r in results])
    save_snapshot(key, results)
    if diff.is_empty:
        print("No changes since last run.")
    else:
        print(diff.summary())
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from pocmap.config import settings
from pocmap.models import CVEInfo, RecentExploitResult, Severity
from pocmap.utils.paths import safe_path

logger = logging.getLogger(__name__)

# Subdirectory under ``cache_dir`` reserved for snapshot envelopes, so snapshots
# never collide with the HTTP response cache (``<cache_dir>/http``).
_SNAPSHOT_SUBDIR = "snapshots"
_ENTRY_SUFFIX = ".json"
_SCHEMA_VERSION = 1

# Default change-detection thresholds. CVSS is on the 0-10 scale; EPSS in this
# codebase is on the 0-100 percentage scale (see :class:`pocmap.models.CVEInfo`).
DEFAULT_CVSS_DELTA: float = 1.0
DEFAULT_EPSS_DELTA: float = 10.0

# Ordinal ranking of severities, used to classify a severity change as an
# escalation vs. a de-escalation. Anything unknown ranks below ``LOW``.
_SEVERITY_RANK: dict[str, int] = {
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


class ChangeReason(str, Enum):
    """Why a CVE present in both snapshots is reported as *changed*."""

    KEV_GAINED = "kev_gained"
    KEV_LOST = "kev_lost"
    SEVERITY_ESCALATED = "severity_escalated"
    SEVERITY_DEESCALATED = "severity_deescalated"
    CVSS_INCREASED = "cvss_increased"
    CVSS_DECREASED = "cvss_decreased"
    EPSS_JUMPED = "epss_jumped"
    POC_GAINED = "poc_gained"


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SnapshotRecord:
    """The change-relevant projection of a single CVE in a result set.

    Only the fields that participate in :func:`diff_snapshots` are retained, so
    a snapshot stays tiny and stable across runs.

    Attributes:
        cve_id: The CVE identifier (e.g. ``CVE-2021-44228``).
        severity: CVSS severity label (``LOW``/``MEDIUM``/``HIGH``/``CRITICAL``)
            or ``None`` when unknown.
        base_score: CVSS base score (0.0-10.0) or ``None``.
        epss: EPSS score on the 0-100 scale or ``None``.
        kev_status: Whether the CVE is in the CISA KEV catalog.
        has_poc: Whether at least one PoC/exploit was found for the CVE.
    """

    cve_id: str
    severity: str | None = None
    base_score: float | None = None
    epss: float | None = None
    kev_status: bool = False
    has_poc: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict for this record."""
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "base_score": self.base_score,
            "epss": self.epss,
            "kev_status": self.kev_status,
            "has_poc": self.has_poc,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SnapshotRecord | None:
        """Rebuild a record from stored JSON, or ``None`` if it is unusable."""
        cve_id = data.get("cve_id")
        if not isinstance(cve_id, str) or not cve_id:
            return None
        return cls(
            cve_id=cve_id,
            severity=_coerce_severity(data.get("severity")),
            base_score=_coerce_float(data.get("base_score")),
            epss=_coerce_float(data.get("epss")),
            kev_status=bool(data.get("kev_status", False)),
            has_poc=bool(data.get("has_poc", False)),
        )


# Anything the store knows how to snapshot. Duck-typed model objects
# (:class:`RecentExploitResult`, :class:`CVEInfo`) and plain mappings are all
# accepted so the CLI can hand over either ``latest`` or ``discover`` output.
SnapshotInput = SnapshotRecord | CVEInfo | RecentExploitResult | Mapping[str, Any]


@dataclass(frozen=True)
class CVEChange:
    """A single CVE that appears in both snapshots but moved meaningfully.

    Attributes:
        cve_id: The CVE identifier.
        reasons: Ordered, de-duplicated reasons the CVE is considered changed.
        previous: The record from the previous snapshot.
        current: The record from the current snapshot.
    """

    cve_id: str
    reasons: tuple[ChangeReason, ...]
    previous: SnapshotRecord
    current: SnapshotRecord

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict for this change."""
        return {
            "cve_id": self.cve_id,
            "reasons": [reason.value for reason in self.reasons],
            "previous": self.previous.to_dict(),
            "current": self.current.to_dict(),
        }


@dataclass(frozen=True)
class SnapshotDiff:
    """The delta between a previous and a current snapshot.

    Attributes:
        added: Records present in *current* but not *previous* (new CVEs).
        removed: Records present in *previous* but not *current* (gone).
        changed: CVEs present in both that moved meaningfully.
        unchanged: Count of CVEs present in both with no meaningful change.
    """

    added: tuple[SnapshotRecord, ...] = field(default_factory=tuple)
    removed: tuple[SnapshotRecord, ...] = field(default_factory=tuple)
    changed: tuple[CVEChange, ...] = field(default_factory=tuple)
    unchanged: int = 0

    @property
    def is_empty(self) -> bool:
        """``True`` when nothing was added, removed, or changed."""
        return not (self.added or self.removed or self.changed)

    @property
    def total_changes(self) -> int:
        """Number of added + removed + changed CVEs (excludes *unchanged*)."""
        return len(self.added) + len(self.removed) + len(self.changed)

    @property
    def added_ids(self) -> tuple[str, ...]:
        """CVE ids of the added records."""
        return tuple(record.cve_id for record in self.added)

    @property
    def removed_ids(self) -> tuple[str, ...]:
        """CVE ids of the removed records."""
        return tuple(record.cve_id for record in self.removed)

    @property
    def changed_ids(self) -> tuple[str, ...]:
        """CVE ids of the changed records."""
        return tuple(change.cve_id for change in self.changed)

    def summary(self) -> str:
        """Return a compact one-line human summary of the diff."""
        if self.is_empty:
            return f"No changes ({self.unchanged} unchanged)."
        return (
            f"{len(self.added)} added, {len(self.removed)} removed, "
            f"{len(self.changed)} changed, {self.unchanged} unchanged."
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict for the whole diff."""
        return {
            "added": [record.to_dict() for record in self.added],
            "removed": [record.to_dict() for record in self.removed],
            "changed": [change.to_dict() for change in self.changed],
            "unchanged": self.unchanged,
            "summary": self.summary(),
        }


# ---------------------------------------------------------------------------
# Coercion helpers
# ---------------------------------------------------------------------------

def _coerce_float(value: Any) -> float | None:
    """Return *value* as a ``float``, or ``None`` if it is missing/invalid."""
    if value is None or value == "" or value == "N/A":
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _coerce_severity(value: Any) -> str | None:
    """Normalize a severity into its upper-case label string, or ``None``."""
    if value is None:
        return None
    if isinstance(value, Severity):
        return value.value
    text = str(value).strip().upper()
    if not text or text == "N/A":
        return None
    return text


def _normalize_params(params: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return *params* as a key-sorted plain dict (stable for hashing)."""
    if not params:
        return {}
    return {str(key): params[key] for key in sorted(params)}


def _extract_record(item: SnapshotInput) -> SnapshotRecord:
    """Project any supported input into a :class:`SnapshotRecord`.

    Accepts an already-normalized :class:`SnapshotRecord`, a model object
    (:class:`RecentExploitResult` or :class:`CVEInfo`), or a plain mapping.

    Raises:
        TypeError: If *item* is of an unsupported type.
    """
    if isinstance(item, SnapshotRecord):
        return item
    if isinstance(item, RecentExploitResult):
        return _from_cve_info(item.cve_info, has_poc=item.has_poc)
    if isinstance(item, CVEInfo):
        return _from_cve_info(item, has_poc=False)
    if isinstance(item, Mapping):
        return _from_mapping(item)
    raise TypeError(  # pragma: no cover - defensive; the union is exhaustive
        f"Cannot snapshot object of type {type(item).__name__!r}"
    )


def _from_cve_info(cve: CVEInfo, *, has_poc: bool) -> SnapshotRecord:
    """Build a record from a :class:`CVEInfo` model."""
    severity: str | None = None
    base_score: float | None = None
    if cve.cvss is not None:
        severity = _coerce_severity(cve.cvss.severity)
        base_score = _coerce_float(cve.cvss.base_score)
    return SnapshotRecord(
        cve_id=cve.id,
        severity=severity,
        base_score=base_score,
        epss=_coerce_float(cve.epss),
        kev_status=bool(cve.kev_status),
        has_poc=has_poc,
    )


def _from_mapping(data: Mapping[str, Any]) -> SnapshotRecord:
    """Build a record from a plain mapping (accepts ``cve_id`` or ``id``).

    Raises:
        TypeError: If no CVE identifier is present.
    """
    raw_id = data.get("cve_id") or data.get("id")
    if not isinstance(raw_id, str) or not raw_id:
        raise TypeError("Mapping input is missing a 'cve_id'/'id' string")
    return SnapshotRecord(
        cve_id=raw_id,
        severity=_coerce_severity(data.get("severity")),
        base_score=_coerce_float(data.get("base_score")),
        epss=_coerce_float(data.get("epss")),
        kev_status=bool(data.get("kev_status", False)),
        has_poc=bool(data.get("has_poc", False)),
    )


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class SnapshotStore:
    """On-disk store of query result-set snapshots under ``<cache_dir>/snapshots``.

    Args:
        cache_dir: Base cache directory. Defaults to
            :data:`pocmap.config.settings.cache_dir`. Snapshot envelopes live in
            the ``snapshots`` subdirectory beneath it.
    """

    def __init__(self, cache_dir: Path | str | None = None) -> None:
        base = Path(cache_dir) if cache_dir is not None else Path(settings.cache_dir)
        self._dir = base / _SNAPSHOT_SUBDIR

    # -- key derivation -----------------------------------------------------

    @staticmethod
    def make_key(command: str, params: Mapping[str, Any] | None = None) -> str:
        """Return a stable, filesystem-safe SHA-256 key for a query.

        Args:
            command: The command the snapshot belongs to (e.g. ``"latest"``).
            params: The query parameters that define the result set.

        Returns:
            A 64-character hex digest suitable for use as a ``query_key``.
        """
        payload = {"command": command, "params": _normalize_params(params)}
        raw = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # -- public API ---------------------------------------------------------

    @property
    def directory(self) -> Path:
        """The directory snapshots are stored in."""
        return self._dir

    def path_for(self, query_key: str) -> Path:
        """Resolve the on-disk path for *query_key*, guarded against traversal.

        Raises:
            ValueError: If *query_key* contains a null byte or would resolve
                outside the snapshot directory (path traversal).
        """
        return Path(safe_path(f"{query_key}{_ENTRY_SUFFIX}", base_dir=str(self._dir)))

    def save(self, query_key: str, cves: Iterable[SnapshotInput]) -> Path:
        """Persist *cves* as the snapshot for *query_key*; return the file path.

        The write is atomic (temp file + :func:`os.replace`). Duplicate CVE ids
        are collapsed, keeping the last occurrence.

        Args:
            query_key: A filesystem-safe token, ideally from :meth:`make_key`.
            cves: The result set to snapshot (models, records, or mappings).

        Raises:
            ValueError: If *query_key* escapes the snapshot directory.
            TypeError: If an item in *cves* is of an unsupported type.
        """
        path = self.path_for(query_key)
        # De-duplicate by CVE id, preserving last-wins and insertion order.
        deduped: dict[str, SnapshotRecord] = {}
        for item in cves:
            record = _extract_record(item)
            deduped[record.cve_id] = record
        records = list(deduped.values())
        envelope: dict[str, Any] = {
            "version": _SCHEMA_VERSION,
            "query_key": query_key,
            "created": time.time(),
            "count": len(records),
            "records": [record.to_dict() for record in records],
        }
        self._dir.mkdir(parents=True, exist_ok=True)
        self._atomic_write(path, envelope)
        return path

    def load(self, query_key: str) -> list[SnapshotRecord] | None:
        """Return the stored records for *query_key*, or ``None``.

        ``None`` means "no usable previous snapshot" — the file is missing,
        unreadable, or corrupt. This never raises for a missing/corrupt entry so
        the caller can transparently treat the first (or a damaged) run as having
        no baseline. A traversal *query_key* is likewise treated as a miss.
        """
        try:
            path = self.path_for(query_key)
        except ValueError:
            return None
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return None  # missing / unreadable -> no previous snapshot
        try:
            envelope = json.loads(raw)
        except (ValueError, TypeError):
            logger.debug("Corrupt snapshot for %s; treating as no-previous", query_key)
            return None
        if not isinstance(envelope, dict):
            return None
        raw_records = envelope.get("records")
        if not isinstance(raw_records, list):
            return None
        records: list[SnapshotRecord] = []
        for entry in raw_records:
            if isinstance(entry, Mapping):
                record = SnapshotRecord.from_dict(entry)
                if record is not None:
                    records.append(record)
        return records

    def clear(self, query_key: str | None = None) -> int:
        """Delete one snapshot (by *query_key*) or all of them.

        Args:
            query_key: A specific snapshot to remove; when ``None``, every
                snapshot in the directory is removed.

        Returns:
            The number of snapshot files removed.
        """
        removed = 0
        if query_key is not None:
            try:
                path = self.path_for(query_key)
            except ValueError:
                return 0
            if self._safe_unlink(path):
                removed += 1
            return removed
        try:
            candidates = list(self._dir.glob(f"*{_ENTRY_SUFFIX}"))
        except OSError:
            return 0
        for candidate in candidates:
            if self._safe_unlink(candidate):
                removed += 1
        return removed

    # -- internals ----------------------------------------------------------

    def _atomic_write(self, path: Path, envelope: dict[str, Any]) -> None:
        """Write *envelope* as JSON to *path* atomically (temp file + replace)."""
        fd, tmp = tempfile.mkstemp(dir=str(self._dir), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(envelope, handle)
            os.replace(tmp, str(path))
        except OSError:
            self._safe_unlink(Path(tmp))
            raise

    @staticmethod
    def _safe_unlink(path: Path) -> bool:
        """Delete *path*, swallowing errors. Returns ``True`` if it was removed."""
        try:
            path.unlink()
            return True
        except OSError:
            return False


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

def _detect_changes(
    previous: SnapshotRecord,
    current: SnapshotRecord,
    cvss_delta: float,
    epss_delta: float,
) -> list[ChangeReason]:
    """Return the reasons *current* differs meaningfully from *previous*."""
    reasons: list[ChangeReason] = []

    if previous.kev_status != current.kev_status:
        reasons.append(
            ChangeReason.KEV_GAINED if current.kev_status else ChangeReason.KEV_LOST
        )

    prev_rank = _SEVERITY_RANK.get(previous.severity or "", 0)
    cur_rank = _SEVERITY_RANK.get(current.severity or "", 0)
    if cur_rank > prev_rank:
        reasons.append(ChangeReason.SEVERITY_ESCALATED)
    elif cur_rank < prev_rank:
        reasons.append(ChangeReason.SEVERITY_DEESCALATED)

    if previous.base_score is not None and current.base_score is not None:
        delta = current.base_score - previous.base_score
        if abs(delta) >= cvss_delta:
            reasons.append(
                ChangeReason.CVSS_INCREASED if delta > 0 else ChangeReason.CVSS_DECREASED
            )

    if (
        previous.epss is not None
        and current.epss is not None
        and abs(current.epss - previous.epss) >= epss_delta
    ):
        reasons.append(ChangeReason.EPSS_JUMPED)

    if not previous.has_poc and current.has_poc:
        reasons.append(ChangeReason.POC_GAINED)

    return reasons


def diff_snapshots(
    previous: Sequence[SnapshotRecord] | None,
    current: Sequence[SnapshotRecord],
    *,
    cvss_delta: float = DEFAULT_CVSS_DELTA,
    epss_delta: float = DEFAULT_EPSS_DELTA,
) -> SnapshotDiff:
    """Compute the delta between a *previous* and *current* snapshot.

    A CVE is:
        * **added** — in *current* but not *previous*.
        * **removed** — in *previous* but not *current*.
        * **changed** — in both, and at least one of: its KEV flag flipped, its
          severity moved up or down a level, its CVSS base score moved by
          ``cvss_delta`` or more, its EPSS moved by ``epss_delta`` or more, or it
          gained a PoC (``has_poc`` went from false to true).
        * **unchanged** — in both with none of the above.

    ``previous is None`` (no baseline, e.g. the first run) is treated as an empty
    previous set, so every current CVE is reported as *added*.

    Args:
        previous: Records from the prior run, or ``None`` for no baseline.
        current: Records from the current run.
        cvss_delta: Minimum absolute CVSS base-score change to flag (0-10 scale).
        epss_delta: Minimum absolute EPSS change to flag (0-100 scale).

    Returns:
        A :class:`SnapshotDiff`. Added/removed/changed lists are sorted by CVE id
        for deterministic output.
    """
    prev_map: dict[str, SnapshotRecord] = {r.cve_id: r for r in (previous or [])}
    cur_map: dict[str, SnapshotRecord] = {r.cve_id: r for r in current}

    added: list[SnapshotRecord] = []
    changed: list[CVEChange] = []
    unchanged = 0

    for cve_id, cur_record in cur_map.items():
        prev_record = prev_map.get(cve_id)
        if prev_record is None:
            added.append(cur_record)
            continue
        reasons = _detect_changes(prev_record, cur_record, cvss_delta, epss_delta)
        if reasons:
            changed.append(
                CVEChange(
                    cve_id=cve_id,
                    reasons=tuple(reasons),
                    previous=prev_record,
                    current=cur_record,
                )
            )
        else:
            unchanged += 1

    removed = [record for cve_id, record in prev_map.items() if cve_id not in cur_map]

    return SnapshotDiff(
        added=tuple(sorted(added, key=lambda r: r.cve_id)),
        removed=tuple(sorted(removed, key=lambda r: r.cve_id)),
        changed=tuple(sorted(changed, key=lambda c: c.cve_id)),
        unchanged=unchanged,
    )


# ---------------------------------------------------------------------------
# Module-level convenience API
# ---------------------------------------------------------------------------

def make_query_key(command: str, params: Mapping[str, Any] | None = None) -> str:
    """Return a stable, filesystem-safe key for a ``latest``/``discover`` query.

    Thin wrapper over :meth:`SnapshotStore.make_key`.
    """
    return SnapshotStore.make_key(command, params)


def save_snapshot(
    query_key: str,
    cves: Iterable[SnapshotInput],
    *,
    cache_dir: Path | str | None = None,
) -> Path:
    """Persist *cves* as the snapshot for *query_key* and return the file path.

    Convenience wrapper over :meth:`SnapshotStore.save`.
    """
    return SnapshotStore(cache_dir).save(query_key, cves)


def load_snapshot(
    query_key: str,
    *,
    cache_dir: Path | str | None = None,
) -> list[SnapshotRecord] | None:
    """Load the snapshot for *query_key*, or ``None`` if missing/corrupt.

    Convenience wrapper over :meth:`SnapshotStore.load`.
    """
    return SnapshotStore(cache_dir).load(query_key)
