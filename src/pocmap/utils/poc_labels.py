"""Heuristic PoC quality labels from title + URL only (no network).

Used by ``find_github_pocs`` so agents can separate scanners, writeups, and
indexes from likely exploit code without fetching repository source. Deeper
verdicts still come from :mod:`pocmap.utils.poc_evidence` via ``verify_github_pocs``.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from urllib.parse import urlparse

# Label vocabulary (stable for agents / MCP docs).
LABEL_SCANNER = "scanner"
LABEL_POC = "poc"
LABEL_VULN_APP = "vulnerable-app"
LABEL_WRITEUP = "writeup"
LABEL_INDEX = "index"

_SCANNER_RE = re.compile(
    r"\b(nuclei|scanner|scan|detection|detect|fingerprint)\b",
    re.IGNORECASE,
)
_VULN_APP_RE = re.compile(
    r"\b(vulhub|vulnerable[-_ ]?app|docker[-_ ]?compose|lab|dvwa|juice[-_ ]?shop)\b",
    re.IGNORECASE,
)
_POC_RE = re.compile(
    r"\b(poc|proof[-_ ]?of[-_ ]?concept|exploit|rce|0day|payload|cve[-_]?\d{4})\b",
    re.IGNORECASE,
)
_WRITEUP_RE = re.compile(
    r"\b(write[-_ ]?up|blog|notes?|analysis|walkthrough|cheatsheet|tutorial)\b",
    re.IGNORECASE,
)
_INDEX_RE = re.compile(
    r"\b(awesome[-_]|collection|curated|links?|list[-_ ]of|poc[-_ ]?list|cve[-_ ]?list)\b",
    re.IGNORECASE,
)


def _haystack(title: str | None, url: str | None) -> str:
    parts: list[str] = []
    if title:
        parts.append(title)
    if url:
        parsed = urlparse(url)
        parts.append(parsed.path.replace("/", " "))
        parts.append(url)
    return " ".join(parts)


def classify_poc_labels(title: str | None, url: str | None) -> list[str]:
    """Return zero or more quality labels for a PoC/exploit listing.

    Order is fixed for stable diffs: index, writeup, scanner, vulnerable-app, poc.
    An entry may carry multiple labels (e.g. scanner + poc).
    """
    text = _haystack(title, url)
    if not text.strip():
        return []

    labels: list[str] = []
    if _INDEX_RE.search(text):
        labels.append(LABEL_INDEX)
    if _WRITEUP_RE.search(text):
        labels.append(LABEL_WRITEUP)
    if _SCANNER_RE.search(text):
        labels.append(LABEL_SCANNER)
    if _VULN_APP_RE.search(text):
        labels.append(LABEL_VULN_APP)
    if _POC_RE.search(text) and LABEL_POC not in labels:
        labels.append(LABEL_POC)
    return labels


def trust_score(
    *,
    stars: int | None = None,
    forks: int | None = None,
    last_commit: str | None = None,
    labels: Iterable[str] | None = None,
    evidence_verdict: str | None = None,
) -> float:
    """Heuristic trust in ``[0.0, 1.0]`` from listing signals (no network).

    Penalties for ``index`` / ``writeup``; bonuses for stars, forks, recency,
    and ``poc`` / ``vulnerable-app``. Evidence verdicts from verify override
    the baseline when present.
    """
    label_set = {str(x) for x in (labels or [])}
    score = 0.35

    star_n = max(0, int(stars or 0))
    fork_n = max(0, int(forks or 0))
    # Log scale: 0 stars ~0, 10 ~0.15, 100 ~0.25, 1000+ ~0.32
    score += min(0.32, math.log10(star_n + 1) * 0.12)
    score += min(0.10, math.log10(fork_n + 1) * 0.05)

    if last_commit:
        age_days = _age_days(last_commit)
        if age_days is not None:
            if age_days <= 90:
                score += 0.15
            elif age_days <= 365:
                score += 0.08
            elif age_days <= 365 * 3:
                score += 0.02
            else:
                score -= 0.05

    if LABEL_POC in label_set:
        score += 0.12
    if LABEL_VULN_APP in label_set:
        score += 0.08
    if LABEL_SCANNER in label_set:
        score += 0.05
    if LABEL_WRITEUP in label_set:
        score -= 0.18
    if LABEL_INDEX in label_set:
        score -= 0.28

    if evidence_verdict == "confirmed":
        score = max(score, 0.85)
    elif evidence_verdict == "likely":
        score = max(score, 0.65)
    elif evidence_verdict == "unrelated":
        score = min(score, 0.15)
    elif evidence_verdict == "unverified":
        score = min(score, 0.45)

    return round(max(0.0, min(1.0, score)), 3)


def _age_days(iso_ts: str) -> float | None:
    """Days since *iso_ts*, or ``None`` if unparseable."""
    text = iso_ts.strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return max(0.0, (now - dt.astimezone(timezone.utc)).total_seconds() / 86400.0)
    except ValueError:
        return None


def labels_from_evidence_verdict(verdict: str | None) -> list[str]:
    """Map a ``poc_evidence`` verdict onto listing labels (additive hint)."""
    if verdict == "confirmed":
        return [LABEL_POC]
    if verdict == "likely":
        return [LABEL_POC]
    if verdict == "unrelated":
        return [LABEL_INDEX]
    return []
