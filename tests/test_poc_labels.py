"""Offline tests for PoC label heuristics and trust scoring."""

from __future__ import annotations

from pocmap.utils.poc_labels import (
    LABEL_INDEX,
    LABEL_POC,
    LABEL_SCANNER,
    LABEL_WRITEUP,
    classify_poc_labels,
    trust_score,
)


def test_classify_scanner_and_poc() -> None:
    labels = classify_poc_labels("Nuclei scanner for Log4Shell", "https://github.com/x/log4shell-scan")
    assert LABEL_SCANNER in labels


def test_classify_index_and_writeup() -> None:
    assert LABEL_INDEX in classify_poc_labels("awesome-cve-list", "https://github.com/x/awesome-pocs")
    assert LABEL_WRITEUP in classify_poc_labels("My analysis writeup", "https://github.com/x/notes")


def test_classify_poc_from_title() -> None:
    labels = classify_poc_labels("RCE exploit PoC", "https://github.com/x/thing")
    assert LABEL_POC in labels


def test_trust_penalizes_index() -> None:
    high = trust_score(stars=100, forks=10, labels=[LABEL_POC], last_commit="2026-07-01T00:00:00Z")
    low = trust_score(stars=100, forks=10, labels=[LABEL_INDEX], last_commit="2026-07-01T00:00:00Z")
    assert high > low


def test_trust_evidence_confirmed_floor() -> None:
    score = trust_score(stars=0, labels=[LABEL_WRITEUP], evidence_verdict="confirmed")
    assert score >= 0.85
