"""CVSS vector parsing and base-score computation.

Some upstreams publish a CVSS **vector** but no numeric score. OSV is the case
that motivated this module: across a 583-advisory sample, 216 entries carried a
``CVSS_V3`` vector, 153 a ``CVSS_V4`` vector, and **none** carried a number.
Without a score, results cannot be ranked or mapped to a SARIF level, and
``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`` is not something a reader can
act on.

Only CVSS 3.0/3.1 base scores are computed. That is deliberate:

* The 3.x base equation is closed-form and fully specified, so the result is
  exactly the published score rather than an approximation.
* CVSS 4.0 scores via a 270-entry macrovector lookup table, and a partial
  implementation would produce numbers that are *close but wrong* — worse than
  no number at all in a tool used to prioritize patching. A 4.0-only advisory
  returns ``None`` here, and callers fall back to the publisher's qualitative
  rating.

Reference: https://www.first.org/cvss/v3.1/specification-document (section 8.1)
"""

from __future__ import annotations

import math
import re

# Metric weights, CVSS 3.1 specification table 8.4.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
# Privileges Required is the one metric whose weight depends on Scope.
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_VECTOR_RE = re.compile(r"^CVSS:(3\.[01])/(.+)$", re.IGNORECASE)


def _roundup(value: float) -> float:
    """Round *value* up to one decimal place, per CVSS 3.1 Appendix A.

    Uses integer arithmetic rather than :func:`math.ceil` on a float, because
    the specification's own worked examples depend on values such as
    ``0.1 + 0.2`` not drifting below the boundary.
    """
    scaled = int(round(value * 100_000))
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str] | None:
    """Parse a CVSS 3.x vector string into its metric map.

    Returns:
        Metric abbreviations mapped to their values, or ``None`` when the string
        is not a CVSS 3.0/3.1 vector (a 2.0 or 4.0 vector included).
    """
    match = _VECTOR_RE.match(vector.strip())
    if match is None:
        return None
    metrics: dict[str, str] = {}
    for part in match.group(2).split("/"):
        key, sep, value = part.partition(":")
        if sep and key and value:
            metrics[key.upper()] = value.upper()
    return metrics


def base_score_from_vector(vector: str) -> float | None:
    """Compute the CVSS 3.x base score for *vector*.

    Args:
        vector: A ``CVSS:3.0``/``CVSS:3.1`` vector string.

    Returns:
        The base score rounded per spec (0.0-10.0), or ``None`` if the vector is
        not 3.x or is missing a required base metric. Temporal and environmental
        metrics present in the string are ignored, as they do not affect the
        base score.

    Example::

        base_score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        # 10.0  (Log4Shell)
    """
    metrics = parse_vector(vector)
    if metrics is None:
        return None

    scope_changed = metrics.get("S") == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = pr_table[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        conf = _CIA[metrics["C"]]
        integ = _CIA[metrics["I"]]
        avail = _CIA[metrics["A"]]
    except KeyError:
        # A missing or unrecognized base metric — report "unknown", never a
        # partially-computed score that would read as authoritative.
        return None

    iss = 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))
    impact = (
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        if scope_changed
        else 6.42 * iss
    )
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08
    return _roundup(min(combined, 10.0))


def severity_band(score: float) -> str:
    """Map a base score onto the CVSS qualitative rating scale.

    Returns one of ``CRITICAL``/``HIGH``/``MEDIUM``/``LOW``/``NONE``, matching
    :class:`pocmap.models.Severity` member values (which have no ``NONE``, so a
    0.0 score is reported as ``LOW`` by callers that must pick an enum member).
    """
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def normalize_qualitative(label: str) -> str | None:
    """Normalize a publisher's qualitative rating onto the CVSS scale.

    GitHub Security Advisories rate ``MODERATE`` where CVSS says ``MEDIUM``;
    everything else already matches. Returns ``None`` for an unrecognized label
    rather than guessing.
    """
    value = label.strip().upper()
    if value == "MODERATE":
        return "MEDIUM"
    if value in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return value
    return None
