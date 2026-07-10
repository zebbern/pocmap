"""SARIF 2.1.0 renderer — turns CVE view models into a SARIF log string.

Pure function, no I/O and no network: ``render_sarif(cves, *, tool_version)``.
SARIF (Static Analysis Results Interchange Format) 2.1.0 is the OASIS standard
consumed by GitHub code scanning, Azure DevOps and other CI security dashboards,
so emitting it lets pocmap findings flow straight into those pipelines.

The generated log is a single ``run`` whose ``tool.driver`` is ``pocmap``. Each
input CVE becomes exactly one ``result`` and, in ``tool.driver.rules``, one
:term:`reportingDescriptor` carrying the ``helpUri`` to the NVD detail page
(SARIF does not permit ``helpUri`` on a ``result`` itself). Every distinct CWE
seen across the input is deduplicated into an additional rule.

Expected input dict shape (per CVE)
-----------------------------------
All keys are optional except ``id``; missing values degrade gracefully::

    {
        "id": "CVE-2021-44228",           # str, becomes the result ruleId
        "description": "Apache Log4j2 ...",  # str -> message.text + rule shortDescription
        "cvss": {                          # dict (or None)
            "base_score": 10.0,            # float | None -> properties.cvss
            "severity": "CRITICAL",        # str -> result.level (see mapping)
        },
        "epss": 97.53,                     # float | None -> properties.epss
        "kev_status": True,                # bool -> properties.kev
        "exploit_count": 12,               # int  -> properties.exploit_count
        "cwes": ["CWE-77", "CWE-94"],      # list[str] -> deduped driver rules
    }

Severity -> SARIF level mapping
-------------------------------
``critical`` / ``high`` -> ``"error"``; ``medium`` -> ``"warning"``;
``low`` -> ``"note"``; anything else / missing -> ``"none"``.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["render_sarif", "SARIF_SCHEMA_URI", "SARIF_VERSION"]

#: URI of the SARIF 2.1.0 JSON schema (emitted as the log's ``$schema``).
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"

#: The only SARIF version this renderer emits.
SARIF_VERSION = "2.1.0"

_TOOL_NAME = "pocmap"
_TOOL_INFO_URI = "https://github.com/zebbern/pocmap"

# Severity (lower-cased) -> SARIF result.level.
_SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

_SHORT_DESC_LIMIT = 300


def _level_for(severity: Any) -> str:
    """Map a CVSS severity label to a SARIF ``result.level`` value."""
    if not severity:
        return "none"
    return _SEVERITY_TO_LEVEL.get(str(severity).strip().lower(), "none")


def _truncate(text: str, limit: int = _SHORT_DESC_LIMIT) -> str:
    """Truncate ``text`` to ``limit`` characters with an ellipsis if needed."""
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _cwe_rule(cwe_id: str) -> dict[str, Any]:
    """Build a reportingDescriptor for a CWE, linking to its MITRE definition."""
    number = cwe_id.split("-")[-1] if "-" in cwe_id else cwe_id
    return {
        "id": cwe_id,
        "name": cwe_id,
        "helpUri": f"https://cwe.mitre.org/data/definitions/{number}.html",
    }


def render_sarif(cves: list[dict[str, Any]], *, tool_version: str) -> str:
    """Render CVE view models as a SARIF 2.1.0 log document.

    Args:
        cves: List of CVE dicts (see module docstring for the expected shape).
        tool_version: Version string recorded as ``tool.driver.version``
            (typically the pocmap package version).

    Returns:
        A pretty-printed JSON string: one SARIF ``run`` with a ``result`` per
        input CVE and a deduplicated ``tool.driver.rules`` array.
    """
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}

    def _ensure_rule(rule: dict[str, Any]) -> int:
        """Append ``rule`` if its id is new; return the id's index in ``rules``."""
        rule_id = rule["id"]
        existing = rule_index.get(rule_id)
        if existing is not None:
            return existing
        index = len(rules)
        rule_index[rule_id] = index
        rules.append(rule)
        return index

    results: list[dict[str, Any]] = []
    for cve in cves:
        cve_id = str(cve.get("id") or "")
        description = str(cve.get("description") or "")

        cvss = cve.get("cvss")
        if isinstance(cvss, dict):
            base_score = cvss.get("base_score")
            severity = cvss.get("severity")
        else:
            base_score = None
            severity = None

        # Per-CVE rule carries the NVD helpUri (results cannot hold helpUri).
        cve_rule: dict[str, Any] = {
            "id": cve_id,
            "name": cve_id,
            "helpUri": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }
        if description:
            cve_rule["shortDescription"] = {"text": _truncate(description)}
        cve_rule_index = _ensure_rule(cve_rule)

        # Deduplicate CWE rules into the shared driver.rules array.
        for cwe in cve.get("cwes") or []:
            cwe_id = str(cwe).strip()
            if cwe_id:
                _ensure_rule(_cwe_rule(cwe_id))

        results.append(
            {
                "ruleId": cve_id,
                "ruleIndex": cve_rule_index,
                "level": _level_for(severity),
                "message": {"text": description or cve_id},
                "properties": {
                    "cvss": base_score,
                    "epss": cve.get("epss"),
                    "kev": bool(cve.get("kev_status", False)),
                    "exploit_count": cve.get("exploit_count"),
                },
            }
        )

    log: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": tool_version,
                        "informationUri": _TOOL_INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(log, indent=2, default=str)
