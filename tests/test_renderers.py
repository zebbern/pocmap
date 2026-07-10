"""Native pytest tests for the pure output renderers (offline).

Covers the three ``view_model -> str`` renderers in
``pocmap.utils.renderers``:

* :func:`render_csv` — parses back via :class:`csv.DictReader` with the
  expected header and row count, including a value that contains the delimiter.
* :func:`render_markdown` — produces a valid GFM table and escapes a literal
  ``|`` in the data.
* :func:`render_sarif` — a SARIF 2.1.0 log: valid JSON, ``version == "2.1.0"``,
  ``$schema`` present, ``tool.driver.name == "pocmap"``, one result per input
  CVE, correct severity->level mapping, KEV/EPSS in ``properties``, and — when
  :mod:`jsonschema` is importable — structural validation against the bundled
  SARIF 2.1.0 JSON schema.

Everything runs from in-memory fixtures; no network or filesystem writes.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import pytest

import pocmap
from pocmap.utils.renderers import render_csv, render_markdown, render_sarif

# ---------------------------------------------------------------------------
# Fixtures (in-memory dicts)
# ---------------------------------------------------------------------------

CVE_ROWS: list[dict[str, Any]] = [
    {
        "id": "CVE-2021-44228",
        "description": "Apache Log4j2 JNDI | RCE",  # contains a pipe on purpose
        "cvss": {"base_score": 10.0, "severity": "CRITICAL"},
        "epss": 97.53,
        "kev_status": True,
        "exploit_count": 12,
        "cwes": ["CWE-77", "CWE-94"],
    },
    {
        "id": "CVE-2023-38408",
        "description": "OpenSSH ssh-agent forwarding RCE",
        "cvss": {"base_score": 9.8, "severity": "HIGH"},
        "epss": 31.24,
        "kev_status": True,
        "exploit_count": 3,
        "cwes": ["CWE-94"],  # duplicate CWE across rows -> must dedupe
    },
    {
        "id": "CVE-2024-21413",
        "description": "Outlook moniker medium-severity issue",
        "cvss": {"base_score": 5.5, "severity": "MEDIUM"},
        "epss": 12.0,
        "kev_status": False,
        "exploit_count": 1,
        "cwes": [],
    },
    {
        "id": "CVE-2024-00001",
        "description": "A low severity finding",
        "cvss": {"base_score": 2.1, "severity": "LOW"},
        "epss": 0.5,
        "kev_status": False,
        "exploit_count": 0,
    },
    {
        "id": "CVE-2024-00002",
        "description": "No CVSS data available",
        "cvss": None,
        "epss": None,
        "kev_status": False,
    },
]


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def test_csv_parses_with_expected_header_and_row_count() -> None:
    output = render_csv(CVE_ROWS)
    reader = csv.DictReader(io.StringIO(output))

    assert reader.fieldnames is not None
    # Header is the stable union of all row keys (first-appearance order).
    assert reader.fieldnames[0] == "id"
    assert "cwes" in reader.fieldnames
    assert reader.fieldnames == [
        "id",
        "description",
        "cvss",
        "epss",
        "kev_status",
        "exploit_count",
        "cwes",
    ]

    parsed = list(reader)
    assert len(parsed) == len(CVE_ROWS)
    assert parsed[0]["id"] == "CVE-2021-44228"
    # The pipe-bearing description survives the CSV round-trip intact.
    assert parsed[0]["description"] == "Apache Log4j2 JNDI | RCE"
    # Nested values are stringified (JSON); the last row's missing keys are empty.
    assert parsed[0]["cvss"].startswith("{")
    assert parsed[-1]["exploit_count"] == ""
    assert parsed[-1]["cwes"] == ""


def test_csv_is_crlf_terminated() -> None:
    output = render_csv(CVE_ROWS)
    assert "\r\n" in output
    # Every physical record ends in CRLF (excel dialect default).
    assert output.endswith("\r\n")


def test_csv_ragged_rows_produce_union_header() -> None:
    rows = [{"a": 1, "b": 2}, {"b": 3, "c": 4}]
    reader = csv.DictReader(io.StringIO(render_csv(rows)))
    assert reader.fieldnames == ["a", "b", "c"]
    parsed = list(reader)
    assert parsed[0]["c"] == ""  # missing in first row
    assert parsed[1]["a"] == ""  # missing in second row


def test_csv_empty_input_returns_empty_string() -> None:
    assert render_csv([]) == ""


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def test_markdown_contains_valid_table_and_escapes_pipe() -> None:
    output = render_markdown(CVE_ROWS, title="Findings")
    lines = output.splitlines()

    assert lines[0] == "# Findings"
    # Locate the header + separator rows of the GFM table.
    header_idx = next(i for i, ln in enumerate(lines) if ln.startswith("| id "))
    header_line = lines[header_idx]
    separator_line = lines[header_idx + 1]

    assert header_line.startswith("|") and header_line.endswith("|")
    # Separator row: one `---` group per column, GFM-valid.
    assert set(separator_line.replace("|", "").split()) == {"---"}
    assert separator_line.count("---") == 7

    # The pipe inside the description must be escaped so it can't split the row.
    joined = "\n".join(lines)
    assert "Apache Log4j2 JNDI \\| RCE" in joined
    # A data row keeps the same column count as the header.
    data_row = lines[header_idx + 2]
    assert data_row.count(" | ") == header_line.count(" | ")


def test_markdown_without_title_starts_with_table() -> None:
    output = render_markdown([{"a": "1"}])
    assert output.startswith("| a |")


def test_markdown_empty_input() -> None:
    assert render_markdown([]) == ""
    assert render_markdown([], title="Nothing") == "# Nothing\n"


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------

def _sarif_log() -> dict[str, Any]:
    return json.loads(render_sarif(CVE_ROWS, tool_version="2.0.0"))


def test_sarif_is_valid_json_with_version_and_schema() -> None:
    log = _sarif_log()
    assert log["version"] == "2.1.0"
    assert "$schema" in log and log["$schema"]


def test_sarif_single_run_driver_is_pocmap() -> None:
    log = _sarif_log()
    assert len(log["runs"]) == 1
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "pocmap"
    assert driver["version"] == "2.0.0"


def test_sarif_one_result_per_cve() -> None:
    log = _sarif_log()
    results = log["runs"][0]["results"]
    assert len(results) == len(CVE_ROWS)
    assert [r["ruleId"] for r in results] == [c["id"] for c in CVE_ROWS]


def test_sarif_severity_to_level_mapping() -> None:
    results = _sarif_log()["runs"][0]["results"]
    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels["CVE-2021-44228"] == "error"    # CRITICAL
    assert levels["CVE-2023-38408"] == "error"     # HIGH
    assert levels["CVE-2024-21413"] == "warning"   # MEDIUM
    assert levels["CVE-2024-00001"] == "note"      # LOW
    assert levels["CVE-2024-00002"] == "none"      # no CVSS -> unknown


def test_sarif_kev_and_epss_in_properties() -> None:
    results = _sarif_log()["runs"][0]["results"]
    props = {r["ruleId"]: r["properties"] for r in results}
    assert props["CVE-2021-44228"]["kev"] is True
    assert props["CVE-2021-44228"]["epss"] == 97.53
    assert props["CVE-2021-44228"]["cvss"] == 10.0
    assert props["CVE-2021-44228"]["exploit_count"] == 12
    assert props["CVE-2024-21413"]["kev"] is False


def test_sarif_help_uri_points_to_nvd() -> None:
    rules = _sarif_log()["runs"][0]["tool"]["driver"]["rules"]
    by_id = {r["id"]: r for r in rules}
    assert (
        by_id["CVE-2021-44228"]["helpUri"]
        == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    )


def test_sarif_cwe_rules_are_deduped() -> None:
    rules = _sarif_log()["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    # CWE-94 appears in two different CVEs but must be present exactly once.
    assert rule_ids.count("CWE-94") == 1
    assert "CWE-77" in rule_ids


def test_sarif_validates_against_bundled_schema() -> None:
    jsonschema = pytest.importorskip(
        "jsonschema",
        reason="jsonschema not installed; skipping SARIF schema validation",
    )
    schema_path = Path(pocmap.__file__).parent / "data" / "sarif-2.1.0-schema.json"
    assert schema_path.is_file(), f"bundled SARIF schema missing at {schema_path}"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    log = _sarif_log()
    # Raises jsonschema.ValidationError if the SARIF document is non-conformant.
    jsonschema.validate(instance=log, schema=schema)


def test_sarif_empty_input_is_valid_empty_run() -> None:
    log = json.loads(render_sarif([], tool_version="2.0.0"))
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["tool"]["driver"]["rules"] == []
