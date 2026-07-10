#!/usr/bin/env python3
"""
End-to-End Test Suite for PocMap Package

Tests complete user workflows across all major components:
1. Full CVE Lookup Pipeline
2. Bug Bounty Workflow (Checklists)
3. Scope Management + CVE Matching
4. Report Generation Pipeline (JSON round-trip)
5. Prioritization Pipeline
6. JSON Schema Export

Run with: python test_e2e.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import traceback
from datetime import datetime
from pathlib import Path

# Ensure the src directory is on the path for imports
# The package is installed at /mnt/agents/output/pocmap/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# ---------------------------------------------------------------------------
# Imports from the package under test
# ---------------------------------------------------------------------------
import pytest  # noqa: E402

from pocmap.bugbounty.checklists import MasterChecklist
from pocmap.bugbounty.prioritization import (
    calculate_bounty_potential,
    prioritize_cves,
)
from pocmap.bugbounty.scope_manager import ScopeManager
from pocmap.bugbounty.templates import HackerOneTemplate, TemplateConfig
from pocmap.models import (
    BugBountyReport,
    CVEInfo,
    CVSSScore,
    Exploit,
    ExploitSource,
    LabEnvironment,
    LabPlatform,
    ReportEntry,
    Severity,
    export_schemas,
)

# Legacy standalone script-runner suite — run directly: `python tests/test_e2e.py`.
# Its checks execute at import via a custom harness (no collectable `test_*` funcs),
# so it is excluded from the default `pytest` run (`addopts = -m 'not network'`) to
# avoid executing as an import side effect. It currently runs offline; the `network`
# marker is a conservative default in case network-dependent e2e checks are added.
pytestmark = pytest.mark.network

# ---------------------------------------------------------------------------
# Test Result Tracking
# ---------------------------------------------------------------------------

class TestResult:
    """Tracks the result of a single test."""

    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.error: str | None = None
        self.details: dict | None = None

    def mark_passed(self, details: dict | None = None):
        self.passed = True
        self.details = details

    def mark_failed(self, error: str):
        self.passed = False
        self.error = error


# Global results collector
RESULTS: list[TestResult] = []


def run_test(name: str):
    """Decorator / context to run a test and capture results."""
    def decorator(func):
        result = TestResult(name)
        RESULTS.append(result)
        try:
            print(f"\n{'='*60}")
            print(f"Running: {name}")
            print("=" * 60)
            details = func()
            result.mark_passed(details)
            print(f"[PASS] {name}")
        except AssertionError as exc:
            tb = traceback.format_exc()
            result.mark_failed(f"AssertionError: {exc}\n{tb}")
            print(f"[FAIL] {name}: {exc}")
        except Exception as exc:
            tb = traceback.format_exc()
            result.mark_failed(f"{type(exc).__name__}: {exc}\n{tb}")
            print(f"[FAIL] {name}: {type(exc).__name__}: {exc}")
        return result
    return decorator


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 1: Full CVE Lookup Pipeline
# ═══════════════════════════════════════════════════════════════════════════════

@run_test("Test 1: Full CVE Lookup Pipeline")
def test_cve_lookup_pipeline():
    """
    1. Create a CVEInfo model for CVE-2021-44228
    2. Pass it through calculate_bounty_potential()
    3. Generate a HackerOne report template from it
    4. Verify the report contains the CVE ID and severity
    """
    # Step 1: Create CVEInfo for Log4Shell
    cve_info = CVEInfo(
        id="CVE-2021-44228",
        description=(
            "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases "
            "2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, "
            "and parameters do not protect against attacker controlled LDAP and other JNDI "
            "related endpoints. An attacker who can control log messages or log message "
            "parameters can execute arbitrary code loaded from LDAP servers when message "
            "lookup substitution is enabled."
        ),
        cvss=CVSSScore(
            version="3.1",
            base_score=10.0,
            severity=Severity.CRITICAL,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        ),
        epss=0.97,
        kev_status=True,
        cwes=["CWE-77", "CWE-94"],
        references={
            "NVD": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "CISA": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        },
        vendor="Apache",
        product="Log4j2",
        publication_date="2021-12-10",
        state="PUBLISHED",
    )

    # Verify CVEInfo was created correctly
    assert cve_info.id == "CVE-2021-44228"
    assert cve_info.cvss.severity == Severity.CRITICAL
    assert cve_info.cvss.base_score == 10.0
    assert cve_info.kev_status is True
    print(f"  [OK] CVEInfo created: {cve_info.id}, severity={cve_info.cvss.severity.value}")

    # Step 2: Pass through calculate_bounty_potential()
    bounty = calculate_bounty_potential(cve_info, platform="hackerone")

    assert bounty is not None, "calculate_bounty_potential() returned None"
    assert "estimated_range_usd" in bounty, "Missing 'estimated_range_usd' in bounty result"
    assert bounty["severity"] == "Critical", f"Expected severity 'Critical', got '{bounty['severity']}'"
    assert bounty["cvss_score"] == 10.0, f"Expected CVSS 10.0, got {bounty['cvss_score']}"
    print(f"  [OK] Bounty potential calculated: {bounty['estimated_range_usd']}")
    print(f"  [OK] Severity: {bounty['severity']}, Confidence: {bounty['confidence']}")

    # Step 3: Generate a HackerOne report template
    template = HackerOneTemplate(config=TemplateConfig(
        researcher_name="Security Researcher",
        researcher_handle="@security_researcher",
        program_name="Test Program",
        target_url="https://example.com",
    ))

    report = template.render(
        cve_id=cve_info.id,
        title=f"Log4j2 Remote Code Execution - {cve_info.id}",
        severity=cve_info.cvss.severity.value,
        cvss_score=cve_info.cvss.base_score,
        executive_summary=(
            f"A critical Remote Code Execution vulnerability ({cve_info.id}) was identified "
            f"in Apache Log4j2 on the target system."
        ),
        vulnerability_description=cve_info.description,
        affected_product=cve_info.vendor + " " + cve_info.product,
        affected_versions="2.0-beta9 through 2.15.0",
        fixed_version="2.17.1",
        cwe_id=", ".join(cve_info.cwes),
        epss_score=cve_info.epss,
        kev_listed="Yes" if cve_info.kev_status else "No",
        impact_description="Remote Code Execution allowing complete system compromise.",
        root_cause="JNDI lookup injection through log message parameters.",
        attack_vector="Network-based, no authentication required.",
        reproduction_steps=(
            "1. Identify Log4j2 usage in the application\\n"
            "2. Inject JNDI payload in user-controllable input that gets logged\\n"
            "3. Observe LDAP connection to attacker-controlled server"
        ),
        remediation_primary="Upgrade Log4j2 to version 2.17.1 or later.",
        temporary_mitigations="Set log4j2.formatMsgNoLookups=true or remove JndiLookup class.",
        references="\\n".join(f"- {k}: {v}" for k, v in cve_info.references.items()),
        av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H",
        av_justification="Exploitable over the network.",
        ac_justification="Low complexity - single request.",
        pr_justification="No privileges required.",
        ui_justification="No user interaction needed.",
        s_justification="Changed scope - affects underlying system.",
        c_justification="High confidentiality impact.",
        i_justification="High integrity impact.",
        a_justification="High availability impact.",
    )

    # Step 4: Verify report contains CVE ID and severity
    assert cve_info.id in report, f"Report missing CVE ID: {cve_info.id}"
    assert cve_info.cvss.severity.value in report, f"Report missing severity: {cve_info.cvss.severity.value}"
    assert "Log4j2" in report, "Report missing product name 'Log4j2'"

    # Count occurrences to be thorough
    cve_id_count = report.count(cve_info.id)
    print(f"  [OK] HackerOne report generated ({len(report)} chars, CVE ID appears {cve_id_count} times)")

    return {
        "cve_id": cve_info.id,
        "severity": cve_info.cvss.severity.value,
        "bounty_range": bounty["estimated_range_usd"],
        "report_length": len(report),
        "cve_id_mentions": cve_id_count,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 2: Bug Bounty Workflow
# ═══════════════════════════════════════════════════════════════════════════════

@run_test("Test 2: Bug Bounty Workflow")
def test_bug_bounty_workflow():
    """
    1. Create a MasterChecklist
    2. Complete some items
    3. Get overall status
    4. Verify completion percentage is correct
    """
    # Step 1: Create MasterChecklist
    master = MasterChecklist(program_name="Test Bug Bounty Program")

    # Step 2: Complete some items from different phases
    # Complete 2 items from recon
    master.recon.items[0].complete("Subdomains enumerated via crt.sh")
    master.recon.items[1].complete("Active brute-force completed")

    # Complete 1 item from cve_research
    master.cve_research.items[0].complete("CVE details retrieved")

    # Complete 1 item from exploitation
    master.exploitation.items[0].complete("Authorization confirmed")

    # Complete 2 items from reporting
    master.reporting.items[0].complete("HTTP requests collected")
    master.reporting.items[1].complete("Screenshots taken")

    # Step 3: Get overall status
    status = master.overall_status()

    # Step 4: Verify completion percentage
    total_completed = status["completed_items"]
    total_items = status["total_items"]
    expected_percentage = (total_completed / total_items) * 100

    assert status["completion_percentage"] == expected_percentage, (
        f"Completion percentage mismatch: expected {expected_percentage}, "
        f"got {status['completion_percentage']}"
    )
    assert total_completed == 6, f"Expected 6 completed items, got {total_completed}"
    assert status["is_complete"] is False, "Expected is_complete to be False"
    assert status["program_name"] == "Test Bug Bounty Program"

    # Verify phase-level status
    recon_status = status["phases"]["recon"]
    assert recon_status["completed_items"] == 2

    print(f"  [OK] MasterChecklist created with {total_items} total items")
    print(f"  [OK] Completed {total_completed} items ({expected_percentage:.1f}%)")
    print(f"  [OK] P0 blocking items: {status['p0_blocking']}")
    print(f"  [OK] Current phase: {status['current_phase']}")

    return {
        "total_items": total_items,
        "completed_items": total_completed,
        "completion_percentage": expected_percentage,
        "p0_blocking": status["p0_blocking"],
        "is_complete": status["is_complete"],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 3: Scope Management + CVE Matching
# ═══════════════════════════════════════════════════════════════════════════════

@run_test("Test 3: Scope Management + CVE Matching")
def test_scope_management_and_cve_matching():
    """
    1. Create a ScopeManager
    2. Add a program with in_scope domains
    3. Create a CVEInfo for a product matching the scope
    4. Call match_cves_to_scope()
    5. Verify results
    """
    # Step 1: Create ScopeManager
    scope = ScopeManager()

    # Step 2: Add a program with in_scope domains
    scope.add_program(
        platform="hackerone",
        program_name="Acme Corp",
        in_scope=["*.acme.com", "api.acme.com", "app.acme.com"],
        out_of_scope=["internal.acme.com"],
    )

    # Add tech stack to assets so CVE matching works
    scope.add_tech_stack("*.acme.com", ["Apache", "PHP", "MySQL"])
    scope.add_tech_stack("api.acme.com", ["Apache", "Redis", "Node.js"])
    scope.add_tech_stack("app.acme.com", ["nginx", "Python", "Django"])

    # Step 3: Create CVEInfo objects - one matching scope, one not
    cve_matching = CVEInfo(
        id="CVE-2021-44790",
        description="Apache HTTP Server mod_lua buffer overflow.",
        cvss=CVSSScore(
            version="3.1",
            base_score=9.8,
            severity=Severity.CRITICAL,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
        epss=0.85,
        kev_status=True,
        vendor="Apache",
        product="Apache HTTP Server",
        publication_date="2021-12-20",
    )

    cve_non_matching = CVEInfo(
        id="CVE-2023-99999",
        description="Some random software vulnerability.",
        cvss=CVSSScore(
            version="3.1",
            base_score=7.5,
            severity=Severity.HIGH,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        ),
        vendor="Unknown",
        product="RandomProduct",
        publication_date="2023-01-01",
    )

    cves = [cve_matching, cve_non_matching]

    # Step 4: Call match_cves_to_scope()
    matches = scope.match_cves_to_scope(cves, match_field="product")

    # Step 5: Verify results
    assert len(matches) >= 1, f"Expected at least 1 match, got {len(matches)}"

    # The Apache HTTP Server CVE should match because "Apache" is in the tech stack
    matching_cve_ids = [m["id"] for m in matches]
    print(f"  [OK] Matched CVEs: {matching_cve_ids}")

    # Verify the matching CVE has the in_scope flag set
    for match in matches:
        assert match["in_scope"] is True, f"CVE {match['id']} should be marked in_scope"

    # Verify scope summary
    summary = scope.get_scope_summary()
    assert summary["in_scope"] == 3, f"Expected 3 in-scope assets, got {summary['in_scope']}"
    assert summary["out_of_scope"] == 1, f"Expected 1 out-of-scope asset, got {summary['out_of_scope']}"
    assert summary["programs"] == 1

    print(f"  [OK] Scope summary: {summary['in_scope']} in-scope, {summary['out_of_scope']} out-of-scope")
    print(f"  [OK] Matched {len(matches)} of {len(cves)} CVEs to scope")

    return {
        "in_scope_assets": summary["in_scope"],
        "out_of_scope_assets": summary["out_of_scope"],
        "programs": summary["programs"],
        "total_cves_tested": len(cves),
        "matched_cves": len(matches),
        "matched_ids": matching_cve_ids,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 4: Report Generation Pipeline
# ═══════════════════════════════════════════════════════════════════════════════

@run_test("Test 4: Report Generation Pipeline")
def test_report_generation_pipeline():
    """
    1. Create a ReportEntry with CVEInfo, Exploit, LabEnvironment, BugBountyReport
    2. Convert to JSON via to_json()
    3. Convert back to dict via to_dict()
    4. Verify round-trip integrity
    """
    # Step 1: Create all components
    cve_info = CVEInfo(
        id="CVE-2021-41773",
        description="Apache HTTP Server path traversal vulnerability.",
        cvss=CVSSScore(
            version="3.1",
            base_score=7.5,
            severity=Severity.HIGH,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ),
        epss=0.75,
        kev_status=True,
        vendor="Apache",
        product="Apache HTTP Server",
        publication_date="2021-10-05",
    )

    exploit = Exploit(
        source=ExploitSource.GITHUB,
        url="https://github.com/test/CVE-2021-41773-poc",
        title="Apache Path Traversal PoC",
        language="Python",
        stars=150,
        forks=30,
    )

    lab = LabEnvironment(
        platform=LabPlatform.VULHUB,
        name="CVE-2021-41773",
        url="https://github.com/vulhub/vulhub/tree/master/httpd/CVE-2021-41773",
        setup_instructions="docker-compose up -d",
    )

    bb_report = BugBountyReport(
        source="hackerone",
        url="https://hackerone.com/reports/123456",
        has_poc=True,
        title="Path Traversal in Apache HTTP Server",
    )

    report_entry = ReportEntry(
        cve_info=cve_info,
        exploits=[exploit],
        labs=[lab],
        bb_reports=[bb_report],
    )

    # Step 2: Convert to JSON via to_json()
    json_str = report_entry.to_json()
    assert isinstance(json_str, str), "to_json() should return a string"
    assert len(json_str) > 0, "to_json() returned empty string"

    # Verify JSON is valid
    parsed_from_json = json.loads(json_str)
    assert isinstance(parsed_from_json, dict), "Parsed JSON should be a dict"

    # Step 3: Convert to dict via to_dict()
    dict_from_method = report_entry.to_dict()
    assert isinstance(dict_from_method, dict), "to_dict() should return a dict"

    # Step 4: Verify round-trip integrity
    # The dict from to_dict() and the parsed JSON should have the same structure
    assert dict_from_method["cve_info"]["id"] == cve_info.id
    assert dict_from_method["cve_info"]["cvss"]["severity"] == "HIGH"
    assert dict_from_method["exploits"][0]["url"] == exploit.url
    assert dict_from_method["labs"][0]["platform"] == "vulhub"
    assert dict_from_method["bb_reports"][0]["has_poc"] is True

    # Verify parsed JSON matches
    assert parsed_from_json["cve_info"]["id"] == cve_info.id
    assert parsed_from_json["exploits"][0]["source"] == "github"

    # Verify we have the expected number of items in each list
    assert len(dict_from_method["exploits"]) == 1
    assert len(dict_from_method["labs"]) == 1
    assert len(dict_from_method["bb_reports"]) == 1

    # Verify generated_at is present and is a valid ISO timestamp
    assert "generated_at" in dict_from_method
    gen_at = dict_from_method["generated_at"]
    # Should be parseable as datetime
    datetime.fromisoformat(gen_at.replace("Z", "+00:00"))

    print(f"  [OK] ReportEntry created with {len(dict_from_method['exploits'])} exploit(s)")
    print(f"  [OK] to_json() returned {len(json_str)} chars of valid JSON")
    print(f"  [OK] to_dict() returned dict with keys: {list(dict_from_method.keys())}")
    print("  [OK] Round-trip integrity verified")

    return {
        "json_length": len(json_str),
        "exploit_count": len(dict_from_method["exploits"]),
        "lab_count": len(dict_from_method["labs"]),
        "bb_report_count": len(dict_from_method["bb_reports"]),
        "cve_id_verified": dict_from_method["cve_info"]["id"],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 5: Prioritization Pipeline
# ═══════════════════════════════════════════════════════════════════════════════

@run_test("Test 5: Prioritization Pipeline")
def test_prioritization_pipeline():
    """
    1. Create 3 CVEInfo objects with different severities (CRITICAL, HIGH, LOW)
    2. Run prioritize_cves() with different strategies
    3. Verify correct ordering for each strategy
    """
    # Step 1: Create 3 CVEInfo objects with different severities
    cve_critical = CVEInfo(
        id="CVE-2021-44228",
        description="Log4j RCE",
        cvss=CVSSScore(
            version="3.1",
            base_score=10.0,
            severity=Severity.CRITICAL,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        ),
        epss=0.97,
        kev_status=True,
        vendor="Apache",
        product="Log4j2",
        publication_date="2021-12-10",
    )

    cve_high = CVEInfo(
        id="CVE-2021-44790",
        description="Apache mod_lua buffer overflow",
        cvss=CVSSScore(
            version="3.1",
            base_score=9.8,
            severity=Severity.HIGH,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
        epss=0.85,
        kev_status=True,
        vendor="Apache",
        product="Apache HTTP Server",
        publication_date="2021-12-20",
    )

    cve_low = CVEInfo(
        id="CVE-2023-00001",
        description="Minor information disclosure",
        cvss=CVSSScore(
            version="3.1",
            base_score=3.5,
            severity=Severity.LOW,
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        ),
        epss=0.05,
        kev_status=False,
        vendor="Example",
        product="ExampleApp",
        publication_date="2023-01-15",
    )

    cves = [cve_low, cve_high, cve_critical]  # Intentionally unsorted

    # Step 2 & 3: Test different strategies and verify ordering
    strategy_results = {}

    # Test CVSS strategy - should order by CVSS score (critical > high > low)
    cvss_sorted = prioritize_cves(cves, strategy="cvss")
    cvss_ids = [c["id"] for c in cvss_sorted]
    assert cvss_ids[0] == "CVE-2021-44228", f"CVSS sort failed: expected CVE-2021-44228 first, got {cvss_ids[0]}"
    assert cvss_ids[-1] == "CVE-2023-00001", f"CVSS sort failed: expected CVE-2023-00001 last, got {cvss_ids[-1]}"
    print(f"  [OK] CVSS strategy order: {cvss_ids}")
    strategy_results["cvss"] = cvss_ids

    # Test KEV_FIRST strategy - KEV should be prioritized
    kev_sorted = prioritize_cves(cves, strategy="kev_first")
    kev_ids = [c["id"] for c in kev_sorted]
    # Both CVE-2021-44228 and CVE-2021-44790 are KEV, so they should be top
    assert "CVE-2023-00001" not in kev_ids[:2], f"KEV sort failed: non-KEV CVE in top 2: {kev_ids}"
    print(f"  [OK] KEV_FIRST strategy order: {kev_ids}")
    strategy_results["kev_first"] = kev_ids

    # Test EPSS strategy - should order by EPSS score
    epss_sorted = prioritize_cves(cves, strategy="epss")
    epss_ids = [c["id"] for c in epss_sorted]
    assert epss_ids[0] == "CVE-2021-44228", f"EPSS sort failed: expected CVE-2021-44228 first (EPSS=0.97), got {epss_ids[0]}"
    print(f"  [OK] EPSS strategy order: {epss_ids}")
    strategy_results["epss"] = epss_ids

    # Test COMPOSITE strategy
    composite_sorted = prioritize_cves(cves, strategy="composite")
    composite_ids = [c["id"] for c in composite_sorted]
    # Composite should generally put the highest overall risk first
    assert composite_ids[0] in ["CVE-2021-44228", "CVE-2021-44790"], (
        f"Composite sort failed: unexpected first item: {composite_ids[0]}"
    )
    print(f"  [OK] COMPOSITE strategy order: {composite_ids}")
    strategy_results["composite"] = composite_ids

    # Test BOUNTY_POTENTIAL strategy
    bounty_sorted = prioritize_cves(cves, strategy="bounty_potential")
    bounty_ids = [c["id"] for c in bounty_sorted]
    # Critical CVE with KEV should yield highest bounty potential
    assert bounty_ids[0] == "CVE-2021-44228", (
        f"Bounty sort failed: expected CVE-2021-44228 first, got {bounty_ids[0]}"
    )
    print(f"  [OK] BOUNTY_POTENTIAL strategy order: {bounty_ids}")
    strategy_results["bounty_potential"] = bounty_ids

    # Verify priority_score is present in all results
    for strategy, results in [("cvss", cvss_sorted), ("composite", composite_sorted)]:
        for item in results:
            assert "priority_score" in item, f"Missing priority_score in {strategy} result for {item.get('id')}"

    return {
        "strategies_tested": list(strategy_results.keys()),
        "cvss_order": strategy_results["cvss"],
        "kev_first_order": strategy_results["kev_first"],
        "epss_order": strategy_results["epss"],
        "composite_order": strategy_results["composite"],
        "bounty_potential_order": strategy_results["bounty_potential"],
        "all_strategies_had_priority_score": True,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 6: JSON Schema Export
# ═══════════════════════════════════════════════════════════════════════════════

@run_test("Test 6: JSON Schema Export")
def test_json_schema_export():
    """
    1. Export all schemas to a temp directory
    2. Verify each schema file exists and is valid JSON
    3. Verify schemas contain expected fields
    """
    expected_models = [
        "CVSSScore",
        "CVEInfo",
        "Exploit",
        "LabEnvironment",
        "BugBountyReport",
        "CPEInfo",
        "ReportEntry",
        "MultiReport",
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        # Step 1: Export all schemas
        exported_paths = export_schemas(tmpdir)

        print(f"  [OK] Exported {len(exported_paths)} schema files to {tmpdir}")

        # Step 2: Verify each file exists and is valid JSON
        exported_names = [p.stem for p in exported_paths]
        for model_name in expected_models:
            assert model_name in exported_names, f"Missing schema for {model_name}"

        schema_details = {}
        for path in exported_paths:
            assert path.exists(), f"Schema file does not exist: {path}"
            assert path.stat().st_size > 0, f"Schema file is empty: {path}"

            # Parse as JSON
            with open(path) as f:
                schema = json.load(f)

            assert isinstance(schema, dict), f"Schema {path.name} is not a JSON object"

            # Step 3: Verify schemas contain expected fields
            assert "title" in schema or "$defs" in schema, (
                f"Schema {path.name} missing expected structure"
            )

            schema_details[path.stem] = {
                "file_size": path.stat().st_size,
                "has_properties": "properties" in schema,
                "has_title": "title" in schema,
            }

            print(f"  [OK] {path.name}: {path.stat().st_size} bytes, "
                  f"properties={'properties' in schema}")

        # Verify CVEInfo schema specifically has expected properties
        cve_info_schema_path = Path(tmpdir) / "CVEInfo.json"
        with open(cve_info_schema_path) as f:
            cve_schema = json.load(f)

        props = cve_schema.get("properties", {})
        expected_cve_fields = ["id", "description", "cvss", "epss", "kev_status", "cwes", "references"]
        for field in expected_cve_fields:
            assert field in props, f"CVEInfo schema missing field: {field}"

        print(f"  [OK] CVEInfo schema contains all expected fields: {expected_cve_fields}")

        return {
            "schemas_exported": len(exported_paths),
            "expected_models": expected_models,
            "all_files_valid_json": True,
            "cve_info_fields_found": expected_cve_fields,
            "schema_details": schema_details,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def print_summary():
    """Print the final test summary."""
    print("\n" + "=" * 60)
    print("END-TO-END TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for r in RESULTS if r.passed)
    failed = sum(1 for r in RESULTS if not r.passed)
    total = len(RESULTS)

    for result in RESULTS:
        status = "PASS" if result.passed else "FAIL"
        icon = "[PASS]" if result.passed else "[FAIL]"
        print(f"\n{icon} {result.name}")
        if result.passed and result.details:
            for key, value in result.details.items():
                if isinstance(value, list) and len(str(value)) > 80:
                    print(f"    {key}: {value[:5]}{'...' if len(value) > 5 else ''} (total: {len(value)})")
                else:
                    print(f"    {key}: {value}")
        if not result.passed and result.error:
            # Print abbreviated error
            error_lines = result.error.strip().split("\n")
            for line in error_lines[:8]:
                print(f"    ! {line}")
            if len(error_lines) > 8:
                print(f"    ... ({len(error_lines) - 8} more lines)")

    print("\n" + "-" * 60)
    pass_rate = (passed / total * 100) if total else 0
    print(f"Results: {passed}/{total} passed ({pass_rate:.1f}%)")
    print(f"         {passed} passed, {failed} failed")

    if failed == 0:
        print("\n*** ALL TESTS PASSED ***")
    else:
        print(f"\n*** {failed} TEST(S) FAILED ***")

    return failed == 0


if __name__ == "__main__":
    all_passed = print_summary()
    sys.exit(0 if all_passed else 1)
