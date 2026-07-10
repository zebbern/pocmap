"""
Bug Bounty Methodology Workflows

Provides structured, repeatable workflows for common bug bounty scenarios.
Each workflow includes phases, entry/exit criteria, required tools, expected
outputs, and time estimates.

Integration:
    - Uses pocmap.services.cve_service for CVE lookups
    - Uses pocmap.services.exploit_service for PoC retrieval
    - Integrates with checklists module for phase tracking

Example:
    workflow = CVEToBountyWorkflow()
    result = workflow.execute_phase("recon", context={"target": "example.com"})
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pocmap.bugbounty.checklists import (
    BaseChecklist,
    CVEResearchChecklist,
    ExploitationChecklist,
    ReconnaissanceChecklist,
    ReportingChecklist,
)


class Difficulty(Enum):
    """Difficulty rating for workflow steps."""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"

    @property
    def weight(self) -> int:
        weights = {"beginner": 1, "intermediate": 2, "advanced": 3, "expert": 4}
        return weights[self.value]


class PhaseStatus(Enum):
    """Status of a workflow phase."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


@dataclass
class WorkflowPhase:
    """
    A single phase within a workflow.

    Attributes:
        name: Phase identifier
        description: What this phase accomplishes
        checklist: Associated checklist for this phase
        entry_criteria: Conditions that must be met to start
        exit_criteria: Conditions that must be met to complete
        required_tools: Tools needed for this phase
        expected_outputs: What this phase should produce
        time_estimate_hours: Estimated time to complete
        difficulty: Difficulty rating
        status: Current execution status
        depends_on: Phases that must complete before this one
    """
    name: str
    description: str
    checklist: BaseChecklist | None = None
    entry_criteria: list[str] = field(default_factory=list)
    exit_criteria: list[str] = field(default_factory=list)
    required_tools: list[str] = field(default_factory=list)
    expected_outputs: list[str] = field(default_factory=list)
    time_estimate_hours: float = 1.0
    difficulty: Difficulty = Difficulty.INTERMEDIATE
    status: PhaseStatus = PhaseStatus.NOT_STARTED
    depends_on: list[str] = field(default_factory=list)
    notes: str = ""
    started_at: str | None = None
    completed_at: str | None = None

    def start(self) -> None:
        """Mark phase as started."""
        self.status = PhaseStatus.IN_PROGRESS
        self.started_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"

    def complete(self) -> None:
        """Mark phase as completed."""
        self.status = PhaseStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"

    def block(self, reason: str = "") -> None:
        """Mark phase as blocked."""
        self.status = PhaseStatus.BLOCKED
        if reason:
            self.notes = reason

    def skip(self, reason: str = "") -> None:
        """Skip this phase."""
        self.status = PhaseStatus.SKIPPED
        if reason:
            self.notes = reason

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "entry_criteria": self.entry_criteria,
            "exit_criteria": self.exit_criteria,
            "required_tools": self.required_tools,
            "expected_outputs": self.expected_outputs,
            "time_estimate_hours": self.time_estimate_hours,
            "difficulty": self.difficulty.value,
            "status": self.status.value,
            "depends_on": self.depends_on,
            "notes": self.notes,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass
class WorkflowResult:
    """
    Result of executing a workflow or phase.

    Attributes:
        success: Whether execution was successful
        phase: Phase name
        outputs: Produced artifacts and findings
        errors: Any errors encountered
        duration_seconds: Time taken
        next_recommended_action: Suggested next step
    """
    success: bool
    phase: str
    outputs: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    next_recommended_action: str = ""


class BaseWorkflow:
    """Base class for all bug bounty workflows."""

    def __init__(
        self,
        name: str,
        description: str,
        phases: list[WorkflowPhase],
    ):
        self.name = name
        self.description = description
        self.phases = phases
        self.created_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
        self.metadata: dict[str, Any] = {}

    def get_phase(self, name: str) -> WorkflowPhase | None:
        """Get a phase by name."""
        for phase in self.phases:
            if phase.name == name:
                return phase
        return None

    def get_ready_phases(self) -> list[WorkflowPhase]:
        """Get phases that are ready to start (dependencies met)."""
        ready = []
        completed_names = {
            p.name for p in self.phases
            if p.status in (PhaseStatus.COMPLETED, PhaseStatus.SKIPPED)
        }
        for phase in self.phases:
            if phase.status == PhaseStatus.NOT_STARTED:
                deps_met = all(dep in completed_names for dep in phase.depends_on)
                if deps_met:
                    ready.append(phase)
        return ready

    def get_current_phase(self) -> WorkflowPhase | None:
        """Get the currently active phase."""
        for phase in self.phases:
            if phase.status == PhaseStatus.IN_PROGRESS:
                return phase
        ready = self.get_ready_phases()
        return ready[0] if ready else None

    def overall_progress(self) -> dict[str, Any]:
        """Get overall workflow progress."""
        total = len(self.phases)
        completed = sum(1 for p in self.phases if p.status == PhaseStatus.COMPLETED)
        in_progress = sum(1 for p in self.phases if p.status == PhaseStatus.IN_PROGRESS)
        not_started = sum(1 for p in self.phases if p.status == PhaseStatus.NOT_STARTED)
        blocked = sum(1 for p in self.phases if p.status == PhaseStatus.BLOCKED)
        total_time = sum(p.time_estimate_hours for p in self.phases)

        current_phase = self.get_current_phase()
        return {
            "workflow": self.name,
            "total_phases": total,
            "completed": completed,
            "in_progress": in_progress,
            "not_started": not_started,
            "blocked": blocked,
            "completion_percentage": (completed / total * 100) if total else 0,
            "total_estimated_hours": total_time,
            "current_phase": current_phase.name if current_phase else "none",
            "is_complete": completed == total and total > 0,
        }

    def execute_phase(
        self,
        phase_name: str,
        context: dict[str, Any],
        executor: Callable[..., Any] | None = None,
    ) -> WorkflowResult:
        """
        Execute a specific phase of the workflow.

        Args:
            phase_name: Name of phase to execute
            context: Execution context with variables
            executor: Optional custom executor function

        Returns:
            WorkflowResult with execution details
        """
        phase = self.get_phase(phase_name)
        if not phase:
            return WorkflowResult(
                success=False,
                phase=phase_name,
                errors=[f"Phase '{phase_name}' not found in workflow"],
            )

        # Check dependencies
        completed_names = {
            p.name for p in self.phases
            if p.status in (PhaseStatus.COMPLETED, PhaseStatus.SKIPPED)
        }
        missing_deps = [d for d in phase.depends_on if d not in completed_names]
        if missing_deps:
            return WorkflowResult(
                success=False,
                phase=phase_name,
                errors=[f"Dependencies not met: {missing_deps}"],
            )

        phase.start()
        start_time = datetime.now(timezone.utc)

        try:
            result = executor(phase, context) if executor else self._default_execute(phase, context)

            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            phase.complete()

            return WorkflowResult(
                success=True,
                phase=phase_name,
                outputs=result,
                duration_seconds=duration,
                next_recommended_action=self._get_next_action(),
            )
        except Exception as e:
            phase.block(str(e))
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            return WorkflowResult(
                success=False,
                phase=phase_name,
                errors=[str(e)],
                duration_seconds=duration,
            )

    def _default_execute(self, phase: WorkflowPhase, context: dict[str, Any]) -> dict[str, Any]:
        """Default execution - returns phase checklist as output."""
        if phase.checklist:
            return {"checklist": phase.checklist.to_dict()}
        return {"message": f"Phase '{phase.name}' executed manually"}

    def _get_next_action(self) -> str:
        """Get recommended next action."""
        current = self.get_current_phase()
        if current:
            return f"Execute phase: {current.name} - {current.description}"
        return "Workflow complete"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "phases": [p.to_dict() for p in self.phases],
            "progress": self.overall_progress(),
            "created_at": self.created_at,
        }

    def export_json(self, filepath: str) -> None:
        with open(filepath, "w") as f:
            json.dump(self.to_dict(), f, indent=2)


class CVEToBountyWorkflow(BaseWorkflow):
    """
    Workflow: From CVE discovery to bug bounty report submission.

    Guides a researcher from identifying a relevant CVE through
    exploitation to submitting a professional bug bounty report.

    Total time estimate: 4-16 hours
    Difficulty: Beginner to Intermediate
    Expected bounty range: $500 - $10,000+

    Entry criteria:
        - Bug bounty program selected and rules reviewed
        - In-scope targets identified with technology stack
        - PocMap access configured

    Exit criteria:
        - Validated vulnerability with PoC
        - Report submitted to platform
        - All evidence documented
    """

    def __init__(self) -> None:
        phases = [
            WorkflowPhase(
                name="scope_review",
                description="Review bug bounty program scope, rules, and legal terms",
                checklist=None,
                entry_criteria=[
                    "Bug bounty program identified",
                    "Program rules page accessible",
                ],
                exit_criteria=[
                    "Scope documented (in-scope and out-of-scope)",
                    "Testing authorization confirmed",
                    "Safe harbor policy reviewed",
                    "Responsible disclosure timeline noted",
                ],
                required_tools=["browser", "note-taking app"],
                expected_outputs=["scope_document.md", "target_inventory.json"],
                time_estimate_hours=0.5,
                difficulty=Difficulty.BEGINNER,
            ),
            WorkflowPhase(
                name="recon",
                description="Map attack surface and identify technology stack",
                checklist=ReconnaissanceChecklist(),
                entry_criteria=[
                    "Scope review complete",
                    "Target domains/IPs identified",
                ],
                exit_criteria=[
                    "All subdomains enumerated and verified",
                    "Technology stack documented per host",
                    "Interesting endpoints identified",
                ],
                required_tools=[
                    "subfinder", "httpx", "nmap", "wappalyzer",
                    "screenshot tool",
                ],
                expected_outputs=[
                    "subdomains.txt",
                    "tech_stack.json",
                    "live_hosts.txt",
                    "screenshots/",
                ],
                time_estimate_hours=2.0,
                difficulty=Difficulty.INTERMEDIATE,
            ),
            WorkflowPhase(
                name="cve_lookup",
                description="Find CVEs affecting identified technology stack",
                checklist=None,
                entry_criteria=[
                    "Technology stack documented",
                    "Software names and versions identified",
                ],
                exit_criteria=[
                    "Relevant CVEs identified for each technology",
                    "CVE details fetched via PocMap",
                    "CVEs prioritized by exploitability",
                ],
                required_tools=["pocmap", "nvd-api", "vuldb"],
                expected_outputs=[
                    "cve_candidates.json",
                    "cve_details/",
                ],
                time_estimate_hours=1.0,
                difficulty=Difficulty.INTERMEDIATE,
                depends_on=["recon"],
            ),
            WorkflowPhase(
                name="cve_research",
                description="Deep-dive analysis of prioritized CVEs",
                checklist=CVEResearchChecklist(),
                entry_criteria=[
                    "CVE candidates identified",
                    "Target versions confirmed",
                ],
                exit_criteria=[
                    "EPSS and KEV scores checked",
                    "Exploit availability confirmed",
                    "Patch gap identified",
                    "Target confirmed vulnerable",
                ],
                required_tools=[
                    "pocmap", "epss-api", "cisa-kev",
                    "exploitdb", "github",
                ],
                expected_outputs=[
                    "cve_analysis.json",
                    "exploit_notes.md",
                    "poc_code/",
                ],
                time_estimate_hours=2.0,
                difficulty=Difficulty.INTERMEDIATE,
                depends_on=["cve_lookup"],
            ),
            WorkflowPhase(
                name="exploitation",
                description="Validate vulnerability and develop safe PoC",
                checklist=ExploitationChecklist(),
                entry_criteria=[
                    "CVE research complete",
                    "Exploit available",
                    "Lab environment ready",
                ],
                exit_criteria=[
                    "Vulnerability confirmed in lab",
                    "Safe PoC developed",
                    "Impact assessed and documented",
                    "Target tested (if authorized)",
                ],
                required_tools=[
                    "docker", "burp-suite", "pocmap exploit",
                    "proxy tool",
                ],
                expected_outputs=[
                    "poc_evidence/",
                    "impact_assessment.md",
                    "exploitation_timeline.md",
                ],
                time_estimate_hours=3.0,
                difficulty=Difficulty.ADVANCED,
                depends_on=["cve_research"],
            ),
            WorkflowPhase(
                name="reporting",
                description="Compile and submit bug bounty report",
                checklist=ReportingChecklist(),
                entry_criteria=[
                    "Exploitation complete",
                    "Evidence collected",
                    "Impact documented",
                ],
                exit_criteria=[
                    "Report drafted and proofread",
                    "CVSS scored with justification",
                    "Remediation suggestions included",
                    "Report submitted to platform",
                ],
                required_tools=[
                    "pocmap templates", "cvss-calculator",
                    "markdown editor",
                ],
                expected_outputs=[
                    "bounty_report.md",
                    "evidence_package.zip",
                    "submission_id.txt",
                ],
                time_estimate_hours=2.0,
                difficulty=Difficulty.BEGINNER,
                depends_on=["exploitation"],
            ),
        ]
        super().__init__(
            name="CVE to Bounty Workflow",
            description="Complete workflow from CVE discovery to bug bounty submission",
            phases=phases,
        )


class ZeroDayHuntingWorkflow(BaseWorkflow):
    """
    Workflow: Proactive zero-day vulnerability discovery.

    Guides researchers through finding previously unknown vulnerabilities
    using CVE patterns and variant analysis.

    Total time estimate: 16-40 hours
    Difficulty: Advanced to Expert
    Expected bounty range: $2,000 - $50,000+

    Entry criteria:
        - Strong understanding of vulnerability classes
        - Experience with reverse engineering or source review
        - Target application identified and accessible

    Exit criteria:
        - New vulnerability discovered and validated
        - Vendor notified (if applicable)
        - Report submitted
    """

    def __init__(self) -> None:
        phases = [
            WorkflowPhase(
                name="target_selection",
                description="Select target application and understand its architecture",
                checklist=None,
                entry_criteria=[
                    "Bug bounty program with broad scope selected",
                    "Target application identified",
                ],
                exit_criteria=[
                    "Application architecture mapped",
                    "Technology stack fully understood",
                    "Attack surface identified",
                    "Previous CVEs for same product researched",
                ],
                required_tools=["browser", "wappalyzer", "source access (if OSS)"],
                expected_outputs=["architecture_map.md", "tech_stack_deep_dive.md"],
                time_estimate_hours=3.0,
                difficulty=Difficulty.INTERMEDIATE,
            ),
            WorkflowPhase(
                name="pattern_research",
                description="Research vulnerability patterns in similar products",
                checklist=CVEResearchChecklist(),
                entry_criteria=[
                    "Target architecture understood",
                    "Product category identified",
                ],
                exit_criteria=[
                    "Historical CVEs for similar products analyzed",
                    "Common vulnerability patterns documented",
                    "Potential vulnerable code paths identified",
                    "Root cause patterns cataloged",
                ],
                required_tools=[
                    "pocmap", "github", "exploitdb",
                    " academic papers",
                ],
                expected_outputs=[
                    "pattern_analysis.json",
                    "vuln_patterns.md",
                    "suspicious_code_locations.md",
                ],
                time_estimate_hours=4.0,
                difficulty=Difficulty.ADVANCED,
                depends_on=["target_selection"],
            ),
            WorkflowPhase(
                name="variant_analysis",
                description="Find variants of known CVEs in target code",
                checklist=None,
                entry_criteria=[
                    "Vulnerability patterns documented",
                    "Source code or binary accessible",
                ],
                exit_criteria=[
                    "Known vulnerability patterns searched in target",
                    "Similar code paths identified",
                    "Potential variants flagged",
                ],
                required_tools=[
                    "grep", "semgrep", "codeql", "ghidra", "ida",
                ],
                expected_outputs=[
                    "variant_candidates.json",
                    "code_matches/",
                ],
                time_estimate_hours=6.0,
                difficulty=Difficulty.EXPERT,
                depends_on=["pattern_research"],
            ),
            WorkflowPhase(
                name="fuzzing_testing",
                description="Fuzz and dynamically test suspicious areas",
                checklist=ExploitationChecklist(),
                entry_criteria=[
                    "Variant candidates identified",
                    "Testing environment ready",
                ],
                exit_criteria=[
                    "Fuzzing campaigns executed",
                    "Crashes/anomalies documented",
                    "Triage completed",
                    "Exploitability determined",
                ],
                required_tools=[
                    "afl++", "libfuzzer", "burp-suite",
                    "custom fuzzers", "valgrind", "asan",
                ],
                expected_outputs=[
                    "fuzzing_results/",
                    "crash_reports/",
                    "exploitability_assessment.md",
                ],
                time_estimate_hours=8.0,
                difficulty=Difficulty.EXPERT,
                depends_on=["variant_analysis"],
            ),
            WorkflowPhase(
                name="exploit_development",
                description="Develop reliable exploit for discovered vulnerability",
                checklist=None,
                entry_criteria=[
                    "Crash confirmed exploitable",
                    "Root cause understood",
                ],
                exit_criteria=[
                    "Reliable exploit developed",
                    "Multiple target versions tested",
                    "Impact fully demonstrated",
                    "Bypass techniques documented",
                ],
                required_tools=[
                    "python", "pwntools", "gdb", "pwndbg",
                    "burp-suite",
                ],
                expected_outputs=[
                    "exploit.py",
                    "exploit_video.mp4",
                    "impact_demonstration.md",
                ],
                time_estimate_hours=10.0,
                difficulty=Difficulty.EXPERT,
                depends_on=["fuzzing_testing"],
            ),
            WorkflowPhase(
                name="coordinated_disclosure",
                description="Notify vendor and coordinate disclosure timeline",
                checklist=ReportingChecklist(),
                entry_criteria=[
                    "Exploit reliable and documented",
                    "Impact clearly demonstrated",
                ],
                exit_criteria=[
                    "Vendor notified securely",
                    "Disclosure timeline agreed",
                    "Patch verified",
                    "Public disclosure published (if applicable)",
                ],
                required_tools=["email pgp", "vendor security portal"],
                expected_outputs=[
                    "vendor_notification.md",
                    "cve_request.json",
                    "disclosure_blog_post.md",
                ],
                time_estimate_hours=4.0,
                difficulty=Difficulty.INTERMEDIATE,
                depends_on=["exploit_development"],
            ),
            WorkflowPhase(
                name="bounty_submission",
                description="Submit to bug bounty program if applicable",
                checklist=ReportingChecklist(),
                entry_criteria=[
                    "Vulnerability confirmed",
                    "Vendor notified (if required)",
                ],
                exit_criteria=[
                    "Bug bounty report submitted",
                    "All evidence attached",
                    "Bounty awarded",
                ],
                required_tools=["hackerone/bugcrowd/intigriti portal"],
                expected_outputs=[
                    "bounty_report.md",
                    "submission_confirmation.txt",
                ],
                time_estimate_hours=2.0,
                difficulty=Difficulty.BEGINNER,
                depends_on=["coordinated_disclosure"],
            ),
        ]
        super().__init__(
            name="Zero-Day Hunting Workflow",
            description="Proactive vulnerability discovery through pattern analysis and variant hunting",
            phases=phases,
        )


class PatchGapAnalysisWorkflow(BaseWorkflow):
    """
    Workflow: Find unpatched systems for known CVEs.

    Systematically identifies organizations running vulnerable software
    versions and validates exploitability for bug bounty submission.

    Total time estimate: 2-8 hours per target
    Difficulty: Intermediate
    Expected bounty range: $300 - $5,000

    Entry criteria:
        - Known CVE with public exploit selected
        - List of potential targets identified
        - PocMap configured

    Exit criteria:
        - Confirmed unpatched systems identified
        - Vulnerability validated
        - Report submitted
    """

    def __init__(self) -> None:
        phases = [
            WorkflowPhase(
                name="cve_selection",
                description="Select high-impact CVE with reliable exploit",
                checklist=CVEResearchChecklist(),
                entry_criteria=[
                    "CVE database access available",
                    "Bug bounty programs identified",
                ],
                exit_criteria=[
                    "CVE selected with CVSS >= 7.0",
                    "Public exploit verified working",
                    "EPSS score checked",
                    "Affected products/versions documented",
                ],
                required_tools=[
                    "pocmap", "epss-api", "exploitdb", "github",
                ],
                expected_outputs=[
                    "selected_cve.json",
                    "exploit_verification_report.md",
                ],
                time_estimate_hours=1.0,
                difficulty=Difficulty.INTERMEDIATE,
            ),
            WorkflowPhase(
                name="target_discovery",
                description="Find bug bounty targets running vulnerable software",
                checklist=ReconnaissanceChecklist(),
                entry_criteria=[
                    "CVE selected",
                    "Vulnerable product/version known",
                ],
                exit_criteria=[
                    "Bug bounty programs with vulnerable tech identified",
                    "Target hosts enumerated",
                    "Version fingerprinting attempted",
                    "Vulnerable targets confirmed",
                ],
                required_tools=[
                    "shodan", "censys", "httpx", "wappalyzer",
                    "bugcrowd/hackerone directory",
                ],
                expected_outputs=[
                    "targets.json",
                    "version_fingerprints.json",
                ],
                time_estimate_hours=2.0,
                difficulty=Difficulty.INTERMEDIATE,
                depends_on=["cve_selection"],
            ),
            WorkflowPhase(
                name="version_validation",
                description="Confirm targets run vulnerable versions",
                checklist=None,
                entry_criteria=[
                    "Potential targets identified",
                    "Version fingerprinting data collected",
                ],
                exit_criteria=[
                    "Version confirmed vulnerable on each target",
                    "False positives eliminated",
                    "Target priority list created",
                ],
                required_tools=[
                    "httpx", "curl", "banner-grabbing scripts",
                    "nmap -sV",
                ],
                expected_outputs=[
                    "validated_targets.json",
                    "version_evidence/",
                ],
                time_estimate_hours=1.5,
                difficulty=Difficulty.INTERMEDIATE,
                depends_on=["target_discovery"],
            ),
            WorkflowPhase(
                name="exploit_validation",
                description="Validate CVE is exploitable on target",
                checklist=ExploitationChecklist(),
                entry_criteria=[
                    "Vulnerable targets confirmed",
                    "Safe exploit available",
                ],
                exit_criteria=[
                    "Vulnerability confirmed exploitable",
                    "Impact demonstrated with safe payload",
                    "Evidence collected",
                ],
                required_tools=[
                    "pocmap exploit", "burp-suite", "proxy",
                ],
                expected_outputs=[
                    "exploitation_evidence/",
                    "impact_assessment.md",
                ],
                time_estimate_hours=2.0,
                difficulty=Difficulty.ADVANCED,
                depends_on=["version_validation"],
            ),
            WorkflowPhase(
                name="reporting",
                description="Submit patch gap finding to bug bounty program",
                checklist=ReportingChecklist(),
                entry_criteria=[
                    "Vulnerability validated",
                    "Evidence collected",
                    "Bug bounty scope confirmed",
                ],
                exit_criteria=[
                    "Report submitted to platform",
                    "All evidence attached",
                    "Remediation suggestions provided",
                ],
                required_tools=[
                    "pocmap templates", "platform portal",
                ],
                expected_outputs=[
                    "patchgap_report.md",
                    "submission_confirmation.txt",
                ],
                time_estimate_hours=1.5,
                difficulty=Difficulty.BEGINNER,
                depends_on=["exploit_validation"],
            ),
        ]
        super().__init__(
            name="Patch Gap Analysis Workflow",
            description="Find and exploit unpatched systems for known CVEs",
            phases=phases,
        )
