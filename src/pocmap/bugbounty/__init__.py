"""
PocMap - Bug Bounty Hunter Toolkit

A comprehensive toolkit for bug bounty hunters and security professionals
that integrates with the PocMap package. Provides structured checklists,
methodologies, report templates, prioritization algorithms, scope management,
and automation scripts.

Modules:
    checklists: Structured vulnerability assessment checklists
    methodology: Bug bounty methodology workflows
    templates: Report templates for various platforms
    prioritization: Vulnerability prioritization algorithms
    scope_manager: Bug bounty scope management tools
    automation: Automation scripts for CVE assessment

Example:
    from pocmap.bugbounty import (
        CVEToBountyWorkflow,
        prioritize_cves,
        ScopeManager,
        HackerOneTemplate,
    )
"""

from pocmap.bugbounty.automation import (
    BulkCVEAssessor,
    NotificationManager,
    ReportDrafter,
    ScopeMonitor,
)
from pocmap.bugbounty.checklists import (
    ChecklistItem,
    CVEResearchChecklist,
    ExploitationChecklist,
    ReconnaissanceChecklist,
    ReportingChecklist,
)
from pocmap.bugbounty.methodology import (
    CVEToBountyWorkflow,
    PatchGapAnalysisWorkflow,
    ZeroDayHuntingWorkflow,
)
from pocmap.bugbounty.prioritization import (
    calculate_bounty_potential,
    prioritize_cves,
    threat_model,
)
from pocmap.bugbounty.scope_manager import (
    Asset,
    ScopeManager,
    ScopeParser,
)
from pocmap.bugbounty.templates import (
    BugcrowdTemplate,
    ExecutiveSummaryTemplate,
    HackerOneTemplate,
    InternalAssessmentTemplate,
)

__version__ = "2.0.0"
__author__ = "PocMap Team"

__all__ = [
    # Checklists
    "ChecklistItem",
    "ReconnaissanceChecklist",
    "CVEResearchChecklist",
    "ExploitationChecklist",
    "ReportingChecklist",
    # Methodology
    "CVEToBountyWorkflow",
    "ZeroDayHuntingWorkflow",
    "PatchGapAnalysisWorkflow",
    # Templates
    "HackerOneTemplate",
    "BugcrowdTemplate",
    "InternalAssessmentTemplate",
    "ExecutiveSummaryTemplate",
    # Prioritization
    "prioritize_cves",
    "calculate_bounty_potential",
    "threat_model",
    # Scope Manager
    "ScopeManager",
    "ScopeParser",
    "Asset",
    # Automation
    "BulkCVEAssessor",
    "ScopeMonitor",
    "ReportDrafter",
    "NotificationManager",
]
