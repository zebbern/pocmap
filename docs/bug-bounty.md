# Bug Bounty Toolkit

The `pocmap.bugbounty` module provides a comprehensive toolkit for bug bounty hunters.
These helpers are a **Python API** (and packaged playbooks) — the CLI only exposes
`pocmap bugbounty <CVE>` for write-up search, not checklists/workflows/scope commands:

### Structured Checklists

Phase-based checklists with P0-P4 priority levels, completion tracking, and time estimates:

```python
from pocmap.bugbounty import (
    ReconnaissanceChecklist,
    CVEResearchChecklist,
    ExploitationChecklist,
    ReportingChecklist,
)

# Create and track a checklist
checklist = ReconnaissanceChecklist()
checklist.items[0].complete(notes="Subdomain enumeration complete")
print(checklist.completion_status())  # Progress percentage
```

### Methodology Workflows

Structured, repeatable workflows with entry/exit criteria and difficulty ratings:

```python
from pocmap.bugbounty import (
    CVEToBountyWorkflow,        # CVE -> bug bounty pipeline
    ZeroDayHuntingWorkflow,     # Proactive vulnerability discovery
    PatchGapAnalysisWorkflow,   # Patch timing gap exploitation
)

workflow = CVEToBountyWorkflow()
result = workflow.execute_phase("recon", context={"target": "example.com"})
```

### Report Templates

Platform-specific report templates for HackerOne, Bugcrowd, and internal assessments:

```python
from pocmap.bugbounty import HackerOneTemplate, BugcrowdTemplate

template = HackerOneTemplate()
report = template.render(
    cve_data=cve_info,
    impact="Remote code execution achieved via crafted JNDI lookup",
    steps_to_reproduce=[
        "1. Identify Log4j 2.x instance",
        "2. Send crafted payload to vulnerable endpoint",
        "3. Observe DNS callback confirming RCE",
    ],
)
```

### Prioritization Engine

Multi-strategy CVE prioritization with bounty potential estimation:

```python
from pocmap.bugbounty import prioritize_cves, calculate_bounty_potential

# Sort by composite score (CVSS + EPSS + KEV + exploit availability)
sorted_cves = prioritize_cves(cve_list, strategy="composite")

# Or prioritize by specific factors
sorted_cves = prioritize_cves(cve_list, strategy="epss")        # Exploitation probability
sorted_cves = prioritize_cves(cve_list, strategy="kev_first")   # Known exploited first
sorted_cves = prioritize_cves(cve_list, strategy="bounty_potential")

# Estimate bounty potential
for cve in sorted_cves[:10]:
    bounty = calculate_bounty_potential(cve)
    print(f"{cve['id']}: potential=${bounty['estimated_median']}")
```

### Scope Management

Parse and manage bug bounty program scope, match CVEs to in-scope assets:

```python
from pocmap.bugbounty import ScopeManager, Asset

scope = ScopeManager()
scope.add_program(
    platform="hackerone",
    program="example",
    in_scope=["*.example.com", "api.example.com"],
    out_of_scope=["*.internal.example.com"],
)

# Parse scope from file
scope.parse_scope_file("scope.txt")

# Find CVEs affecting in-scope assets
matches = scope.match_cves_to_scope(cve_list)
```

### Playbooks

JSON playbooks for structured workflows:

```python
from pocmap.bugbounty.playbooks import load_playbook, list_playbooks

# List available playbooks
for pb in list_playbooks():
    print(f"{pb['name']}: {pb['description']} ({pb['difficulty']})")

# Load and execute a playbook
playbook = load_playbook("cve-assessment")
for phase in playbook["phases"]:
    print(f"Phase {phase['phase_id']}: {phase['name']}")
    for step in phase["steps"]:
        print(f"  [{step['priority']}] {step['description']}")
```

Available playbooks:
- **cve-assessment**: Full CVE assessment workflow with risk scoring and remediation
- **rapid-response**: Emergency response for critical/KEV CVEs with time-bounded actions
- **bb-submission**: Complete bug bounty submission pipeline from finding to report
