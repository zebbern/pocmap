"""MCP prompt templates."""

from __future__ import annotations

from pocmap.mcp.server import mcp


@mcp.prompt(
    name="vulnerability_assessment",
    description="Structured vulnerability assessment workflow for analyzing CVEs. Guides through systematic evaluation of threat context, exploitability, and remediation priorities.",
)
def vulnerability_assessment_prompt(cve_id: str) -> str:
    """Prompt: Vulnerability assessment workflow.

    Args:
        cve_id: The CVE identifier to assess
    """
    return f"""You are performing a comprehensive vulnerability assessment for {cve_id.upper().strip()}. Follow this structured workflow:

## Phase 1: Context Gathering
- Look up the CVE details to understand what the vulnerability is
- Check the CVSS score and severity to understand technical impact
- Get the EPSS score to assess exploitation probability
- Check KEV status to determine if it's actively exploited

## Phase 2: Exploit Landscape Analysis
- Find all available GitHub PoCs and examine their quality and recency
- Check for Metasploit modules (indicates reliable, weaponized exploits)
- Look for ExploitDB entries (often the first exploits available)
- Find Nuclei templates (for detection and verification)

## Phase 3: Real-World Impact
- Search for bug bounty reports showing real-world exploitation
- Identify practice labs for hands-on understanding

## Phase 4: Risk Assessment & Prioritization
- Combine CVSS severity + EPSS probability + KEV status for a holistic risk score
- If EPSS > 0.5 OR KEV=true: CRITICAL priority for patching
- If CVSS >= 9.0: HIGH priority regardless of other factors
- If CVSS >= 7.0 and EPSS > 0.2: MEDIUM-HIGH priority
- Consider available exploits as an indicator of ease of exploitation

## Phase 5: Recommendations
Provide actionable remediation advice including:
- Immediate containment steps
- Patch availability and timeline
- Detection rules or monitoring recommendations
- Compensating controls if patching is delayed

Execute this workflow for {cve_id.upper().strip()} and provide a comprehensive assessment."""


@mcp.prompt(
    name="exploit_research",
    description="Deep exploit research prompt for analyzing available exploit code, understanding exploitation techniques, and building detection rules.",
)
def exploit_research_prompt(cve_id: str, focus_area: str = "all") -> str:
    """Prompt: Exploit research workflow.

    Args:
        cve_id: The CVE identifier to research
        focus_area: Specific focus - 'all', 'detection', 'exploitation', 'remediation', or 'analysis'
    """
    focus_map = {
        "all": "comprehensive analysis covering all aspects",
        "detection": "building detection rules and indicators of compromise",
        "exploitation": "understanding exploitation techniques and attack vectors",
        "remediation": "finding patches, workarounds, and compensating controls",
        "analysis": "deep technical analysis of the vulnerability root cause",
    }
    focus_desc = focus_map.get(focus_area.lower(), focus_map["all"])

    return f"""You are conducting exploit research for {cve_id.upper().strip()} with a focus on {focus_desc}.

## Research Objectives
1. **Find all available exploits** - GitHub PoCs, Metasploit modules, ExploitDB entries, Nuclei templates
2. **Analyze exploitation techniques** - Understand the attack vector, prerequisites, and impact
3. **Assess exploit maturity** - Check if exploits are reliable, weaponized, or proof-of-concept only
4. **Build detection capability** - Identify IOCs, network signatures, and behavioral patterns

## Research Questions to Answer
- What is the vulnerability type and root cause?
- What are the prerequisites for exploitation?
- What is the attack vector (network, local, adjacent, physical)?
- Does the exploit require authentication?
- What is the blast radius if exploited?
- Are there public reports of in-the-wild exploitation?
- What detection methods are available?

## Deliverables
Provide a research brief with:
1. Executive summary (2-3 sentences)
2. Available exploits inventory with quality ratings
3. Exploitation technique analysis
4. Detection recommendations (signatures, behavioral rules, log analysis)
5. Remediation guidance

Begin by looking up the CVE details and finding all available exploits for {cve_id.upper().strip()}."""


@mcp.prompt(
    name="bug_bounty_analysis",
    description="Analyze bug bounty reports to extract exploitation techniques, real-world impact assessments, and security lessons learned.",
)
def bug_bounty_analysis_prompt(cve_id: str) -> str:
    """Prompt: Bug bounty report analysis.

    Args:
        cve_id: The CVE identifier to analyze
    """
    return f"""You are analyzing bug bounty reports for {cve_id.upper().strip()} to extract real-world security insights.

## Analysis Framework

### 1. Report Collection
- Find all bug bounty reports and write-ups for this CVE
- Note which platforms (HackerOne, Bugcrowd, Intigriti) have reports
- Identify reports that include PoCs (Proof-of-Concept demonstrations)

### 2. Impact Analysis
For each report found, analyze:
- **Affected scope**: Which companies/services were impacted?
- **Bounty amount**: What was the reward (if disclosed)?
- **Severity**: How did the platform classify it?
- **Exploitation path**: How did the researcher exploit it?
- **Business impact**: What was the real-world consequence?

### 3. Technique Extraction
- Document the specific exploitation techniques used
- Identify any novel or creative attack vectors discovered
- Note any bypasses of existing mitigations
- Catalog tools and methodologies used by researchers

### 4. Lessons Learned
- What does this teach about the vulnerability class?
- What detection/prevention gaps were exposed?
- How can organizations better protect against this?
- What secure coding practices would have prevented this?

### 5. Actionable Recommendations
Provide:
- Security testing guidance for this vulnerability class
- Detection engineering recommendations
- Secure development practices
- Defensive architecture suggestions

Search for bug bounty reports on {cve_id.upper().strip()} and provide a comprehensive analysis."""
