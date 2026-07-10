"""
Vulnerability Assessment Checklists for Bug Bounty Hunting

Provides structured, phase-based checklists for the complete bug bounty lifecycle.
Each checklist is a Python dataclass with items that have descriptions, completion flags,
notes fields, and priority levels (P0-P4).

Integration:
    - Uses pocmap.models.CVE for CVE data
    - Integrates with pocmap.services.cve_service for lookups

Example:
    checklist = ReconnaissanceChecklist()
    checklist.items[0].complete()  # Mark first item done
    print(checklist.completion_status())  # Get progress
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Priority(Enum):
    """Priority levels for checklist items (P0 = critical, P4 = informational)."""
    P0 = "P0"  # Critical - must complete, blocks progress
    P1 = "P1"  # High - strongly recommended
    P2 = "P2"  # Medium - should complete if time permits
    P3 = "P3"  # Low - nice to have
    P4 = "P4"  # Informational - reference/tips

    @property
    def weight(self) -> int:
        """Numeric weight for sorting (lower = higher priority)."""
        weights = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
        return weights[self.value]


@dataclass
class ChecklistItem:
    """
    A single checklist item with metadata for tracking.

    Attributes:
        description: What needs to be done
        priority: P0-P4 priority level
        completed: Whether this item is done
        notes: Free-form notes, findings, or evidence references
        completed_at: Timestamp when marked complete
        tags: Categorization tags for filtering
        tools: Recommended tools for this step
        estimated_time_minutes: Rough time estimate
        tips: Pro tips and edge cases
    """
    description: str
    priority: Priority = Priority.P2
    completed: bool = False
    notes: str = ""
    completed_at: str | None = None
    tags: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    estimated_time_minutes: int = 15
    tips: str = ""

    def complete(self, notes: str = "") -> None:
        """Mark item as completed with optional notes."""
        self.completed = True
        self.completed_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
        if notes:
            self.notes = notes if not self.notes else f"{self.notes}\n{notes}"

    def uncomplete(self) -> None:
        """Reset item to incomplete."""
        self.completed = False
        self.completed_at = None

    def add_note(self, note: str) -> None:
        """Add a note without changing completion status."""
        self.notes = note if not self.notes else f"{self.notes}\n{note}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "description": self.description,
            "priority": self.priority.value,
            "completed": self.completed,
            "notes": self.notes,
            "completed_at": self.completed_at,
            "tags": self.tags,
            "tools": self.tools,
            "estimated_time_minutes": self.estimated_time_minutes,
            "tips": self.tips,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChecklistItem:
        """Deserialize from dictionary."""
        return cls(
            description=data["description"],
            priority=Priority(data.get("priority", "P2")),
            completed=data.get("completed", False),
            notes=data.get("notes", ""),
            completed_at=data.get("completed_at"),
            tags=data.get("tags", []),
            tools=data.get("tools", []),
            estimated_time_minutes=data.get("estimated_time_minutes", 15),
            tips=data.get("tips", ""),
        )


class BaseChecklist:
    """Base class for all checklists."""

    def __init__(self, name: str, phase: str, items: list[ChecklistItem] | None = None) -> None:
        self.name = name
        self.phase = phase
        self.items: list[ChecklistItem] = items or []
        self.created_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"

    def completion_status(self) -> dict[str, Any]:
        """Return completion statistics."""
        total = len(self.items)
        completed = sum(1 for item in self.items if item.completed)
        p0_items = [i for i in self.items if i.priority == Priority.P0]
        p0_completed = sum(1 for i in p0_items if i.completed)
        total_est_time = sum(
            i.estimated_time_minutes for i in self.items if not i.completed
        )
        return {
            "total_items": total,
            "completed_items": completed,
            "completion_percentage": (completed / total * 100) if total else 0,
            "p0_total": len(p0_items),
            "p0_completed": p0_completed,
            "p0_blocking": len(p0_items) - p0_completed,
            "estimated_time_remaining_minutes": total_est_time,
        }

    def get_pending_items(self, max_priority: Priority | None = None) -> list[ChecklistItem]:
        """Get pending items, optionally filtered by max priority."""
        pending = [i for i in self.items if not i.completed]
        if max_priority:
            pending = [i for i in pending if i.priority.weight <= max_priority.weight]
        return sorted(pending, key=lambda x: x.priority.weight)

    def get_by_tag(self, tag: str) -> list[ChecklistItem]:
        """Filter items by tag."""
        return [i for i in self.items if tag in i.tags]

    def is_blocked(self) -> bool:
        """Check if any P0 items are incomplete (blocking)."""
        return any(
            i.priority == Priority.P0 and not i.completed for i in self.items
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize checklist to dictionary."""
        return {
            "name": self.name,
            "phase": self.phase,
            "created_at": self.created_at,
            "items": [item.to_dict() for item in self.items],
            "status": self.completion_status(),
        }

    def to_json(self, indent: int = 2) -> str:
        """Export checklist as JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaseChecklist:
        """Deserialize checklist from dictionary."""
        checklist = cls(
            name=data["name"],
            phase=data["phase"],
            items=[ChecklistItem.from_dict(item) for item in data.get("items", [])],
        )
        checklist.created_at = data.get("created_at", checklist.created_at)
        return checklist


class ReconnaissanceChecklist(BaseChecklist):
    """
    Reconnaissance phase checklist for bug bounty programs.

    Covers subdomain enumeration, tech stack identification,
    WAF detection, and port scanning.

    Time estimate: 2-8 hours depending on scope size
    Difficulty: Beginner to Intermediate
    """

    def __init__(self) -> None:
        items = [
            # Subdomain Enumeration
            ChecklistItem(
                description="Enumerate subdomains using passive sources (crt.sh, C99, Chaos)",
                priority=Priority.P0,
                tags=["subdomain", "passive", "recon"],
                tools=["subfinder", "amass", "chaos-client", "crt.sh"],
                estimated_time_minutes=20,
                tips="Start passive before active to avoid rate limits. crt.sh often finds subdomains that other tools miss.",
            ),
            ChecklistItem(
                description="Enumerate subdomains using active brute-force",
                priority=Priority.P1,
                tags=["subdomain", "active", "recon"],
                tools=["gobuster", "ffuf", "dnsx"],
                estimated_time_minutes=30,
                tips="Use a quality wordlist (best-dns-wordlist.txt). Target specific patterns like api-, staging-, dev-.",
            ),
            ChecklistItem(
                description="Resolve and verify all discovered subdomains",
                priority=Priority.P0,
                tags=["subdomain", "dns", "verification"],
                tools=["dnsx", "massdns", "shuffledns"],
                estimated_time_minutes=10,
                tips="Filter out dead hosts before proceeding. Use -rcode NOERROR to get only resolvable domains.",
            ),
            ChecklistItem(
                description="Take screenshots of all live web services",
                priority=Priority.P1,
                tags=["subdomain", "screenshot", "visual"],
                tools=["gowitness", "aquatone", " EyeWitness"],
                estimated_time_minutes=25,
                tips="Screenshots help quickly identify interesting apps, login portals, admin panels, and default pages.",
            ),
            ChecklistItem(
                description="Identify subdomain takeover candidates",
                priority=Priority.P1,
                tags=["subdomain", "takeover", "critical"],
                tools=["subjack", "nuclei -t subdomain-takeover"],
                estimated_time_minutes=10,
                tips="Check CNAME records pointing to GitHub Pages, Heroku, AWS S3, Azure, Fastly, etc.",
            ),
            # Technology Stack Identification
            ChecklistItem(
                description="Fingerprint web technologies on all live hosts",
                priority=Priority.P0,
                tags=["tech-stack", "fingerprinting"],
                tools=["wappalyzer", "httpx -tech-detect", "whatweb", "builtwith"],
                estimated_time_minutes=15,
                tips="Look for outdated frameworks, CMS versions, and specific middleware. Wappalyzer CLI is fast and accurate.",
            ),
            ChecklistItem(
                description="Identify JavaScript libraries and their versions",
                priority=Priority.P2,
                tags=["tech-stack", "javascript", "client-side"],
                tools=["retire.js", "LinkFinder", "JSFScan"],
                estimated_time_minutes=20,
                tips="Outdated JS libs (jQuery, Angular, React) often have known XSS CVEs. Map endpoints found in JS files.",
            ),
            ChecklistItem(
                description="Detect backend technologies from headers, cookies, and error pages",
                priority=Priority.P1,
                tags=["tech-stack", "headers", "fingerprinting"],
                tools=["httpx", "curl", "custom scripts"],
                estimated_time_minutes=10,
                tips="X-Powered-By, Server headers, Set-Cookie names, and stack traces in error pages leak tech info.",
            ),
            ChecklistItem(
                description="Map API endpoints and document their technologies",
                priority=Priority.P1,
                tags=["api", "tech-stack", "documentation"],
                tools=["postman", "burp-suite", "httpx"],
                estimated_time_minutes=25,
                tips="Look for /api, /graphql, /swagger, /openapi.json. API endpoints often have different security posture than web UI.",
            ),
            # WAF Detection
            ChecklistItem(
                description="Detect WAF/CDN presence on all targets",
                priority=Priority.P0,
                tags=["waf", "cdn", "detection"],
                tools=["wafw00f", "httpx -waf-detect", "nmap http-waf-detect"],
                estimated_time_minutes=15,
                tips="Knowing the WAF helps tailor payloads. Cloudflare, Akamai, AWS WAF each have different bypass techniques.",
            ),
            ChecklistItem(
                description="Test WAF bypass techniques for detected protections",
                priority=Priority.P2,
                tags=["waf", "bypass", "advanced"],
                tools=["burp-suite", "custom payloads"],
                estimated_time_minutes=30,
                tips="Try IP rotation, malformed headers, encoding variations, and case randomization for bypasses.",
            ),
            # Port Scanning
            ChecklistItem(
                description="Run full port scan on all in-scope IPs",
                priority=Priority.P0,
                tags=["port-scan", "network", "infrastructure"],
                tools=["nmap", "masscan", "rustscan"],
                estimated_time_minutes=45,
                tips="Start with masscan for speed, then nmap -sV -sC for service detection. Document all open ports.",
            ),
            ChecklistItem(
                description="Identify services with known CVE exposure",
                priority=Priority.P1,
                tags=["port-scan", "cve-mapping", "vulnerability"],
                tools=["nmap vuln scripts", "pocmap lookup"],
                estimated_time_minutes=20,
                tips="Focus on non-standard ports running web services, databases, and remote access services (SSH, RDP, VNC).",
            ),
            ChecklistItem(
                description="Check for exposed management interfaces",
                priority=Priority.P1,
                tags=["port-scan", "management", "exposure"],
                tools=["nmap", "shodan", "censys"],
                estimated_time_minutes=15,
                tips="Look for Jenkins, Kibana, Grafana, phpMyAdmin, Kubernetes dashboards, Docker APIs on unusual ports.",
            ),
            ChecklistItem(
                description="Document attack surface and create target inventory",
                priority=Priority.P0,
                tags=["documentation", "inventory", "tracking"],
                tools=["notion", "excel", "obsidian"],
                estimated_time_minutes=20,
                tips="Organize by subdomain, IP, port, technology, and priority. This becomes your scope file for automation.",
            ),
            # Cloud & Infrastructure
            ChecklistItem(
                description="Identify cloud providers and services in use",
                priority=Priority.P2,
                tags=["cloud", "infrastructure", "aws", "azure", "gcp"],
                tools=["cloud_enum", "s3scanner", "bucket-stream"],
                estimated_time_minutes=20,
                tips="Look for S3 buckets, Azure blobs, GCS buckets. CompanyName-backup, CompanyName-dev are common patterns.",
            ),
            ChecklistItem(
                description="Check for leaked credentials in public repositories",
                priority=Priority.P1,
                tags=["osint", "credentials", "github", "gitlab"],
                tools=["trufflehog", "gitLeaks", "github-search"],
                estimated_time_minutes=25,
                tips="Search for API keys, access tokens, database passwords, and internal URLs in public repos and gists.",
            ),
            ChecklistItem(
                description="Review historical DNS data for changed infrastructure",
                priority=Priority.P2,
                tags=["dns", "historical", "osint"],
                tools=["securitytrails", "circl.lu", "viewdns.info"],
                estimated_time_minutes=15,
                tips="Historical data reveals previous hosting providers, expired services ripe for takeover, and internal IPs.",
            ),
        ]
        super().__init__(
            name="Reconnaissance Phase",
            phase="recon",
            items=items,
        )


class CVEResearchChecklist(BaseChecklist):
    """
    CVE Research phase checklist for known vulnerability assessment.

    Covers known vulnerability lookup, patch gap analysis,
    exploit availability check, and EPSS/KEV prioritization.

    Time estimate: 1-4 hours per CVE batch
    Difficulty: Intermediate
    """

    def __init__(self) -> None:
        items = [
            # Known Vulnerability Lookup
            ChecklistItem(
                description="Query PocMap for CVE details and PoC availability",
                priority=Priority.P0,
                tags=["cve", "lookup", "poc"],
                tools=["pocmap", "curl", "python api"],
                estimated_time_minutes=5,
                tips="Always start with the AI lookup - it aggregates from multiple sources and may find non-public PoCs.",
            ),
            ChecklistItem(
                description="Cross-reference CVE with multiple databases (NVD, VulDB, MITRE)",
                priority=Priority.P0,
                tags=["cve", "database", "verification"],
                tools=["nvd-api", "vuldb", "cve.circl.lu"],
                estimated_time_minutes=10,
                tips="NVD is authoritative but slow to update. VulDB often has earlier details and exploit predictions.",
            ),
            ChecklistItem(
                description="Verify affected versions and product configurations",
                priority=Priority.P0,
                tags=["cve", "versions", "verification"],
                tools=["vendor advisories", "pocmap"],
                estimated_time_minutes=15,
                tips="Check vendor security advisories for exact version ranges. Some CVEs only affect specific configurations.",
            ),
            ChecklistItem(
                description="Check if the target runs an affected version",
                priority=Priority.P0,
                tags=["cve", "version-check", "target"],
                tools=["nmap -sV", "custom scripts", "banner grabbing"],
                estimated_time_minutes=10,
                tips="Version fingerprinting via banners, favicon hashes, CSS/JS file hashes, or login page source can reveal versions.",
            ),
            # Exploit Availability
            ChecklistItem(
                description="Search for public exploits and PoCs",
                priority=Priority.P0,
                tags=["exploit", "poc", "github"],
                tools=["pocmap search", "exploitdb", "github-search", "packetstorm"],
                estimated_time_minutes=15,
                tips="GitHub is often the fastest source for new PoCs. Search for 'CVE-XXXX-XXXX exploit', 'CVE-XXXX-XXXX poc', 'CVE-XXXX-XXXX python'.",
            ),
            ChecklistItem(
                description="Evaluate exploit quality and reliability",
                priority=Priority.P1,
                tags=["exploit", "quality", "assessment"],
                tools=["manual review", "pocmap analysis"],
                estimated_time_minutes=20,
                tips="Check exploit age, stars/forks, recent commits, and code quality. Avoid untrusted or obfuscated exploits.",
            ),
            ChecklistItem(
                description="Test exploit in isolated lab environment first",
                priority=Priority.P0,
                tags=["exploit", "testing", "lab"],
                tools=["docker", "vmware", "virtualbox"],
                estimated_time_minutes=30,
                tips="Never run unknown exploits directly against targets. Use Docker containers or VMs that match target environment.",
            ),
            ChecklistItem(
                description="Adapt exploit for target-specific conditions (WAF, auth, headers)",
                priority=Priority.P1,
                tags=["exploit", "adaptation", "customization"],
                tools=["burp-suite", "python", "curl"],
                estimated_time_minutes=25,
                tips="Most public exploits need tweaking. Adjust for authentication, CSRF tokens, custom headers, or WAF rules.",
            ),
            # Patch Gap Analysis
            ChecklistItem(
                description="Determine target's patch level vs latest available",
                priority=Priority.P1,
                tags=["patch", "gap", "version"],
                tools=["version detection", "vendor release notes"],
                estimated_time_minutes=15,
                tips="Even if patched, check patch history. Rapid patching after CVE disclosure suggests the org was vulnerable.",
            ),
            ChecklistItem(
                description="Identify compensating controls (WAF rules, IPS signatures)",
                priority=Priority.P2,
                tags=["compensating-controls", "waf", "ips"],
                tools=["waf testing", "nuclei"],
                estimated_time_minutes=20,
                tips="Organizations may have virtual patches via WAF. Test if the vulnerability is actually exploitable in practice.",
            ),
            ChecklistItem(
                description="Check for backup/unpatched instances (staging, dev, old subdomains)",
                priority=Priority.P1,
                tags=["patch", "shadow-it", "unpatched"],
                tools=["subdomain list", "version scanning"],
                estimated_time_minutes=20,
                tips="Production may be patched, but staging, dev, UAT, or old subdomains often lag behind. These are valid targets.",
            ),
            # EPSS / KEV Prioritization
            ChecklistItem(
                description="Query EPSS score for probability of exploitation",
                priority=Priority.P1,
                tags=["epss", "prioritization", "scoring"],
                tools=["epss-api.first.org", "pocmap"],
                estimated_time_minutes=5,
                tips="EPSS > 0.5 indicates high probability. Focus on CVEs with rising EPSS trends even if CVSS is moderate.",
            ),
            ChecklistItem(
                description="Check if CVE is on CISA KEV catalog",
                priority=Priority.P1,
                tags=["kev", "cisa", "prioritization"],
                tools=["cisa.gov/known-exploited-vulnerabilities", "pocmap"],
                estimated_time_minutes=5,
                tips="KEV-listed CVEs are actively exploited in the wild. These are prime bounty candidates with high impact.",
            ),
            ChecklistItem(
                description="Review threat intelligence for active exploitation campaigns",
                priority=Priority.P2,
                tags=["threat-intel", "exploitation", "campaigns"],
                tools=["twitter/x", "reddit", "mastodon", "security blogs"],
                estimated_time_minutes=15,
                tips="Follow @GreyNoiseIO, @Shadowserver, and threat intel feeds for real-world exploitation evidence.",
            ),
            ChecklistItem(
                description="Calculate composite risk score combining CVSS, EPSS, KEV, and exploit availability",
                priority=Priority.P1,
                tags=["scoring", "composite", "prioritization"],
                tools=["pocmap prioritize"],
                estimated_time_minutes=10,
                tips="Don't rely on CVSS alone. A medium CVSS with high EPSS and public exploit is often more valuable than a high CVSS with no exploit.",
            ),
            # Research Documentation
            ChecklistItem(
                description="Document all findings with evidence and references",
                priority=Priority.P0,
                tags=["documentation", "evidence", "references"],
                tools=["obsidian", "notion", "markdown"],
                estimated_time_minutes=20,
                tips="Save screenshots, exploit code links, version proof, and all references. This becomes your report appendix.",
            ),
        ]
        super().__init__(
            name="CVE Research Phase",
            phase="cve-research",
            items=items,
        )


class ExploitationChecklist(BaseChecklist):
    """
    Exploitation phase checklist for proof-of-concept validation.

    Covers PoC validation, impact assessment, and chainability analysis.

    Time estimate: 1-6 hours per vulnerability
    Difficulty: Intermediate to Advanced
    """

    def __init__(self) -> None:
        items = [
            # Proof-of-Concept Validation
            ChecklistItem(
                description="Obtain explicit authorization before testing",
                priority=Priority.P0,
                tags=["authorization", "legal", "compliance"],
                tools=["program policy", "scope verification"],
                estimated_time_minutes=10,
                tips="Verify the CVE is in scope. Check if the program excludes specific vulnerability types or requires pre-approval.",
            ),
            ChecklistItem(
                description="Set up testing environment matching target configuration",
                priority=Priority.P0,
                tags=["lab", "setup", "testing"],
                tools=["docker", "vagrant", "cloud VMs"],
                estimated_time_minutes=30,
                tips="Mirror the target's OS, software version, and configuration as closely as possible for reliable testing.",
            ),
            ChecklistItem(
                description="Run PoC in lab and confirm vulnerability exists",
                priority=Priority.P0,
                tags=["poc", "validation", "lab"],
                tools=["pocmap exploit", "custom scripts"],
                estimated_time_minutes=30,
                tips="Document every step with screenshots/recordings. Use Burp Suite or OWASP ZAP to intercept and document requests.",
            ),
            ChecklistItem(
                description="Develop minimal, safe PoC for target environment",
                priority=Priority.P0,
                tags=["poc", "minimal", "safe"],
                tools=["python", "curl", "burp-suite"],
                estimated_time_minutes=45,
                tips="Use safe payloads that demonstrate vulnerability without causing damage. echo 'PWNED' > /tmp/test is safer than rm -rf.",
            ),
            ChecklistItem(
                description="Test PoC against actual target (if authorized)",
                priority=Priority.P0,
                tags=["poc", "target", "testing"],
                tools=["burp-suite", "custom scripts", "proxy"],
                estimated_time_minutes=20,
                tips="Use a proxy to log all traffic. Start with the most minimal payload and escalate gradually.",
            ),
            # Impact Assessment
            ChecklistItem(
                description="Determine data accessible through vulnerability",
                priority=Priority.P0,
                tags=["impact", "data", "assessment"],
                tools=["sqlmap --dump", "custom scripts", "manual testing"],
                estimated_time_minutes=30,
                tips="Document what data types are accessible: PII, credentials, source code, configs, internal docs. Quantity matters for bounty.",
            ),
            ChecklistItem(
                description="Assess authentication bypass capabilities",
                priority=Priority.P1,
                tags=["impact", "auth-bypass", "assessment"],
                tools=["burp-suite", "custom payloads"],
                estimated_time_minutes=25,
                tips="Can you access admin panels? Impersonate other users? Access APIs without authentication? Each is a separate finding.",
            ),
            ChecklistItem(
                description="Evaluate remote code execution potential",
                priority=Priority.P1,
                tags=["impact", "rce", "assessment"],
                tools=["custom scripts", "reverse shell payloads"],
                estimated_time_minutes=30,
                tips="For RCE CVEs: test with whoami, id, or ping commands. Establish if you have a shell, and what privileges it has.",
            ),
            ChecklistItem(
                description="Check for privilege escalation paths",
                priority=Priority.P2,
                tags=["impact", "privesc", "assessment"],
                tools=["linpeas", "winpeas", "manual enumeration"],
                estimated_time_minutes=30,
                tips="Low-priv RCE to root/admin makes a good finding great. Check sudo, SUID, services, kernel exploits.",
            ),
            ChecklistItem(
                description="Measure blast radius - how many users/systems affected",
                priority=Priority.P1,
                tags=["impact", "blast-radius", "assessment"],
                tools=["counting", "enumeration"],
                estimated_time_minutes=20,
                tips="Is this one server or the entire infrastructure? Can you pivot to other systems? Broader impact = higher bounty.",
            ),
            # Chainability Analysis
            ChecklistItem(
                description="Identify potential vulnerability chains from this entry point",
                priority=Priority.P1,
                tags=["chaining", "attack-path", "advanced"],
                tools=["brainstorming", "threat-modeling"],
                estimated_time_minutes=25,
                tips="XSS + CSRF = account takeover. LFI + log poisoning = RCE. Information disclosure + auth bypass = data breach. Chain = higher bounty.",
            ),
            ChecklistItem(
                description="Map this CVE to other vulnerabilities in the environment",
                priority=Priority.P2,
                tags=["chaining", "mapping", "advanced"],
                tools=["pocmap", "vulnerability scanners"],
                estimated_time_minutes=20,
                tips="An SSRF on server A may reach internal service B with known CVEs. Map the internal network topology.",
            ),
            ChecklistItem(
                description="Assess if vulnerability enables further reconnaissance",
                priority=Priority.P2,
                tags=["chaining", "recon", "information-disclosure"],
                tools=["custom scripts"],
                estimated_time_minutes=15,
                tips="Error messages, verbose responses, or file reads may reveal internal IPs, credentials, or architecture details.",
            ),
            # Safety & Ethics
            ChecklistItem(
                description="Verify no data was modified or damaged during testing",
                priority=Priority.P0,
                tags=["safety", "ethics", "cleanup"],
                tools=["audit logs", "verification scripts"],
                estimated_time_minutes=10,
                tips="Leave no trace. Delete any test files, remove created accounts, and restore any modified settings.",
            ),
            ChecklistItem(
                description="Document all evidence: requests, responses, screenshots, logs",
                priority=Priority.P0,
                tags=["evidence", "documentation", "reporting"],
                tools=["burp-suite", "screenshot tool", "terminal recording"],
                estimated_time_minutes=20,
                tips="Burp state files, HTTP request/response pairs, and terminal recordings (asciinema) are excellent evidence.",
            ),
            ChecklistItem(
                description="Create timeline of exploitation steps for report",
                priority=Priority.P1,
                tags=["documentation", "timeline", "reporting"],
                tools=["markdown", "text editor"],
                estimated_time_minutes=15,
                tips="A step-by-step timeline with timestamps helps triagers reproduce and validates your findings.",
            ),
        ]
        super().__init__(
            name="Exploitation Phase",
            phase="exploitation",
            items=items,
        )


class ReportingChecklist(BaseChecklist):
    """
    Reporting phase checklist for bug bounty submission.

    Covers evidence collection, CVSS scoring, remediation suggestions,
    and report formatting for various platforms.

    Time estimate: 1-3 hours per report
    Difficulty: Beginner (but quality varies greatly)
    """

    def __init__(self) -> None:
        items = [
            # Evidence Collection
            ChecklistItem(
                description="Collect all HTTP requests and responses as evidence",
                priority=Priority.P0,
                tags=["evidence", "http", "burp"],
                tools=["burp-suite", "OWASP ZAP", "mitmproxy"],
                estimated_time_minutes=15,
                tips="Export relevant HTTP history items. Redact only your own credentials - leave everything else intact for triagers.",
            ),
            ChecklistItem(
                description="Take screenshots showing vulnerability and impact",
                priority=Priority.P0,
                tags=["evidence", "screenshot", "visual"],
                tools=["screenshot tool", "sharex", "flameshot"],
                estimated_time_minutes=15,
                tips="Screenshots should clearly show: vulnerable URL, payload, and result. Annotate key areas with arrows/circles.",
            ),
            ChecklistItem(
                description="Record video/GIF for complex multi-step vulnerabilities",
                priority=Priority.P1,
                tags=["evidence", "video", "complex"],
                tools=["asciinema", "obs studio", "screen recording"],
                estimated_time_minutes=20,
                tips="Videos are powerful for SSRF, XXE, and race conditions. Keep under 2 minutes, add narration or captions.",
            ),
            ChecklistItem(
                description="Prepare minimal reproduction steps",
                priority=Priority.P0,
                tags=["evidence", "reproduction", "steps"],
                tools=["markdown editor"],
                estimated_time_minutes=20,
                tips="Write steps that a non-technical person could follow. Include exact URLs, payloads, and expected vs actual results.",
            ),
            # CVSS Scoring
            ChecklistItem(
                description="Calculate CVSS v3.1 base score with justification for each metric",
                priority=Priority.P0,
                tags=["cvss", "scoring", "metrics"],
                tools=["cvss-calculator", "first.org/cvss/calculator"],
                estimated_time_minutes=20,
                tips="Justify every metric choice. 'Attack Vector: Network - the vulnerability is exploitable remotely without authentication.'",
            ),
            ChecklistItem(
                description="Consider environmental score modifiers (scope, confidentiality req)",
                priority=Priority.P2,
                tags=["cvss", "environmental", "scoring"],
                tools=["cvss-calculator"],
                estimated_time_minutes=10,
                tips="If the target handles financial/health data, the environmental score may be higher. Some programs use environmental scores.",
            ),
            ChecklistItem(
                description="Research bounty ranges for similar severity on the platform",
                priority=Priority.P1,
                tags=["bounty", "research", "compensation"],
                tools=["hackerone hacktivity", "bugcrowd leaderboard", " disclosed reports"],
                estimated_time_minutes=15,
                tips="Check disclosed reports of similar severity to set expectations. Don't mention expected bounty in the report.",
            ),
            # Remediation Suggestions
            ChecklistItem(
                description="Provide specific, actionable remediation steps",
                priority=Priority.P0,
                tags=["remediation", "fix", "recommendations"],
                tools=["vendor documentation", "security advisories"],
                estimated_time_minutes=20,
                tips="Include: 1) Upgrade to version X.Y.Z, 2) Apply patch from vendor, 3) Implement WAF rule, 4) Configuration change. Be specific!",
            ),
            ChecklistItem(
                description="Reference official vendor patches and security advisories",
                priority=Priority.P1,
                tags=["remediation", "vendor", "references"],
                tools=["vendor security portal", "cve references"],
                estimated_time_minutes=10,
                tips="Link to the official patch, KB article, or security bulletin. This shows professionalism and helps the fix team.",
            ),
            ChecklistItem(
                description="Suggest temporary mitigations if patch is not immediately available",
                priority=Priority.P1,
                tags=["remediation", "mitigation", "temporary"],
                tools=["waf rules", "configuration guides"],
                estimated_time_minutes=15,
                tips="Virtual patches via WAF, disabling vulnerable features, or network segmentation can reduce risk until a proper fix.",
            ),
            # Report Formatting
            ChecklistItem(
                description="Write clear, concise title summarizing the vulnerability",
                priority=Priority.P0,
                tags=["formatting", "title", "clarity"],
                tools=["text editor"],
                estimated_time_minutes=5,
                tips="Good: 'Remote Code Execution in Apache Struts 2 (CVE-2017-5638) via Content-Type Header'. Bad: 'Found a bug'.",
            ),
            ChecklistItem(
                description="Write executive summary for non-technical stakeholders",
                priority=Priority.P0,
                tags=["formatting", "executive-summary", "communication"],
                tools=["markdown editor"],
                estimated_time_minutes=15,
                tips="2-3 sentences: What is the vulnerability, what could an attacker do, and how urgent is the fix. No technical jargon.",
            ),
            ChecklistItem(
                description="Include detailed technical description with root cause analysis",
                priority=Priority.P0,
                tags=["formatting", "technical", "root-cause"],
                tools=["markdown editor"],
                estimated_time_minutes=20,
                tips="Explain WHY the vulnerability exists, not just what it does. Show understanding of the underlying code/config issue.",
            ),
            ChecklistItem(
                description="Format for target platform (HackerOne/Bugcrowd/Intigriti)",
                priority=Priority.P0,
                tags=["formatting", "platform", "submission"],
                tools=["pocmap templates"],
                estimated_time_minutes=10,
                tips="Each platform has preferred formats. HackerOne likes markdown with clear sections. Bugcrowd has a structured form.",
            ),
            ChecklistItem(
                description="Proofread and remove any identifying information if desired",
                priority=Priority.P1,
                tags=["formatting", "privacy", "review"],
                tools=["text editor"],
                estimated_time_minutes=10,
                tips="Redact your real name, personal tools, or methods you want to keep private. Check spelling and grammar.",
            ),
            ChecklistItem(
                description="Verify all links, attachments, and evidence are accessible",
                priority=Priority.P0,
                tags=["formatting", "verification", "quality"],
                tools=["link checker"],
                estimated_time_minutes=5,
                tips="Broken links or inaccessible attachments delay triage. Test every link before submitting.",
            ),
            # Submission
            ChecklistItem(
                description="Submit to platform and record submission ID",
                priority=Priority.P0,
                tags=["submission", "tracking", "platform"],
                tools=["hackerone", "bugcrowd", "intigriti"],
                estimated_time_minutes=10,
                tips="Note the submission ID, date, and expected response timeline. Set calendar reminders for follow-ups.",
            ),
            ChecklistItem(
                description="Respond promptly to triager questions and requests",
                priority=Priority.P1,
                tags=["submission", "communication", "follow-up"],
                tools=["email", "platform messaging"],
                estimated_time_minutes=5,
                tips="Fast, clear responses build reputation. If asked to retest, do it promptly. Clarify without being defensive.",
            ),
            ChecklistItem(
                description="Request disclosure after fix is confirmed",
                priority=Priority.P2,
                tags=["disclosure", "reputation", "portfolio"],
                tools=["platform disclosure request"],
                estimated_time_minutes=5,
                tips="Disclosed reports build your public profile and attract private program invitations. Request disclosure politely after fix.",
            ),
        ]
        super().__init__(
            name="Reporting Phase",
            phase="reporting",
            items=items,
        )


class MasterChecklist:
    """
    Master checklist combining all phases for a complete engagement.

    Provides a unified view across all phases with overall progress tracking.

    Example:
        master = MasterChecklist()
        print(master.overall_status())
        # Work on recon phase
        recon = master.recon
        recon.items[0].complete()
        print(master.overall_status())
    """

    def __init__(self, program_name: str = "Untitled Program"):
        self.program_name = program_name
        self.recon = ReconnaissanceChecklist()
        self.cve_research = CVEResearchChecklist()
        self.exploitation = ExploitationChecklist()
        self.reporting = ReportingChecklist()
        self.created_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"

    @property
    def all_checklists(self) -> list[BaseChecklist]:
        """Return all phase checklists."""
        return [self.recon, self.cve_research, self.exploitation, self.reporting]

    def overall_status(self) -> dict[str, Any]:
        """Return overall completion status across all phases."""
        total = 0
        completed = 0
        p0_total = 0
        p0_completed = 0
        phase_statuses = {}

        for checklist in self.all_checklists:
            status = checklist.completion_status()
            phase_statuses[checklist.phase] = status
            total += status["total_items"]
            completed += status["completed_items"]
            p0_total += status["p0_total"]
            p0_completed += status["p0_completed"]

        return {
            "program_name": self.program_name,
            "total_items": total,
            "completed_items": completed,
            "completion_percentage": (completed / total * 100) if total else 0,
            "p0_total": p0_total,
            "p0_completed": p0_completed,
            "p0_blocking": p0_total - p0_completed,
            "phases": phase_statuses,
            "current_phase": self._get_current_phase(),
            "is_complete": completed == total and total > 0,
        }

    def _get_current_phase(self) -> str:
        """Determine which phase is currently active."""
        for checklist in self.all_checklists:
            status = checklist.completion_status()
            if status["completion_percentage"] < 100:
                return checklist.phase
        return "complete"

    def get_blocking_items(self) -> list[tuple[str, ChecklistItem]]:
        """Get all P0 incomplete items across all phases."""
        blocking = []
        for checklist in self.all_checklists:
            for item in checklist.items:
                if item.priority == Priority.P0 and not item.completed:
                    blocking.append((checklist.phase, item))
        return blocking

    def export_json(self, filepath: str) -> None:
        """Export entire master checklist to JSON file."""
        data = {
            "program_name": self.program_name,
            "created_at": self.created_at,
            "overall_status": self.overall_status(),
            "phases": {
                checklist.phase: checklist.to_dict()
                for checklist in self.all_checklists
            },
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def import_json(cls, filepath: str) -> MasterChecklist:
        """Import master checklist from JSON file."""
        with open(filepath) as f:
            data = json.load(f)
        master = cls(data.get("program_name", "Untitled Program"))
        master.created_at = data.get("created_at", master.created_at)
        for phase_name, phase_data in data.get("phases", {}).items():
            for checklist in master.all_checklists:
                if checklist.phase == phase_name:
                    checklist.items = [
                        ChecklistItem.from_dict(item)
                        for item in phase_data.get("items", [])
                    ]
                    break
        return master
