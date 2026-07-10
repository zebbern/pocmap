# PocMap: AI Agent Integration Guide

This document is designed specifically for AI agents (Claude, GPT, Cursor, etc.) integrating with the PocMap toolkit via the MCP server or Python API.

## Overview

PocMap provides 19 MCP tools, 3 resources, and 3 prompts for comprehensive vulnerability intelligence. All tools return JSON strings for reliable programmatic parsing.

**When to use this toolkit:**
- User asks about a specific CVE ID
- User needs to find exploit code or PoCs
- User wants to assess vulnerability risk or prioritize patching
- User is doing bug bounty research
- User needs CTF lab environments for practice
- User wants vulnerability reports in JSON or HTML format

## Available Tools and When to Use Each

### CVE Intelligence (3 tools)

| Tool | When to Use | Key Output Fields |
|------|-------------|-------------------|
| `lookup_cve` | User mentions any CVE ID | `cve_id`, `description`, `cvss` (score, severity, version, vector_string), `epss_score`, `kev_status`, `cwes`, `vendor`, `product`, `state` |
| `get_epss_score` | Prioritizing which CVEs to patch first | `epss_score` (0.0-1.0), `risk_level` (LOW/MEDIUM/HIGH/CRITICAL), `interpretation` |
| `check_kev_status` | Determining if a CVE is actively exploited | `kev_status` (bool), `recommendation` (actionable) |

**Decision rule:** Always call `lookup_cve` first when a CVE ID is mentioned. It provides the superset of information. Only call `get_epss_score` or `check_kev_status` individually if the user asks specifically about EPSS or KEV.

### Exploit Discovery (4 tools)

| Tool | When to Use | Returns |
|------|-------------|---------|
| `find_github_pocs` | User wants exploit code, detection scripts, or to understand exploitation | List of repos with `source`, `url`, `title`, `language`, `stars`, `forks` |
| `find_metasploit_module` | Assessing if reliable, weaponized exploit exists | Module `title`, `url`, `rank` |
| `find_exploitdb_entry` | Finding standalone exploit scripts | Entry `title`, `url` |
| `find_nuclei_template` | Detection/verification scanning needs | Template `title`, `url` |

**Decision rule:** Call all 4 when doing comprehensive exploit research. For quick checks, `find_github_pocs` is usually the most informative.

### Bug Bounty Research (1 tool)

| Tool | When to Use | Returns |
|------|-------------|---------|
| `find_bug_bounty_reports` | User wants real-world exploitation techniques, write-ups, or bounty research | Reports with `source`, `url`, `title`, `has_poc` |

### Lab Discovery (2 tools)

| Tool | When to Use | Returns |
|------|-------------|---------|
| `find_practice_labs` | User wants hands-on practice environments | Labs with `platform` (hackthebox/tryhackme/vulhub), `name`, `url` |
| `find_vulhub_docker` | User wants the quickest local Docker setup | Docker URL + `setup_instructions` (clone, cd, docker compose up) |

### Discovery (2 tools)

| Tool | When to Use | Returns |
|------|-------------|---------|
| `find_recent_exploits` | User wants to see newly published CVEs over a time window | Recent CVEs with severity, EPSS, KEV status, and PoC availability |
| `discover_product_cves` | User asks about vulnerabilities in a product without providing a CVE ID | CVEs grouped by confidence: confirmed, possibly, and not enough data |

**Decision rule:** Use `find_recent_exploits` for threat intelligence briefings and monitoring. Use `discover_product_cves` when the user names a product (e.g., "What CVEs affect Apache Struts?") rather than a specific CVE ID.

### CPE Conversion (2 tools)

| Tool | When to Use | Returns |
|------|-------------|---------|
| `cve_to_cpe` | Mapping a CVE to affected products/versions | CPEs with `cpe`, `vendor`, `product`, `version` |
| `cpe_to_cve` | Finding all CVEs affecting a specific product | List of `cve_ids` |

### Report Generation (2 tools)

| Tool | When to Use | Returns |
|------|-------------|---------|
| `generate_json_report` | Structured data for automation, CI/CD, dashboards | Comprehensive JSON report for all provided CVEs |
| `generate_html_report` | Human-readable reports for stakeholders | Self-contained HTML with styled cards |

**Input format:** Both accept comma-separated CVE IDs: `"CVE-2021-44228,CVE-2023-38408"`

### Playbooks (3 tools)

| Tool | When to Use | Returns |
|------|-------------|---------|
| `get_cve_assessment_playbook` | Starting a full vulnerability assessment | Structured multi-phase workflow JSON |
| `get_rapid_response_playbook` | Emergency response to critical CVEs | Time-bounded emergency procedures |
| `get_bug_bounty_playbook` | Bug bounty submission process | Complete submission pipeline workflow |

## Data Models and Their Fields

### CVEInfo
```json
{
  "id": "CVE-2021-44228",
  "description": "Apache Log4j2 2.0-beta9 through 2.15.0...",
  "cvss": {
    "version": "3.1",
    "base_score": 10.0,
    "severity": "CRITICAL",
    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
  },
  "epss": 97.53,
  "kev_status": true,
  "cwes": ["CWE-77", "CWE-94"],
  "references": {"NVD": "https://nvd.nist.gov/...", "Advisory": "https://..."},
  "vendor": "Apache",
  "product": "Log4j",
  "publication_date": "2021-12-10",
  "state": "PUBLISHED",
  "ransomware_usage": null,
  "rejected_reason": null
}
```

### Exploit
```json
{
  "source": "github",
  "url": "https://github.com/user/poc-repo",
  "title": "Log4j RCE PoC",
  "language": "Python",
  "stars": 1250,
  "forks": 340,
  "rank": null
}
```

### LabEnvironment
```json
{
  "platform": "vulhub",
  "name": "log4j/CVE-2021-44228",
  "url": "https://github.com/vulhub/vulhub/tree/master/log4j/CVE-2021-44228",
  "setup_instructions": "docker compose up -d"
}
```

### BugBountyReport
```json
{
  "source": "hackerone",
  "url": "https://hackerone.com/reports/...",
  "has_poc": true,
  "title": "Log4j RCE on Example Corp"
}
```

### CPEInfo
```json
{
  "cpe_string": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
  "vendor": "apache",
  "product": "log4j",
  "version": "2.0"
}
```

## Example Multi-Step Workflows

### Workflow 1: Comprehensive CVE Assessment
```
User: "Tell me about CVE-2021-44228"

Agent steps:
1. lookup_cve("CVE-2021-44228")
   -> Extract: CVSS 10.0 CRITICAL, EPSS 0.9753, KEV=true

2. find_github_pocs("CVE-2021-44228", limit=5)
   -> Extract: Top repos, languages, star counts

3. find_metasploit_module("CVE-2021-44228")
   -> Check if weaponized exploit exists

4. find_nuclei_template("CVE-2021-44228")
   -> Check if detection template exists

5. check_kev_status("CVE-2021-44228")
   -> Confirm KEV status (should match lookup_cve)

6. find_bug_bounty_reports("CVE-2021-44228")
   -> Find real-world exploitation reports

7. find_practice_labs("CVE-2021-44228")
   -> List available practice environments

Response synthesis:
- Provide summary with CVSS, EPSS, KEV status
- List top 3-5 GitHub PoCs with links
- Note Metasploit/Nuclei availability
- Summarize bug bounty findings
- List practice lab options
- Give clear prioritization recommendation (CRITICAL + KEV = patch immediately)
```

### Workflow 2: Vulnerability Prioritization
```
User: "Which of these should I patch first? CVE-2021-44228, CVE-2023-38408, CVE-2024-21413"

Agent steps:
1. lookup_cve for all 3 (can be parallelized conceptually)
2. get_epss_score for all 3
3. check_kev_status for all 3
4. find_github_pocs for all 3 (to count exploit availability)

Scoring logic:
- EPSS > 0.9 AND KEV=true: Patch within 24 hours
- EPSS > 0.5 AND KEV=true: Patch within 48 hours
- CVSS >= 9.0: Patch within 1 week
- EPSS > 0.5: Patch within 2 weeks
- Otherwise: Standard patch cycle

Response: Ordered list with justification for each rank
```

### Workflow 3: Product Vulnerability Assessment
```
User: "What CVEs affect Apache Struts 2.5?"

Agent steps:
1. cpe_to_cve("cpe:2.3:a:apache:struts:2.5")
   -> Get list of CVE IDs

2. For top 5-10 CVEs by recency:
   - lookup_cve for details
   - get_epss_score for prioritization
   - check_kev_status for exploitation context

3. generate_json_report(cve_list)
   -> Produce consolidated report

Response: Summary table of CVEs with CVSS, EPSS, KEV, and patch priority
```

### Workflow 4: Bug Bounty Preparation
```
User: "I'm hunting on a program using Apache Log4j. What should I check?"

Agent steps:
1. cpe_to_cve("cpe:2.3:a:apache:log4j")
   -> All Log4j CVEs

2. Filter by high CVSS (>= 7.0) and available exploits

3. For each high-value CVE:
   - lookup_cve for full details
   - find_github_pocs for exploit techniques
   - find_bug_bounty_reports for past findings
   - find_practice_labs for skill building

4. get_bug_bounty_playbook()
   -> Structured submission workflow

5. Suggest using the bb-submission playbook for report writing

Response: Targeted CVE list + exploitation roadmap + playbook guidance
```

### Workflow 5: Emergency Response
```
User: "CVE-2024-XXXXX just dropped and it's critical. What do I do?"

Agent steps:
1. lookup_cve("CVE-2024-XXXXX")
   -> Confirm severity and details

2. get_rapid_response_playbook()
   -> Get emergency workflow

3. check_kev_status("CVE-2024-XXXXX")
   -> Check if already exploited

4. get_epss_score("CVE-2024-XXXXX")
   -> Assess exploitation probability

5. find_github_pocs + find_metasploit_module + find_nuclei_template
   -> Check exploit availability

6. cve_to_cpe("CVE-2024-XXXXX")
   -> Identify affected products in environment

7. find_vulhub_docker or find_practice_labs
   -> Set up test environment

Response: Time-bounded action items from playbook + immediate containment steps
```

### Workflow 6: Daily Threat Briefing
```
User: "What new critical CVEs dropped in the last 24 hours?"

Agent steps:
1. find_recent_exploits(since="24h", severity="critical,high", sort="epss", limit=10)
   -> Get the most critical recent CVEs sorted by EPSS

2. For each CVE with EPSS > 50:
   - lookup_cve for full details
   - find_github_pocs to assess exploit availability
   - check_kev_status for active exploitation context

3. find_recent_exploits(since="24h", kev_only=true)
   -> Check specifically for new KEV entries

Response: Prioritized list with CVSS, EPSS, KEV status, exploit availability, and recommended patch timeline
```

### Workflow 7: Product Vulnerability Audit
```
User: "We're running Apache Struts 2.5 - what vulnerabilities should we worry about?"

Agent steps:
1. discover_product_cves(product="Apache Struts", version="2.5")
   -> Get CVEs grouped by confidence (confirmed, possibly, unknown)

2. For confirmed CVEs:
   - lookup_cve for full details (CVSS, EPSS, description)
   - get_epss_score for prioritization
   - check_kev_status for active exploitation
   - find_github_pocs to count available exploits

3. For high-confidence CVEs (CRITICAL/HIGH + KEV or EPSS > 50):
   - find_metasploit_module + find_nuclei_template for detection
   - find_practice_labs for testing environments

4. generate_json_report(confirmed_cve_ids)
   -> Produce consolidated audit report

Response: Summary table of confirmed CVEs with CVSS, EPSS, KEV, exploit count, and prioritized remediation order
```

### Workflow 8: Emerging Threat Monitoring
```
User: "Show me the top 10 most dangerous new CVEs from this week"

Agent steps:
1. find_recent_exploits(since="7d", sort="severity", limit=20)
   -> Get this week's CVEs sorted by severity

2. Filter to those with EPSS > 30 OR has_poc=true OR kev_status=true

3. For each qualifying CVE:
   - lookup_cve for full context
   - find_github_pocs(limit=3) for top exploit repos
   - find_nuclei_template for detection capability

Response: Ranked list of emerging threats with exploit maturity assessment and detection recommendations
```

## Common Error Patterns and How to Handle Them

### Error Response Format
All MCP tools return JSON error objects with these fields:
```json
{
  "error": "Description of what went wrong",
  "error_type": "ExceptionClassName",
  "category": "network_error|not_found|invalid_input|permission_error|unknown",
  "retryable": true,
  "context": "Tool name and arguments"
}
```

### Error Categories and Handling

| Category | Cause | Agent Action |
|----------|-------|--------------|
| `network_error` + `retryable: true` | Temporary API failure | Retry the call after a brief pause (2-5 seconds) |
| `network_error` + `retryable: false` | Persistent connectivity issue | Report to user, suggest checking connection |
| `not_found` | CVE doesn't exist in database | Inform user the CVE may not be published yet |
| `invalid_input` | Malformed CVE ID or bad parameter | Correct the input (e.g., `CVE-2021-44228` not `CVE202144228`) |
| `permission_error` | API rate limit or auth failure | Suggest adding GITHUB_API_TOKEN or NVD_API_KEY |
| `unknown` | Unexpected error | Log details and try alternative tool |

### CVE ID Validation
Always validate CVE IDs before calling tools:
- Format: `CVE-YYYY-NNNN+` (e.g., `CVE-2021-44228`)
- Case-insensitive (tools normalize to uppercase)
- Year: 4 digits (1999+)
- Number: 1+ digits

**Common mistakes to catch:**
- `CVE202144228` -> Missing hyphens
- `cve-2021-44228` -> Fine, tools normalize it
- `2021-44228` -> Missing CVE prefix
- `CVE-2021` -> Missing number
- Empty string -> Reject immediately

### Rate Limit Handling
- GitHub API: 60 requests/hour unauthenticated, 5000/hour with token
- NVD API: Slower without API key
- If rate limit errors occur: Suggest the user set `GITHUB_API_TOKEN`

### Not All CVEs Have All Data
- EPSS scores may be `None` for very new or obscure CVEs
- KEV status is `false` for most CVEs (only ~1000 in catalog)
- GitHub PoCs may return empty list for recently disclosed CVEs
- Bug bounty reports exist only for CVEs that have been actively hunted

**Agent guidance:** Always handle `None`/missing values gracefully. Do not assume all fields are populated.

## Discovery Tool Reference

### `find_recent_exploits`

Find recently published CVEs with exploit and PoC intelligence. Scans the NVD for newly published vulnerabilities within a configurable time window.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `since` | str | `"24h"` | Relative time window: `1h`, `24h`, `7d`, `30d`. Ignored if `from_date` is set. |
| `from_date` | str | `""` | Explicit start date (`YYYY-MM-DD`). Overrides `since`. |
| `to_date` | str | `""` | Explicit end date (`YYYY-MM-DD`). Defaults to today. |
| `only_with_poc` | bool | `false` | Only return CVEs with known PoCs on GitHub. |
| `kev_only` | bool | `false` | Only return CISA KEV entries. |
| `min_epss` | float | `0.0` | Minimum EPSS score (0-100). `0` means no filter. |
| `severity` | str | `""` | Comma-separated severity levels (e.g., `CRITICAL,HIGH`). |
| `sort` | str | `"cve_date"` | Sort by: `cve_date`, `severity`, or `epss`. |
| `limit` | int | `50` | Maximum results (1-100). |

**Returns:**
```json
{
  "success": true,
  "total": 10,
  "query": { "since": "24h", "severity": ["CRITICAL"], ... },
  "cves": [
    {
      "cve_id": "CVE-2024-XXXXX",
      "description": "...",
      "severity": "CRITICAL",
      "base_score": 9.8,
      "epss": 85.4,
      "kev_status": true,
      "vendor": "Apache",
      "product": "Struts",
      "publication_date": "2024-01-15",
      "has_poc": true,
      "poc_sources": ["github"]
    }
  ]
}
```

### `discover_product_cves`

Discover CVEs affecting a product by name and version. Supports product aliases, version wildcards, and fuzzy matching.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `product` | str | *(required)* | Product name (e.g., `Apache Struts`, `Log4j`, `nginx`) |
| `version` | str | `""` | Version constraint (e.g., `2.x`, `2.14.1`, `>= 2.0`) |
| `vendor` | str | `""` | Optional vendor name (e.g., `Apache`, `Microsoft`) |
| `limit` | int | `50` | Maximum CVEs to analyze (1-100) |

**Returns:**
```json
{
  "query": "Apache Struts",
  "normalized_vendor": "apache",
  "normalized_product": "apache struts",
  "version_constraint": { "major": 2, "minor": "x", "patch": null, "range_op": null, "raw": "2.x", "is_wildcard": true },
  "total_found": 42,
  "confirmed_affected": [ ... ],
  "possibly_affected": [ ... ],
  "not_enough_data": [ ... ],
  "summary": { "confirmed_count": 15, "possibly_count": 20, "unknown_count": 7 }
}
```

### Version Constraint Format Reference

When using `discover_product_cves`, version constraints support these formats:

| Format | Example | Parsed Meaning |
|--------|---------|---------------|
| Wildcard | `2.x` | Major version 2, any minor/patch |
| Exact | `2.14.1` | Exactly version 2.14.1 |
| Major.Minor | `2.14` | Version 2.14.x |
| Range >= | `>= 2.0` | Version 2.0 and above |
| Range <= | `<= 1.20` | Version 1.20 and below |
| Range > | `> 1.0` | Strictly above version 1.0 |
| Range < | `< 3.0` | Strictly below version 3.0 |

If the version string is unparseable (e.g., `latest`, `unknown`), no version constraint is applied and all matching CVEs are returned.

### Product Aliases for Agents

Common product aliases that resolve automatically:

| User Input | Resolved Product | Vendor |
|-----------|-----------------|--------|
| `struts` | Apache Struts | apache |
| `log4j`, `log4j2` | Log4j | apache |
| `httpd`, `apache2` | Apache HTTP Server | apache |
| `k8s`, `kube` | Kubernetes | google |
| `postgres`, `pgsql` | PostgreSQL | postgresql |
| `es`, `elastic` | Elasticsearch | elastic |
| `nodejs`, `node` | Node.js | nodejs |
| `ghe` | GitHub Enterprise | github |
| `ror` | Ruby on Rails | rubyonrails |
| `wp` | WordPress | wordpress |
| `ie`, `msie` | Internet Explorer | microsoft |

When a user provides a product name, always pass it directly to `discover_product_cves` - the alias system handles normalization.

## JSON Schema Reference

### Exporting Schemas
```python
from pocmap.models import export_schemas
paths = export_schemas("./schemas")
```

### Schema Files Generated

| File | Primary Model | Key Fields |
|------|---------------|------------|
| `CVSSScore.json` | CVSSScore | `version` (enum), `base_score` (0-10), `severity` (enum), `vector_string` |
| `CVEInfo.json` | CVEInfo | `id`, `description`, `cvss`, `epss`, `kev_status`, `cwes`, `references`, `vendor`, `product`, `state` |
| `Exploit.json` | Exploit | `source` (enum), `url`, `title`, `language`, `stars`, `forks`, `rank`, `command` |
| `LabEnvironment.json` | LabEnvironment | `platform` (enum), `name`, `url`, `setup_instructions` |
| `BugBountyReport.json` | BugBountyReport | `source` (enum), `url`, `has_poc`, `title` |
| `CPEInfo.json` | CPEInfo | `cpe_string`, `vendor`, `product`, `version` |
| `ReportEntry.json` | ReportEntry | `cve_info`, `exploits`, `labs`, `bb_reports`, `generated_at` |
| `MultiReport.json` | MultiReport | `entries` (dict of CVE ID -> ReportEntry), `generated_at` |

### Enum Values Reference

**CVSSVersion**: `2.0`, `3.0`, `3.1`, `4.0`, `unknown`

**Severity**: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `UNKNOWN`

**CVEState**: `PUBLISHED`, `RESERVED`, `REJECTED`, `UNKNOWN`

**ExploitSource**: `github`, `exploitdb`, `metasploit`, `nuclei`, `trickest`, `nomi-sec`, `other`

**LabPlatform**: `hackthebox`, `tryhackme`, `vulhub`, `other`

**BugBountySource**: `hackerone`, `pentesterland`, `bugbounty_hunting`, `other`

**MSFRank**: `excellent`, `great`, `good`, `normal`, `average`, `low`, `manual`, `unknown`

### Using Schemas in Agent Context

Provide these schema files to your AI agent at initialization so it understands:
1. What fields to expect from tool outputs
2. How to parse and validate responses
3. What data is available for synthesis

Example system prompt addition:
```
You have access to vulnerability intelligence tools. The data models use these schemas:
- CVEInfo: {cve_id, description, cvss: {base_score, severity, version, vector_string}, epss, kev_status, cwes, references, vendor, product}
- Exploit: {source, url, title, language, stars, forks, command}
- LabEnvironment: {platform, name, url, setup_instructions}
- BugBountyReport: {source, url, has_poc, title}
```

## Direct Python API for Agents

When running as an embedded Python agent (not via MCP):

```python
from pocmap.services.cve_service import CVEService
from pocmap.services.exploit_service import ExploitService
from pocmap.services.lab_service import LabService
from pocmap.services.bb_service import BugBountyService
from pocmap.services.report_service import ReportService
from pocmap.models import export_schemas, CVEInfo, Exploit
from pocmap.bugbounty.playbooks import load_playbook

# Initialize services
cve_svc = CVEService()
exploit_svc = ExploitService()
lab_svc = LabService()
bb_svc = BugBountyService()
report_svc = ReportService()

# Look up CVE
info: CVEInfo = cve_svc.get_cve_info("CVE-2021-44228")

# Find exploits
exploits: list[Exploit] = exploit_svc.find_exploits("CVE-2021-44228")

# Generate report
report = report_svc.generate_report("CVE-2021-44228")

# Load playbook
playbook = load_playbook("cve-assessment")
```

## Resource URIs

When the MCP client supports resources, use these URI patterns:

- `cve://CVE-2021-44228` -> Full CVE details as formatted text
- `exploits://CVE-2021-44228` -> All exploits formatted as numbered list
- `report://CVE-2021-44228` -> Complete JSON report

## Best Practices for Agents

1. **Always validate CVE IDs** before calling tools - malformed IDs waste API calls
2. **Call lookup_cve first** - it provides the broadest information
3. **Handle None values** - EPSS, KEV, and exploit counts may be missing
4. **Parallelize independent calls** - lookup_cve, find_github_pocs, find_bug_bounty_reports are independent
5. **Synthesize don't dump** - Summarize findings rather than returning raw JSON to users
6. **Provide actionable recommendations** - Always conclude with clear next steps based on CVSS + EPSS + KEV
7. **Use playbooks for complex workflows** - They provide structured guidance
8. **Respect rate limits** - Cache results when possible, especially for bulk operations
