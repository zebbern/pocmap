# PocMap MCP Tools Reference

All 19 MCP tools for vulnerability research, exploit discovery, and report generation.

Common types: **Exploit**=`{source,url,title,language,stars,forks}`; **BugBountyReport**=`{source,url,has_poc,title}`; **LabEnvironment**=`{platform,name,url}`; **ReportEntry**=`{cve_id,description,cvss_score,severity,epss,kev,exploits,references}`; **RecentExploitResult**=`{cve_id,description,severity,epss,has_poc,in_kev,published_date}`.

---
## Core CVE Tools

### lookup_cve
**Purpose**: Look up a CVE by ID and return comprehensive metadata.
**When to use**: First step for any CVE investigation. Provides description, CVSS, EPSS, KEV, CWEs, references, vendor/product.
**Parameters**:
- `cve_id` (str, required): CVE identifier, e.g. `"CVE-2021-44228"`
**Returns**: JSON with `id`, `description`, `cvss` (`version`, `base_score`, `severity`, `vector_string`), `epss`, `kev_status`, `cwes` (list), `references` (list), `vendor`, `product`, `publication_date`, `state`.
**Example**:
```json
{"id": "CVE-2021-44228", "description": "Apache Log4j2 JNDI...",
 "cvss": {"version": "3.1", "base_score": 10.0, "severity": "CRITICAL",
  "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
 "epss": 0.975, "kev_status": true, "cwes": ["CWE-20", "CWE-400"],
 "references": ["https://logging.apache.org/log4j/2.x/security.html"],
 "vendor": "Apache", "product": "Log4j2", "publication_date": "2021-12-10",
 "state": "PUBLISHED"}
```
### check_kev_status
**Purpose**: Check if a CVE is in the CISA KEV catalog.
**When to use**: To determine exploitation risk. KEV means actively exploited in the wild.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `in_kev` (bool), `date_added`, `due_date`, `vendor`, `product` (nullable).
**Example**:
```json
{"cve_id": "CVE-2021-44228", "in_kev": true, "date_added": "2021-12-10",
 "due_date": "2021-12-24", "vendor": "Apache", "product": "Log4j"}
```
### get_epss_score
**Purpose**: Get the EPSS score for a CVE.
**When to use**: To assess probability of exploitation in the next 30 days. Use alongside CVSS for risk prioritization.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `epss_score` (float, **0.0-1.0**), `percentile` (float), `date`.
**Example**:
```json
{"cve_id": "CVE-2021-44228", "epss_score": 0.97543,
 "percentile": 0.999, "date": "2024-01-15"}
```
> **Note**: EPSS is 0.0-1.0 scale. Multiply by 100 for percentage.
### cve_to_cpe
**Purpose**: Convert a CVE to CPE identifiers.
**When to use**: To identify affected product configurations or for CPE-based asset correlation.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `cpes` (list of `CPEInfo`: `cpe23Uri`, `vendor`, `product`, `version`, `criteria`, `vulnerable` (bool)).
**Example**:
```json
{"cve_id": "CVE-2021-44228",
 "cpes": [{"cpe23Uri": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
  "vendor": "apache", "product": "log4j", "version": "2.0",
  "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "vulnerable": true}]}
```
### cpe_to_cve
**Purpose**: Convert a CPE to CVE identifiers.
**When to use**: When you have a product/version CPE string and want all affecting CVEs.
**Parameters**:
- `cpe_string` (str, required): CPE 2.3 URI, e.g. `"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"`
**Returns**: JSON with `cpe` (str), `cves` (list of CVE ID strings).
**Example**:
```json
{"cpe": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
 "cves": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"]}
```
---
## Exploit Discovery Tools

### find_github_pocs
**Purpose**: Find PoC exploits for a CVE on GitHub.
**When to use**: When you need working exploit code for testing. Always verify before running.
**Parameters**:
- `cve_id` (str, required): CVE identifier
- `limit` (int, default `10`): Maximum results
**Returns**: JSON with `cve_id`, `exploits` (list of **Exploit**).
**Example**:
```json
{"cve_id": "CVE-2021-44228",
 "exploits": [{"source": "github",
  "url": "https://github.com/user/CVE-2021-44228-PoC",
  "title": "Log4j RCE PoC", "language": "Java", "stars": 1200, "forks": 300}]}
```
### find_metasploit_module
**Purpose**: Find a Metasploit module for a CVE.
**When to use**: When you need a tested exploit framework module with payloads and auxiliary capabilities.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `found` (bool), `module` (**Exploit** or `null`).
**Example**:
```json
{"cve_id": "CVE-2021-44228", "found": true,
 "module": {"source": "metasploit",
  "url": "exploit/multi/http/log4shell_header_injection",
  "title": "Log4Shell HTTP Header Injection", "language": "Ruby",
  "stars": 0, "forks": 0}}
```
### find_exploitdb_entry
**Purpose**: Find an ExploitDB entry for a CVE.
**When to use**: When you need a standalone exploit script from the Offensive Security database.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `found` (bool), `exploit` (**Exploit** or `null`).
**Example**:
```json
{"cve_id": "CVE-2021-44228", "found": true,
 "exploit": {"source": "exploitdb",
  "url": "https://www.exploit-db.com/exploits/50592",
  "title": "Apache Log4j2 RCE", "language": "Python", "stars": 0, "forks": 0}}
```
### find_nuclei_template
**Purpose**: Find a Nuclei template for a CVE.
**When to use**: When you need an automated detection template for scanning at scale or CI/CD.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `found` (bool), `template` (**Exploit** or `null`).
**Example**:
```json
{"cve_id": "CVE-2021-44228", "found": true,
 "template": {"source": "nuclei", "url": "cves/2021/CVE-2021-44228.yaml",
  "title": "Apache Log4j2 RCE", "language": "YAML", "stars": 0, "forks": 0}}
```
---
## Bug Bounty & Lab Tools

### find_bug_bounty_reports
**Purpose**: Find bug bounty reports for a CVE.
**When to use**: When researching real-world exploitation or preparing bug bounty submissions.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `reports` (list of **BugBountyReport**).
**Example**:
```json
{"cve_id": "CVE-2021-44228",
 "reports": [{"source": "hackerone",
  "url": "https://hackerone.com/reports/1425474",
  "has_poc": true, "title": "Log4Shell RCE in Production"}]}
```
### find_practice_labs
**Purpose**: Find practice lab environments for a CVE.
**When to use**: For hands-on practice in a safe, controlled environment.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `labs` (list of **LabEnvironment**).
**Example**:
```json
{"cve_id": "CVE-2021-44228",
 "labs": [{"platform": "HackTheBox", "name": "LogForge",
  "url": "https://app.hackthebox.com/machines/LogForge"},
  {"platform": "TryHackMe", "name": "Log4j2 RCE",
  "url": "https://tryhackme.com/room/log4j2rce"}]}
```
### find_vulhub_docker
**Purpose**: Find a Vulhub Docker environment for a CVE.
**When to use**: When you need a reproducible Docker-based lab for local testing.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `found` (bool), `dockerfile_url` (str or `null`).
**Example**:
```json
{"cve_id": "CVE-2021-44228", "found": true,
 "dockerfile_url": "https://github.com/vulhub/vulhub/tree/master/log4j/CVE-2021-44228"}
```
---
## Report Generation Tools

### generate_json_report
**Purpose**: Generate a structured JSON report for multiple CVEs.
**When to use**: When you need structured data for dashboards or programmatic processing.
**Parameters**:
- `cve_ids` (str, required): Comma-separated CVE IDs, e.g. `"CVE-2021-44228,CVE-2021-45046"`
**Returns**: JSON with `entries` (list of **ReportEntry**) and `errors` (list of failed lookups).
**Example**:
```json
{"entries": [{"cve_id": "CVE-2021-44228", "description": "Apache Log4j2 JNDI...",
  "cvss_score": 10.0, "severity": "CRITICAL", "epss": 0.975, "kev": true,
  "exploits": [], "references": []}], "errors": []}
```
### generate_html_report
**Purpose**: Generate a styled HTML report for multiple CVEs.
**When to use**: When you need a human-readable, shareable report for stakeholders.
**Parameters**:
- `cve_ids` (str, required): Comma-separated CVE IDs
**Returns**: JSON with `format`="html", `content` (HTML string), `cve_count` (int), `status`.
**Example**:
```json
{"format": "html", "content": "<!DOCTYPE html>...",
 "cve_count": 2, "status": "success"}
```
---
## Discovery Tools

### find_recent_exploits
**Purpose**: Discover recently published CVEs with filters.
**When to use**: For daily vulnerability monitoring or threat intelligence.
**Parameters**:
- `since` (str, default `"24h"`): `"1h"`, `"24h"`, `"7d"`, `"30d"`
- `from_date` (str, default `""`): Start `"YYYY-MM-DD"` (overrides `since`)
- `to_date` (str, default `""`): End `"YYYY-MM-DD"`
- `only_with_poc` (bool, default `false`): Only CVEs with known PoCs
- `kev_only` (bool, default `false`): Only CISA KEV entries
- `min_epss` (float, default `0.0`): Minimum EPSS score (**0-100 scale**)
- `severity` (str, default `""`): `"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`
- `sort` (str, default `"cve_date"`): Sort field
- `limit` (int, default `50`): Maximum results
**Returns**: JSON with `results` (list of **RecentExploitResult**) and `metadata` (`total`, `time_range`).
**Example**:
```json
{"results": [{"cve_id": "CVE-2024-1234", "description": "RCE in...",
  "severity": "HIGH", "epss": 0.45, "has_poc": true, "in_kev": false,
  "published_date": "2024-01-15"}],
 "metadata": {"total": 1, "time_range": "2024-01-15 to 2024-01-16"}}
```
> **Note**: `min_epss` uses 0-100 scale (e.g., `50` = EPSS >= 50%). `get_epss_score` returns 0.0-1.0.
### discover_product_cves
**Purpose**: Discover CVEs affecting a specific product and version.
**When to use**: When assessing a product's vulnerability landscape. Supports aliases (e.g., `"struts"` -> `"Apache Struts"`).
**Parameters**:
- `product` (str, required): Product name. Supports aliases.
- `version` (str, default `""`): `"2.x"`, `"2.14.1"`, `"v2.14.1"`
- `vendor` (str, default `""`): Vendor name for disambiguation
- `limit` (int, default `50`): Maximum results
**Returns**: JSON with `query`, `normalized_vendor`, `normalized_product`, `confirmed_affected` (list), `possibly_affected` (list), `not_enough_data` (list).
**Example**:
```json
{"query": "struts", "normalized_vendor": "Apache",
 "normalized_product": "Struts",
 "confirmed_affected": ["CVE-2023-50164", "CVE-2021-31805"],
 "possibly_affected": ["CVE-2024-1234"],
 "not_enough_data": ["CVE-2023-9999"]}
```
---
## Playbook Tools

### get_cve_assessment_playbook
**Purpose**: Retrieve the structured CVE assessment playbook.
**When to use**: When you need a methodical approach to evaluating a CVE.
**Parameters**: None
**Returns**: JSON with `phases` (list of `{name, steps[]}`).
**Example**:
```json
{"phases": [
  {"name": "Initial Assessment",
   "steps": ["Identify CVE and affected versions",
    "Determine if in your environment", "Assess CVSS and EPSS"]},
  {"name": "Impact Analysis",
   "steps": ["Evaluate business impact",
    "Check CISA KEV status", "Review available exploits"]}
]}
```
### get_rapid_response_playbook
**Purpose**: Retrieve the rapid response playbook for critical CVEs.
**When to use**: For zero-day or critical CVE situations requiring accelerated response.
**Parameters**: None
**Returns**: JSON playbook with `phases` and `steps` for rapid response.
**Example**:
```json
{"phases": [
  {"name": "Immediate Triage (< 1h)",
   "steps": ["Confirm CVE and affected assets",
    "Check KEV and EPSS", "Activate IR if EPSS > 0.5 or in KEV"]},
  {"name": "Containment (< 4h)",
   "steps": ["Deploy interim mitigations", "Identify and patch systems"]}
]}
```
### get_bug_bounty_playbook
**Purpose**: Retrieve the bug bounty submission playbook.
**When to use**: When preparing bug bounty reports -- guides disclosure, PoC creation, and report writing.
**Parameters**: None
**Returns**: JSON playbook with `phases` and `steps` for bug bounty workflows.
**Example**:
```json
{"phases": [
  {"name": "Reconnaissance",
   "steps": ["Identify target scope and rules",
    "Map attack surface", "Research known CVEs for target"]},
  {"name": "Exploitation & PoC",
   "steps": ["Develop minimal reproducible PoC",
    "Document exploit chain", "Assess impact"]}
]}
```
---
## Quick Lookup Table

| # | Tool | Category | Required Param | Key Optional Params |
|---|------|----------|---------------|---------------------|
| 1 | `lookup_cve` | Core | `cve_id` | -- |
| 2 | `check_kev_status` | Core | `cve_id` | -- |
| 3 | `get_epss_score` | Core | `cve_id` | -- |
| 4 | `cve_to_cpe` | Core | `cve_id` | -- |
| 5 | `cpe_to_cve` | Core | `cpe_string` | -- |
| 6 | `find_github_pocs` | Exploit | `cve_id` | `limit` (default 10) |
| 7 | `find_metasploit_module` | Exploit | `cve_id` | -- |
| 8 | `find_exploitdb_entry` | Exploit | `cve_id` | -- |
| 9 | `find_nuclei_template` | Exploit | `cve_id` | -- |
| 10 | `find_bug_bounty_reports` | Bug Bounty | `cve_id` | -- |
| 11 | `find_practice_labs` | Bug Bounty | `cve_id` | -- |
| 12 | `find_vulhub_docker` | Bug Bounty | `cve_id` | -- |
| 13 | `generate_json_report` | Report | `cve_ids` (CSV) | -- |
| 14 | `generate_html_report` | Report | `cve_ids` (CSV) | -- |
| 15 | `find_recent_exploits` | Discovery | -- | `since`, `only_with_poc`, `kev_only`, `min_epss` |
| 16 | `discover_product_cves` | Discovery | `product` | `version`, `vendor` |
| 17 | `get_cve_assessment_playbook` | Playbook | -- | -- |
| 18 | `get_rapid_response_playbook` | Playbook | -- | -- |
| 19 | `get_bug_bounty_playbook` | Playbook | -- | -- |
