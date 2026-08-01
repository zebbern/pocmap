# MCP tools

Auto-generated from the registered PocMap MCP server (`python scripts/generate_mcp_docs.py`). Canonical agent guide with return-shape notes: `.claude/skills/pocmap-agent/references/mcp_tools.md`.

**22 tools** registered.

| Tool | Description |
|------|-------------|
| `check_kev_status` | Check if a CVE is listed in the CISA Known Exploited Vulnerabilities (KEV) catalog. |
| `cpe_to_cve` | Convert a CPE (Common Platform Enumeration) identifier to its associated CVEs. |
| `cve_to_cpe` | Convert a CVE ID to its associated CPE (Common Platform Enumeration) identifiers. |
| `discover_package_cves` | Find vulnerabilities in a software PACKAGE (a dependency) and the exact releases that fix them. |
| `discover_product_cves` | Discover CVEs affecting a product by name and version. |
| `find_bug_bounty_reports` | Find bug bounty reports and write-ups for a CVE. |
| `find_exploitdb_entry` | Find an ExploitDB entry for a CVE. |
| `find_github_pocs` | Find GitHub repositories containing Proof-of-Concept (PoC) exploits for a CVE. |
| `find_metasploit_module` | Find a Metasploit Framework module for a CVE. |
| `find_nuclei_template` | Find a Nuclei vulnerability scanner template for a CVE. |
| `find_practice_labs` | Find CTF (Capture The Flag) labs, vulnerable machines, and practice environments for a CVE. |
| `find_recent_exploits` | Find recently published CVEs with exploit and PoC intelligence. |
| `find_vulhub_docker` | Find a Vulhub Docker environment for a CVE. |
| `generate_html_report` | Generate a comprehensive HTML vulnerability report for one or more CVEs. |
| `generate_json_report` | START HERE for any question about one or more known CVE IDs. |
| `get_attack_techniques` | Get the MITRE ATT&CK techniques a CVE maps to — how it is exploited, and what the attacker achieves afterwards. |
| `get_bug_bounty_playbook` | Get the bug bounty submission playbook from finding to report submission. |
| `get_cve_assessment_playbook` | Get the complete CVE assessment playbook with detailed step-by-step workflow. |
| `get_epss_score` | Get the EPSS (Exploit Prediction Scoring System) score for a CVE. |
| `get_rapid_response_playbook` | Get the rapid response playbook for emergency critical CVE handling. |
| `lookup_cve` | Look up detailed information about a CVE (Common Vulnerabilities and Exposures) identifier. |
| `verify_github_pocs` | Read the SOURCE of the top GitHub PoC repositories for a CVE and report what each one actually contains, instead of trusting that a repo which mentions a CVE exploits it. |

## Tool details

### `check_kev_status`

Check if a CVE is listed in the CISA Known Exploited Vulnerabilities (KEV) catalog. The KEV catalog contains vulnerabilities that have been actively exploited in the wild. CVEs in the KEV catalog are mandated for patching by US federal agencies within specific timeframes. Use this tool to determine if a vulnerability is being actively exploited - KEV entries should be prioritized for immediate remediation regardless of CVSS score.

**Input schema**

```json
{
  "properties": {
    "cve_id": {
      "title": "Cve Id",
      "type": "string"
    }
  },
  "required": [
    "cve_id"
  ],
  "title": "check_kev_statusArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `cpe_to_cve`

Convert a CPE (Common Platform Enumeration) identifier to its associated CVEs. Given a software/hardware product identifier, this finds all known vulnerabilities affecting that product. Returns a list of CVE identifiers. Use this tool for vulnerability assessment of specific products - provide a CPE or product name to discover all CVEs that affect it. This is essential for asset-based vulnerability management.

**Input schema**

```json
{
  "properties": {
    "cpe": {
      "title": "Cpe",
      "type": "string"
    }
  },
  "required": [
    "cpe"
  ],
  "title": "cpe_to_cveArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `cve_to_cpe`

Convert a CVE ID to its associated CPE (Common Platform Enumeration) identifiers. CPEs are standardized identifiers for software and hardware products. This conversion helps identify the exact software versions and configurations that are affected by a vulnerability. Returns CPE 2.3 URIs with vendor, product, and version information. Use this tool for asset inventory correlation - map CVEs to actual products in your environment to determine exposure.

**Input schema**

```json
{
  "properties": {
    "cve_id": {
      "title": "Cve Id",
      "type": "string"
    }
  },
  "required": [
    "cve_id"
  ],
  "title": "cve_to_cpeArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `discover_package_cves`

Find vulnerabilities in a software PACKAGE (a dependency) and the exact releases that fix them. Use this whenever the user asks about a library, a dependency, a lockfile, an SBOM, or 'what should I upgrade to' — e.g. requirements.txt, package.json, pom.xml, go.mod, Gemfile, Cargo.toml. This is the ONLY pocmap tool that returns fixed versions; lookup_cve and discover_product_cves are keyed on CPE products and cannot answer 'what do I upgrade to'. Conversely this tool CANNOT answer questions about deployed products like nginx, Confluence or FortiOS — use discover_product_cves for those. Backed by OSV.dev (no API key, no NVD rate limit) and enriched with EPSS and CISA KEV, so results are ranked by real-world exploitation risk: KEV first, then EPSS, then CVSS. Always pass 'version' when the user knows it — OSV then returns only advisories that genuinely apply to that release instead of every one ever filed. Ecosystem is case-insensitive here ('pypi' works) and Maven names need the full 'groupId:artifactId'. Note fixed_versions often lists SEVERAL releases: maintainers backport a fix to each supported branch, so pick the one on the user's major version.

**Input schema**

```json
{
  "properties": {
    "ecosystem": {
      "title": "Ecosystem",
      "type": "string"
    },
    "name": {
      "title": "Name",
      "type": "string"
    },
    "version": {
      "default": "",
      "title": "Version",
      "type": "string"
    },
    "limit": {
      "default": 50,
      "title": "Limit",
      "type": "integer"
    }
  },
  "required": [
    "ecosystem",
    "name"
  ],
  "title": "discover_package_cvesArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `discover_product_cves`

Discover CVEs affecting a product by name and version. Use when the user provides a product name but not a specific CVE ID. Supports version wildcards like '2.x' and product aliases (e.g., 'struts' matches 'Apache Struts'). Results are grouped by confidence: confirmed_affected (vendor+product+version match), possibly_affected (vendor or product match but version unclear), and not_enough_data (insufficient product/version info). This tool searches the NVD database using keyword search and applies fuzzy product name matching and version constraint parsing for accurate results.

**Input schema**

```json
{
  "properties": {
    "product": {
      "title": "Product",
      "type": "string"
    },
    "version": {
      "default": "",
      "title": "Version",
      "type": "string"
    },
    "vendor": {
      "default": "",
      "title": "Vendor",
      "type": "string"
    },
    "limit": {
      "default": 50,
      "title": "Limit",
      "type": "integer"
    }
  },
  "required": [
    "product"
  ],
  "title": "discover_product_cvesArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `find_bug_bounty_reports`

Find bug bounty reports and write-ups for a CVE. Bug bounty reports provide real-world exploitation techniques, impact assessments, and detailed write-ups from security researchers who found the vulnerability in production. Returns reports from platforms like HackerOne, PentesterLand, and Bug Bounty Hunting with titles, URLs, and indicators of whether a Proof-of-Concept is included. Use this tool when you want to understand how a vulnerability is exploited in real-world scenarios, learn from security researchers' methodologies, or find detailed technical write-ups.

**Input schema**

```json
{
  "properties": {
    "cve_id": {
      "title": "Cve Id",
      "type": "string"
    }
  },
  "required": [
    "cve_id"
  ],
  "title": "find_bug_bounty_reportsArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `find_exploitdb_entry`

Find an ExploitDB entry for a CVE. ExploitDB is the ultimate archive of exploit code and proof-of-concepts. An entry typically contains working exploit code that can be downloaded and used directly. Returns the entry title, source URL on exploit-db.com, and searchsploit command. Use this tool when looking for standalone exploit scripts that can be run independently of frameworks like Metasploit. ExploitDB entries are often the first exploits published.

**Input schema**

```json
{
  "properties": {
    "cve_id": {
      "title": "Cve Id",
      "type": "string"
    },
    "limit": {
      "default": 1,
      "title": "Limit",
      "type": "integer"
    }
  },
  "required": [
    "cve_id"
  ],
  "title": "find_exploitdb_entryArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `find_github_pocs`

Find GitHub repositories containing Proof-of-Concept (PoC) exploits for a CVE. Returns a list of GitHub repos with titles, URLs, programming languages, star counts, fork counts, and relevance rankings. These repos often contain working exploit code, vulnerable applications for testing, detection scripts, and educational materials. Use this tool when the user wants to find exploit code, understand how a vulnerability is exploited, or find detection/remediation scripts on GitHub. Results are sorted by stars.

**Input schema**

```json
{
  "properties": {
    "cve_id": {
      "title": "Cve Id",
      "type": "string"
    },
    "limit": {
      "default": 10,
      "title": "Limit",
      "type": "integer"
    }
  },
  "required": [
    "cve_id"
  ],
  "title": "find_github_pocsArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `find_metasploit_module`

Find a Metasploit Framework module for a CVE. Metasploit is a widely-used penetration testing framework. If a module exists, it means the vulnerability can be reliably exploited using Metasploit's standardized interface. Returns the module title, source URL, and msfconsole command. Use this tool when assessing whether automated exploitation is possible, or when planning penetration tests. The existence of a Metasploit module indicates mature exploit code.

**Input schema**

```json
{
  "properties": {
    "cve_id": {
      "title": "Cve Id",
      "type": "string"
    },
    "limit": {
      "default": 1,
      "title": "Limit",
      "type": "integer"
    }
  },
  "required": [
    "cve_id"
  ],
  "title": "find_metasploit_moduleArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `find_nuclei_template`

Find a Nuclei vulnerability scanner template for a CVE. Nuclei is a fast, community-powered vulnerability scanner that uses YAML templates to detect security issues. If a template exists, you can use Nuclei to quickly scan for the vulnerability across your infrastructure. Returns the template title and source URL on GitHub. Use this tool when you need to detect or verify the presence of a vulnerability in your environment. Nuclei templates provide standardized, reliable detection.

**Input schema**

```json
{
  "properties": {
    "cve_id": {
      "title": "Cve Id",
      "type": "string"
    },
    "limit": {
      "default": 1,
      "title": "Limit",
      "type": "integer"
    }
  },
  "required": [
    "cve_id"
  ],
  "title": "find_nuclei_templateArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `find_practice_labs`

Find CTF (Capture The Flag) labs, vulnerable machines, and practice environments for a CVE. These labs provide safe, legal environments to practice exploiting the vulnerability. Returns labs from Vulhub (Docker-based) and HackTheBox. Each lab includes the platform name, challenge name, URL, and setup instructions. Use this tool when you want hands-on practice with a vulnerability, need to demonstrate exploitation safely, or want to build detection rules in a controlled environment.

**Input schema**

```json
{
  "properties": {
    "cve_id": {
      "title": "Cve Id",
      "type": "string"
    }
  },
  "required": [
    "cve_id"
  ],
  "title": "find_practice_labsArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `find_recent_exploits`

Find recently published CVEs with exploit and PoC intelligence. Scans the NVD for newly published vulnerabilities within a configurable time window, then enriches each CVE with CVSS scoring, CISA KEV status, and PoC availability from GitHub. Results can be filtered by severity, KEV status, minimum EPSS score, and PoC availability. Use this tool to stay on top of emerging threats, monitor vulnerability disclosures, or build daily/weekly security briefings. Time window can be specified as a relative string (e.g., '24h', '7d') or as explicit date range.

**Input schema**

```json
{
  "properties": {
    "since": {
      "default": "24h",
      "title": "Since",
      "type": "string"
    },
    "from_date": {
      "default": "",
      "title": "From Date",
      "type": "string"
    },
    "to_date": {
      "default": "",
      "title": "To Date",
      "type": "string"
    },
    "only_with_poc": {
      "default": false,
      "title": "Only With Poc",
      "type": "boolean"
    },
    "kev_only": {
      "default": false,
      "title": "Kev Only",
      "type": "boolean"
    },
    "min_epss": {
      "default": 0.0,
      "title": "Min Epss",
      "type": "number"
    },
    "severity": {
      "default": "",
      "title": "Severity",
      "type": "string"
    },
    "sort": {
      "default": "cve_date",
      "title": "Sort",
      "type": "string"
    },
    "limit": {
      "default": 50,
      "title": "Limit",
      "type": "integer"
    }
  },
  "title": "find_recent_exploitsArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `find_vulhub_docker`

Find a Vulhub Docker environment for a CVE. Vulhub provides pre-built Docker Compose environments for vulnerable applications, making it trivial to spin up a practice lab with 'docker compose up'. Returns the GitHub URL to the Vulhub directory containing the Docker files and setup instructions. Use this tool when you want the quickest way to set up a local practice environment for a vulnerability. Docker environments are isolated, reproducible, and easy to clean up.

**Input schema**

```json
{
  "properties": {
    "cve_id": {
      "title": "Cve Id",
      "type": "string"
    }
  },
  "required": [
    "cve_id"
  ],
  "title": "find_vulhub_dockerArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `generate_html_report`

Generate a comprehensive HTML vulnerability report for one or more CVEs. The report includes styled cards with CVE details (description, CVSS, EPSS, KEV status), all discovered exploits and PoCs with source badges, available practice labs, and bug bounty reports. The HTML is self-contained with embedded CSS for immediate viewing. Use this tool when creating human-readable reports for stakeholders, security teams, or documentation. The HTML report can be saved to a file and opened in any browser.

**Input schema**

```json
{
  "properties": {
    "cve_ids": {
      "title": "Cve Ids",
      "type": "string"
    }
  },
  "required": [
    "cve_ids"
  ],
  "title": "generate_html_reportArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `generate_json_report`

START HERE for any question about one or more known CVE IDs. Returns everything the individual tools return, in a single call: CVE details (description, CVSS, EPSS, KEV status), every discovered exploit and PoC across GitHub, Metasploit, ExploitDB and Nuclei, practice labs, and bug bounty reports. Prefer this over calling lookup_cve + find_github_pocs + find_metasploit_module + find_nuclei_template + check_kev_status + find_bug_bounty_reports + find_practice_labs separately — it is one round trip instead of seven. Each entry includes a sources block (per-source ok/empty/rate_limited/error) so an empty exploit list is never a silent negative. Accepts comma-separated IDs, so it also answers 'compare/prioritize these CVEs' in one call. Reach for the single-purpose tools afterwards only to drill into a specific source. Also suitable for automation, CI/CD, and dashboards.

**Input schema**

```json
{
  "properties": {
    "cve_ids": {
      "title": "Cve Ids",
      "type": "string"
    }
  },
  "required": [
    "cve_ids"
  ],
  "title": "generate_json_reportArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `get_attack_techniques`

Get the MITRE ATT&CK techniques a CVE maps to — how it is exploited, and what the attacker achieves afterwards. Use this when the user asks how a vulnerability would actually be used, what to detect or hunt for, or how to prioritize defensively; ATT&CK technique IDs are actionable in a way the CWEs from lookup_cve are not. Each technique carries a mapping_type: 'exploitation_technique' is how the CVE itself is exploited (what a detection engineer wants), while 'primary_impact'/'secondary_impact' are what follows. Each also carries the curator's explanation of why it applies. IMPORTANT: these are expert-curated mappings covering the CISA KEV catalogue, so an empty result is normal and means NO CURATED MAPPING EXISTS — it does not mean the CVE is harmless or unexploitable. Nothing is inferred: pocmap deliberately returns nothing rather than guessing from the CVE's CWEs, because that inference was measured against this data and produced unrelated results.

**Input schema**

```json
{
  "properties": {
    "cve_id": {
      "title": "Cve Id",
      "type": "string"
    }
  },
  "required": [
    "cve_id"
  ],
  "title": "get_attack_techniquesArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `get_bug_bounty_playbook`

Get the bug bounty submission playbook from finding to report submission. This playbook guides researchers through the complete bug bounty workflow: reconnaissance, vulnerability identification, PoC development, report writing, submission formatting, and follow-up communication. Use this tool when preparing a bug bounty report or learning the submission process.

**Input schema**

```json
{
  "properties": {},
  "title": "get_bug_bounty_playbookArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=False`

### `get_cve_assessment_playbook`

Get the complete CVE assessment playbook with detailed step-by-step workflow. This playbook guides AI agents through systematic evaluation of CVEs including context gathering, exploit landscape analysis, real-world impact assessment, risk prioritization, and actionable remediation recommendations. Use this tool when starting a comprehensive vulnerability assessment workflow.

**Input schema**

```json
{
  "properties": {},
  "title": "get_cve_assessment_playbookArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=False`

### `get_epss_score`

Get the EPSS (Exploit Prediction Scoring System) score for a CVE. EPSS is a probability score that predicts the likelihood a vulnerability will be exploited in the wild within the next 30 days. The returned score is on a 0.0--1.0 scale (e.g. 0.85 means 85%% probability). Higher scores mean greater risk. Use this tool when prioritizing vulnerability remediation - CVEs with EPSS > 0.5 should be patched urgently. EPSS complements CVSS by adding threat intelligence context.

**Input schema**

```json
{
  "properties": {
    "cve_id": {
      "title": "Cve Id",
      "type": "string"
    }
  },
  "required": [
    "cve_id"
  ],
  "title": "get_epss_scoreArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `get_rapid_response_playbook`

Get the rapid response playbook for emergency critical CVE handling. This playbook provides a fast-track workflow for CVEs with CRITICAL severity, high EPSS scores, or active KEV status. It includes immediate containment steps, rapid detection, emergency patching procedures, and stakeholder communication templates. Use this tool when dealing with an actively exploited or high-impact vulnerability.

**Input schema**

```json
{
  "properties": {},
  "title": "get_rapid_response_playbookArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=False`

### `lookup_cve`

Look up detailed information about a CVE (Common Vulnerabilities and Exposures) identifier. Returns the CVE description, CVSS scores, EPSS probability, KEV status, CWE identifiers, affected vendor/product, publication date, and reference links. Use this tool when the user provides a CVE ID and wants to understand what the vulnerability is about. The CVE ID must be in the format CVE-YYYY-NNNN+ (e.g. CVE-2021-44228). Data sources: NVD, CVE.org, CISA KEV catalog, EPSS.

**Input schema**

```json
{
  "properties": {
    "cve_id": {
      "title": "Cve Id",
      "type": "string"
    }
  },
  "required": [
    "cve_id"
  ],
  "title": "lookup_cveArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=True`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=True`

### `verify_github_pocs`

Read the SOURCE of the top GitHub PoC repositories for a CVE and report what each one actually contains, instead of trusting that a repo which mentions a CVE exploits it. Use this when it matters that a PoC is real — before telling a user 'working exploit code exists', or when find_github_pocs returned low-star results you cannot judge. Each repo gets a verdict: 'confirmed' (names the CVE in code AND ships runnable code), 'likely' (a writeup, no code), 'unverified' (has code but never names this CVE — unproven, not disproven), or 'unrelated' (an awesome-list / notes index). Only 'confirmed' claims the repo exploits the CVE. Also returns the language derived from file extensions, with no GitHub API calls. REQUIRES the operator to have set POCMAP_ALLOW_FETCH_POC_SOURCE=1, because it downloads third-party exploit code to disk; if unset the tool returns an error saying so — report that to the user rather than retrying.

**Input schema**

```json
{
  "properties": {
    "cve_id": {
      "title": "Cve Id",
      "type": "string"
    },
    "limit": {
      "default": 5,
      "title": "Limit",
      "type": "integer"
    }
  },
  "required": [
    "cve_id"
  ],
  "title": "verify_github_pocsArguments",
  "type": "object"
}
```

**Annotations:** `read_only_hint=False`, `destructive_hint=False`, `idempotent_hint=False`, `open_world_hint=True`

