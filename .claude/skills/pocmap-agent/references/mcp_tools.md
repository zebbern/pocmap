# PocMap MCP Tools Reference

All **22** MCP tools for vulnerability research, exploit discovery, and report generation.
This file is the **canonical MCP / agent consumption guide** (not `AGENTS.md`).

**Start the server:** `uvx --from pocmap[server] pocmap-mcp` (or installed `pocmap-mcp` /
`python -m pocmap.mcp_server`). Implementation: `src/pocmap/mcp/` (facade
`src/pocmap/mcp_server.py`; `mcp.server.mcpserver.MCPServer`, mcp SDK 2.x). Tools
return **dicts** (`structuredContent`), not JSON strings.

Common types: **Exploit**=`{source,url,title,language,stars,forks,rank,command}`
(`language`/`stars`/`forks` are `null` for every non-GitHub source; `rank` is set only
for Metasploit; `command` is set only for the Metasploit/ExploitDB/Nuclei sources);
**BugBountyReport**=`{source,url,has_poc,title}`; **LabEnvironment**=`{platform,name,url}`;
**SourceStatus**=`{source,status,count,retryable[,category,detail]}` —
`status` ∈ `ok|empty|rate_limited|error`;
**ReportEntry**=`{cve_info,exploits,labs,bb_reports,sources}`;
**RecentExploitResult**=`{cve_info,has_poc,poc_sources,discovered_at}`.

> **Normalized CVE shape (all MCP CVE payloads).** `lookup_cve`,
> `discover_product_cves`, `generate_json_report` entries, and
> `find_recent_exploits` `cve_info` all use the MCP normalizer: `cvss.score`,
> `epss_score` on a **0.0–1.0** scale, `references` as a **list**, plus
> `affected_products`. The `min_epss` *filter* on `find_recent_exploits` stays
> on the **0–100** scale (input only).

---
## Core CVE Tools

### lookup_cve
**Purpose**: Look up a CVE by ID and return comprehensive metadata.
**When to use**: First step for any CVE investigation. Provides description, CVSS, EPSS, KEV, CWEs, references, vendor/product.
**Parameters**:
- `cve_id` (str, required): CVE identifier, e.g. `"CVE-2021-44228"`
**Returns**: JSON with `id`, `description`, `cvss` (`version`, **`score`**, `severity`, `vector_string`), **`epss_score`** (0.0-1.0), `kev_status`, `cwes` (list), `references` (list), `vendor`, `product`, `affected_products` (list of `{vendor,product}`), `publication_date`, `state`.
**Example**:
```json
{"id": "CVE-2021-44228", "description": "Apache Log4j2 JNDI...",
 "cvss": {"version": "3.1", "score": 10.0, "severity": "CRITICAL",
  "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
 "epss_score": 0.975, "kev_status": true, "cwes": ["CWE-20", "CWE-400"],
 "references": ["https://logging.apache.org/log4j/2.x/security.html"],
 "vendor": "Apache", "product": "Log4j2",
 "affected_products": [{"vendor": "apache", "product": "log4j"},
  {"vendor": "fedoraproject", "product": "fedora"}],
 "publication_date": "2021-12-10", "state": "PUBLISHED"}
```
> **Note**: the score key is `cvss.score`, not `cvss.base_score`, and the EPSS key is
> `epss_score` on a 0.0-1.0 scale. `vendor`/`product` are only the *first* of
> `affected_products` — check the full list to answer "does this affect X?".
> On failure the tool returns the error envelope instead (`error`, `error_type`,
> `category`, `retryable`, `context`, `cve_id`).
### check_kev_status
**Purpose**: Check if a CVE is in the CISA KEV catalog.
**When to use**: To determine exploitation risk. KEV means actively exploited in the wild.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `kev_status` (bool), `in_kev_catalog` (bool, same value), `description` (what the KEV catalog is), `recommendation` (actionable text).
**Example**:
```json
{"cve_id": "CVE-2021-44228", "kev_status": true, "in_kev_catalog": true,
 "description": "CISA Known Exploited Vulnerabilities (KEV) catalog lists vulnerabilities that have been actively exploited in the wild.",
 "recommendation": "PRIORITIZE FOR IMMEDIATE PATCHING - this CVE is actively exploited."}
```
> **Note**: there is no `date_added`, `due_date`, `vendor` or `product` here — the tool
> reports membership only. On an upstream failure it returns the error envelope rather
> than `kev_status: false`, so a `false` is a real "not in KEV".
### get_epss_score
**Purpose**: Get the EPSS score for a CVE.
**When to use**: To assess probability of exploitation in the next 30 days. Use alongside CVSS for risk prioritization.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `epss_score` (float, **0.0-1.0**, or `null`), `risk_level` (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`, or `UNKNOWN`), `available` (bool), `interpretation` (guidance text).
**Example**:
```json
{"cve_id": "CVE-2021-44228", "epss_score": 0.97543, "risk_level": "CRITICAL",
 "available": true,
 "interpretation": "EPSS > 0.9: patch immediately. EPSS > 0.5: high priority. EPSS > 0.2: medium priority. EPSS <= 0.2: lower priority."}
```
> **Note**: EPSS is 0.0-1.0 scale here. Multiply by 100 for percentage. There is no
> `percentile` or `date` field. `risk_level` thresholds: `>0.9` CRITICAL, `>0.5` HIGH,
> `>0.2` MEDIUM, else LOW. `available: false` (with `epss_score: null`) means the lookup
> succeeded but the CVE has no EPSS data; an upstream failure returns the error envelope instead.
### get_attack_techniques
**Purpose**: MITRE ATT&CK techniques a CVE maps to.
**When to use**: When the user asks how a vulnerability would actually be exploited, what
to detect or hunt for, or how to prioritize defensively. ATT&CK technique IDs are
actionable where `lookup_cve`'s CWEs are not.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `total_count`, `coverage_note`, and `techniques` (ordered
exploitation-first), each `{technique_id, name, mapping_type, comment, url, references}`.
`mapping_type` is `exploitation_technique` (how the CVE itself is exploited),
`primary_impact` or `secondary_impact` (what the attacker achieves next).
**Example**:
```json
{"cve_id": "CVE-2021-44228", "total_count": 5,
 "techniques": [{"technique_id": "T1190", "name": "Exploit Public-Facing Application",
   "mapping_type": "exploitation_technique",
   "comment": "This remote code execution vulnerability is exploited through maliciously-crafted requests...",
   "url": "https://attack.mitre.org/techniques/T1190/", "references": ["..."]}]}
```
> **An empty list means UNMAPPED, not harmless.** Mappings are expert-curated over the
> CISA KEV catalogue, so most CVEs have none. pocmap deliberately does not infer
> techniques from CWEs — that chain was measured against the curated data and produced
> unrelated results — so nothing is returned rather than a guess. Sub-technique URLs use
> the parent path (`T1505.003` -> `/techniques/T1505/003/`).
### cve_to_cpe
**Purpose**: Convert a CVE to CPE identifiers.
**When to use**: To identify affected product configurations or for CPE-based asset correlation.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `total_count`, `cpes` (list of `CPEInfo`: `cpe`, `vendor`, `product`, `version`).
**Example**:
```json
{"cve_id": "CVE-2021-44228", "total_count": 1,
 "cpes": [{"cpe": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
  "vendor": "apache", "product": "log4j", "version": "2.0"}]}
```
### cpe_to_cve
**Purpose**: Convert a CPE to CVE identifiers.
**When to use**: When you have a product/version CPE string and want all affecting CVEs.
**Parameters**:
- `cpe` (str, required): CPE 2.3 URI, e.g. `"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"`
**Returns**: JSON with `cpe` (str), `total_count`, `cve_ids` (list of CVE ID strings).
**Example**:
```json
{"cpe": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "total_count": 3,
 "cve_ids": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"]}
```
---
## Exploit Discovery Tools

### find_github_pocs
**Purpose**: Find PoC exploits for a CVE on GitHub.
**When to use**: When you need working exploit code for testing. Always verify before running.
**Parameters**:
- `cve_id` (str, required): CVE identifier
- `limit` (int, default `10`): Maximum results
**Returns**: JSON with `cve_id`, `total_count`, `pocs` (list of **Exploit** — the key is
`pocs`, not `exploits`), and `sources` (per-source health).
**Example**:
```json
{"cve_id": "CVE-2021-44228", "total_count": 1,
 "pocs": [{"source": "github",
  "url": "https://github.com/user/CVE-2021-44228-PoC",
  "title": "Log4j RCE PoC", "language": "Java", "stars": 1200, "forks": 300,
  "rank": null, "command": null}],
 "sources": [{"source": "github", "status": "ok", "count": 1, "retryable": false}]}
```
> **Always read `sources` before concluding "no PoCs exist."** Each entry is
> `{source, status, count, retryable}` plus `category` and `detail` when something went
> wrong. `status` is one of `ok` (responded, >=1 result), `empty` (responded, 0 results),
> `rate_limited` (throttled — retry, or set `GITHUB_API_TOKEN`), or `error` (network/HTTP
> failure). An empty `pocs` with `status: "rate_limited"` means *unknown*, not *none*.
>
> Results union the Nomi-sec and TrickestCVE indexes, deduped, aggregator repos filtered.
> **Trust the order**: sorting happens *before* metadata enrichment, so Trickest-only
> entries (which arrive with no star/language data) always sort last regardless of their
> true popularity — treat a trailing entry with `stars: null`/`language: null` as an
> unverified lead, not a known PoC. `limit` is also applied before enrichment, which costs
> one GitHub API call per repo against an unauthenticated budget of 60/hour; request only
> what you will use.
### find_metasploit_module
**Purpose**: Find a Metasploit module for a CVE.
**When to use**: When you need a tested exploit framework module with payloads and auxiliary capabilities.
**Parameters**:
- `cve_id` (str, required): CVE identifier
- `limit` (int, default `1`): Maximum results to scan (1-10)
**Returns**: JSON with `cve_id`, `found` (bool), `module` (**Exploit** or `null`), `note`.
The `url` is the Rapid7 module page; `title` is the module fullname; `command` is the
ready-to-run msfconsole invocation; `rank` is the reliability rating.
**Example**:
```json
{"cve_id": "CVE-2021-44228", "found": true,
 "module": {"source": "metasploit",
  "url": "https://www.rapid7.com/db/modules/exploit/multi/http/log4shell_header_injection",
  "title": "exploit/multi/http/log4shell_header_injection",
  "language": null, "stars": null, "forks": null, "rank": "excellent",
  "command": "msfconsole -q -x 'use exploit/multi/http/log4shell_header_injection'"},
 "note": "Metasploit module available - indicates mature, reliable exploit code."}
```
### find_exploitdb_entry
**Purpose**: Find an ExploitDB entry for a CVE.
**When to use**: When you need a standalone exploit script from the Offensive Security database.
**Parameters**:
- `cve_id` (str, required): CVE identifier
- `limit` (int, default `1`): Maximum results to scan (1-10)
**Returns**: JSON with `cve_id`, `found` (bool), `entry` (**Exploit** or `null`), `note`.
`title` is the exploit's path within the ExploitDB repo (not a prose title); `command` is
the searchsploit invocation that mirrors the exploit locally.
**Example**:
```json
{"cve_id": "CVE-2021-44228", "found": true,
 "entry": {"source": "exploitdb",
  "url": "https://www.exploit-db.com/exploits/50592",
  "title": "exploits/java/remote/50592.py",
  "language": null, "stars": null, "forks": null, "rank": null,
  "command": "searchsploit -m 50592"},
 "note": "ExploitDB entry available - often the first standalone exploit published."}
```
### find_nuclei_template
**Purpose**: Find a Nuclei template for a CVE.
**When to use**: When you need an automated detection template for scanning at scale or CI/CD.
**Parameters**:
- `cve_id` (str, required): CVE identifier
- `limit` (int, default `1`): Maximum results to scan (1-10)
**Returns**: JSON with `cve_id`, `found` (bool), `template` (**Exploit** or `null`), `note`.
`url` is the ProjectDiscovery cloud library page; `title` is the template path; `command`
is the nuclei invocation (`null` when the template path is unknown).
**Example**:
```json
{"cve_id": "CVE-2021-44228", "found": true,
 "template": {"source": "nuclei",
  "url": "https://cloud.projectdiscovery.io/library/CVE-2021-44228",
  "title": "http/cves/2021/CVE-2021-44228.yaml",
  "language": null, "stars": null, "forks": null, "rank": null,
  "command": "nuclei -t http/cves/2021/CVE-2021-44228.yaml [-u <target>]"},
 "note": "Nuclei template available - can be used for rapid detection/verification."}
```
> **Note on all three DB tools**: `language`, `stars` and `forks` are always `null` — those
> are GitHub-repo metadata and these sources are not GitHub repos. `limit` bounds how many
> entries *of that source* are considered; the three tools are independent, so a Metasploit
> hit never suppresses the ExploitDB entry or Nuclei template.
---
## Bug Bounty & Lab Tools

### find_bug_bounty_reports
**Purpose**: Find bug bounty reports for a CVE.
**When to use**: When researching real-world exploitation or preparing bug bounty submissions.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `total_count`, `reports` (list of **BugBountyReport**).
**Example**:
```json
{"cve_id": "CVE-2021-44228", "total_count": 1,
 "reports": [{"source": "hackerone",
  "url": "https://hackerone.com/reports/1425474",
  "has_poc": true, "title": "Log4Shell RCE in Production"}]}
```
> **Note**: `source` is a lowercase enum value — `hackerone`, `pentesterland`,
> `bugbounty_hunting`, or `other`.
### find_practice_labs
**Purpose**: Find practice lab environments for a CVE.
**When to use**: For hands-on practice in a safe, controlled environment.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `total_count`, `labs` (list of **LabEnvironment**).
**Example**:
```json
{"cve_id": "CVE-2021-44228", "total_count": 2,
 "labs": [{"platform": "hackthebox", "name": "LogForge",
  "url": "https://app.hackthebox.com/machines/LogForge"},
]}
```
> **Note**: `platform` is a lowercase enum value — `vulhub`, `hackthebox` or `other`
> (not `HackTheBox`). Match on the lowercase form. pocmap no longer queries TryHackMe;
> its room index was never published, so every lookup returned a misleading "no room". `setup_instructions`
> is *not* included here; use `find_vulhub_docker` for Docker setup steps.
### find_vulhub_docker
**Purpose**: Find a Vulhub Docker environment for a CVE.
**When to use**: When you need a reproducible Docker-based lab for local testing.
**Parameters**:
- `cve_id` (str, required): CVE identifier
**Returns**: JSON with `cve_id`, `found` (bool), `url` (str or `null`), and `setup_instructions` (`clone`, `navigate`, `start`, `stop` commands) when found.
**Example**:
```json
{"cve_id": "CVE-2021-44228", "found": true,
 "url": "https://github.com/vulhub/vulhub/tree/master/log4j/CVE-2021-44228",
 "setup_instructions": {
  "clone": "git clone --depth 1 https://github.com/vulhub/vulhub.git",
  "navigate": "cd vulhub/log4j/CVE-2021-44228",
  "start": "docker compose up -d", "stop": "docker compose down"}}
```
---
## Report Generation Tools

### generate_json_report
**Purpose**: Everything known about one or more CVEs, in a single call.
**When to use**: **Default entry point for any question about known CVE IDs.** One round
trip covering CVE details, all registered exploit sources (built-ins + plugins), labs,
and bug bounty reports. Takes comma-separated IDs for compare/prioritize. Drill into a
single-purpose tool afterwards only when you need one source in isolation.
**Parameters**:
- `cve_ids` (str, required): Comma-separated CVE IDs, e.g. `"CVE-2021-44228,CVE-2021-45046"`
**Returns**: JSON with `generated_at`, `total_requested`, `total_entries`, `total_errors`,
`entries` (list of **ReportEntry**), and `errors` (list of `{cve_id, error}` for CVEs whose
lookup failed). Each entry is `{cve_info, exploits, labs, bb_reports, sources}` —
normalized `cve_info` (`cvss.score`, `epss_score` 0.0–1.0); `exploits` from
`ExploitService.find_exploits_with_status` (includes plugins); **always read `sources`**
before treating an empty exploit list as "none found".
**Example**:
```json
{"generated_at": "2024-01-15T09:30:00Z", "total_requested": 1,
 "total_entries": 1, "total_errors": 0,
 "entries": [{
   "cve_info": {"id": "CVE-2021-44228", "description": "Apache Log4j2 JNDI...",
     "cvss": {"version": "3.1", "score": 10.0, "severity": "CRITICAL",
      "vector_string": "CVSS:3.1/AV:N/..."},
     "epss_score": 0.975, "kev_status": true, "cwes": ["CWE-20"],
     "references": [], "vendor": "Apache", "product": "Log4j2",
     "affected_products": [], "publication_date": "2021-12-10", "state": "PUBLISHED"},
   "exploits": [], "labs": [], "bb_reports": [],
   "sources": [{"source": "github", "status": "ok", "count": 0, "retryable": false},
    {"source": "db", "status": "empty", "count": 0, "retryable": false}]}],
 "errors": []}
```
> **Note**: more than 100 CVEs returns `{"error": ..., "category": "invalid_input"}`.
> Collection is sequential server-side (not concurrent).
### generate_html_report
**Purpose**: Generate a styled HTML report for multiple CVEs.
**When to use**: When you need a human-readable, shareable report for stakeholders.
**Parameters**:
- `cve_ids` (str, required): Comma-separated CVE IDs
**Returns**: JSON with `format`="html", `content` (HTML string), `cve_count` (int), and
`status` — which is the literal string **`"ok"`**, not `"success"`.
**Example**:
```json
{"format": "html", "content": "<!DOCTYPE html>...",
 "cve_count": 2, "status": "ok"}
```
> **Note**: `cve_count` counts the CVEs *requested*, not the ones that resolved — a failed
> lookup is rendered as an error row in the HTML but still counted. More than 100 CVEs
> returns `{"error": ..., "category": "invalid_input"}`.
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
**Returns**: JSON with `success` (bool), `total` (int), `query` (the echoed filter
parameters), and `cves` (list of **RecentExploitResult**). There is no `results` key and no
`metadata` block.
**Example**:
```json
{"success": true, "total": 1,
 "query": {"since": "24h", "from_date": null, "to_date": null,
  "only_with_poc": false, "kev_only": false, "min_epss": null,
  "severity": ["CRITICAL"], "sort": "cve_date", "limit": 50},
 "cves": [{
   "cve_info": {"id": "CVE-2024-1234", "description": "RCE in...",
     "cvss": {"version": "3.1", "score": 8.8, "severity": "HIGH",
      "vector_string": "CVSS:3.1/AV:N/..."},
     "epss_score": 0.45, "kev_status": false, "cwes": [],
     "references": ["https://nvd.nist.gov/..."],
     "vendor": "Acme", "product": "Widget", "publication_date": "2024-01-15",
     "state": "PUBLISHED", "affected_products": []},
   "has_poc": true, "poc_sources": ["github"],
   "discovered_at": "2024-01-16T09:30:00"}]}
```
> **Note**: each item nests the CVE under `cve_info` — nothing is hoisted to the item's top
> level. `cve_info` uses the **same normalizer** as `lookup_cve` (`cvss.score`,
> `epss_score` 0.0–1.0, `references` as a list). The `min_epss` *input filter* still uses
> the 0–100 scale (e.g. `50` = EPSS >= 50%). On failure the tool returns
> `{"success": false, "error": ...}`.
### discover_package_cves
**Purpose**: Find vulnerabilities in a software **package** (a dependency) and the exact releases that fix them.
**When to use**: Any question about a library, lockfile or SBOM entry — `requirements.txt`, `package.json`, `pom.xml`, `go.mod`, `Gemfile`, `Cargo.toml` — or "what should I upgrade to". This is the ONLY tool that returns fixed versions. It CANNOT answer questions about deployed products (nginx, Confluence, FortiOS): use `discover_product_cves` for those.
**Parameters**:
- `ecosystem` (str, required): `PyPI`, `npm`, `Go`, `Maven`, `crates.io`, `RubyGems`, `Packagist`, `NuGet`, `Hex`, `Pub`, or a distro (`Debian:12`, `Ubuntu:22.04`, `Alpine:v3.19`, `Red Hat`, `Bitnami`). Case-insensitive; normalized for you.
- `name` (str, required): Package name. Maven needs the full `groupId:artifactId` — a bare artifact matches nothing and looks falsely clean.
- `version` (str, default `""`): Installed version. Strongly recommended.
- `limit` (int, default `50`, max 500): Maximum advisories.
**Returns**: JSON with `ecosystem`, `package`, `version`, `total_found` (found, before `limit`), `returned`, `truncated`, `fixable_count`, `unfixed_count`, `search_sources` (only feeds that produced data), and `vulnerabilities` — ranked **CISA KEV > EPSS > CVSS**, each with `id`, `cve_ids`, `aliases`, `summary`, `severity`, `cvss_score` (0-10), `cvss_vector`, `epss_score` (**0.0-1.0**), `kev_status`, `fixed_versions`, `introduced_versions`, `has_fix`, `withdrawn`, `published`, `url`.

Four traps worth knowing:
1. `fixed_versions` usually lists SEVERAL releases — maintainers backport to every
   supported branch. Recommend the one on the user's own major version.
2. An empty list is NOT proof of safety: OSV returns the same empty body for an unknown
   package as for a clean one. Check the spelling first.
3. `fixed_versions: []` means no fix is published — the user needs a workaround, not an
   upgrade. Say so explicitly.
4. `cvss_score` is `null` for a CVSS 4.0-only advisory (pocmap does not score 4.0);
   `severity` still carries the publisher's rating.

**Example**:
```json
{"ecosystem": "Maven", "package": "org.apache.logging.log4j:log4j-core",
 "version": "2.14.1", "total_found": 7, "fixable_count": 7, "unfixed_count": 0,
 "search_sources": ["osv", "epss", "cisa_kev"],
 "vulnerabilities": [
   {"id": "GHSA-jfh8-c2jp-5v3q", "cve_ids": ["CVE-2021-44228"],
    "severity": "CRITICAL", "cvss_score": 10.0, "epss_score": 0.9999,
    "kev_status": true, "fixed_versions": ["2.15.0", "2.3.1", "2.12.2"],
    "has_fix": true, "url": "https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q"}]}
```

### discover_product_cves
**Purpose**: Discover CVEs affecting a specific product and version.
**When to use**: When assessing a product's vulnerability landscape. Supports aliases (e.g., `"struts"` -> `"Apache Struts"`).
**Parameters**:
- `product` (str, required): Product name. Supports aliases.
- `version` (str, default `""`): `"2.x"`, `"2.14.1"`, `"v2.14.1"`
- `vendor` (str, default `""`): Vendor name for disambiguation
- `limit` (int, default `50`): Maximum results
**Returns**: JSON with `query`, `normalized_vendor`, `normalized_product`, `version_constraint` (object or `null`), `total_found`, `search_sources`, `matched_cpes`, `confirmed_affected`, `possibly_affected`, `not_enough_data` (each a list of full normalized CVE dicts, same shape as `lookup_cve`), and `summary` (`confirmed_count`, `possibly_count`, `unknown_count`).

`search_sources` says how the CVEs were found, and gates how much to trust the tiers:
`["nvd_cpe_match"]` = the product resolved to canonical CPEs (authoritative, and
`matched_cpes` lists them); `["nvd_keyword_search"]` = it did not, so this is a
full-text search over CVE descriptions — noisy and incomplete, and `matched_cpes` is empty.

**Example**:
```json
{"query": "struts", "normalized_vendor": "apache",
 "normalized_product": "apache struts",
 "version_constraint": {"major": 2, "minor": "x", "patch": null,
  "range_op": null, "raw": "2.x", "is_wildcard": true},
 "total_found": 3,
 "search_sources": ["nvd_cpe_match"],
 "matched_cpes": ["cpe:2.3:*:apache:struts"],
 "confirmed_affected": [{"id": "CVE-2023-50164", "description": "...",
  "cvss": {"version": "3.1", "score": 9.8, "severity": "CRITICAL",
   "vector_string": "CVSS:3.1/AV:N/..."}, "epss_score": 0.94,
  "kev_status": true, "vendor": "Apache", "product": "Struts",
  "affected_products": [{"vendor": "apache", "product": "struts"}]}],
 "possibly_affected": [], "not_enough_data": [],
 "summary": {"confirmed_count": 1, "possibly_count": 0, "unknown_count": 0}}
```
---
## Playbook Tools

All three take **no parameters** and return the playbook JSON file verbatim. They share one
shape: playbook metadata at the top level plus `phases`, where every phase is
`{phase_id, name, description, estimated_time_minutes, steps}` and every **step is an
object**, not a string:

```json
{"step_id": "1.1",
 "description": "Review bug bounty program rules and scope",
 "action": "Read program policy page. Document in-scope domains, IPs, and wildcard patterns...",
 "tools": ["browser"], "output": "scope_notes.md", "priority": "P0",
 "tips": "Screenshot the scope page - it may change."}
```

`step_id`, `description`, `action`, `tools` and `priority` (`P0`-`P4`) are present on every
step; the remaining keys vary by playbook (see each entry below). Common top-level metadata:
`$schema`, `name`, `description`, `version`, `author`, `created`, `difficulty`,
`estimated_time_hours`, `prerequisites`, `phases`.

### get_cve_assessment_playbook
**Purpose**: Retrieve the structured CVE assessment playbook (6 phases).
**When to use**: When you need a methodical approach to evaluating a CVE.
**Parameters**: None
**Returns**: The playbook JSON. Steps additionally carry `output` and `tips`. Extra top-level
keys: `checklist_references`, `templates`, `Escalation_rules`.
**Example** (abridged):
```json
{"name": "CVE Assessment Playbook", "difficulty": "intermediate",
 "estimated_time_hours": 4, "prerequisites": ["..."],
 "phases": [{"phase_id": "1", "name": "Scope Preparation",
   "description": "Prepare and validate bug bounty scope",
   "estimated_time_minutes": 30,
   "steps": [{"step_id": "1.1", "description": "Review bug bounty program rules and scope",
     "action": "Read program policy page...", "tools": ["browser"],
     "output": "scope_notes.md", "priority": "P0", "tips": "..."}]}]}
```
### get_rapid_response_playbook
**Purpose**: Retrieve the rapid response playbook for critical CVEs.
**When to use**: For zero-day or critical CVE situations requiring accelerated response.
**Parameters**: None
**Returns**: The playbook JSON. Steps additionally carry `command`, `output`,
`time_limit_minutes`, `tips` and `go_no_go_criteria` — this is the time-boxed playbook, so
honour `time_limit_minutes`. Extra top-level keys: `trigger_conditions`, `goal`,
`time_budget`, `speed_optimization`, `risk_mitigation`.
### get_bug_bounty_playbook
**Purpose**: Retrieve the bug bounty submission playbook.
**When to use**: When preparing bug bounty reports -- guides disclosure, PoC creation, and report writing.
**Parameters**: None
**Returns**: The playbook JSON. Steps additionally carry `checklist` and `failure_action`.
Extra top-level keys: `trigger_conditions`, `supported_platforms`,
`report_quality_checklist`, `common_pitfalls`, `Escalation_contacts`.
---
## Quick Lookup Table (22 tools)

| # | Tool | Category | Required Param | Key Optional Params |
|---|------|----------|---------------|---------------------|
| 1 | `lookup_cve` | Core | `cve_id` | -- |
| 2 | `check_kev_status` | Core | `cve_id` | -- |
| 3 | `get_epss_score` | Core | `cve_id` | -- |
| 4 | `get_attack_techniques` | Core | `cve_id` | -- |
| 5 | `cve_to_cpe` | Core | `cve_id` | -- |
| 6 | `cpe_to_cve` | Core | `cpe` | -- |
| 7 | `find_github_pocs` | Exploit | `cve_id` | `limit` (default 10) |
| 8 | `verify_github_pocs` | Exploit | `cve_id` | `limit` (default 5); needs opt-in env |
| 9 | `find_metasploit_module` | Exploit | `cve_id` | `limit` (default 1) |
| 10 | `find_exploitdb_entry` | Exploit | `cve_id` | `limit` (default 1) |
| 11 | `find_nuclei_template` | Exploit | `cve_id` | `limit` (default 1) |
| 12 | `find_bug_bounty_reports` | Research | `cve_id` | -- |
| 13 | `find_practice_labs` | Labs | `cve_id` | -- |
| 14 | `find_vulhub_docker` | Labs | `cve_id` | -- |
| 15 | `generate_json_report` | Report | `cve_ids` (CSV) | -- |
| 16 | `generate_html_report` | Report | `cve_ids` (CSV) | -- |
| 17 | `find_recent_exploits` | Discovery | -- | `since`, `only_with_poc`, `kev_only`, `min_epss` |
| 18 | `discover_product_cves` | Discovery | `product` | `version`, `vendor`, `limit` |
| 19 | `discover_package_cves` | Discovery | `ecosystem`, `name` | `version`, `limit` |
| 20 | `get_cve_assessment_playbook` | Playbook | -- | -- |
| 21 | `get_rapid_response_playbook` | Playbook | -- | -- |
| 22 | `get_bug_bounty_playbook` | Playbook | -- | -- |

## Resources (3) & Prompts (3)

| Kind | Name | URI / args |
|------|------|------------|
| Resource | `cve_info` | `cve://{cve_id}` (text) |
| Resource | `cve_exploits` | `exploits://{cve_id}` (text) |
| Resource | `cve_report` | `report://{cve_id}` (JSON) |
| Prompt | `vulnerability_assessment` | `cve_id` |
| Prompt | `exploit_research` | `cve_id`, `focus_area` |
| Prompt | `bug_bounty_analysis` | `cve_id` |

## Error envelope

On failure tools return a dict with `error`, `error_type`, `category`, `retryable`,
`context` (and never success keys like `total_count: 0` / `kev_status: false` that would
look like a real answer). Categories: `not_found`, `rate_limited`, `offline`,
`network_error`, `invalid_input`, `permission_error`, `not_enabled`, `unknown`.
