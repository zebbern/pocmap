# PocMap: AI Agent Integration Guide

This document is designed specifically for AI agents (Claude, GPT, Cursor, etc.) integrating with the PocMap toolkit via the MCP server or Python API.

## Overview

PocMap provides 22 MCP tools, 3 resources, and 3 prompts for comprehensive vulnerability intelligence. All tools return JSON strings for reliable programmatic parsing.

**When to use this toolkit:**
- User asks about a specific CVE ID
- User needs to find exploit code or PoCs
- User wants to assess vulnerability risk or prioritize patching
- User is doing bug bounty research
- User needs CTF lab environments for practice
- User wants vulnerability reports in JSON or HTML format

## Connecting the MCP server

Recommended Claude Desktop / MCP client config ([`uv`](https://github.com/astral-sh/uv) on `PATH`):

```json
{
  "mcpServers": {
    "pocmap": {
      "command": "uvx",
      "args": ["--from", "pocmap[server]", "pocmap-mcp"],
      "env": {
        "GITHUB_API_TOKEN": "ghp_xxxxxxxxxxxx",
        "NVD_API_KEY": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      }
    }
  }
}
```

Alternatives after `pip install "pocmap[server]"`: command `pocmap-mcp` (no args), or
`python` with args `["-m", "pocmap.mcp_server"]`. See `README.md` → *AI Agent Integration*
and `examples/mcp-config.json`.

## Start here: one call instead of seven

`generate_json_report(cve_ids)` is the default entry point for any question about known
CVE IDs. It returns, for each CVE in one round trip:

| | |
|---|---|
| `cve_info` | description, CVSS, EPSS, KEV status, CWEs, references, `affected_products` |
| `exploits` | every source at once — GitHub PoCs, Metasploit, ExploitDB, Nuclei |
| `labs` | Vulhub / HackTheBox / TryHackMe environments |
| `bb_reports` | HackerOne / PentesterLand write-ups |

That is the same information as `lookup_cve` + `find_github_pocs` +
`find_metasploit_module` + `find_nuclei_template` + `check_kev_status` +
`find_bug_bounty_reports` + `find_practice_labs`, which is **seven sequential round
trips** — each one a separate inference turn — for data the server fetches concurrently
anyway. It takes comma-separated IDs, so "which of these three should I patch first"
is also a single call.

Use the single-purpose tools when you genuinely need one source (the user asked
specifically for Metasploit), when you are drilling into something the report surfaced,
or when you have no CVE ID yet (`discover_product_cves`, `find_recent_exploits`).

## Available Tools and When to Use Each

### CVE Intelligence (4 tools)

| Tool | When to Use | Key Output Fields |
|------|-------------|-------------------|
| `lookup_cve` | User mentions any CVE ID | `id` (the CVE identifier — `cve_id` appears only in the error envelope), `description`, `cvss` (score, severity, version, vector_string), `epss_score`, `kev_status`, `cwes`, `vendor`, `product`, `affected_products`, `state` |
| `get_epss_score` | Prioritizing which CVEs to patch first | `epss_score` (0.0-1.0), `risk_level` (LOW/MEDIUM/HIGH/CRITICAL), `interpretation` |
| `check_kev_status` | Determining if a CVE is actively exploited | `kev_status` (bool), `recommendation` (actionable) |
| `get_attack_techniques` | User asks how a CVE would be exploited, what to detect, or how to hunt for it | `techniques[]` with `technique_id`, `name`, `mapping_type`, `comment`, `url` |

**Decision rule:** For anything beyond "what is this CVE", start with **`generate_json_report`**
— it returns CVE details *plus* exploits, labs and bug bounty reports in one round trip
instead of seven (see [Start here](#start-here-one-call-instead-of-seven)). Use `lookup_cve`
when you only need the CVE metadata itself; it is the cheapest call and provides the
superset of the other two in this table. Only call `get_epss_score` or `check_kev_status`
individually if the user asks specifically about EPSS or KEV.

**`get_attack_techniques` — empty is not "harmless".** Mappings are expert-curated over
the CISA KEV catalogue, so most CVEs have none and `total_count: 0` means *no curated
mapping exists*. Never report that as "this CVE has no known exploitation technique".
pocmap deliberately does not infer techniques from the CVE's CWEs: that chain was
measured against the curated data and produced unrelated results (for Log4Shell it
suggests "Steal Web Session Cookie"), so nothing is better than a plausible guess.

Read `mapping_type` before using a technique. `exploitation_technique` is how the CVE
itself is exploited — that is what a detection or hunting question wants.
`primary_impact` / `secondary_impact` are what the attacker achieves afterwards, which
suits risk and blast-radius questions. Each carries the curator's `comment` explaining
why it applies; quote that rather than paraphrasing a bare technique ID.

**Upstream-failure note:** On an upstream failure (throttle/offline/network), `get_epss_score` and `check_kev_status` now return the standard error envelope (`category` `rate_limited`/`offline`/`network_error` with a `retryable` flag), **not** `available: false` / `kev_status: false`. A genuine "no EPSS data" / "not in KEV" from a *successful* lookup still returns `available: false` / `kev_status: false`.

### Exploit Discovery (5 tools)

| Tool | When to Use | Returns |
|------|-------------|---------|
| `find_github_pocs` | User wants exploit code, detection scripts, or to understand exploitation | `cve_id`, `total_count`, `pocs` (repos with `source`, `url`, `title`, `language`, `stars`, `forks`), and `sources` (per-source health) |
| `find_metasploit_module` | Assessing if reliable, weaponized exploit exists | Best-ranked `module`: `url` (Rapid7 page), `title` (module fullname), `rank`, `command` (msfconsole invocation) |
| `find_exploitdb_entry` | Finding standalone exploit scripts | `entry`: `url`, `title` (path in the ExploitDB repo), `command` (searchsploit invocation) |
| `find_nuclei_template` | Detection/verification scanning needs | `template`: `url` (ProjectDiscovery library), `title` (template path), `command` (nuclei invocation) |

For the three database tools, `language`/`stars`/`forks` are always `null` — those are
GitHub-repo metadata and these sources are not GitHub repos.

**Decision rule:** Call all 4 when doing comprehensive exploit research. For quick checks, `find_github_pocs` is usually the most informative.

**`limit` semantics:** each of the three database tools returns at most one entry (`limit`
bounds how many entries *of that source* are considered). They are independent — a CVE
having a Metasploit module no longer suppresses its ExploitDB entry or Nuclei template.

**`find_github_pocs` and `limit`:** the limit is applied *before* per-repository metadata
enrichment, which costs one GitHub API call each against an unauthenticated budget of 60
per hour. Request only as many PoCs as you will actually use; a large `limit` on a
popular CVE is the fastest way to a `rate_limited` envelope.

Results are the union of the Nomi-sec and TrickestCVE indexes, deduped, with
CVE-aggregator repos filtered out. **Trust the order.** Nomi-sec only indexes repos that
name the CVE and carries real star counts, so its entries rank first; TrickestCVE is
broader but includes repos that merely *mention* a CVE, and those sort last with
`stars: 0` and `language: null`. Prefer the top of the list, and treat a zero-star,
null-language entry as an unverified lead rather than a known PoC.

**Verifying a PoC is real:** `find_github_pocs` returns *leads*. When it matters that a
repository actually exploits the CVE — before telling a user "working exploit code
exists", or when the results are low-star repos you cannot judge — call
**`verify_github_pocs`**, which reads each repo's source and returns a verdict:
`confirmed` (names the CVE in code AND ships code), `likely` (a writeup),
`unverified` (has code but never names this CVE — unproven, not disproven), or
`unrelated` (an index — judged by how many *distinct* CVEs the repo cites, since a PoC
is about one vulnerability and a list is about dozens). Only `confirmed` claims the repo
exploits the CVE;
report the others as leads. It requires the operator to have set
`POCMAP_ALLOW_FETCH_POC_SOURCE=1` (it writes exploit code to disk); if unset the tool
returns an error saying so — surface that to the user instead of retrying.
If the user insists they set it, the likely cause is that they used `export` in a shell:
MCP clients launch the server with a filtered environment (only `HOME`, `LOGNAME`, `PATH`,
`SHELL`, `TERM`, `USER`), so **no `POCMAP_*` variable set in a shell reaches the server**.
Tell them to move it into their MCP client config's `env` block — the same place
`GITHUB_API_TOKEN` and `NVD_API_KEY` go.

### Bug Bounty Research (1 tool)

| Tool | When to Use | Returns |
|------|-------------|---------|
| `find_bug_bounty_reports` | User wants real-world exploitation techniques, write-ups, or bounty research | Reports with `source`, `url`, `title`, `has_poc` |

### Lab Discovery (2 tools)

| Tool | When to Use | Returns |
|------|-------------|---------|
| `find_practice_labs` | User wants hands-on practice environments | Labs with `platform` (hackthebox/tryhackme/vulhub), `name`, `url` |
| `find_vulhub_docker` | User wants the quickest local Docker setup | Docker URL + `setup_instructions` (clone, cd, docker compose up) |

### Discovery (3 tools)

| Tool | When to Use | Returns |
|------|-------------|---------|
| `find_recent_exploits` | User wants to see newly published CVEs over a time window | Recent CVEs with severity, EPSS, KEV status, and PoC availability |
| `discover_product_cves` | User asks about a deployed **product** without giving a CVE ID | CVEs grouped by confidence: confirmed, possibly, and not enough data |
| `discover_package_cves` | User asks about a **dependency** — a library, lockfile, or SBOM entry | Advisories ranked by risk, each with the releases that fix it |

**Decision rule — product vs package.** These two are not interchangeable, and picking
the wrong one produces a confidently empty answer:

* **`discover_product_cves`** is keyed on CPE, the way NVD files vulnerabilities for
  deployed software: nginx, Confluence, FortiOS, Exchange. It cannot tell you what release
  fixes anything.
* **`discover_package_cves`** is keyed on a package coordinate, the way ecosystems ship
  dependencies: `PyPI/django`, `npm/lodash`, `Maven/org.apache.logging.log4j:log4j-core`.
  It is the **only** tool here that returns fixed versions.

Asking `discover_package_cves` about "nginx" with no ecosystem is an error, not an empty
result; asking `discover_product_cves` "what do I upgrade django to" cannot be answered at
all. Match the tool to how the user is running the software: installed from a package
manager -> package; deployed as a product -> product.

### CPE Conversion (2 tools)

| Tool | When to Use | Returns |
|------|-------------|---------|
| `cve_to_cpe` | Mapping a CVE to affected products/versions | CPEs with `cpe`, `vendor`, `product`, `version` |
| `cpe_to_cve` | Finding all CVEs affecting a specific product | List of `cve_ids` |

**Upstream-failure note:** On an upstream failure (throttle/offline/network), `cve_to_cpe` and `cpe_to_cve` now return the standard error envelope (`category` `rate_limited`/`offline`/`network_error` with a `retryable` flag), **not** an empty list. A genuinely empty result from a *successful* lookup still returns `total_count: 0` with an empty list.

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
  "rejected_reason": null,
  "affected_products": [
    {"vendor": "apache", "product": "log4j"},
    {"vendor": "fedoraproject", "product": "fedora"}
  ]
}
```

**`vendor`/`product` are only the first of `affected_products`.** A CVE is normally filed
against several `(vendor, product)` pairs — the vulnerable component plus every
distribution that shipped it. When answering "does this CVE affect *X*?", check the whole
`affected_products` list, not the scalar fields.

The Python API additionally exposes `affected_cpes` (raw CPE 2.3 strings) and
`cpe_matches` (applicability statements with `version_start_including` /
`version_end_excluding` bounds) on `CVEInfo`. The MCP normalizer drops both, so they are
absent from `lookup_cve` and `discover_product_cves` — the one exception is
`find_recent_exploits`, whose nested `cve_info` is a raw model dump and does carry them.
To reason about version applicability, use `discover_product_cves`, which evaluates it for you.

### Exploit
```json
{
  "source": "github",
  "url": "https://github.com/user/poc-repo",
  "title": "Log4j RCE PoC",
  "language": "Python",
  "stars": 1250,
  "forks": 340,
  "rank": null,
  "command": null
}
```

`rank` is set only for Metasploit modules; `command` only for the Metasploit / ExploitDB /
Nuclei sources (`msfconsole …` / `searchsploit -m …` / `nuclei -t …`). For a GitHub PoC both
are `null`; conversely `language`/`stars`/`forks` are `null` for every non-GitHub source.

### LabEnvironment
```json
{
  "platform": "vulhub",
  "name": "log4j/CVE-2021-44228",
  "url": "https://github.com/vulhub/vulhub/tree/master/log4j/CVE-2021-44228",
  "setup_instructions": "docker compose up -d"
}
```

`platform` is always lowercase (`hackthebox`, `tryhackme`, `vulhub`, `other`) — match on that
form. `find_practice_labs` returns only `{platform, name, url}`; `setup_instructions` is a
Python-model field, so use `find_vulhub_docker` for Docker setup steps over MCP.

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
1. generate_json_report("CVE-2021-44228")     <- ONE call, not seven

   entries[0].cve_info   -> CVSS 10.0 CRITICAL, EPSS 0.9999, KEV=true, CWEs, references
   entries[0].exploits   -> GitHub PoCs (stars/language) + Metasploit + ExploitDB + Nuclei
   entries[0].labs       -> Vulhub / HackTheBox / TryHackMe environments
   entries[0].bb_reports -> HackerOne / PentesterLand write-ups

Response synthesis:
- Provide summary with CVSS, EPSS, KEV status
- List top 3-5 GitHub PoCs with links (exploits[] where source == "github",
  already sorted by stars — prefer the top; a zero-star, null-language entry is
  an unverified lead, not a known PoC)
- Note Metasploit/Nuclei availability (source == "metasploit" / "nuclei";
  each carries a ready-to-run `command`)
- Summarize bug bounty findings
- List practice lab options
- Give clear prioritization recommendation (CRITICAL + KEV = patch immediately)

Only follow up with a single-purpose tool if the report left a gap you actually
need — e.g. find_github_pocs("CVE-2021-44228", limit=20) for a wider PoC sweep.
```

### Workflow 2: Vulnerability Prioritization
```
User: "Which of these should I patch first? CVE-2021-44228, CVE-2023-38408, CVE-2024-21413"

Agent steps:
1. generate_json_report("CVE-2021-44228,CVE-2023-38408,CVE-2024-21413")

   One call. Each entry carries the CVSS, EPSS and KEV needed to rank, plus the
   exploit list whose length is the "how available is this" signal — no separate
   get_epss_score / check_kev_status / find_github_pocs passes.

Scoring logic (note: cve_info.epss_score is 0.0-1.0):
- EPSS > 0.9 AND KEV=true: Patch within 24 hours
- EPSS > 0.5 AND KEV=true: Patch within 48 hours
- CVSS >= 9.0: Patch within 1 week
- EPSS > 0.5: Patch within 2 weeks
- Otherwise: Standard patch cycle

Check `total_errors` / `errors[]` before ranking: a CVE that failed to fetch must
be reported as unknown, never silently ranked last.

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
   -> All Log4j CVE ids

2. generate_json_report("<comma-joined ids, highest-value first>")
   -> Full details, exploit techniques, past bug bounty findings and practice
      labs for the whole batch in one call (the old steps 2-3, which were four
      tools per CVE). Cap the id list to the ones you will actually discuss.

3. get_bug_bounty_playbook()
   -> Structured submission workflow (local data; independent of step 2, so
      issue both together)

4. Suggest using the bb-submission playbook for report writing

Response: Targeted CVE list + exploitation roadmap + playbook guidance
```

### Workflow 5: Emergency Response
```
User: "CVE-2024-XXXXX just dropped and it's critical. What do I do?"

Agent steps (2 calls, and they are independent — issue them together):
1. generate_json_report("CVE-2024-XXXXX")
   -> Severity, KEV, EPSS, exploit availability across all four sources,
      and a lab to reproduce in. Covers steps 1, 3, 4, 5 and 7 of the old
      seven-step version.

2. get_rapid_response_playbook()
   -> Emergency workflow (pure local data, no network)

Then, only if you need to scope blast radius in the user's estate:
3. cve_to_cpe("CVE-2024-XXXXX")
   -> Affected product configurations to match against inventory

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

Agent steps (2 calls total, not 1 + 7-per-CVE):
1. discover_product_cves(product="Apache Struts", version="2.5")
   -> CVEs grouped by confidence (confirmed, possibly, not_enough_data).
      Check `search_sources`: "nvd_cpe_match" is authoritative;
      "nvd_keyword_search" means the product could not be resolved to a CPE,
      so say so rather than presenting the tiers as fact.
      Each CVE already carries full details (CVSS, EPSS, KEV, description) —
      there is no need to lookup_cve them again.

2. generate_json_report("<comma-joined confirmed CVE ids>")
   -> Exploit availability across all four sources, labs and bug bounty
      reports for the whole set, in one call. Covers what the old steps 2-4
      did with seven calls per CVE.

Prioritize on cve_info.epss_score (0.0-1.0) + kev_status + CVSS, and use
len(entries[].exploits) as the exploit-availability signal.

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
  "category": "rate_limited|offline|network_error|not_found|invalid_input|permission_error|not_enabled|unknown",
  "retryable": true,
  "context": "Tool name and arguments"
}
```

### Error Categories and Handling

| Category | Cause | Agent Action |
|----------|-------|--------------|
| `rate_limited` + `retryable: true` | Upstream API throttled the request (HTTP 429, or GitHub `X-RateLimit-Remaining: 0`) | Back off and retry; suggest adding GITHUB_API_TOKEN or NVD_API_KEY to raise limits |
| `offline` + `retryable: false` | Offline mode (or `POCMAP_OFFLINE=1`) with a cache miss | Do not retry in-state; a network run is needed to populate the cache |
| `network_error` + `retryable: true` | Temporary API failure | Retry the call after a brief pause (2-5 seconds) |
| `network_error` + `retryable: false` | Persistent connectivity issue | Report to user, suggest checking connection |
| `not_found` | CVE doesn't exist in database | Inform user the CVE may not be published yet |
| `invalid_input` | Malformed CVE ID or bad parameter | Correct the input (e.g., `CVE-2021-44228` not `CVE202144228`) |
| `permission_error` | Auth failure or forbidden access | Suggest checking GITHUB_API_TOKEN / NVD_API_KEY validity |
| `not_enabled` + `retryable: false` | An opt-in capability is switched off (currently only `verify_github_pocs`) | Relay the `remediation` field to the user and stop; do not retry until they confirm they enabled it |
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
      "cve_info": {
        "id": "CVE-2024-XXXXX",
        "description": "...",
        "cvss": { "version": "3.1", "base_score": 9.8, "severity": "CRITICAL",
                  "vector_string": "CVSS:3.1/AV:N/..." },
        "epss": 85.4,
        "kev_status": true,
        "cwes": [],
        "references": { "NVD": "https://nvd.nist.gov/..." },
        "vendor": "Apache",
        "product": "Struts",
        "publication_date": "2024-01-15",
        "state": "PUBLISHED",
        "affected_products": [], "affected_cpes": [], "cpe_matches": []
      },
      "has_poc": true,
      "poc_sources": ["github"],
      "discovered_at": "2024-01-16T09:30:00"
    }
  ]
}
```

**The CVE fields are nested under `cve_info`** — nothing is hoisted to the item's top level.
This is also the one tool that returns the **raw** `CVEInfo` dump rather than the normalized
shape, so within `cve_info` the score is `cvss.base_score` (not `cvss.score`), the EPSS key
is `epss` on the **0-100** scale (not `epss_score` on 0.0-1.0), `references` is a name->URL
object (not a list), and `affected_cpes`/`cpe_matches` are present. On failure the tool
returns `{"success": false, "error": "..."}`.

### `discover_package_cves`

Find vulnerabilities affecting a package coordinate, with remediation. Backed by
[OSV.dev](https://osv.dev), which needs no API key and is not subject to NVD's
5-requests-per-30-seconds limit, then enriched with EPSS and CISA KEV from pocmap's
existing bulk feeds (two cached downloads for the whole result set — no per-CVE calls, no
NVD budget).

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ecosystem` | str | *(required)* | `PyPI`, `npm`, `Go`, `Maven`, `crates.io`, `RubyGems`, `Packagist`, `NuGet`, `Hex`, `Pub`, or a distro (`Debian:12`, `Ubuntu:22.04`, `Alpine:v3.19`, `Red Hat`, `Bitnami`). Case-insensitive here. |
| `name` | str | *(required)* | Package name as the ecosystem spells it. |
| `version` | str | `""` | Installed version. Strongly recommended. |
| `limit` | int | `50` | Maximum advisories (1-500). |

**Returns:**
```json
{
  "ecosystem": "Maven",
  "package": "org.apache.logging.log4j:log4j-core",
  "version": "2.14.1",
  "total_found": 7,
  "returned": 7,
  "truncated": false,
  "fixable_count": 7,
  "unfixed_count": 0,
  "search_sources": ["osv", "epss", "cisa_kev"],
  "vulnerabilities": [
    {
      "id": "GHSA-jfh8-c2jp-5v3q",
      "cve_ids": ["CVE-2021-44228"],
      "severity": "CRITICAL",
      "cvss_score": 10.0,
      "epss_score": 0.9999,
      "kev_status": true,
      "fixed_versions": ["2.15.0", "2.3.1", "2.12.2"],
      "has_fix": true,
      "url": "https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q"
    }
  ]
}
```

**Reading the result — six things that will bite you:**

1. **`fixed_versions` usually lists several releases, and they are not alternatives in
   time order.** Maintainers backport a fix to every supported branch, so log4j-core is
   fixed in `2.3.1`, `2.12.2` *and* `2.15.0`. Recommend the one on the user's own major
   version — telling a 2.12.x user to jump to 2.15.0 is a needless major upgrade, and
   telling a 2.14 user to "upgrade" to 2.3.1 is a downgrade into a different branch.
2. **An empty `vulnerabilities` list is not proof the package is clean.** OSV returns an
   empty body for an unknown package *and* for a package with no known issues — they are
   indistinguishable. Check the spelling before reporting "no vulnerabilities", especially
   for Maven, where a bare artifact name (`log4j-core` instead of
   `org.apache.logging.log4j:log4j-core`) matches nothing and looks clean.
3. **`fixed_versions: []` means no fix is published**, not that the advisory is harmless.
   Say so explicitly — that is the case where the user needs a workaround, not an upgrade.
4. **`epss_score` is 0.0-1.0 here** (matching `lookup_cve`), while `cvss_score` is 0-10.
   `cvss_score` is `null` for an advisory published with only a CVSS 4.0 vector, which
   pocmap does not score locally; `severity` still carries the publisher's rating.
5. **`total_found` is what was found; `returned` is what you got.** When `truncated` is
   true, `limit` dropped the rest — report the real total, not the length of the list, or
   you understate exposure. `fixable_count`/`unfixed_count` describe the *returned* set.
6. **`search_sources` lists only the feeds that actually produced data.** If `cisa_kev` is
   absent, the catalogue was unavailable and every `kev_status: false` in the response is
   unverified — say so rather than reporting the CVEs as not-exploited.

Results are ordered KEV first, then EPSS, then CVSS — so the top entry is what is actually
being exploited, which is rarely the same as the highest CVSS.

### `discover_product_cves`

Discover CVEs affecting a product by name and version. The product name is resolved
through the NVD CPE dictionary to canonical `vendor:product` identifiers, then CVEs are
fetched by CPE applicability match with the version constraint evaluated by NVD.

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
  "search_sources": ["nvd_cpe_match"],
  "matched_cpes": ["cpe:2.3:*:apache:struts"],
  "confirmed_affected": [ ... ],
  "possibly_affected": [ ... ],
  "not_enough_data": [ ... ],
  "summary": { "confirmed_count": 15, "possibly_count": 20, "unknown_count": 7 }
}
```

**Check `search_sources` before trusting the tiers.** It reports how the CVEs were found:

| Value | `matched_cpes` | How to read the result |
|-------|----------------|------------------------|
| `nvd_cpe_match` | the resolved CPE prefixes | Authoritative. The CVEs genuinely list this product in their applicability data. |
| `nvd_keyword_search` | empty | Degraded fallback — the product could not be resolved to any CPE, so this is a full-text search over CVE *descriptions*. Expect both false positives and misses; say so when reporting to the user. |

**Rate limits.** One dictionary lookup plus one query per resolved `vendor:product` pair
(capped at 5). Unauthenticated NVD allows 5 requests / 30s, so `discover_product_cves`
is the most `NVD_API_KEY`-sensitive tool; a `rate_limited` envelope here usually means
the key is missing rather than that the product is unknown.

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
| `CVEInfo.json` | CVEInfo | `id`, `description`, `cvss`, `epss`, `kev_status`, `cwes`, `references`, `vendor`, `product`, `state`, `affected_products`, `cpe_matches` |
| `Exploit.json` | Exploit | `source` (enum), `url`, `title`, `language`, `stars`, `forks`, `rank`, `command` |
| `LabEnvironment.json` | LabEnvironment | `platform` (enum), `name`, `url`, `setup_instructions` |
| `BugBountyReport.json` | BugBountyReport | `source` (enum), `url`, `has_poc`, `title` |
| `CPEInfo.json` | CPEInfo | `cpe_string`, `vendor`, `product`, `version` |
| `RecentExploitResult.json` | RecentExploitResult | `cve_info`, `has_poc`, `poc_sources` (enum list), `discovered_at` |
| `ReportEntry.json` | ReportEntry | `cve_info`, `exploits`, `labs`, `bb_reports`, `generated_at` |
| `MultiReport.json` | MultiReport | `entries` (dict of CVE ID -> ReportEntry), `generated_at` |
| `VersionConstraint.json` | VersionConstraint | `major`, `minor`, `patch`, `range_op`, `raw`, `is_wildcard` |
| `ProductDiscoveryResult.json` | ProductDiscoveryResult | `query`, `normalized_vendor`, `normalized_product`, `version_constraint`, `confirmed_affected`, `possibly_affected`, `not_enough_data`, `total_found`, `search_sources`, `matched_cpes` |
| `PackageVulnerability.json` | PackageVulnerability | `id`, `aliases`, `cve_ids`, `summary`, `severity`, `cvss_score`, `cvss_vector`, `fixed_versions`, `introduced_versions`, `epss`, `kev_status`, `withdrawn`, `url` |
| `PackageDiscoveryResult.json` | PackageDiscoveryResult | `ecosystem`, `package`, `version`, `vulnerabilities`, `total_found`, `fixable_count`, `unfixed_count`, `search_sources` |

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
- CVEInfo: {id, description, cvss: {base_score, severity, version, vector_string}, epss, kev_status, cwes, references, vendor, product, affected_products}
- Exploit: {source, url, title, language, stars, forks, rank, command}
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

## Learned User Preferences

- Prefer minimal diffs that achieve the requested outcome (packaging, docs, and feature work).
- Prefer uvx-based MCP install for Claude/Cursor (`uvx --from pocmap[server] pocmap-mcp`) without a local clone or absolute path; keep the `pocmap` CLI entrypoint unchanged.
- When MCP install or run paths change, update README and related agent/docs configs to match.
- Publishes and owns the PyPI project `pocmap` (https://pypi.org/project/pocmap/).

## Learned Workspace Facts

- MCP server implementation lives in `src/pocmap/mcp_server.py`, exposed as the `pocmap-mcp` console script and `python -m pocmap.mcp_server`; repo-root `mcp_server.py` is a thin launcher shim.
- Do not target a top-level `mcp_server` module for the console script — that name collides with unrelated site-packages; use `pocmap.mcp_server:main`.
- The `[server]` extra requires `mcp>=2.0,<3` and builds on `mcp.server.mcpserver.MCPServer` (the 2.x rename of `FastMCP`). The SDK supports up to protocol `2026-07-28`, but over STDIO an `initialize` handshake negotiates `2025-11-25` (verified live) — `2026-07-28` is the stateless `server/discover` path. Host/port moved off the constructor onto `run()`, since the protocol core is now stateless.
