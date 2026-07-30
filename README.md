# PocMap

[![Version](https://img.shields.io/badge/version-2.5.0-blue.svg)](https://github.com/zebbern/pocmap)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Pydantic](https://img.shields.io/badge/pydantic-v2-purple.svg)](https://docs.pydantic.dev/)

AI-agent-optimized CVE exploit discovery toolkit for bug bounty hunters and security professionals. Find Proof-of-Concept exploits, CTF labs, bug bounty reports, and vulnerability intelligence from a single interface.

## Key Features

- **Multi-Source Discovery**: Queries GitHub, Exploit-DB, Metasploit, Nuclei, CTF labs, and bug bounty platforms simultaneously
- **Structured Pydantic Models**: All data validated and serialized with full type safety and JSON Schema support
- **MCP Server Integration**: 22 AI-native tools via Model Context Protocol for Claude Desktop, Cursor, and other AI agents
- **Bug Bounty Toolkit**: Complete hunter toolkit with checklists, workflows, report templates, prioritization engine, and scope management
- **Rich CLI**: 13 commands with colorized tables, progress bars, and bulk processing
- **Composable Output**: `table`, `json`, `csv`, `md`, and `sarif` output on read commands, plus a stable [exit-code contract](#output-formats--exit-codes) for scripting and CI
- **CI Security Gate**: `bulk --fail-on kev|critical|high|epss>=N` fails the build on policy matches and emits SARIF 2.1.0 for GitHub code scanning
- **Caching & Offline Mode**: persistent, TTL'd HTTP response cache and a first-class `--offline` mode for air-gapped or repeatable runs
- **Snapshot Diffs**: `latest`/`discover --diff` show only what changed since the last identical run
- **Concurrent Processing**: Thread pool-based bulk CVE processing with exponential backoff retry logic
- **Report Generation**: Self-contained HTML reports (styled cards and tables, inline CSS, no external assets or JS) plus JSON export
- **Security-Hardened**: SSRF protection, sandboxed Jinja2 templates, path traversal prevention, input validation

## Installation

```bash
# From PyPI (CLI + library)
pip install pocmap

# With the MCP server (MCP SDK 2.x — required for pocmap-mcp)
pip install "pocmap[server]"

# From source (editable)
git clone https://github.com/zebbern/pocmap.git
cd pocmap
pip install -e ".[server,dev]"

# Verify
pocmap --version
pocmap-mcp --help    # only after installing with the [server] extra
```

Every CLI command is also available as `python -m pocmap ...` if the `pocmap` script is
not on your `PATH`. The MCP server is also available as `python -m pocmap.mcp_server`.

**Requirements:**
- Python 3.10+ (developed/verified on 3.12)
- Core dependencies: pydantic>=2.0, requests>=2.28, urllib3, typer>=0.9, click, rich>=13.0, beautifulsoup4, markdown, jinja2, python-dotenv (see `pyproject.toml` for the full list and version pins)

**Optional:**
- `GITHUB_API_TOKEN` - GitHub PAT for higher rate limits (recommended)
- `NVD_API_KEY` - NVD API key for increased rate limits
- The `[server]` extra (MCP SDK `mcp>=2.0,<3`) is required only for the MCP server / `pocmap-mcp`

## Quick Start

```bash
# Look up a single CVE
pocmap lookup CVE-2021-44228

# Show full description and references
pocmap lookup CVE-2021-44228 --description

# Filter PoCs by programming language
pocmap lookup CVE-2021-44228 --language Python

# Process multiple CVEs from a file
pocmap bulk cves.txt --output ./reports

# Search CTF labs for hands-on practice
pocmap labs CVE-2021-44228

# Search bug bounty reports
pocmap bugbounty CVE-2021-44228

# Get CPEs (affected products) for a CVE
pocmap cpes CVE-2021-44228

# Convert CPE to CVEs
pocmap cpe2cve "cpe:2.3:a:apache:log4j:2.0"

# Export JSON schemas for AI agent integration
pocmap schemas --output ./schemas

# Find recently published CVEs from the last 24 hours
pocmap latest

# Find recent critical CVEs with PoCs from the last 7 days
pocmap latest --since 7d --severity critical --only-with-poc

# Discover CVEs affecting a product by name
pocmap discover "Apache Struts"

# Discover CVEs for a specific product version
pocmap discover "Log4j" --version 2.x

# Machine-readable output (any read command): table (default), json, csv, md, sarif
pocmap lookup CVE-2021-44228 --format json
pocmap latest --since 7d --format sarif --output out/

# Use pocmap as a CI gate (exit 6 if any CVE is in CISA KEV)
pocmap bulk cves.txt --format sarif --fail-on kev

# Only show what changed since the last identical run
pocmap latest --since 24h --diff

# Run self-diagnostics and inspect/clear the response cache
pocmap doctor
pocmap cache info
pocmap cache clear

# Serve everything from the local cache (no network)
pocmap --offline lookup CVE-2021-44228

# Show help with all options
pocmap --help
```

### CLI Commands (13)

| Command | Purpose |
|---------|---------|
| `lookup` | Look up a single CVE plus discovered PoCs, DB exploits, and labs |
| `bulk` | Process many CVEs from a file or stdin; JSON/HTML reports and CI gate |
| `labs` | Find CTF labs and vulnerable environments for a CVE |
| `bugbounty` | Find bug bounty reports / write-ups for a CVE |
| `cpes` | List affected CPE identifiers for a CVE |
| `cpe2cve` | List CVE IDs affecting a CPE identifier |
| `readme` | Print a GitHub repo's README |
| `schemas` | Export JSON schemas for all data models |
| `latest` | Find recently published CVEs with exploit intelligence |
| `discover` | Discover CVEs affecting a product by name and version |
| `package` | Find vulnerabilities in a dependency and the releases that fix them |
| `doctor` | Run self-diagnostics (Python, extras, tokens, cache, connectivity) |
| `cache` | Inspect (`info`) and clear (`clear`) the persistent HTTP cache |

Global options (on `pocmap` itself, before the command): `--format/-f {table,json,csv,md,sarif}`,
`--offline`, `--quiet/-q`, `--version/-v`. Read commands also accept `--format`/`--quiet` locally,
which override the global value.

## Python API

### CVE Information Lookup

```python
from pocmap.services.cve_service import CVEService

cve_svc = CVEService()
info = cve_svc.get_cve_info("CVE-2021-44228")

print(info.id)                    # "CVE-2021-44228"
print(info.description)           # Full vulnerability description
print(info.cvss.base_score)       # 10.0
print(info.cvss.severity.value)   # "CRITICAL"
print(info.cvss.vector_string)    # "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
print(info.epss)                  # 97.53 (exploitation probability)
print(info.kev_status)            # True (in CISA KEV catalog)
print(info.cwes)                  # ["CWE-77", "CWE-94"]
print(info.vendor)                # "Apache"
print(info.product)               # "Log4j"
print(info.publication_date)      # "2021-12-10"
```

### Exploit Discovery

```python
from pocmap.services.exploit_service import ExploitService

exploit_svc = ExploitService()

# Find all exploits across all sources
exploits = exploit_svc.find_exploits("CVE-2021-44228")
for ex in exploits:
    print(f"[{ex.source.value}] {ex.title}")
    print(f"  URL: {ex.url}")
    print(f"  Language: {ex.language} | Stars: {ex.stars} | Forks: {ex.forks}")

# Filter by programming language
python_pocs = exploit_svc.filter_by_language(exploits, "Python")
go_pocs = exploit_svc.filter_by_language(exploits, "Go")

# Get a GitHub repo's README
readme = exploit_svc.get_readme("https://github.com/example/poc")
```

### Lab Environments

```python
from pocmap.services.lab_service import LabService

lab_svc = LabService()
labs = lab_svc.find_labs("CVE-2021-44228")
for lab in labs:
    print(f"[{lab.platform.value}] {lab.name}: {lab.url}")
    if lab.setup_instructions:
        print(f"  Setup: {lab.setup_instructions}")
```

### Bug Bounty Reports

```python
from pocmap.services.bb_service import BugBountyService

bb_svc = BugBountyService()
reports = bb_svc.find_reports("CVE-2021-44228")
for report in reports:
    print(f"[{report.source.value}] {report.title}")
    print(f"  URL: {report.url} | PoC included: {report.has_poc}")
```

### Report Generation

```python
from pocmap.services.report_service import ReportService

report_svc = ReportService()

# Single CVE report
entry = report_svc.generate_report("CVE-2021-44228")
print(entry.to_json())

# Bulk report with JSON and HTML output
multi = report_svc.generate_bulk_report([
    "CVE-2021-44228",
    "CVE-2023-38408",
    "CVE-2024-21413",
])
report_svc.save_json_report(multi, "./output")
report_svc.save_html_report(multi, "./output")
```

### Schema Export for AI Agents

```python
from pocmap.models import export_schemas

paths = export_schemas("./schemas")
# Generates: CVSSScore.json, CVEInfo.json, Exploit.json,
#            LabEnvironment.json, BugBountyReport.json,
#            CPEInfo.json, RecentExploitResult.json, ReportEntry.json,
#            MultiReport.json, VersionConstraint.json,
#            ProductDiscoveryResult.json,
#            PackageVulnerability.json, PackageDiscoveryResult.json
```

## Bug Bounty Toolkit

The `pocmap.bugbounty` module provides a comprehensive toolkit for bug bounty hunters:

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

## Recent CVE Discovery

Monitor newly published vulnerabilities and filter by severity, exploitability, and time window. Ideal for security briefings, threat intelligence feeds, and proactive vulnerability management.

### `pocmap latest`

```bash
# Recent CVEs from the last 24 hours (default)
pocmap latest

# Specify a relative time window
pocmap latest --since 7d
pocmap latest --since 30d
pocmap latest --since 1h

# Explicit date range
pocmap latest --from 2024-01-01 --to 2024-01-31

# Only CVEs with known PoCs on GitHub
pocmap latest --only-with-poc

# Only CISA KEV entries
pocmap latest --kev-only

# Minimum EPSS score filter
pocmap latest --min-epss 50.0

# Filter by severity levels (comma-separated)
pocmap latest --severity critical,high

# Sort results
pocmap latest --sort cve_date     # newest first (default)
pocmap latest --sort severity     # highest severity first
pocmap latest --sort epss         # highest EPSS first

# Limit results and save to JSON
pocmap latest --since 7d --severity critical --only-with-poc --limit 10 --output ./report.json
```

**Options:**

| Option | Description |
|--------|-------------|
| `--since` | Relative time window: `1h`, `24h`, `7d`, `30d` |
| `--from` | Start date in `YYYY-MM-DD` format (overrides `--since`) |
| `--to` | End date in `YYYY-MM-DD` format |
| `--only-with-poc` | Only return CVEs with known PoCs on GitHub |
| `--kev-only` | Only return CISA Known Exploited Vulnerabilities |
| `--min-epss` | Minimum EPSS score (0-100), e.g., `50.0` for EPSS >= 50% |
| `--severity` | Comma-separated severities: `critical`, `high`, `medium`, `low` |
| `--sort` | Sort by: `cve_date`, `severity`, or `epss` |
| `--limit` | Maximum results (1-100, default: 50) |
| `--output`, `-o` | Save JSON report to file |
| `--diff`, `--since-last` | Show only what changed since the last identical run (added/removed/changed) |
| `--notify <url>` | POST a summary of notable CVEs (critical/high or KEV) to a webhook; with `--diff`, only the delta is sent |
| `--format`, `-f` | Output format: `table` (default), `json`, `csv`, `md`, `sarif` |
| `--quiet`, `-q` | Suppress decorative output |

**Output includes:** CVE ID, description, CVSS severity/score, EPSS, KEV status, vendor, product, publication date, PoC availability, and PoC source counts.

## Product Discovery

Find all CVEs affecting a specific product without needing a CVE ID. Product names are
resolved through the **NVD CPE dictionary** to canonical `vendor:product` identifiers,
and CVEs are then fetched by CPE applicability match with the version constraint applied
by NVD itself.

### `pocmap discover`

```bash
# Discover CVEs for a product by name
pocmap discover "Apache Struts"

# With version wildcard
pocmap discover "Log4j" --version 2.x

# Exact version
pocmap discover "nginx" --version 1.20.1

# With vendor hint
pocmap discover "struts" --vendor apache --version 2.x

# Save results to JSON
pocmap discover "Apache Struts" --version 2.x --output ./struts-cves.json
```

**Options:**

| Option | Description |
|--------|-------------|
| `--version`, `-v` | Version constraint: `2.x`, `2.14.1`, `>= 2.0` |
| `--vendor` | Vendor name hint: `apache`, `microsoft`, `google` |
| `--limit` | Maximum CVEs to analyze (1-100, default: 50) |
| `--output`, `-o` | Save JSON report to file |
| `--diff`, `--since-last` | Show only what changed since the last identical run (added/removed/changed) |
| `--notify <url>` | POST a summary of notable CVEs (critical/high or KEV) to a webhook; with `--diff`, only the delta is sent |
| `--format`, `-f` | Output format: `table` (default), `json`, `csv`, `md`, `sarif` |
| `--quiet`, `-q` | Suppress decorative output |

### How a product name is resolved

1. **Alias fast path.** A small curated table maps common shorthands to canonical names
   (see below). A hit skips the dictionary lookup; a miss costs nothing.
2. **NVD CPE dictionary.** The product name is resolved to every `vendor:product` pair
   NVD files CVEs under, ranked by how many CPE entries back each pair. **All** pairs are
   searched and the results unioned, because products change hands: `nginx` resolves to
   `igor_sysoev:nginx` (0 CVEs), `nginx:nginx` (2) and `f5:nginx` (41), so taking only the
   top-ranked pair would find almost nothing. At most 5 pairs are queried (a rate-limit
   bound, not a precision one — NVD allows 5 requests/30s unauthenticated); any dropped
   pairs are logged, never silently discarded.

   **Editions and product families are included.** NVD files enterprise software under a
   separate product per edition, so a query also admits any product in the *same vendor's
   namespace* whose name extends the target: "Confluence" reaches
   `atlassian:confluence_server` and `atlassian:confluence_data_center`, "Jira" reaches
   `jira_service_desk`, `jira_software_data_center` and `jira_service_management`. A
   third party's lookalike does not — `redhat:kubernetes-client` is not Kubernetes, and
   `perforce:gliffy` is not Confluence. The bias is deliberate: an extra CVE in the list
   is visible and dismissible, a missing one is neither.
3. **Keyword fallback.** If the product cannot be resolved at all, `discover` falls back
   to NVD full-text search. This is materially weaker — it matches CVE *descriptions*, so
   it is both noisy and incomplete. The result reports which path ran:

| `search_sources` | `matched_cpes` | Meaning |
|------------------|----------------|---------|
| `nvd_cpe_match` | the resolved CPE prefixes | Authoritative applicability match |
| `nvd_keyword_search` | empty | Unresolvable product; noisy full-text fallback |

> **Rate limits.** Discovery costs one dictionary lookup plus one query per resolved pair.
> Unauthenticated NVD allows 5 requests per 30 seconds, so setting `NVD_API_KEY` is
> considerably more valuable than it used to be. Responses are cached (see
> [Caching & Offline Mode](#caching--offline-mode)), so repeat runs are cheap.

### Product Alias System

The discovery command recognizes common product aliases and abbreviations, so you don't need to know the exact canonical product name:

| Alias Input | Resolved Product |
|-------------|-----------------|
| `struts` | Apache Struts |
| `log4j`, `log4j2` | Log4j |
| `httpd`, `apache2` | Apache HTTP Server |
| `k8s`, `kube` | Kubernetes |
| `postgres`, `pgsql` | PostgreSQL |
| `es`, `elastic` | Elasticsearch |
| `nodejs`, `node` | Node.js |
| `ghe` | GitHub Enterprise |
| `ror` | Ruby on Rails |
| `wp` | WordPress |
| `ie`, `msie` | Internet Explorer |

Aliases are matched on the whole name, ignoring separators — `apache struts`,
`apache_struts` and `Apache-Struts` are equivalent — and a known vendor phrase is peeled
off first, so `"Palo Alto PAN-OS"` becomes vendor=`palo alto` + product=`pan-os`.
Matching is deliberately not substring-based: anything the table does not recognize goes
to the CPE dictionary, which covers the full NVD catalogue rather than this short list.

### Version Constraint Format

Version constraints support multiple formats for flexible version matching:

| Format | Example | Meaning |
|--------|---------|---------|
| Wildcard | `2.x` | Any version in major version 2 |
| Exact | `2.14.1` | Exactly version 2.14.1 |
| Major.Minor | `2.14` | Version 2.14.x |
| Range (>=) | `>= 2.0` | Version 2.0 and above |
| Range (<=) | `<= 1.20` | Version 1.20 and below |
| Range (>) | `> 1.0` | Above version 1.0 |
| Range (<) | `< 3.0` | Below version 3.0 |
| None (omit) | - | Any version |

Results are grouped into three confidence tiers. Matching considers **every**
`(vendor, product)` pair a CVE is filed under, not just one — a CVE typically names the
vulnerable component plus every distribution that shipped it, and judging it by a single
pair misclassifies the component the CVE is actually about:

- **Confirmed**: Vendor AND product match AND version constraint is met
- **Possibly**: Vendor OR product matches but version info is unclear
- **Not enough data**: CVE has insufficient product/version information

Version matching is an interval-overlap test that honours NVD's out-of-band range
attributes (`versionStartIncluding` / `versionEndExcluding`), which is where modern CVE
records express affected ranges — the literal version field in the CPE string is usually
just `*`.

## Dependency Vulnerabilities

`pocmap discover` answers "is the nginx we run vulnerable". `pocmap package` answers the
other half: **is the dependency we ship vulnerable, and what do we upgrade to.**

The two are keyed differently and are not interchangeable. NVD files vulnerabilities
against a CPE *product*, which is right for deployed software but carries no package
coordinate and no fix version. [OSV.dev](https://osv.dev) files them against a *package*
(`PyPI/django`, `Maven/org.apache.logging.log4j:log4j-core`) and records the releases that
fix each one. OSV needs no API key and is not bound by NVD's 5-requests-per-30-seconds
limit, so this path stays fast without `NVD_API_KEY`.

```bash
# What's wrong with the version we actually ship, and what fixes it
pocmap package PyPI django --version 3.2.0
pocmap package npm lodash --version 4.17.20
pocmap package Maven org.apache.logging.log4j:log4j-core --version 2.14.1

# Ecosystem names are case-insensitive here and normalized for you
pocmap package pypi requests --version 2.25.0
pocmap package debian:12 nginx

# Only what you can actually act on, as JSON
pocmap package PyPI django --version 3.2.0 --fixable-only --format json

# SARIF for code scanning, in a CI dependency gate
pocmap package npm lodash --version 4.17.20 --format sarif --output out/
```

```
Package Vulnerabilities: Maven/org.apache.logging.log4j:log4j-core@2.14.1
Found 7 | with a fix: 7 | no fix published: 0
Severity  CVSS   EPSS  KEV  Advisory        Fixed in
CRITICAL  10.0  100.0  yes  CVE-2021-44228  2.15.0, 2.3.1, 2.12.2
CRITICAL   9.0  100.0  yes  CVE-2021-45046  2.16.0, 2.12.2
HIGH       8.6  100.0       CVE-2021-45105  2.12.3, 2.17.0, 2.3.1
```

**Options:**

| Option | Description |
|--------|-------------|
| `--version`, `-v` | Installed version. Strongly recommended — OSV then evaluates its own affected ranges and returns only advisories that genuinely apply. |
| `--fixable-only` | Only advisories with a published fix. Applied *after* ranking and `--limit`, so it narrows the top-N by risk rather than fetching N fixable ones. |
| `--limit` | Maximum advisories (1-1000, default: 100), taken from the top of the risk ranking. |
| `--output`, `-o` | Save the JSON report to a file. |
| `--format`, `-f` | `table` (default), `json`, `csv`, `md`, `sarif`. |
| `--quiet`, `-q` | Suppress decorative output. |

**Supported ecosystems.** All 50 OSV ecosystems, including `PyPI`, `npm`, `Go`, `Maven`,
`crates.io`, `RubyGems`, `Packagist`, `NuGet`, `Hex`, `Pub`, `CRAN`, `Hackage`,
`ConanCenter`, `SwiftURL`, `vcpkg`, and the distributions `Debian`, `Ubuntu`, `Alpine`,
`Red Hat`, `Rocky Linux`, `AlmaLinux`, `SUSE`, `Wolfi`, `Chainguard` and `Bitnami`. OSV
itself is case-**sensitive** (`pypi` is rejected outright); pocmap normalizes common
spellings and aliases first, so `pypi`, `cargo`, `golang`, `composer` and `debian:12` all
resolve. A release qualifier is preserved: `alpine:v3.19` -> `Alpine:v3.19`.

### Reading the results

**Ranking is by exploitation risk, not CVSS.** Results are ordered CISA KEV first, then
EPSS, then CVSS — the top row is what is actually being exploited, which is often not the
highest-scoring entry. EPSS and KEV come from bulk catalogues pocmap already caches, so
enriching a 100-advisory result costs two cached downloads, not 100 API calls.

**Several `Fixed in` versions is normal.** Maintainers backport a fix to each supported
branch, so log4j-core is fixed in `2.3.1`, `2.12.2` *and* `2.15.0`. Take the one on your
own major version.

**An empty result is not proof of safety.** OSV returns an empty body both for a package
it has never heard of and for one with no known issues, so the two are indistinguishable
— check the spelling first. This matters most for Maven, where the name must be the full
`groupId:artifactId`; a bare `log4j-core` matches nothing and looks clean.

**Counts describe different things.** `total_found` is how many advisories were found;
`returned`/`truncated` describe what `--limit` left. `--fixable-only` never reports a
package as clean — if it empties the list, the output says how many were filtered out.

**`no fix published` means exactly that** — the advisory is real and there is no upgrade
to take, so it needs a workaround or a risk decision rather than a version bump.

**Severity source.** A CVSS 3.x vector is scored locally to a base score. CVSS 4.0 scores
via a lookup table that pocmap does not implement, so a 4.0-only advisory shows `-` for
CVSS and falls back to the publisher's own rating rather than a plausible-but-wrong number.

## Output Formats & Exit Codes

Read commands emit machine-readable output via `--format/-f`. `--format` and `--quiet/-q`
can be set globally (before the command) or per command (the local value wins).

```bash
pocmap lookup CVE-2021-44228 --format json      # structured view model to stdout
pocmap latest --since 7d --format csv           # spreadsheet-ready rows
pocmap discover "Log4j" --format md             # Markdown table for tickets/wikis
pocmap latest --since 24h --format sarif        # SARIF 2.1.0 for code scanning
pocmap -f json latest --since 7d                # global form
```

| Format | Value | Notes |
|--------|-------|-------|
| Table | `table` | Default. Rich colorized tables (human-facing). |
| JSON | `json` | JSON-serializable view model to stdout, nothing else. |
| CSV | `csv` | One row per record (`csv.DictReader`-friendly). |
| Markdown | `md` | A Markdown table for tickets/wikis. |
| SARIF | `sarif` | SARIF 2.1.0 log for CI code scanning. |

**Format support by command:**
- `lookup`, `doctor`, `cache info`, `cache clear`: `table`, `json`
- `labs`, `bugbounty`, `cpes`, `cpe2cve`: `table`, `json`, `csv`, `md`
- `latest`, `discover`: `table`, `json`, `csv`, `md`, `sarif`
- `bulk`: `table` (writes JSON + HTML files), `json`, `csv`, `sarif`

SARIF results are keyed on CVE IDs, so it is available only on the CVE-list commands
(`latest`, `discover`, `bulk`). Requesting `--format sarif` on any other command exits
`4` (invalid input) with a clear message. Severity maps to SARIF levels as
`critical`/`high` -> `error`, `medium` -> `warning`, `low` -> `note`; EPSS, KEV, exploit
count, and CVSS ride along in `result.properties`, and each CVE's NVD page is the rule `helpUri`.

### Exit-Code Contract

Every command returns a stable, documented exit code (see `src/pocmap/utils/exit_codes.py`)
so scripts and CI can react to *why* a command stopped, not just whether it succeeded:

| Code | Name | Meaning |
|------|------|---------|
| `0` | `OK` | Success — the command ran and produced output. |
| `1` | `ERROR` | Generic / unclassified error. |
| `2` | `NO_RESULTS` | Ran fine but found nothing (empty result set). |
| `3` | `NOT_FOUND` | Requested resource does not exist upstream (e.g. unknown CVE). |
| `4` | `INVALID_INPUT` | Caller input was malformed (bad CVE ID, unsafe path, bad `--fail-on`). |
| `5` | `UPSTREAM_ERROR` | An upstream data source failed (network, rate limit, 5xx, offline cache miss). |
| `6` | `POLICY_FAIL` | A `bulk --fail-on` policy condition matched (the CI gate tripped). |

These values are a public contract: existing codes are never renumbered.

## Caching & Offline Mode

PocMap keeps a **persistent, TTL'd HTTP response cache** on disk (default `./.cache`).
This turns network-bound calls into sub-second cached ones, dodges GitHub/NVD rate
limits, and backs a real offline mode. Non-200 and error responses are never cached.

```bash
# Warm the cache with a normal (online) run, then work entirely offline
pocmap lookup CVE-2021-44228
pocmap --offline lookup CVE-2021-44228     # served from cache, zero network I/O

# Inspect / clear the cache
pocmap cache info                          # location, entry count, on-disk size
pocmap cache clear                         # delete every cached entry
```

In `--offline` mode (or with `POCMAP_OFFLINE=1`) HTTP GETs are served only from the
cache; a cache miss surfaces a clear offline error and exits `5` (`UPSTREAM_ERROR`)
rather than masquerading as "not found" or "no results". An **expired**-but-cached
entry is served **stale** offline (an air-gapped run cannot refresh it, so stale
data beats an error) — only a genuinely absent entry raises. Online runs are
unaffected: they still honour the TTL and refetch expired entries.

**Cache / offline configuration:**

| Variable | Default | Description |
|----------|---------|-------------|
| `POCMAP_CACHE_ENABLED` | `true` | Enable/disable the persistent HTTP cache. |
| `POCMAP_CACHE_DIR` | `./.cache` | Directory for cached responses. |
| `POCMAP_CACHE_TTL` | `3600` | Seconds a cached entry stays fresh. |
| `POCMAP_CACHE_MAX_MB` | `200` | On-disk cache cap (MB) before LRU eviction. |
| `POCMAP_OFFLINE` | `false` | Serve only from cache; a miss errors instead of hitting the network. |

## Verifying PoCs (opt-in)

The CVE indexes list repositories that *mention* a CVE, which is not the same as
repositories that exploit it — link lists, course notes and personal repos all show up.
Star count does not separate them either: a popular repo can be an index, and a genuine
one-file PoC often has zero stars.

`verify_github_pocs` downloads the top PoCs' **source** and reports what each actually
contains:

| Verdict | Meaning |
|---------|---------|
| `confirmed` | Names the CVE **in code** and ships runnable code. The only tier that claims the repo exploits the CVE. |
| `likely` | Names the CVE but has no code — a writeup. |
| `unverified` | Has code, but never names this CVE. Unproven, *not* disproven: a PoC may be named for its target instead. |
| `unrelated` | No mention, or an index — a link list, notes repo or scan dump. |

It also derives the language from file extensions, so it needs **zero** GitHub API calls.

The index test is *how many distinct CVEs the repository cites*, not how many files it
has: a PoC or a writeup is about one vulnerability, while a link list cites dozens.
Across a 55-repository sample, genuine PoCs cited at most 3 distinct CVEs and the
indexes cited 10, 22 and 118 — so the boundary sits in a wide empty gap. Citing many
CVEs only counts against a repo that also ships essentially no code, so a multi-CVE
exploit toolkit is not mistaken for a list.

```bash
export POCMAP_ALLOW_FETCH_POC_SOURCE=1     # CLI / Python API
```

> **Using the MCP server? `export` will not work.** MCP clients launch the server with a
> filtered environment — the stdio transport inherits only `HOME`, `LOGNAME`, `PATH`,
> `SHELL`, `TERM` and `USER` — so **no `POCMAP_*` variable set in your shell reaches the
> server**, and `verify_github_pocs` will keep returning `not_enabled`. Put it in your
> client config's `env` block instead (this applies to `GITHUB_API_TOKEN` and
> `NVD_API_KEY` too):
>
> ```json
> {
>   "mcpServers": {
>     "pocmap": {
>       "command": "uvx",
>       "args": ["--from", "pocmap[server]", "pocmap-mcp"],
>       "env": {
>         "POCMAP_ALLOW_FETCH_POC_SOURCE": "1",
>         "POCMAP_POC_SOURCE_DIR": "/home/you/.local/share/pocmap/poc-source",
>         "GITHUB_API_TOKEN": "ghp_xxxxxxxxxxxx"
>       }
>     }
>   }
> }
> ```

**This is off by default and must be set deliberately.** It writes third-party exploit
code to disk, which endpoint protection will often quarantine — run it on an isolated VM
or a dedicated research host. pocmap never executes, imports, or evaluates fetched
content; it only reads bytes.

The fetcher is bounded and hardened: owner/repo names are validated before they reach the
URL, transfers go through the same SSRF-guarded HTTP client as everything else (per-hop
redirect re-validation included), downloads and *extracted* sizes are both capped so a
decompression bomb cannot fill the disk, and archive members that are absolute, contain
`..`, or are symlinks/devices are dropped rather than extracted.

| Variable | Default | Description |
|----------|---------|-------------|
| `POCMAP_ALLOW_FETCH_POC_SOURCE` | `false` | Master switch. Nothing is fetched unless this is set. |
| `POCMAP_POC_SOURCE_DIR` | `<cache_dir>/poc-source` | Extraction root. |
| `POCMAP_POC_SOURCE_MAX_MB` | `100` | Per-repo cap on download and extracted size. |
| `POCMAP_POC_SOURCE_TOTAL_MAX_MB` | `1000` | Total cap; oldest fetched repos are evicted first. |

Offline mode has nothing to serve here — tarballs deliberately bypass the HTTP response
cache — so `--offline` reports that plainly instead of failing obscurely.

### Where to point `POCMAP_POC_SOURCE_DIR`

The default sits under the response cache, which is convenient but is *not* the right
place on every machine. Two things decide it: whether an on-access scanner will quarantine
the files, and whether the directory is synced anywhere.

**Windows.** Defender scans NTFS on access and will quarantine exploit source, which both
interrupts the fetch and silently corrupts any scoring that reads the files back. Either
put the directory inside WSL2 — its ext4 lives in a VHDX that Defender does not
real-time scan the way it does NTFS — or add a Defender exclusion for a dedicated path:

```powershell
# Option A: run pocmap inside WSL2 and keep the source there
#   (from your WSL shell)
export POCMAP_POC_SOURCE_DIR="$HOME/.local/share/pocmap/poc-source"

# Option B: stay on Windows and exclude one dedicated directory (admin PowerShell)
New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\pocmap\poc-source"
Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\pocmap\poc-source"
$env:POCMAP_POC_SOURCE_DIR = "$env:LOCALAPPDATA\pocmap\poc-source"
```

Exclude the narrowest path that works — one directory used only for this — never your
home directory or the whole repo.

**Linux / macOS.** No on-access scanner by default, so a per-user cache path is fine:

```bash
export POCMAP_POC_SOURCE_DIR="$HOME/.cache/pocmap/poc-source"
```

**VM or dedicated research host.** Anywhere. This is the intended environment and needs
no special handling.

**Do not point it at a synced or shared folder.** OneDrive, Dropbox, iCloud Drive and
Google Drive will upload the exploit source to cloud storage, where the provider's own
scanner may flag the account and the content may be shared further than intended. This is
easy to hit by accident on Windows, where `Documents` is frequently redirected to
OneDrive — so a repo cloned there gets a OneDrive-synced `.cache/` with it. Prefer
`%LOCALAPPDATA%` (never synced) over anything under `Documents`.

The same reasoning applies to `POCMAP_CACHE_DIR`, though it holds only API responses
rather than exploit code, so it is far less sensitive.

## Diagnostics: `doctor` & `cache`

`pocmap doctor` is the fastest path from "installed" to "working". It checks the Python
version, the optional `[server]` extra, the *format* of your `GITHUB_API_TOKEN` /
`NVD_API_KEY` (never printing their values), that the cache directory is writable, and
runs a live connectivity probe against NVD and the GitHub API. It prints a PASS/WARN/FAIL
table and **exits nonzero if any check FAILs**.

```bash
pocmap doctor                  # full run with a live connectivity probe
pocmap doctor --offline        # skip the network probe (labelled SKIPPED)
pocmap doctor --format json    # machine-readable check results
```

`pocmap cache info|clear` reports and clears the response cache (see above).

## PocMap in CI

`bulk` is a composable CI gate. Point it at a CVE list (a file, or `-` to read stdin),
choose a machine format, and use `--fail-on` to fail the build on a policy match:

```bash
# Fail the build (exit 6) if any dependency CVE is in the CISA KEV catalog,
# and write a SARIF log for GitHub code scanning.
pocmap bulk cves.txt --format sarif --output out/ --fail-on kev

# Pipe CVE IDs straight from another tool
grep -oE 'CVE-[0-9]{4}-[0-9]+' sbom.txt | pocmap bulk - --format json --fail-on critical
```

`--fail-on` accepts `critical`, `high` (HIGH *or worse*), `kev`, or `epss>=N` (e.g.
`epss>=50` on the 0-100 EPSS scale). A match exits `6` (`POLICY_FAIL`) — distinct from a
generic error — so CI can tell a tripped gate apart from an operational failure; no match
exits `0`. A malformed `--fail-on` exits `4`. In `table` mode `bulk` preserves its
historical behaviour (writes a JSON **and** an HTML report to `--output`); the machine
formats (`json`/`csv`/`sarif`) emit a clean stdout summary and write no files, so the
stream stays parseable.

See [`examples/ci-github-actions.yml`](examples/ci-github-actions.yml) for a ready-to-use
GitHub Actions job that runs the gate and uploads the SARIF to code scanning, and the
[`examples/`](examples/) directory for more runnable scripts.

## AI Agent Integration

PocMap includes a full MCP (Model Context Protocol) server exposing 22 AI-native tools for integration with Claude Desktop, Cursor, and other MCP-compatible clients.

### MCP Server Setup for Claude Desktop

Recommended: [`uv`](https://github.com/astral-sh/uv) on `PATH`, no local clone required.
`--from pocmap[server]` pulls the package with the MCP SDK and runs the `pocmap-mcp`
console script over STDIO.

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows:** `%APPDATA%/Claude/claude_desktop_config.json`

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

Pin a release with `pocmap-mcp@X.Y.Z` as the last arg (that PyPI version must include the
`pocmap-mcp` entry point). Optional env vars raise GitHub / NVD rate limits.

**Already installed locally** (`pip install "pocmap[server]"` or `pip install -e ".[server]"`):

```json
{
  "mcpServers": {
    "pocmap": {
      "command": "pocmap-mcp",
      "args": [],
      "env": {
        "GITHUB_API_TOKEN": "ghp_xxxxxxxxxxxx",
        "NVD_API_KEY": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      }
    }
  }
}
```

### Running the MCP Server

The MCP server requires the MCP SDK (`[server]` extra). It serves protocol
`2026-07-28` (stateless core); the SDK still speaks earlier protocol versions to
clients that have not upgraded:

```bash
pip install "pocmap[server]"
# or from a clone: pip install -e ".[server]"
```

```bash
# STDIO (default — what Claude Desktop / most MCP clients expect)
pocmap-mcp
python -m pocmap.mcp_server

# Other transports / flags
pocmap-mcp --transport sse
pocmap-mcp --transport http --host 0.0.0.0 --port 9000
pocmap-mcp --debug
```

Repo-root `python mcp_server.py` is a thin launcher shim to the same module (handy in a
git checkout). See also [`examples/mcp-config.json`](examples/mcp-config.json).

### MCP Tools (22 Total)

| Tool | Category | Description |
|------|----------|-------------|
| `lookup_cve` | CVE Intel | Full CVE details from NVD, CVE.org, CISA KEV, EPSS |
| `get_epss_score` | CVE Intel | EPSS exploitation probability score (0.0-1.0) with risk level |
| `check_kev_status` | CVE Intel | Check CISA Known Exploited Vulnerabilities catalog status |
| `get_attack_techniques` | CVE Intel | MITRE ATT&CK techniques a CVE maps to — how it's exploited and what follows |
| `find_github_pocs` | Exploits | GitHub PoC repos with stars, language, and forks |
| `verify_github_pocs` | Exploits | **Reads PoC source** to score whether a repo really exploits the CVE (opt-in) |
| `find_metasploit_module` | Exploits | Metasploit module availability and msfconsole command |
| `find_exploitdb_entry` | Exploits | ExploitDB entry with searchsploit command |
| `find_nuclei_template` | Exploits | Nuclei scanner template for detection/verification |
| `find_bug_bounty_reports` | Research | Bug bounty write-ups from HackerOne, PentesterLand |
| `find_practice_labs` | Labs | CTF labs on Vulhub, HackTheBox, TryHackMe |
| `find_vulhub_docker` | Labs | Vulhub Docker Compose environment with setup steps |
| `find_recent_exploits` | Discovery | Recently published CVEs with PoC/KEV/severity filters |
| `discover_product_cves` | Discovery | Find CVEs by product name with version constraints |
| `discover_package_cves` | Discovery | **Dependency vulnerabilities + the releases that fix them** (OSV, no API key) |
| `cve_to_cpe` | Conversion | Convert CVE to affected CPE identifiers |
| `cpe_to_cve` | Conversion | Find all CVEs affecting a given product (CPE) |
| `generate_json_report` | Reports | **One-shot CVE assessment** — details + all exploits + labs + bug bounty reports for one or many CVEs in a single call |
| `generate_html_report` | Reports | Self-contained HTML report with styled cards |
| `get_cve_assessment_playbook` | Playbooks | Full CVE assessment workflow playbook |
| `get_rapid_response_playbook` | Playbooks | Emergency response playbook for critical CVEs |
| `get_bug_bounty_playbook` | Playbooks | Bug bounty submission workflow playbook |

### MCP Resources

| Resource | URI Pattern | Content |
|----------|-------------|---------|
| CVE Info | `cve://{cve_id}` | Full CVE details as human-readable text |
| Exploits | `exploits://{cve_id}` | All available exploits and PoCs |
| Report | `report://{cve_id}` | Generated vulnerability report (JSON) |

### MCP Prompts

| Prompt | Description |
|--------|-------------|
| `vulnerability_assessment` | 5-phase structured CVE assessment workflow |
| `exploit_research` | Deep exploit analysis with detection engineering focus |
| `bug_bounty_analysis` | Real-world impact analysis from bug bounty write-ups |

### Example Agent Workflow

```
User: "Should I prioritize CVE-2021-44228, CVE-2023-38408, or CVE-2024-21413?"

Agent:
1. lookup_cve("CVE-2021-44228")     -> CVSS 10.0 CRITICAL, EPSS 0.9753, KEV=true
2. lookup_cve("CVE-2023-38408")     -> CVSS 9.8 CRITICAL, EPSS 0.3124, KEV=true
3. lookup_cve("CVE-2024-21413")     -> CVSS 8.8 HIGH, EPSS 0.8912, KEV=true
4. get_epss_score for each          -> Confirm exploitation probabilities
5. find_github_pocs for each        -> Count available exploits
6. check_kev_status for each        -> Confirm KEV status
7. Prioritize: Log4j (highest EPSS + most exploits) > CVE-2024-21413 > CVE-2023-38408
```

## JSON Schemas

Export structured JSON schemas for all data models to integrate with AI agents, validation pipelines, and external tools:

```python
from pocmap.models import export_schemas

paths = export_schemas("./schemas")
for p in paths:
    print(f"  {p.name}")
# CVSSScore.json
# CVEInfo.json
# Exploit.json
# LabEnvironment.json
# BugBountyReport.json
# CPEInfo.json
# RecentExploitResult.json
# ReportEntry.json
# MultiReport.json
# VersionConstraint.json
# ProductDiscoveryResult.json
# PackageVulnerability.json
# PackageDiscoveryResult.json
```

Use these schemas for:
- **AI Agent Context**: Provide schema files to AI agents so they understand data structures
- **Validation Pipelines**: Validate incoming/outgoing data against schemas
- **API Documentation**: Auto-generate API docs from schemas
- **Type Generation**: Generate TypeScript, Go, or Rust types from JSON schemas

## Architecture

```
+------------------+     +------------------+     +------------------+
|     CLI Layer    |     |   MCP Server     |     |   Python API     |
|   (Typer/Rich)   |     |  (MCP SDK / 21   |     |   (Services)     |
+------------------+     |     Tools)       |     +------------------+
         |               +------------------+             |
         |                         |                      |
         v                         v                      v
+------------------+     +------------------+     +------------------+
|   Service Layer  |<--->|   Service Layer  |<--->|   Service Layer  |
|                  |     |                  |     |                  |
|  CVEService      |     |  ExploitService  |     |  ReportService   |
|  BugBountyService|     |  LabService      |     |  + 2 more        |
+------------------+     +------------------+     +------------------+
         |                         |                      |
         v                         v                      v
+------------------+     +------------------+     +------------------+
|  Client Layer    |     |  Client Layer    |     |   Models Layer   |
|                  |     |                  |     |                  |
|  NVDClient       |     |  GitHubClient    |     |  CVEInfo         |
|  CPEDictClient   |     |  ExploitClient   |     |  Exploit         |
|  CVEOrgClient    |     |  + others        |     |  + 11 more       |
+------------------+     +------------------+     +------------------+
         |                         |
         v                         v
+-------------------------------------------------------------+
|                    External Data Sources                     |
|  NVD API  CVE.org  CISA KEV  EPSS  GitHub  ExploitDB  etc.  |
+-------------------------------------------------------------+
```

**Layered architecture:**
1. **Presentation Layer**: CLI (`cli.py`) + MCP Server (`pocmap.mcp_server` / `pocmap-mcp`)
2. **Service Layer**: Business logic (7 services: CVE, Exploit, Lab, Report, Bug Bounty, Recent, Product Discovery)
3. **Client Layer**: External API clients (NVD, GitHub, CVE.org, ExploitDB, etc.)
4. **Model Layer**: 16 Pydantic models with full validation and JSON Schema support (13 exported as standalone JSON schemas)
5. **Utility Layer**: HTTP client with retries, formatters, validators, config
6. **Toolkit Layer**: Bug bounty hunter toolkit (checklists, methodology, templates, prioritization, scope, automation)

## Security Features

### SSRF Protection
All HTTP requests pass through `is_safe_url()` validation that blocks:
- Internal hosts: `localhost`, `127.0.0.1`, `0.0.0.0`, `::1` (matched by exact host / dotted-suffix, so public hosts that merely *contain* those strings — e.g. the IPv6 literal `2606:4700:4700::1111` — are not falsely blocked)
- Cloud metadata endpoints: `169.254.169.254` (AWS), `metadata.google.internal` (GCP), `100.100.100.200` (Alibaba)
- Private IP ranges, loopback, link-local, and reserved addresses
- Numeric-encoded IPs (decimal/hex/octal) and IPv4-mapped IPv6 that canonicalize to an internal address
- Non-HTTP(S) schemes: `file://`, `ftp://`, `gopher://`, `dict://`

Redirects are followed manually and **every hop is re-validated** through the same guard, and credential-bearing headers (`Authorization`, `Cookie`, NVD `apiKey`) are **stripped on a cross-origin redirect** so a token is never replayed to a redirect target.

### CSV Injection Prevention
CSV export neutralizes spreadsheet **formula injection** (CWE-1236): a string cell
that begins with a formula character (`=`, `+`, `-`, `@`, tab, or CR) is prefixed
with a single quote so externally-sourced text (CVE descriptions, repo names) cannot
execute when the file is opened in Excel / Google Sheets. Genuine numbers are left intact.

### Sandboxed Templates
Jinja2 templates use `SandboxedEnvironment` with `BaseLoader` (no filesystem access) and `select_autoescape` for HTML/XML contexts. Prevents Server-Side Template Injection (SSTI) attacks.

### Path Traversal Protection
File operations use `safe_path()` which normalizes paths and validates they stay within the base directory. Raises `ValueError` on traversal attempts.

### Input Validation
- CVE IDs validated against `^CVE-\d{4}-\d+$` regex pattern
- CPE strings parsed with strict format validation
- Maximum bulk size limit (100 CVEs) prevents DoS
- All inputs sanitized before external API calls

### XSS Prevention
- HTML report generation uses auto-escaped template rendering
- All user-facing output is properly escaped
- No inline JavaScript execution in generated HTML reports

## Configuration

Configuration is loaded from environment variables (prefixed with `POCMAP_`) and optional `.env` file:

```bash
# Create .env file
cat > .env << 'EOF'
GITHUB_API_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
POCMAP_HTTP_TIMEOUT=30
POCMAP_MAX_RETRIES=3
POCMAP_BACKOFF_FACTOR=1.5
POCMAP_THREAD_POOL_SIZE=10
POCMAP_LOG_LEVEL=INFO
POCMAP_CACHE_ENABLED=true
POCMAP_CACHE_TTL=3600
POCMAP_CACHE_MAX_MB=200
EOF
```

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_API_TOKEN` | None | GitHub personal access token for higher rate limits |
| `NVD_API_KEY` | None | NVD API key for increased rate limits |
| `POCMAP_HTTP_TIMEOUT` | 30 | HTTP request timeout in seconds |
| `POCMAP_MAX_RETRIES` | 3 | Maximum retry attempts for failed requests |
| `POCMAP_BACKOFF_FACTOR` | 1.5 | Exponential backoff multiplier |
| `POCMAP_THREAD_POOL_SIZE` | 10 | Worker thread count for bulk operations |
| `POCMAP_LOG_LEVEL` | INFO | Logging verbosity (DEBUG, INFO, WARNING, ERROR) |
| `POCMAP_CACHE_ENABLED` | true | Enable the persistent HTTP response cache |
| `POCMAP_CACHE_DIR` | ./.cache | Directory for cached responses |
| `POCMAP_CACHE_TTL` | 3600 | Seconds a cached entry stays fresh |
| `POCMAP_CACHE_MAX_MB` | 200 | On-disk cache cap (MB) before LRU eviction |
| `POCMAP_OFFLINE` | false | Serve HTTP only from cache; a miss errors instead of hitting the network |
| `POCMAP_ALLOW_FETCH_POC_SOURCE` | false | Opt in to downloading PoC **source code** to disk (see below) |
| `POCMAP_POC_SOURCE_DIR` | `<cache>/poc-source` | Where fetched PoC source is extracted |
| `POCMAP_POC_SOURCE_MAX_MB` | 100 | Per-repo cap, applied to download **and** extracted size |
| `POCMAP_POC_SOURCE_TOTAL_MAX_MB` | 1000 | Total on-disk cap for fetched sources |

See [Caching & Offline Mode](#caching--offline-mode) and the [exit-code contract](#output-formats--exit-codes)
for how these behave at runtime.

## Contributing

### Adding New Exploit Sources

New exploit sources can be registered via the plugin pattern:

1. Create a new client in `src/pocmap/clients/`:
```python
# src/pocmap/clients/my_source_client.py
from pocmap.models import Exploit, ExploitSource

class MySourceClient:
    """Client for My Exploit Source."""

    SOURCE = ExploitSource.OTHER  # or add to enum

    def search(self, cve_id: str) -> list[Exploit]:
        # Implement search logic
        return []
```

2. Integrate into `ExploitService` in `src/pocmap/services/exploit_service.py`:
```python
from pocmap.clients.my_source_client import MySourceClient

class ExploitService:
    def __init__(self):
        self._my_source = MySourceClient()

    def find_exploits(self, cve_id: str) -> list[Exploit]:
        exploits = []
        exploits.extend(self._my_source.search(cve_id))
        # ... existing sources
        return exploits
```

3. Add tests and documentation.

### Third-Party Exploit Sources (plugins — no fork needed)

External packages can add exploit sources **without modifying pocmap** by registering an
entry point in the `pocmap.exploit_sources` group. A source is any object exposing
`search(cve_id: str) -> list[Exploit]` (the `ExploitSourcePlugin` protocol):

```toml
# your package's pyproject.toml
[project.entry-points."pocmap.exploit_sources"]
my-source = "my_pkg.source:MySource"
```

```python
# my_pkg/source.py
from pocmap.models import Exploit, ExploitSource

class MySource:
    source = "my-source"

    def search(self, cve_id: str) -> list[Exploit]:
        return [Exploit(source=ExploitSource.OTHER, url="https://…", title="…")]
```

`pip install` your package and its results automatically appear in `pocmap lookup` and
`ExploitService.find_exploits`. Plugins are **error-isolated**: a failing plugin degrades
to a `FetchStatus.ERROR` (visible via `find_exploits_with_status`) without affecting the
built-in sources. A complete runnable example is in
[`examples/example-exploit-source/`](examples/example-exploit-source/). Note: entry-point
plugins execute third-party code you chose to install — pocmap only calls their `search()`
and aggregates the results with per-source status isolation.

### Development Setup

```bash
git clone https://github.com/zebbern/pocmap.git
cd pocmap
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest -v

# Run type checker
mypy src/pocmap

# Run linter
ruff check src/pocmap
```

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

*PocMap is not a weapon. It is a research and defensive tool for security professionals and bug bounty hunters. Always operate within the bounds of applicable law and program scope.*
