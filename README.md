# PocMap

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/zebbern/pocmap)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Pydantic](https://img.shields.io/badge/pydantic-v2-purple.svg)](https://docs.pydantic.dev/)

AI-agent-optimized CVE exploit discovery toolkit for bug bounty hunters and security professionals. Find Proof-of-Concept exploits, CTF labs, bug bounty reports, and vulnerability intelligence from a single interface.

## Key Features

- **Multi-Source Discovery**: Queries GitHub, Exploit-DB, Metasploit, Nuclei, CTF labs, and bug bounty platforms simultaneously
- **Structured Pydantic Models**: All data validated and serialized with full type safety and JSON Schema support
- **MCP Server Integration**: 19 AI-native tools via Model Context Protocol for Claude Desktop, Cursor, and other AI agents
- **Bug Bounty Toolkit**: Complete hunter toolkit with checklists, workflows, report templates, prioritization engine, and scope management
- **Rich CLI**: 12 commands with colorized tables, progress bars, and bulk processing
- **Composable Output**: `table`, `json`, `csv`, `md`, and `sarif` output on read commands, plus a stable [exit-code contract](#output-formats--exit-codes) for scripting and CI
- **CI Security Gate**: `bulk --fail-on kev|critical|high|epss>=N` fails the build on policy matches and emits SARIF 2.1.0 for GitHub code scanning
- **Caching & Offline Mode**: persistent, TTL'd HTTP response cache and a first-class `--offline` mode for air-gapped or repeatable runs
- **Snapshot Diffs**: `latest`/`discover --diff` show only what changed since the last identical run
- **Concurrent Processing**: Thread pool-based bulk CVE processing with exponential backoff retry logic
- **Report Generation**: Self-contained HTML reports (styled cards and tables, inline CSS, no external assets or JS) plus JSON export
- **Security-Hardened**: SSRF protection, sandboxed Jinja2 templates, path traversal prevention, input validation

## Installation

PocMap is **not yet published to PyPI** — install from source in editable mode.
(PyPI / `pipx install pocmap` is planned via release automation; until then use the
`git clone` flow below.)

```bash
# Install from source (editable)
git clone https://github.com/zebbern/pocmap.git
cd pocmap
pip install -e .

# With the MCP server (FastMCP SDK — required to run mcp_server.py)
pip install -e ".[server]"

# With async support
pip install -e ".[async]"

# With development dependencies (pytest, mypy, ruff)
pip install -e ".[dev]"

# Verify installation
pocmap --version        # -> pocmap v2.0.0
```

Every command is also available as `python -m pocmap ...` if the `pocmap` script is
not on your `PATH`.

**Requirements:**
- Python 3.10+ (developed/verified on 3.12)
- Dependencies: pydantic>=2.0, requests>=2.28, typer>=0.9, rich>=13.0

**Optional:**
- `GITHUB_API_TOKEN` - GitHub PAT for higher rate limits (recommended)
- `NVD_API_KEY` - NVD API key for increased rate limits
- The `[server]` extra (FastMCP SDK) is required only for the MCP server

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

### CLI Commands (12)

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
#            CPEInfo.json, ReportEntry.json, MultiReport.json
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
    print(f"{cve['id']}: potential=${bounty['estimate']}")
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
| `--format`, `-f` | Output format: `table` (default), `json`, `csv`, `md`, `sarif` |
| `--quiet`, `-q` | Suppress decorative output |

**Output includes:** CVE ID, description, CVSS severity/score, EPSS, KEV status, vendor, product, publication date, PoC availability, and PoC source counts.

## Product Discovery

Find all CVEs affecting a specific product without needing a CVE ID. Uses fuzzy product name matching, version constraint parsing, and NVD keyword search.

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
| `--format`, `-f` | Output format: `table` (default), `json`, `csv`, `md`, `sarif` |
| `--quiet`, `-q` | Suppress decorative output |

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

Aliases are resolved via fuzzy matching against a curated mapping of 60+ products. You can also use partial matches (e.g., "apache struts" is split into vendor=`apache` + product=`struts`).

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

Results are grouped into three confidence tiers:
- **Confirmed**: Vendor AND product match AND version constraint is met
- **Possibly**: Vendor OR product matches but version info is unclear
- **Not enough data**: CVE has insufficient product/version information

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
rather than masquerading as "not found" or "no results".

**Cache / offline configuration:**

| Variable | Default | Description |
|----------|---------|-------------|
| `POCMAP_CACHE_ENABLED` | `true` | Enable/disable the persistent HTTP cache. |
| `POCMAP_CACHE_DIR` | `./.cache` | Directory for cached responses. |
| `POCMAP_CACHE_TTL` | `3600` | Seconds a cached entry stays fresh. |
| `POCMAP_CACHE_MAX_MB` | `200` | On-disk cache cap (MB) before LRU eviction. |
| `POCMAP_OFFLINE` | `false` | Serve only from cache; a miss errors instead of hitting the network. |

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

PocMap includes a full MCP (Model Context Protocol) server exposing 19 AI-native tools for integration with Claude Desktop, Cursor, and other MCP-compatible clients.

### MCP Server Setup for Claude Desktop

Add to your Claude Desktop configuration file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows:** `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "pocmap": {
      "command": "python",
      "args": ["/path/to/pocmap/mcp_server.py"],
      "env": {
        "GITHUB_API_TOKEN": "ghp_xxxxxxxxxxxx",
        "NVD_API_KEY": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      }
    }
  }
}
```

### Running the MCP Server

The MCP server requires the FastMCP SDK, which ships in the `server` extra. Install it first:

```bash
pip install -e ".[server]"
```

```bash
# STDIO transport (default, for Claude Desktop)
python mcp_server.py

# SSE transport on port 8000
python mcp_server.py --transport sse

# HTTP transport
python mcp_server.py --transport http --host 0.0.0.0 --port 9000

# Debug mode
python mcp_server.py --debug
```

### MCP Tools (19 Total)

| Tool | Category | Description |
|------|----------|-------------|
| `lookup_cve` | CVE Intel | Full CVE details from NVD, CVE.org, CISA KEV, EPSS |
| `get_epss_score` | CVE Intel | EPSS exploitation probability score (0.0-1.0) with risk level |
| `check_kev_status` | CVE Intel | Check CISA Known Exploited Vulnerabilities catalog status |
| `find_github_pocs` | Exploits | GitHub PoC repos with stars, language, and forks |
| `find_metasploit_module` | Exploits | Metasploit module availability and msfconsole command |
| `find_exploitdb_entry` | Exploits | ExploitDB entry with searchsploit command |
| `find_nuclei_template` | Exploits | Nuclei scanner template for detection/verification |
| `find_bug_bounty_reports` | Research | Bug bounty write-ups from HackerOne, PentesterLand |
| `find_practice_labs` | Labs | CTF labs on Vulhub, HackTheBox, TryHackMe |
| `find_vulhub_docker` | Labs | Vulhub Docker Compose environment with setup steps |
| `find_recent_exploits` | Discovery | Recently published CVEs with PoC/KEV/severity filters |
| `discover_product_cves` | Discovery | Find CVEs by product name with version constraints |
| `cve_to_cpe` | Conversion | Convert CVE to affected CPE identifiers |
| `cpe_to_cve` | Conversion | Find all CVEs affecting a given product (CPE) |
| `generate_json_report` | Reports | Comprehensive JSON report for CVEs |
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
# ReportEntry.json
# MultiReport.json
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
|   (Typer/Rich)   |     |  (FastMCP/19     |     |   (Services)     |
+------------------+     |     Tools)       |     +------------------+
         |               +------------------+             |
         |                         |                      |
         v                         v                      v
+------------------+     +------------------+     +------------------+
|   Service Layer  |<--->|   Service Layer  |<--->|   Service Layer  |
|                  |     |                  |     |                  |
|  CVEService      |     |  ExploitService  |     |  ReportService   |
|  BugBountyService|     |  LabService      |     |  + 3 more        |
+------------------+     +------------------+     +------------------+
         |                         |                      |
         v                         v                      v
+------------------+     +------------------+     +------------------+
|  Client Layer    |     |  Client Layer    |     |   Models Layer   |
|                  |     |                  |     |                  |
|  NVDClient       |     |  GitHubClient    |     |  CVEInfo         |
|  CVEOrgClient    |     |  ExploitClient   |     |  Exploit         |
|  + others        |     |  + others        |     |  + 6 more        |
+------------------+     +------------------+     +------------------+
         |                         |
         v                         v
+-------------------------------------------------------------+
|                    External Data Sources                     |
|  NVD API  CVE.org  CISA KEV  EPSS  GitHub  ExploitDB  etc.  |
+-------------------------------------------------------------+
```

**Layered architecture:**
1. **Presentation Layer**: CLI (`cli.py`) + MCP Server (`mcp_server.py`)
2. **Service Layer**: Business logic (7 services: CVE, Exploit, Lab, Report, Bug Bounty, Recent, Product Discovery)
3. **Client Layer**: External API clients (NVD, GitHub, CVE.org, ExploitDB, etc.)
4. **Model Layer**: 8 Pydantic models with full validation and JSON Schema support
5. **Utility Layer**: HTTP client with retries, formatters, validators, config
6. **Toolkit Layer**: Bug bounty hunter toolkit (checklists, methodology, templates, prioritization, scope, automation)

## Security Features

### SSRF Protection
All HTTP requests pass through `is_safe_url()` validation that blocks:
- Internal hosts: `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`
- Cloud metadata endpoints: `169.254.169.254` (AWS), `metadata.google.internal` (GCP)
- Private IP ranges, loopback, link-local, and reserved addresses
- Non-HTTP(S) schemes: `file://`, `ftp://`, `gopher://`, `dict://`

### Sandboxed Templates
Jinja2 templates use `SandboxedEnvironment` with `BaseLoader` (no filesystem access) and `select_autoescape` for HTML/XML contexts. Prevents Server-Side Template Injection (SSTI) attacks.

### Path Traversal Protection
File operations use `_safe_path()` which normalizes paths and validates they stay within the base directory. Raises `ValueError` on traversal attempts.

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
