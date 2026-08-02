# PocMap

[![Version](https://img.shields.io/badge/version-2.7.0-blue.svg)](https://github.com/zebbern/pocmap)
[![PyPI](https://img.shields.io/pypi/v/pocmap.svg)](https://pypi.org/project/pocmap/)
[![Docs](https://img.shields.io/badge/docs-zebbern.github.io-blue.svg)](https://zebbern.github.io/pocmap/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Pydantic](https://img.shields.io/badge/pydantic-v2-purple.svg)](https://docs.pydantic.dev/)

AI-agent-optimized CVE exploit discovery toolkit for bug bounty hunters and security professionals. Find Proof-of-Concept exploits, CTF labs, bug bounty reports, and vulnerability intelligence from a single interface.

Full guides: [Documentation](https://zebbern.github.io/pocmap/)

## Key Features

- **Multi-Source Discovery**: Queries GitHub, Exploit-DB, Metasploit, Nuclei, CTF labs, and bug bounty platforms simultaneously
- **GitHub Search PoC Fallback**: Curated indexes first; when they miss (index-lag CVEs), falls back to GitHub repository search. Rate limits surface as `rate_limited`, never as empty
- **Structured Pydantic Models**: All data validated and serialized with full type safety and JSON Schema support
- **MCP Server Integration**: 22 AI-native tools via Model Context Protocol for Claude Desktop, Cursor, and other AI agents
- **Bug Bounty Toolkit**: Python-API hunter toolkit (checklists, workflows, report templates, prioritization, scope/automation); CLI `bugbounty` searches write-ups only
- **Rich CLI**: 13 commands with colorized tables, progress bars, and bulk processing
- **Composable Output**: `table`, `json`, `csv`, `md`, and `sarif` output on read commands, plus a stable [exit-code contract](https://zebbern.github.io/pocmap/cli/#exit-code-contract) for scripting and CI
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

Options, discovery internals, formats, caching, and CI: [CLI reference](https://zebbern.github.io/pocmap/cli/).

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

# Find all exploits across all sources (curated indexes, then GitHub Search fallback)
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

The `pocmap.bugbounty` module is a **Python API** (and packaged playbooks) for checklists,
methodology workflows, report templates, prioritization, scope management, and
automation. The CLI only exposes `pocmap bugbounty <CVE>` for write-up search.

Full examples: [Bug Bounty Toolkit](https://zebbern.github.io/pocmap/bug-bounty/).

## Recent CVE Discovery

```bash
pocmap latest
pocmap latest --since 7d --severity critical --only-with-poc
pocmap latest --kev-only --min-epss 50.0
```

Filters, sorting, `--diff`, and `--notify`: [Recent CVE discovery](https://zebbern.github.io/pocmap/cli/#recent-cve-discovery).

## Product Discovery

Find CVEs by product name/version via NVD CPE matching.

```bash
pocmap discover "Log4j" --version 2.x
pocmap discover "struts" --vendor apache --version 2.x
```

Resolution rules, aliases, and version constraints: [Product discovery](https://zebbern.github.io/pocmap/cli/#product-discovery).

## Dependency Vulnerabilities

`pocmap package` answers whether a dependency you ship is vulnerable and which releases fix it (OSV; no API key).

```bash
pocmap package PyPI django --version 3.2.0
pocmap package npm lodash --version 4.17.20 --format sarif --output out/
```

Ecosystems, ranking, and how to read results: [Dependency vulnerabilities](https://zebbern.github.io/pocmap/cli/#dependency-vulnerabilities).

## Output Formats & Exit Codes

```bash
pocmap lookup CVE-2021-44228 --format json
pocmap latest --since 7d --format sarif
```

Formats: `table`, `json`, `csv`, `md`, `sarif`. Stable exit codes `0`–`6` (including `POLICY_FAIL=6` for CI gates): [Output formats & exit codes](https://zebbern.github.io/pocmap/cli/#output-formats-exit-codes).

## Caching & Offline Mode

```bash
pocmap lookup CVE-2021-44228
pocmap --offline lookup CVE-2021-44228
pocmap cache info
pocmap cache clear
```

TTL, cache location, and offline stale-serve behaviour: [Caching & offline mode](https://zebbern.github.io/pocmap/cli/#caching-offline-mode).

## Verifying PoCs (opt-in)

`verify_github_pocs` downloads PoC **source** (off by default) and scores `confirmed` / `likely` / `unverified` / `unrelated`. Requires `POCMAP_ALLOW_FETCH_POC_SOURCE=1` (MCP clients: put it in the client `env` block — shell `export` does not reach the server).

Full guidance: [Verifying PoCs](https://zebbern.github.io/pocmap/verifying-pocs/).

## Diagnostics & CI

```bash
pocmap doctor
pocmap bulk cves.txt --format sarif --fail-on kev
```

See [Diagnostics](https://zebbern.github.io/pocmap/cli/#diagnostics-doctor-and-cache) and [PocMap in CI](https://zebbern.github.io/pocmap/cli/#pocmap-in-ci). Ready-made job: [`examples/ci-github-actions.yml`](examples/ci-github-actions.yml).

## AI Agent Integration

PocMap includes a full MCP (Model Context Protocol) server exposing 22 AI-native tools for integration with Claude Desktop, Cursor, and other MCP-compatible clients.

**Canonical MCP / agent consumption guide:** [`.claude/skills/pocmap-agent/references/mcp_tools.md`](.claude/skills/pocmap-agent/references/mcp_tools.md)
(parameters, return shapes, EPSS scales, error envelopes). Skill overview:
[`.claude/skills/pocmap-agent/SKILL.md`](.claude/skills/pocmap-agent/SKILL.md).
Generated inventory: [MCP tools](https://zebbern.github.io/pocmap/reference/mcp-tools/).

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

### MCP Server Setup for Cursor

Project config: `.cursor/mcp.json` in the workspace root. For a global server, use
**Cursor Settings → MCP**. Same `uvx` / `env` shape as Claude Desktop above.

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

**Already installed locally** (Claude or Cursor — `pip install "pocmap[server]"` or
`pip install -e ".[server]"`):

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

Requires the `[server]` extra (MCP SDK). Protocol revisions up to `2026-07-28` are
supported; STDIO clients typically negotiate `2025-11-25` at `initialize`.

```bash
pip install "pocmap[server]"
# or from a clone: pip install -e ".[server]"

# STDIO (default — what Claude Desktop / Cursor / most MCP clients expect)
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
| `find_practice_labs` | Labs | CTF labs on Vulhub and HackTheBox |
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

```bash
pocmap schemas --output ./schemas
```

```python
from pocmap.models import export_schemas
paths = export_schemas("./schemas")
```

Schema reference: [Data model schemas](https://zebbern.github.io/pocmap/reference/schemas/).

## Architecture

Layered: CLI / MCP / Python API → services → clients → Pydantic models, with SSRF-guarded HTTP and a bug-bounty toolkit layer.

Details and package layout: [Architecture](https://zebbern.github.io/pocmap/architecture/).

## Security Features

- **SSRF protection** — exact-host/suffix URL allow checks, DNS-rebinding resolution, per-hop redirect re-validation, credential headers stripped on cross-origin redirects
- **CSV formula injection neutralization** (CWE-1236) on CSV export
- **Sandboxed Jinja2** templates (`SandboxedEnvironment`, no filesystem loader)
- **Path traversal** blocked via `safe_path()`
- **Input validation** — CVE/CPE checks, bulk capped at 100 CVEs
- **XSS-safe HTML reports** — auto-escaped templates, no external assets or JS

## Configuration

Configuration is loaded from environment variables (prefixed with `POCMAP_`) and an optional
`.env` file, discovered from the current directory upward:

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
| `POCMAP_CACHE_DIR` | platform user cache | Directory for cached responses (see [Caching](https://zebbern.github.io/pocmap/cli/#caching-offline-mode)) |
| `POCMAP_CACHE_TTL` | 3600 | Seconds a cached entry stays fresh |
| `POCMAP_CACHE_MAX_MB` | 200 | On-disk cache cap (MB) before LRU eviction |
| `POCMAP_OFFLINE` | false | Serve HTTP only from cache; a miss errors instead of hitting the network |
| `POCMAP_ALLOW_FETCH_POC_SOURCE` | false | Opt in to downloading PoC **source code** to disk (see [Verifying PoCs](https://zebbern.github.io/pocmap/verifying-pocs/)) |
| `POCMAP_POC_SOURCE_DIR` | `<cache>/poc-source` | Where fetched PoC source is extracted |
| `POCMAP_POC_SOURCE_MAX_MB` | 100 | Per-repo cap, applied to download **and** extracted size |
| `POCMAP_POC_SOURCE_TOTAL_MAX_MB` | 1000 | Total on-disk cap for fetched sources |

## Contributing

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

In-tree client walkthrough and dev setup: [Contributing](https://zebbern.github.io/pocmap/contributing/).

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
