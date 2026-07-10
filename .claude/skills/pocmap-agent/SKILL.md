---
name: pocmap-agent
description: >
  Use the PocMap Python package for CVE exploit discovery, vulnerability research,
  and bug bounty hunting. Provides 19 MCP tools and 10 CLI commands for looking up
  CVEs, finding exploits/PoCs, discovering recent vulnerabilities, product-based
  CVE discovery, CPE/CVSS analysis, bug bounty report lookup, and practice lab
  environments. Trigger when the user mentions CVE lookup, exploit discovery,
  PoC finding, vulnerability assessment, bug bounty research, security analysis,
  CPE to CVE conversion, EPSS scoring, KEV catalog checking, recent CVE monitoring,
  product vulnerability discovery, or security report generation.
---

# PocMap Agent Skill

Use the PocMap Python package to look up CVEs, find exploits and PoCs, discover
recent vulnerabilities, map products to CVEs, analyze CPE/CVSS data, check CISA KEV
and EPSS scores, find bug bounty reports, and locate practice lab environments.

> **Accuracy note:** This skill is verified against the source in `src/pocmap/`.
> The public Python API is **synchronous** (no `async`/`await`). If any example
> disagrees with the code, the code in `src/pocmap/services/` and `config.py` wins.

## Quick Start

Install from source (this repo uses a `src/` layout, installed editable):

```bash
pip install -e ".[dev]"     # package + pytest/ruff/mypy
pip install -e ".[server]"  # FastMCP SDK for the MCP server (the 'server' extra)
```

Run via CLI (both forms work):

```bash
pocmap lookup CVE-2021-44228
python -m pocmap lookup CVE-2021-44228
python -m pocmap --help      # authoritative list of all 10 commands
```

Use in Python (synchronous; services are context managers):

```python
from pocmap.services import CVEService

with CVEService() as svc:
    info = svc.get_cve_info("CVE-2021-44228")
    print(info.cvss, info.epss, info.kev_status)
```

Run the MCP server (entrypoint is at the **repo root**, not inside the package):

```bash
python mcp_server.py                      # STDIO (default)
python mcp_server.py --transport sse      # SSE on 127.0.0.1:8000
python mcp_server.py --transport http     # Streamable HTTP
# There is NO `python -m pocmap.mcp_server` — that module does not exist.
```

## Package Architecture

Layered: **CLI / MCP (presentation) → `services/` → `clients/` → `models` (pydantic)**.

### Services Layer (`pocmap.services`) — real classes and methods

All are synchronous; all support `with ... as svc:` and a `close()` method.

| Service | Key methods (verified) |
|---------|------------------------|
| `CVEService` | `get_cve_info(cve_id)`, `get_cpes(cve_id)`, `get_description(cve_id)`, `cpe_to_cves(cpe)`, `validate_cve_id(cve_id)` (classmethod) |
| `ExploitService` | `find_exploits(cve_id)`, `find_github_pocs(cve_id)`, `find_db_exploits(cve_id)`, `get_readme(repo_url)`, `filter_by_language(...)`, `sort_by_popularity(...)` |
| `LabService` | `find_labs(cve_id)`, `search_vulhub(cve_id)`, `search_hackthebox(cve_id)`, `search_tryhackme(cve_id)` |
| `ReportService` | `generate_report(cve_id)`, `generate_bulk_report(cve_ids)`, `generate_bulk_report_from_file(path)`, `save_json_report(...)`, `save_html_report(...)` |
| `BugBountyService` | `find_reports(cve_id)`, `search_hackerone(cve_id)`, `search_pentesterland(cve_id)`, `search_bugbounty_hunting(cve_id)` |
| `RecentService` | `find_recent_cves(...)` |
| `ProductDiscoveryService` | `discover_by_product(product, version=, vendor=, limit=)`, `normalize_product(product)`, `parse_version(version)`, `search_nvd_by_keyword(...)`, `match_cves_to_product(...)` |

### Toolkit Layer (`pocmap.bugbounty`)

Checklists, methodology, prioritization (EPSS+CVSS triage), scope management,
templates, automation (batch/monitoring/webhooks), and JSON playbooks under
`bugbounty/playbooks/`.

## Decision Guide

Pick the right MCP tool or CLI command. **All MCP tool names below are exact.**

| Goal | MCP Tool | CLI Command |
|------|----------|-------------|
| Look up a CVE by ID | `lookup_cve` | `pocmap lookup CVE-XXXX-XXXX` |
| Recent CVEs / monitoring | `find_recent_exploits` | `pocmap latest --since 24h` |
| CVEs for a product | `discover_product_cves` | `pocmap discover "Product" --version 2.x` |
| GitHub PoCs for a CVE | `find_github_pocs` | `pocmap lookup CVE-… ` (PoCs shown) |
| Metasploit module | `find_metasploit_module` | — |
| ExploitDB entry | `find_exploitdb_entry` | — |
| Nuclei template | `find_nuclei_template` | — |
| CISA KEV status | `check_kev_status` | — |
| EPSS score | `get_epss_score` | — |
| Bug bounty reports | `find_bug_bounty_reports` | `pocmap bugbounty CVE-…` |
| Practice labs | `find_practice_labs` | `pocmap labs CVE-…` |
| Vulhub Docker lab | `find_vulhub_docker` | `pocmap labs CVE-…` |
| CVE → CPE | `cve_to_cpe` | `pocmap cpes CVE-…` |
| CPE → CVEs | `cpe_to_cve` | `pocmap cpe2cve "cpe:2.3:…"` |
| JSON report (multi-CVE) | `generate_json_report` | `pocmap bulk cves.txt` |
| HTML report (multi-CVE) | `generate_html_report` | `pocmap bulk cves.txt` |
| Assessment playbook | `get_cve_assessment_playbook` | — |
| Rapid-response playbook | `get_rapid_response_playbook` | — |
| Bug-bounty playbook | `get_bug_bounty_playbook` | — |
| Export tool schemas | — | `pocmap schemas` |
| Show a repo README | — | `pocmap readme <github-url>` |

## Key Constraints

- **CVE ID format:** `CVE-YYYY-NNNN+` (4-digit year, 4+ digit id). Validated by
  `utils.validators.validate_cve_id` against `^CVE-\d{4}-\d+$`.
  (Note: `models.validate_cve_id` only checks empty/length, not the regex.)
- **Time window (`--since`):** `1h`, `24h`, `7d`, `30d`.
- **Severity (`--severity`):** `critical`, `high`, `medium`, `low` (case-insensitive;
  comma-separated accepted).
- **EPSS scales differ — convert at the boundary:** the CLI `--min-epss` and the
  MCP `find_recent_exploits` `min_epss` use a **0–100** scale; `get_epss_score`
  returns **0.0–1.0**. In the Python API, `CVEInfo.epss` is **0–100**.
- **Bulk cap:** at most **100** CVEs per bulk/report call.
- **Product aliases:** `discover_product_cves` / `ProductDiscoveryService` resolve
  aliases (e.g. `struts` → `Apache Struts`).

## Error Handling (MCP tools)

Every MCP tool returns a JSON **string**. On failure it contains an `error` key
and a `category`. Always check it:

```python
data = json.loads(result)
if "error" in data:
    category = data.get("category", "unknown")   # not_found | network_error | invalid_input | unknown
    retryable = data.get("retryable", False)
```

Retry only when `retryable` is true: wait 2s, retry; then 4s, retry once more
(3 attempts total); then surface the last error with its `suggestion`.

## Python API Examples (synchronous)

```python
from pocmap.services import CVEService, ExploitService

with CVEService() as cve, ExploitService() as exp:
    info = cve.get_cve_info("CVE-2021-44228")   # CVEInfo
    pocs = exp.find_github_pocs("CVE-2021-44228")  # list[Exploit]
    print(info.cvss, "PoCs:", len(pocs))
```

```python
from pocmap.services import ProductDiscoveryService

with ProductDiscoveryService() as disco:
    result = disco.discover_by_product("apache", version="2.4.x")
    # result groups CVEs into confirmed / possibly-affected / not-enough-data
```

```python
from pocmap.services import ReportService

with ReportService() as rs:
    report = rs.generate_bulk_report(["CVE-2021-44228", "CVE-2021-45046"])
```

## Environment Configuration

Settings live in `src/pocmap/config.py` (frozen `Settings`, singleton `settings`),
loaded from env + optional repo-root `.env`. Verified variables:

| Variable | Purpose |
|----------|---------|
| `POCMAP_GITHUB_API_TOKEN` or `GITHUB_API_TOKEN` | GitHub token (raises rate limits) |
| `POCMAP_NVD_API_KEY` or `NVD_API_KEY` | NVD API key (raises rate limits) |
| `POCMAP_HTTP_TIMEOUT` | Request timeout, seconds (default 30) |
| `POCMAP_MAX_RETRIES` | Max retries (default 3) |
| `POCMAP_BACKOFF_FACTOR` | Backoff multiplier (default 1.5) |
| `POCMAP_CACHE_DIR` | Cache directory (default `<repo>/.cache`) |
| `POCMAP_LOG_LEVEL` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |

> Do NOT use `POCMAP_REQUEST_TIMEOUT`, `POCMAP_CACHE_TTL`, or `POCMAP_GITHUB_TOKEN` —
> those appear in older docs but are not read by `config.py`.

## References

- `references/mcp_tools.md` — all 19 MCP tools with parameters and return shapes.
- `references/cli_commands.md` — all 10 CLI commands with real flags.

## External Links

- GitHub: https://github.com/zebbern/pocmap
