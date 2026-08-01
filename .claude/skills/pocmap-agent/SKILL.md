---
name: pocmap-agent
description: >
  Use the PocMap Python package for CVE exploit discovery, vulnerability research,
  and bug bounty hunting. Provides 22 MCP tools and 13 CLI commands for looking up
  CVEs, finding exploits/PoCs, discovering recent vulnerabilities, product-based
  CVE discovery, CPE/CVSS analysis, bug bounty report lookup, and practice lab
  environments. Trigger when the user mentions CVE lookup, exploit discovery,
  PoC finding, vulnerability assessment, bug bounty research, security analysis,
  CPE to CVE conversion, EPSS scoring, KEV catalog checking, recent CVE monitoring,
  product vulnerability discovery, or security report generation.
---

# PocMap Agent Skill

Use PocMap to look up CVEs, find exploits/PoCs, discover recent vulnerabilities,
map products/packages to CVEs, check KEV/EPSS, find bug bounty reports, and locate
practice labs.

> **Source of truth:** `src/pocmap/` wins over this skill. The public Python API is
> **synchronous**. Full MCP contracts live in `references/mcp_tools.md` (canonical
> agent consumption guide). CLI flags: `references/cli_commands.md`.

## Quick Start

```bash
pip install "pocmap[server]"   # CLI + MCP (mcp SDK 2.x / MCPServer via [server])
# from a clone: pip install -e ".[server,dev]"

pocmap lookup CVE-2021-44228
python -m pocmap --help        # authoritative CLI list (13 commands)

# MCP server (src/pocmap/mcp/ → pocmap-mcp via mcp_server facade)
uvx --from pocmap[server] pocmap-mcp
pocmap-mcp                     # after install
python -m pocmap.mcp_server
```

```python
from pocmap.services import CVEService

with CVEService() as svc:
    info = svc.get_cve_info("CVE-2021-44228")
    print(info.cvss, info.epss, info.kev_status)  # epss is 0–100 in the Python model
```

## Decision Guide

| Goal | MCP tool | CLI |
|------|----------|-----|
| **Everything about known CVE ID(s)** | **`generate_json_report`** (start here) | `pocmap lookup` / `bulk` |
| Look up one CVE | `lookup_cve` | `pocmap lookup CVE-…` |
| Recent CVEs / monitoring | `find_recent_exploits` | `pocmap latest --since 24h` |
| CVEs for a deployed product | `discover_product_cves` | `pocmap discover "Product"` |
| CVEs for a dependency / lockfile | `discover_package_cves` | — |
| GitHub PoCs (+ `sources` health) | `find_github_pocs` | (shown in `lookup`) |
| Metasploit / ExploitDB / Nuclei | `find_metasploit_module` / `find_exploitdb_entry` / `find_nuclei_template` | — |
| How it is exploited (ATT&CK) | `get_attack_techniques` | — |
| Verify PoC is real | `verify_github_pocs` (needs `POCMAP_ALLOW_FETCH_POC_SOURCE=1`) | — |
| KEV / EPSS | `check_kev_status` / `get_epss_score` | — |
| Bug bounty / labs | `find_bug_bounty_reports` / `find_practice_labs` / `find_vulhub_docker` | `bugbounty` / `labs` |
| CVE ↔ CPE | `cve_to_cpe` / `cpe_to_cve` | `cpes` / `cpe2cve` |
| HTML report | `generate_html_report` | `pocmap bulk` |
| Playbooks | `get_*_playbook` | — |

## Key Constraints

- **CVE ID:** `CVE-YYYY-NNNN+` (`^CVE-\d{4}-\d+$`). Lowercase is normalized.
- **Bulk / report:** max **100** CVEs per call.
- **EPSS scales (convert at the boundary):**
  - Filter `min_epss` on CLI / `find_recent_exploits`: **0–100**
  - MCP normalized CVE fields (`epss_score` on `lookup_cve`, reports, recent): **0.0–1.0**
  - `get_epss_score`: **0.0–1.0**
  - Python `CVEInfo.epss`: **0–100**
- **`--since`:** `1h`, `24h`, `7d`, `30d`. **Severity:** `critical|high|medium|low`.
- **Product vs package:** `discover_product_cves` = deployed product (nginx, Confluence).
  `discover_package_cves` = dependency/SBOM (PyPI/npm/Maven/…) — only tool with fix versions.
- **Silent negatives:** always read `sources` / error `category` before concluding "none".
  Empty + `rate_limited`/`error` means *unknown*, not *none*. Empty ATT&CK list means
  *unmapped*, not harmless.

> **Env vars for MCP.** Clients launch the server with a filtered env. Put
> `GITHUB_API_TOKEN` / `NVD_API_KEY` / `POCMAP_*` in the client config `env` block —
> shell exports do not reach MCP. Settings: `src/pocmap/config.py`
> (`POCMAP_HTTP_TIMEOUT`, not `POCMAP_REQUEST_TIMEOUT`; `GITHUB_API_TOKEN`, not
> `POCMAP_GITHUB_TOKEN`).

## Error Handling (MCP)

Every tool returns a **dict** (`structuredContent`), not a JSON string. Failures use
an error envelope — check `error` first:

```text
error, error_type, category, retryable, context
# category: not_found | rate_limited | offline | network_error |
#           invalid_input | permission_error | not_enabled | unknown
```

Retry only when `retryable` is true (≈3 attempts with backoff), then surface
`suggestion`/`hint` if present.

## Architecture (brief)

**CLI / MCP → `services/` → `clients/` → `models` (pydantic).** Services are sync
context managers. Key classes: `CVEService`, `ExploitService` (`find_exploits` /
`find_exploits_with_status`), `ReportService`, `RecentService`,
`ProductDiscoveryService`, `PackageService`, `LabService`, `BugBountyService`.

## References

- `references/mcp_tools.md` — all **22** MCP tools, resources, prompts, return shapes
- `references/cli_commands.md` — all **13** CLI commands with real flags
- GitHub: https://github.com/zebbern/pocmap
