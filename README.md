# PocMap

[![Version](https://img.shields.io/badge/version-2.8.1-blue.svg)](https://github.com/zebbern/pocmap)
[![PyPI](https://img.shields.io/pypi/v/pocmap.svg)](https://pypi.org/project/pocmap/)
[![Docs](https://img.shields.io/badge/docs-zebbern.github.io-blue.svg)](https://zebbern.github.io/pocmap/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Pydantic](https://img.shields.io/badge/pydantic-v2-purple.svg)](https://docs.pydantic.dev/)

AI-agent-optimized CVE / PoC / exploit discovery toolkit — CLI, Python API, and MCP server.

**Docs:** [https://zebbern.github.io/pocmap/](https://zebbern.github.io/pocmap/)

## Features

- **Multi-source PoCs** — GitHub, Exploit-DB, Metasploit, Nuclei, labs, bug bounty write-ups; curated indexes first, then GitHub Search fallback for index-lag CVEs
- **MCP server** — 22 tools for Claude Desktop, Cursor, and other MCP clients
- **CLI + CI** — table/json/csv/md/sarif output, exit-code contract, `bulk --fail-on` SARIF gate
- **Cache & offline** — persistent TTL'd HTTP cache and first-class `--offline` mode
- **Bug bounty toolkit** — Python API checklists, workflows, templates, scope (CLI `bugbounty` searches write-ups only)

## Install

```bash
pip install pocmap
pip install "pocmap[server]"          # MCP SDK / pocmap-mcp
pip install -e ".[server,dev]"        # from a clone
```

Python 3.10+. Optional: `GITHUB_API_TOKEN`, `NVD_API_KEY` for higher rate limits.

More: [Getting started](https://zebbern.github.io/pocmap/getting-started/) · [Configuration](https://zebbern.github.io/pocmap/configuration/)

## Quick start

```bash
pocmap lookup CVE-2021-44228
pocmap bulk cves.txt --format sarif --fail-on kev
pocmap latest --since 7d --severity critical --only-with-poc
pocmap discover "Log4j" --version 2.x
pocmap package PyPI django --version 3.2.0
pocmap doctor
pocmap lookup CVE-2021-44228 --format json
pocmap --offline lookup CVE-2021-44228
```

`pocmap --help` lists all commands. Guides: [CLI reference](https://zebbern.github.io/pocmap/cli/).

### MCP Server Setup 

Recommended: [`uv`](https://github.com/astral-sh/uv) on `PATH`, no local clone required.
`--from pocmap[server]` pulls the package with the MCP SDK and runs the `pocmap-mcp`
console script over STDIO.

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

### Example Agent Workflow

```
User: "Should I prioritize CVE-2021-44228, CVE-2023-38408, or CVE-2024-21413?"

Agent:
1. generate_json_report("CVE-2021-44228,CVE-2023-38408,CVE-2024-21413")
2. Read each entry's triage.priority / reasons (KEV, EPSS, exploit counts)
3. Prefer Log4j when triage shows KEV + highest EPSS + most PoCs
```

PoC-only ask → `find_github_pocs` (check `labels` / `trust_score` / `sources`).
Dependency ask → `discover_package_cves` (use `canonical_cve` + `aliases`, not product discovery).


Claude Desktop / Cursor JSON configs and transports:
[Getting started → MCP](https://zebbern.github.io/pocmap/getting-started/#mcp-server).
Tool inventory: [MCP tools](https://zebbern.github.io/pocmap/reference/mcp-tools/).
Agent contract: [`.claude/skills/pocmap-agent/references/mcp_tools.md`](.claude/skills/pocmap-agent/references/mcp_tools.md).

## Python API

```python
from pocmap.services.cve_service import CVEService

with CVEService() as svc:
    info = svc.get_cve_info("CVE-2021-44228")
print(info.cvss.base_score, info.kev_status, info.epss)
```

Full service examples: [Python API](https://zebbern.github.io/pocmap/python-api/).

## Docs

| Topic | Link |
|-------|------|
| Getting started / MCP clients | [getting-started](https://zebbern.github.io/pocmap/getting-started/) |
| CLI (`latest`, `discover`, `package`, formats, cache, CI) | [cli](https://zebbern.github.io/pocmap/cli/) |
| Python API | [python-api](https://zebbern.github.io/pocmap/python-api/) |
| Configuration | [configuration](https://zebbern.github.io/pocmap/configuration/) |
| Bug bounty toolkit | [bug-bounty](https://zebbern.github.io/pocmap/bug-bounty/) |
| Verifying PoCs (opt-in) | [verifying-pocs](https://zebbern.github.io/pocmap/verifying-pocs/) |
| Architecture | [architecture](https://zebbern.github.io/pocmap/architecture/) |
| Contributing / plugins | [contributing](https://zebbern.github.io/pocmap/contributing/) |
| Schemas | [schemas](https://zebbern.github.io/pocmap/reference/schemas/) |

## License

MIT — see [LICENSE](LICENSE).

*PocMap is a research and defensive tool. Always operate within applicable law and program scope.*
