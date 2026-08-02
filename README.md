# PocMap

[![Version](https://img.shields.io/badge/version-2.7.0-blue.svg)](https://github.com/zebbern/pocmap)
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
- **Security-hardened** — SSRF guards, sandboxed Jinja2, path checks, CSV formula neutralization

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

## MCP

```bash
uvx --from pocmap[server] pocmap-mcp
```

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
