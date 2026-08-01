# Getting started

## Install

```bash
# CLI + library
pip install pocmap

# With MCP server
pip install "pocmap[server]"

# Dev clone
pip install -e ".[server,dev,docs]"
```

Requires Python 3.10+.

Optional API keys raise rate limits:

- `GITHUB_API_TOKEN`
- `NVD_API_KEY`

(Also accepted with a `POCMAP_` prefix for some settings — see `src/pocmap/config.py`.)

## CLI quick start

```bash
pocmap lookup CVE-2021-44228
pocmap bulk CVE-2021-44228 CVE-2024-3094 --format json
pocmap latest --since 7d --kev-only
pocmap doctor
```

Full command list: `pocmap --help`.

## MCP server

```bash
# Recommended for Claude Desktop / Cursor (uv on PATH)
uvx --from pocmap[server] pocmap-mcp

# Or after pip install
pocmap-mcp
python -m pocmap.mcp_server
```

Default transport is STDIO. Network transports:

```bash
pocmap-mcp --transport sse --host 127.0.0.1 --port 8000
pocmap-mcp --transport http --port 9000
```

**Tool routing:** PoC / exploit-repos only: use `find_github_pocs` (or Metasploit /
ExploitDB / Nuclei). Full assessment (severity, KEV/EPSS, all exploit sources,
labs, bounty): use `generate_json_report` — one call with a per-source `sources`
health block.

Agent consumption guide (return shapes, EPSS scales, error envelopes):
[`.claude/skills/pocmap-agent/references/mcp_tools.md`](https://github.com/zebbern/pocmap/blob/main/.claude/skills/pocmap-agent/references/mcp_tools.md)
in the repository. Generated inventory on this site:
[MCP tools](reference/mcp-tools.md).

## Bug bounty toolkit vs CLI

The CLI `pocmap bugbounty` command **searches write-ups** for a CVE.

Checklists, methodology workflows, report templates, prioritization helpers,
scope management (`ScopeManager`), and automation (`ScopeMonitor`) live in the
**Python API** under `pocmap.bugbounty` and packaged playbooks — they are not
separate CLI commands. See the repository README → *Bug Bounty Toolkit*.

## Reports: MCP vs CLI / Python API

- **MCP** `generate_json_report` / `generate_html_report` use
  `ExploitService.find_exploits_with_status` and include a `sources` block so
  empty ≠ rate-limited ≠ error.
- **CLI / `ReportService`** use `find_exploits` (same exploit aggregation,
  including plugins) but do **not** currently surface per-source health on the
  report model. Prefer MCP (or call `find_exploits_with_status` yourself) when
  you need fetch honesty in automation.
