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

Requires Python 3.10+. Every CLI command is also available as `python -m pocmap ...`.

Optional API keys raise rate limits:

- `GITHUB_API_TOKEN`
- `NVD_API_KEY`

Full env table: [Configuration](configuration.md).

## CLI quick start

```bash
pocmap lookup CVE-2021-44228
pocmap bulk CVE-2021-44228 CVE-2024-3094 --format json
pocmap latest --since 7d --kev-only
pocmap discover "Log4j" --version 2.x
pocmap package PyPI django --version 3.2.0
pocmap doctor
pocmap --offline lookup CVE-2021-44228
```

Full command list: `pocmap --help`. Deeper CLI guides (`latest`, `discover`,
`package`, formats, caching, CI): [CLI reference](cli.md).

## MCP server

Recommended: [`uv`](https://github.com/astral-sh/uv) on `PATH`, no local clone required.

```bash
uvx --from pocmap[server] pocmap-mcp

# Or after pip install
pocmap-mcp
python -m pocmap.mcp_server
```

Default transport is STDIO. Network transports:

```bash
pocmap-mcp --transport sse --host 127.0.0.1 --port 8000
pocmap-mcp --transport http --port 9000
pocmap-mcp --debug
```

Repo-root `python mcp_server.py` is a thin launcher for uninstalled clones. See also
[`examples/mcp-config.json`](https://github.com/zebbern/pocmap/blob/main/examples/mcp-config.json).

### Claude Desktop

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

Pin a release with `pocmap-mcp@X.Y.Z` as the last arg. Put `POCMAP_*` flags
(e.g. `POCMAP_ALLOW_FETCH_POC_SOURCE`) in this `env` block — shell `export` does
not reach the MCP server.

### Cursor

Project config: `.cursor/mcp.json` in the workspace root. For a global server, use
**Cursor Settings → MCP**. Same `uvx` / `env` shape as Claude Desktop.

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

**Already installed locally** (`pip install "pocmap[server]"` or editable install):

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

### Tool routing

PoC / exploit-repos only: use `find_github_pocs` (or Metasploit / ExploitDB / Nuclei).
Full assessment (severity, KEV/EPSS, all exploit sources, labs, bounty): use
`generate_json_report` — one call with a per-source `sources` health block.

Agent consumption guide (return shapes, EPSS scales, error envelopes):
[`.claude/skills/pocmap-agent/references/mcp_tools.md`](https://github.com/zebbern/pocmap/blob/main/.claude/skills/pocmap-agent/references/mcp_tools.md).
Generated inventory: [MCP tools](reference/mcp-tools.md).

## Bug bounty toolkit vs CLI

The CLI `pocmap bugbounty` command **searches write-ups** for a CVE.

Checklists, methodology workflows, report templates, prioritization helpers,
scope management (`ScopeManager`), and automation (`ScopeMonitor`) live in the
**Python API** under `pocmap.bugbounty` and packaged playbooks — they are not
separate CLI commands. See [Bug Bounty Toolkit](bug-bounty.md).

## Reports: MCP vs CLI / Python API

- **MCP** `generate_json_report` / `generate_html_report` use
  `ExploitService.find_exploits_with_status` and include a `sources` block so
  empty ≠ rate-limited ≠ error.
- **CLI / `ReportService`** use `find_exploits` (same exploit aggregation,
  including plugins) but do **not** currently surface per-source health on the
  report model. Prefer MCP (or call `find_exploits_with_status` yourself) when
  you need fetch honesty in automation.

Python service examples: [Python API](python-api.md).
