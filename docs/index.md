# PocMap

AI-agent-optimized CVE / PoC / exploit-discovery toolkit — CLI, Python API, and
MCP server (22 tools).

## What you get

- Multi-source exploit discovery (GitHub, Exploit-DB, Metasploit, Nuclei, labs, bug bounty write-ups)
- Structured Pydantic models with JSON Schema export
- MCP server for Claude Desktop, Cursor, and other MCP clients
- Rich CLI with table / JSON / CSV / Markdown / SARIF output
- Security-hardened HTTP (SSRF guards, sandboxed HTML reports)

## Start here

1. [Getting started](getting-started.md) — install, first CLI lookups, Claude/Cursor MCP configs
2. [CLI reference](cli.md) — `latest`, `discover`, `package`, formats, caching, CI gate
3. [Python API](python-api.md) — service examples and schema export
4. [Configuration](configuration.md) — env vars, cache, offline, PoC source fetch
5. [Bug Bounty Toolkit](bug-bounty.md) — checklists, workflows, templates, scope, playbooks
6. [Verifying PoCs](verifying-pocs.md) — opt-in source download and verdict tiers
7. [MCP tools reference](reference/mcp-tools.md) — generated inventory + input schemas
8. [Data model schemas](reference/schemas.md) — Pydantic JSON Schema for core models
9. [Architecture](architecture.md) — layers and where code lives
10. [Contributing](contributing.md) — in-tree sources, plugins, local setup

Install and a short quick start also live in the
[GitHub README](https://github.com/zebbern/pocmap).
