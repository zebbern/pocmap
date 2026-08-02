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

1. [Getting started](getting-started.md) — install, first CLI lookups, MCP connect
2. [CLI reference](cli.md) — `latest`, `discover`, `package`, formats, caching, CI gate
3. [Bug Bounty Toolkit](bug-bounty.md) — checklists, workflows, templates, scope, playbooks
4. [Verifying PoCs](verifying-pocs.md) — opt-in source download and verdict tiers
5. [MCP tools reference](reference/mcp-tools.md) — generated inventory + input schemas
6. [Data model schemas](reference/schemas.md) — Pydantic JSON Schema for core models
7. [Architecture](architecture.md) — layers and where code lives
8. [Contributing](contributing.md) — in-tree sources, plugins, local setup

Quick start and MCP client configs also live in the
[GitHub README](https://github.com/zebbern/pocmap).
