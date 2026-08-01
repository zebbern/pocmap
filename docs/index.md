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
2. [MCP tools reference](reference/mcp-tools.md) — generated inventory + input schemas
3. [Data model schemas](reference/schemas.md) — Pydantic JSON Schema for core models
4. [Architecture](architecture.md) — layers and where code lives

For the full narrative README (examples, CI gate, caching, plugins), see the
[GitHub repository](https://github.com/zebbern/pocmap).
