# PocMap Product Roadmap

**Grounded in:** v2.6.2 (`src/pocmap/`). Rewritten 2026-07-31 — the previous revision was
written against v2.0.0 and had drifted far enough to mislead: it described 9 CLI commands,
19 MCP tools, `FIX-GHPOC` as a live bug, and the package as "not on PyPI".

**Premise:** the foundation is done. This tracks product value and adoption — what makes a
security professional reach for pocmap weekly.

---

## Baseline today

- **CLI** (`src/pocmap/cli.py`): 13 commands — `lookup`, `bulk`, `labs`, `bugbounty`, `cpes`,
  `cpe2cve`, `readme`, `schemas`, `latest`, `discover`, `package`, `doctor`, `cache`.
  `--format {table,json,csv,md,sarif}` on read commands, `--quiet`, shell completion, and a
  documented 0-6 exit-code contract (`utils/exit_codes.py`).
- **MCP** (`src/pocmap/mcp_server.py`, `pocmap-mcp`): 22 tools, 3 resources, 3 prompts on
  `mcp` SDK 2.x. Tools return real structured content under object schemas, carry
  `ToolAnnotations`, and share an error taxonomy (`category`/`retryable`/`error_type`).
- **HTTP**: SSRF-guarded client with per-hop redirect re-validation, credential stripping on
  cross-origin redirects, and a persistent TTL'd response cache backing a real `--offline`.
- **Data**: NVD (CVE + CPE dictionary), CVE.org, CISA KEV, EPSS, GitHub, ExploitDB,
  Metasploit, Nuclei, Vulhub, HackTheBox, OSV.
- **Distribution**: on PyPI via Trusted Publishing; CI runs ruff + `mypy --strict` + the
  offline suite on 3.10-3.13.

## Shipped

`FIX-GHPOC` · `RENDER-LAYER` · `HTTP-CACHE` · `ERR-RESULT` · `DOCTOR` · `JSON-EVERYWHERE` ·
`EXPORT-CSV-MD` · `EXPORT-SARIF` · `STDIN-BULK-CI` · `WATCH-DIFF` · `OFFLINE-MODE` ·
`COMPLETION` · `PAGER-FIX` · `RELEASE-CI` · `QUICKSTART-EXAMPLES` · `NOTIFY` ·
`PLUGIN-SOURCES`

Beyond the original roadmap: CPE-dictionary product resolution, opt-in PoC source
verification, CVE→ATT&CK mappings, and the OSV-backed `package` command (dependency
vulnerabilities *with the releases that fix them* — the question the CPE path structurally
cannot answer).

---

## Open

### `MCP-SPLIT` — modularize `src/pocmap/mcp_server.py`
- **Why:** Maintainability of the differentiator. It is a single ~100 KB file holding all 22
  tools, and it is exactly where the 2.6.0 report-tool regression hid.
- **Scope:** Split into a package (`mcp/tools/`, `mcp/resources.py`, `mcp/prompts.py`,
  `mcp/errors.py`, `mcp/adapter.py`) behind the same `pocmap-mcp` entry point. No behaviour
  change. Note the implementation now lives in `src/pocmap/`; repo-root `mcp_server.py` is
  only a launcher shim.
- **Acceptance (offline):** `tests/test_mcp_tool_contract.py` already pins the full tool
  inventory and every tool's return contract through `mcp.call_tool` — it must stay green
  across the refactor, unchanged. `ruff` / `mypy --strict` clean.
- **Effort:** L · **Risk:** Med (churn; the contract test is the mitigation).

### `DOCS-SITE` — hosted docs + versioned reference
- **Why:** A searchable, linkable site beats one long README for discoverability, and gives
  agent users a stable URL for the tool table and JSON schemas.
- **Scope:** `mkdocs-material` generated from README/AGENTS content, plus an auto-generated
  MCP tool reference and schema pages; GitHub Pages deploy.
- **Acceptance:** `mkdocs build --strict` passes with no broken links.
  **[needs-user]:** enabling Pages for the repo.
- **Effort:** M · **Risk:** Low.

### `TUI` — interactive triage (`pocmap tui`)
- **Why:** Keyboard-driven triage (browse `latest`, drill into a CVE, open PoCs)
  differentiates from one-shot CLIs. Optional — build only if demand shows.
- **Scope:** A small Textual app over the existing services, behind a `[tui]` extra so the
  core install stays lean.
- **Effort:** L · **Risk:** Low (additive).

---

## Keeping this file honest

It drifted because nothing checked it. If it disagrees with `README.md`, `AGENTS.md`, or
`src/`, the code wins — correct this file or delete it, but do not trust it over the source.
