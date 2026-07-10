## /goal: production-ready

**Category**: VERIFY
**Scope**: Defines "ready for real professional use" for pocmap (Python CVE/PoC/exploit-discovery library + Typer CLI + FastMCP server, `src/` layout). Covers correctness, code health, packaging, docs, security, and test integrity. Excludes new features.

### Objective
A competent security engineer can install pocmap from a clean checkout, run the CLI, MCP server, and library by following only the repo's own docs, and trust that its guards, types, packaging, and documentation are consistent and truthful.

### Success Criteria (verify ALL)
- Single source of truth: divergent shadow modules reconciled — root `models.py`/`services.py`/`__init__.py` removed or unified so `src/pocmap/` is authoritative and `mcp_server.py` never silently falls back to stale mocks.
- Packaging complete: every runtime import (incl. `mcp`/FastMCP) is declared in `pyproject.toml`; `pip install -e ".[dev]"` plus documented steps yield a working CLI, importable API, and launchable server.
- Tests: the documented test command runs with zero collection errors and 0 failures on the offline suite; network-dependent tests are separated/marked; pytest config points where tests actually live.
- Types & lint clean: `ruff check src` and `mypy src` (strict) report 0 errors, or each remaining item is explicitly justified.
- Docs match code: MCP tool names, CLI commands, service method names, sync-vs-async, env vars, and run commands across AGENTS.md / mcp_config.json / skills / README all match source (0 drift).
- Security invariants intact and covered by a test each: SSRF (`is_safe_url` + DNS-rebinding resolution), path traversal (`_safe_path`), Jinja2 `SandboxedEnvironment`, no secret leakage.
- No dead code, unused dependencies, duplicated logic (e.g. duplicate `_safe_path`), or debug leftovers in shipped paths.

### Constraints
- MUST NOT change public CLI command names, MCP tool names/signatures, or model schemas without flagging it as a breaking change.
- MUST NOT weaken any security guard, remove a blocked host/scheme, or disable the Jinja2 sandbox/autoescape.
- MUST NOT fabricate CVE data, test results, or benchmarks, or claim "passes" without running the command.
- MUST keep the fast unit suite offline-runnable (no new mandatory network calls in unit tests).
- LIMIT: findings report ≤ 4000 words, grouped by severity.

### Output Specification
A prioritized findings report. Each item = {file:line, category (correctness | security | packaging | docs-drift | duplication | dead-code | test-integrity | typing), severity (P0–P3), one-line problem, concrete fix}. End with a "definition-of-done gaps" list mapping every open item to the Success Criteria above.

### Verification Method
An independent reviewer, from a clean checkout, re-runs the documented install plus `ruff check src`, `mypy src`, and the offline test command, and confirms each claimed-green criterion against pasted output; then spot-checks 5 doc claims against source for drift.

### Failure Modes to Prevent
- Rubber-stamping ("looks good" without running commands): require pasted command output for every green criterion.
- Scope creep into new features: only correctness/health/packaging/docs/security/test items count.
- Silent truncation of coverage: explicitly list any area not audited.

### Context
Security-sensitive tool that fetches attacker-adjacent content and handles API tokens; guards must never regress. Baseline facts: `src/` is authoritative; MCP entrypoint is repo-root `python mcp_server.py` (no `-m pocmap.mcp_server`); the public API is synchronous; 19 MCP tools / 10 CLI commands.
