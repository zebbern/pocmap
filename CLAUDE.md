# PocMap Conventions

PocMap is an AI-friendly CVE / PoC / exploit-discovery toolkit (CLI + MCP server + Python API).
This file covers how to **develop** the project. For how AI agents **consume** the MCP tools, see
`AGENTS.md`. For full usage/API docs, see `README.md`.

## Commands
- Install (dev): `pip install -e ".[dev]"`  (installs pytest, mypy, ruff)
- MCP server also needs FastMCP: `pip install -e ".[server]"` (the `server` extra; or `pip install mcp`)
- Run CLI: `pocmap lookup CVE-2021-44228`  (or `python -m pocmap ...`); full command list: `python -m pocmap --help`
- Lint: `ruff check src/pocmap`
- Type check: `mypy src/pocmap`   (strict mode is on in `pyproject.toml`)
- Run MCP server: `python mcp_server.py`  (add `--transport sse|http`, `--host`, `--port`, `--debug`)
- Tests: `pytest` works and is offline by default; see Testing below.

## Stack
- Python >=3.10 (developed/verified on 3.12). Fully type-annotated, `mypy --strict`.
- pydantic v2 (models), typer + rich (CLI), requests/urllib3 (HTTP), beautifulsoup4, markdown, python-dotenv.
- `mcp` (FastMCP) SDK for the MCP server — declared as the `[server]` extra (`pip install -e ".[server]"`).
- Layered: CLI/MCP (presentation) → `services/` → `clients/` → `models` (pydantic). See README "Architecture".

## Project Structure — IMPORTANT
- **Real code lives in `src/pocmap/`** — the single source of truth. Edit here: `cli.py`, `config.py`,
  `models.py`, `services/`, `clients/`, `bugbounty/`, `utils/`, `data/`, `templates/`. Installed as editable `pocmap`.
  (The old repo-root shadow `models.py`/`services.py`/`__init__.py` mock modules were **removed**; `mcp_server.py`
  now imports the real package directly and fails loudly if it's missing — there is no silent mock fallback.)
- **MCP server entrypoints are at the repo ROOT**, not inside the package: `mcp_server.py` (all 19 tools,
  3 resources, 3 prompts), `mcp_transport_stdio.py`, `mcp_transport_sse.py`. There is **no**
  `src/pocmap/mcp_server.py`, so `python -m pocmap.mcp_server` does not work — use `python mcp_server.py`.
- Playbook JSON is loaded from `src/pocmap/bugbounty/playbooks/`.

## Testing
Tests live in `tests/`. `pytest` works and is **offline by default** — `pyproject.toml` sets
`addopts = "-m 'not network'"` and registers a `network` marker for genuinely network-bound tests.
```bash
pytest                              # offline default run (native tests + import-time script suites)
pytest tests/test_ssrf.py -q        # native regression tests (SSRF, EPSS scale, HTML report)
python tests/test_edge_cases.py     # offline characterization suite (48 checks) — also a direct runner
```
- **Native pytest tests** (real `assert`s): `tests/test_ssrf.py`, `tests/test_epss_scale.py`, `tests/test_report_html.py`.
- **Legacy script-runners** (`tests/test_edge_cases.py`, `test_e2e.py`, `test_new_features_edge.py`): checks run at
  import via a custom harness; run directly with `python tests/<file>.py`. They currently run offline; the latter two
  are `network`-marked and excluded from the default `pytest` run.

## Configuration
- `src/pocmap/config.py` is the source of truth for settings (a frozen `Settings` dataclass, singleton `settings`).
- Loaded from env + optional `.env` in repo root. Prefix env vars with `POCMAP_`
  (e.g. `POCMAP_HTTP_TIMEOUT`, `POCMAP_MAX_RETRIES`, `POCMAP_LOG_LEVEL`, `POCMAP_CACHE_DIR`).
- API keys: `GITHUB_API_TOKEN`, `NVD_API_KEY` (also accepted `POCMAP_`-prefixed) — optional, raise rate limits.
- Note: some skill docs list env vars that don't exist in code (`POCMAP_REQUEST_TIMEOUT`,
  `POCMAP_CACHE_TTL`, `POCMAP_GITHUB_TOKEN`). Trust `config.py`.

## Conventions / Gotchas
- ruff: line length 100, `E501` ignored; rule sets `E,F,W,I,N,UP,B,C4,SIM` (see `pyproject.toml`).
- Public Python API is **synchronous**. Real method names live in `services/` (e.g. `CVEService().get_cve_info(cve)`),
  not the async `lookup_cve()` shown in some skill examples. Verify against the source, not the skill docs.
- Services are used as context managers in the CLI (`with CVEService() as svc: ...`).
- Security invariants to preserve when touching HTTP/templates/files: SSRF guard `is_safe_url()`
  (`utils/http.py`) — plus request-time DNS-rebinding resolution (`resolves_to_internal_ip`) and manual
  per-hop redirect re-validation in `HTTPClient`; Jinja2 `SandboxedEnvironment`; and the shared
  `safe_path()` path-traversal check (`utils/paths.py`). CVE IDs validated in `utils/validators.py`
  (`^CVE-\d{4}-\d+$`, plus null-byte/length guards); bulk capped at 100 CVEs. The generated HTML report is
  self-contained (no external assets/JS).
- Most CLI/service calls hit live external APIs (NVD, CVE.org, CISA KEV, EPSS, GitHub, ExploitDB, Nuclei,
  Vulhub, etc.) — expect network dependence and rate limits.

## Additional Context
@README.md
@AGENTS.md
