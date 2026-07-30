# PocMap Conventions

PocMap is an AI-friendly CVE / PoC / exploit-discovery toolkit (CLI + MCP server + Python API).
This file covers how to **develop** the project. For how AI agents **consume** the MCP tools, see
`AGENTS.md`. For full usage/API docs, see `README.md`.

## Commands
- Install (PyPI): `pip install "pocmap[server]"` (omit `[server]` for CLI-only)
- Install (dev clone): `pip install -e ".[server,dev]"` (pytest, mypy, ruff + the MCP SDK)
- Run CLI: `pocmap lookup CVE-2021-44228`  (or `python -m pocmap ...`); full command list: `python -m pocmap --help`
- Lint: `ruff check src/pocmap`
- Type check: `mypy src/pocmap`   (strict mode is on in `pyproject.toml`; `pocmap.mcp_server` is excluded)
- Run MCP server: `uvx --from pocmap[server] pocmap-mcp` or installed `pocmap-mcp` / `python -m pocmap.mcp_server` (add `--transport sse|http`, `--host`, `--port`, `--debug`)
- Tests: `pytest` works and is offline by default; see Testing below.

## Stack
- Python >=3.10 (developed/verified on 3.12). Fully type-annotated, `mypy --strict`.
- pydantic v2 (models), typer + rich (CLI), requests/urllib3 (HTTP), beautifulsoup4, markdown, python-dotenv.
- `mcp` SDK 2.x (`mcp.server.mcpserver.MCPServer`) for the MCP server — declared as the
  `[server]` extra (`pip install "pocmap[server]"`). Serves protocol `2026-07-28`.
- Layered: CLI/MCP (presentation) → `services/` → `clients/` → `models` (pydantic). See README "Architecture".

## Project Structure — IMPORTANT
- **Real code lives in `src/pocmap/`** — the single source of truth. Edit here: `cli.py`, `config.py`,
  `models.py`, `services/`, `clients/`, `bugbounty/`, `utils/`, `data/`, `templates/`, `mcp_server.py`.
  Installed as editable `pocmap`. (The old repo-root shadow `models.py`/`services.py`/`__init__.py` mock
  modules were **removed**; there is no silent mock fallback.)
- **MCP server implementation** is `src/pocmap/mcp_server.py` (21 tools, 3 resources, 3 prompts), exposed as
  the `pocmap-mcp` console script. Repo-root `mcp_server.py` is a thin launcher shim; `mcp_transport_stdio.py`
  / `mcp_transport_sse.py` remain at the repo root for alternate transports.
- Playbook JSON is loaded from `src/pocmap/bugbounty/playbooks/`.

## Testing
Tests live in `tests/`. `pytest` works and is **offline by default** — `pyproject.toml` sets
`addopts = "-m 'not network'"` and registers a `network` marker for genuinely network-bound tests.
```bash
pytest                              # offline default run (native tests + import-time script suites)
pytest tests/test_ssrf.py -q        # native regression tests (SSRF, EPSS scale, HTML report)
python tests/test_edge_cases.py     # offline characterization suite (48 checks) — also a direct runner
```
- **Native pytest tests** (real `assert`s) are now the bulk of coverage — SSRF, EPSS scale, HTML report,
  cache, output/renderers/SARIF, snapshot-diff, offline, doctor, CLI formats/features, notify, and plugins
  (`test_ssrf.py`, `test_cache.py`, `test_output.py`, `test_renderers.py`, `test_snapshot.py`,
  `test_offline.py`, `test_doctor.py`, `test_cli_*.py`, `test_plugins.py`, …).
- **Legacy script-runners** (`tests/test_edge_cases.py`, `test_e2e.py`, `test_new_features_edge.py`): checks run at
  import via a custom harness; run directly with `python tests/<file>.py`. They currently run offline; the latter two
  are `network`-marked and excluded from the default `pytest` run.

## Release / CI
- CI (`.github/workflows/ci.yml`): ruff + `mypy --strict` (blocking) + offline `pytest` on Python 3.10/3.11/3.12.
- Cut a release (`.github/workflows/release.yml`): bump `__version__` in `src/pocmap/__init__.py`
  (single source of truth — `pyproject.toml` reads it dynamically), update `CHANGELOG.md`, commit, then
  `git tag vX.Y.Z && git push origin vX.Y.Z`. The tag triggers a PyPI publish via Trusted Publishing
  (OIDC, no stored token). PRs / `workflow_dispatch` build + `twine check` only (no publish).

## Configuration
- `src/pocmap/config.py` is the source of truth for settings (a frozen `Settings` dataclass, singleton `settings`).
- Loaded from env + optional `.env` in repo root. Prefix env vars with `POCMAP_`
  (e.g. `POCMAP_HTTP_TIMEOUT`, `POCMAP_MAX_RETRIES`, `POCMAP_LOG_LEVEL`, `POCMAP_CACHE_DIR`).
- Cache / offline (v2.1.0): `POCMAP_CACHE_ENABLED`, `POCMAP_CACHE_DIR`, `POCMAP_CACHE_TTL`,
  `POCMAP_CACHE_MAX_MB`, `POCMAP_OFFLINE` (persistent HTTP cache + offline mode — see README).
- API keys: `GITHUB_API_TOKEN`, `NVD_API_KEY` (also accepted `POCMAP_`-prefixed) — optional, raise rate limits.
- Note: some skill docs use wrong env-var names — it's `POCMAP_HTTP_TIMEOUT` (not
  `POCMAP_REQUEST_TIMEOUT`) and `GITHUB_API_TOKEN` (not `POCMAP_GITHUB_TOKEN`). Trust `config.py`.

## Conventions / Gotchas
- ruff: line length 100, `E501` ignored; rule sets `E,F,W,I,N,UP,B,C4,SIM` (see `pyproject.toml`).
- Public Python API is **synchronous**. Real method names live in `services/` (e.g. `CVEService().get_cve_info(cve)`),
  not the async `lookup_cve()` shown in some skill examples. Verify against the source, not the skill docs.
- Services are used as context managers in the CLI (`with CVEService() as svc: ...`).
- Security invariants to preserve when touching HTTP/templates/files: SSRF guard `is_safe_url()`
  (`utils/http.py`, exact-host/suffix matching — never substring) — plus request-time DNS-rebinding
  resolution (`resolves_to_internal_ip`) and manual per-hop redirect re-validation in `HTTPClient`, which
  also **strips credential headers (`Authorization`/`Cookie`/`apiKey`) on cross-origin redirects**
  (`_should_strip_auth`); Jinja2 `SandboxedEnvironment`; the shared `safe_path()` path-traversal check
  (`utils/paths.py`); and CSV export neutralizes spreadsheet formula injection (`utils/renderers/csv_renderer.py`).
  CVE IDs validated in `utils/validators.py` (`^CVE-\d{4}-\d+$`, plus null-byte/length guards); bulk capped
  at 100 CVEs. The generated HTML report is self-contained (no external assets/JS).
- Most CLI/service calls hit live external APIs (NVD, CVE.org, CISA KEV, EPSS, GitHub, ExploitDB, Nuclei,
  Vulhub, etc.) — expect network dependence and rate limits.
- Third-party exploit sources plug in via the `pocmap.exploit_sources` entry-point group
  (`ExploitSourcePlugin.search(cve_id) -> list[Exploit]`, error-isolated per source). See
  `examples/example-exploit-source/` and README "Third-Party Exploit Sources".

## Additional Context
@README.md
@AGENTS.md
