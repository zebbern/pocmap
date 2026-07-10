# Changelog

All notable changes to PocMap are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-07-10

### Added
- **Response caching** — persistent, TTL'd HTTP cache (`POCMAP_CACHE_ENABLED` / `POCMAP_CACHE_TTL` / `POCMAP_CACHE_MAX_MB`): far faster repeat calls and fewer upstream rate-limit hits.
- **Machine-readable output everywhere** — global `--format {table,json,csv,md,sarif}` + `--quiet` on the read commands; **SARIF 2.1.0** on `latest`/`discover` for GitHub code scanning / CI pipelines.
- **`bulk` as a CI gate** — read CVE ids from stdin (`bulk -`), machine `--format`, and `--fail-on {critical,high,kev,epss>=N}` which exits `POLICY_FAIL` (6) when any CVE matches.
- **Snapshot diff** — `latest`/`discover --diff` (`--since-last`) reports what changed since the previous run (added/removed, KEV flips, severity/CVSS/EPSS moves, newly-available PoCs).
- **Webhook notifications** — `latest`/`discover --notify <url>` posts a summary of notable CVEs (composes with `--diff`) through the SSRF-guarded sender.
- **Offline mode** — global `--offline` / `POCMAP_OFFLINE`: serve only from cache and report a distinct offline error on a miss.
- **Diagnostics** — `pocmap doctor` (Python/token/cache/connectivity checks) and `pocmap cache info|clear`.
- **Stable exit-code contract** — 0 OK, 1 ERROR, 2 NO_RESULTS, 3 NOT_FOUND, 4 INVALID_INPUT, 5 UPSTREAM_ERROR, 6 POLICY_FAIL.
- **Shell completion** (`--install-completion` / `--show-completion`).
- **Pluggable exploit sources** — third-party packages register sources via the `pocmap.exploit_sources` entry-point group (`ExploitSourcePlugin`); a failing plugin is isolated to a `FetchStatus.ERROR`. See `examples/example-exploit-source/`.
- **Source-status reporting** — per-source `FetchStatus` (OK/EMPTY/RATE_LIMITED/ERROR) so a throttled or down upstream is no longer indistinguishable from "no results".
- **Release automation** — tag-triggered PyPI publish via Trusted Publishing (OIDC); a build + `twine check` gate on PRs. Runnable `examples/` and a refreshed README.

### Fixed
- **Dead MCP GitHub-PoC discovery** — the MCP adapter passed a `limit` argument `ExploitService.find_github_pocs` didn't accept, raising a swallowed `TypeError`; PoC discovery is restored across the MCP surface.
- Our own programming errors (`TypeError`/`NameError`) are no longer swallowed into empty results.
- `_url_domain` no longer echoes `user:token@` userinfo when logging webhook targets.
- `readme` uses a portable pager (`click.echo_via_pager`) instead of shelling out to `less`.

### Changed
- `click` and (on 3.10) `typing_extensions` declared as direct dependencies; `jinja2` too. `mypy --strict` is now **blocking** in CI, which also runs the full offline pytest suite. Network-bound test scripts are marked and excluded by default.

## [2.0.0] - 2026-07-10

### Security
- **SSRF hardening against DNS rebinding.** `is_safe_url()` now resolves hostnames
  at request time and validates every resolved address against the denylist, so a
  hostname that passes an initial check cannot later rebind to an internal address.
- **Redirect re-validation.** HTTP redirects are followed manually and each redirect
  target is re-checked through the same SSRF guard instead of being trusted.
- **Numeric / encoded IP blocking.** Decimal, octal, and hex-encoded IP literals and
  IPv4-mapped IPv6 addresses are now normalized and blocked, closing SSRF-guard bypasses.
- **Webhook egress routed through the SSRF-checked client.** Outbound webhook requests
  now go through the same validated HTTP client rather than a separate unguarded path.

### Fixed
- **EPSS scale.** EPSS scores are now normalized consistently to the 0-1 probability
  scale (previously a 0-100 vs 0-1 mismatch produced inflated values).
- **EPSS client crash.** Fixed a broken `except` clause in the EPSS API client that
  could raise while handling an error.
- **Recent-CVE filtering.** Corrected multi-severity filtering and the `min_epss`
  threshold in recent-CVE discovery so combined filters return the right results.
- **HTML report layout.** Fixed column alignment in the generated HTML report.

### Changed
- **Single source of truth.** Removed the divergent repo-root shadow modules
  (`models.py`, `services.py`, `__init__.py`) so the installed `src/pocmap/` package
  is authoritative and the MCP server no longer silently falls back to stale mocks.
- **Version single-sourced.** The package version is now declared once in
  `src/pocmap/__init__.py` and read dynamically by the build backend.

### Packaging
- Added an `mcp` optional dependency under the `[server]` extra
  (`pip install -e ".[server]"`) so the FastMCP server's runtime import is declared.
- Ship `py.typed` and broadened `package-data` (data files, templates, playbook JSON)
  so type information and bundled assets are included in the distribution.
- Added the `LICENSE` file (MIT) to the project.

### Tests / CI
- Moved the test scripts into a `tests/` layout. The offline suite
  (`python tests/test_edge_cases.py`) runs without network access; `test_e2e.py` and
  `test_new_features_edge.py` make live network calls and are kept separate.
- Added a GitHub Actions CI workflow (lint + advisory type-check + offline tests) on
  Python 3.10 / 3.11 / 3.12.

### Added
- CVE/PoC/exploit-discovery toolkit: a Typer CLI, a FastMCP server exposing 19 tools,
  a synchronous Python API, and the bug-bounty toolkit (checklists, playbooks, scoring).

[2.1.0]: https://github.com/zebbern/pocmap/releases/tag/v2.1.0
[2.0.0]: https://github.com/zebbern/pocmap/releases/tag/v2.0.0
