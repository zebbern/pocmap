# Changelog

All notable changes to PocMap are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[2.0.0]: https://github.com/zebbern/pocmap/releases/tag/v2.0.0
