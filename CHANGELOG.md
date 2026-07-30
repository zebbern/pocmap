# Changelog

All notable changes to PocMap are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`get_attack_techniques` (21st MCP tool) — CVE to MITRE ATT&CK technique mapping.**
  pocmap already returned CWEs, but a CWE names a weakness *class*, which an agent cannot
  act on. An ATT&CK technique answers the operational question: how is this exploited, and
  what does the attacker do next. Each technique carries a `mapping_type`
  (`exploitation_technique` — what a detection engineer wants — versus
  `primary_impact` / `secondary_impact`) and the curator's explanation of why it applies.
  Source is the Center for Threat-Informed Defense's expert-curated KEV mappings (419
  CVEs, 155 techniques). The published path is version- and date-stamped with no "latest"
  alias, so a pinned URL is tried first and directory discovery only runs if it 404s —
  the feed self-heals without spending GitHub API budget on the normal path.

  **Nothing is inferred.** The obvious way to cover every CVE is the published
  `CWE -> CAPEC -> ATT&CK` chain; it was implemented, measured against the curated data,
  and rejected. It produces **zero** overlap with the expert mappings, and only yields
  output at all when the CWE is too generic to be meaningful — precise weaknesses
  (CWE-502 deserialization, CWE-77/78 command injection, CWE-917 EL injection) reach no
  technique, while the catch-all CWE-20 fans out to seven unrelated ones, suggesting
  "Steal Web Session Cookie" for Log4Shell. A CVE with no curated mapping therefore
  returns an empty list, and the tool description tells agents that empty means
  *unmapped*, not *unexploitable*.
- **`reason` on PoC evidence.** `verify_github_pocs` returned a verdict plus the raw
  signals, leaving every consumer to re-derive why. Each verdict now states the deciding
  signal in one line (e.g. "cites 118 distinct CVEs with 0 code file(s) — an index, not a
  PoC for this one").

## [2.4.0] - 2026-07-30

### Changed
- **BREAKING (dependency): the `[server]` extra now requires `mcp>=2.0,<3`.** The MCP
  server is built on `mcp.server.mcpserver.MCPServer` (the 2.x rename of `FastMCP`) and
  reports protocol `2026-07-28`, whose core is stateless. The SDK still speaks earlier
  protocol versions to clients that have not upgraded, so this does not cut off existing
  MCP clients — but the `mcp>=1.2,<2` pin is gone and 1.x is no longer supported.
  Bind address moved off the server constructor onto `run()`, where the transport owns it.

### Changed (agent guidance)
- **`generate_json_report` is now documented as the default entry point for CVE questions.**
  It always returned CVE details + every exploit source + labs + bug bounty reports in one
  call, but its description said "use when you need structured data for automation", and
  `AGENTS.md` Workflow 1 instructed agents to make **seven** sequential calls for exactly
  that data (Workflow 7 was worse: seven *per CVE*). Every workflow is now 1-3 calls.
  No behavior change — the tool already did this.

### Added
- **`verify_github_pocs` (20th MCP tool) — reads PoC source instead of trusting the
  index.** The CVE indexes list repositories that *mention* a CVE, not ones that exploit
  it, and star count does not separate them: for CVE-2023-38408 the union surfaces 69
  repos of which 6 have any stars, including link lists and course notes. This fetches
  the top PoCs' source and returns a verdict per repo — `confirmed` (names the CVE **in
  code** and ships runnable code), `likely` (a writeup), `unverified` (has code but never
  names this CVE — unproven, not disproven), `unrelated` (an index). Only `confirmed`
  claims the repo exploits the CVE. Language is derived from file extensions, so this
  costs **zero** GitHub API calls.

  The index test is `distinct_cves` — how many *different* CVE IDs the repository cites —
  rather than a file-count heuristic, because a PoC or a writeup is about one
  vulnerability while a list is about dozens. Calibrated on a 55-repository sample across
  four CVEs: genuine PoCs cited at most 3 distinct CVEs, the indexes cited 10, 22 and 118,
  so the threshold of 5 sits in a wide empty gap. It only applies to repositories that are
  not code-driven — either almost no code, or documentation outnumbering code several
  times over — so a multi-CVE exploit toolkit is not mistaken for a list, while a writeup
  collection that ships helper scripts still is.
- **`doctor` checks where fetched PoC source would land.** Once fetching is enabled it
  warns when `POCMAP_POC_SOURCE_DIR` looks cloud-synced (OneDrive, Dropbox, iCloud, Google
  Drive, Nextcloud, …), since syncing exploit source uploads it to a provider whose own
  scanner may flag the account. `SKIPPED` while fetching is off.
- **Opt-in PoC source fetching** behind `POCMAP_ALLOW_FETCH_POC_SOURCE=1`, with
  `POCMAP_POC_SOURCE_DIR`, `POCMAP_POC_SOURCE_MAX_MB` (per repo, applied to download
  *and* extracted size) and `POCMAP_POC_SOURCE_TOTAL_MAX_MB` (evicts oldest first).
  Off by default and never inferred: it writes third-party exploit code to disk, which
  endpoint protection commonly quarantines. pocmap never executes fetched content.
  Hardened against the archive-handling failure modes — owner/repo validated before
  reaching the URL, transfers routed through the SSRF-guarded `HTTPClient`, downloads and
  extraction both capped, and absolute / `..` / symlink / device members dropped rather
  than extracted (tarfile's `data` filter where available, plus an independent check for
  older 3.10/3.11 patch releases).
- **`not_enabled` error category** for a switched-off opt-in capability, carrying a
  `remediation` field. Agents should relay it and stop rather than retry.
- **`command` on MCP exploit results.** `ServiceAdapter._normalize_exploit` now emits
  `Exploit.command`, so `find_metasploit_module`, `find_exploitdb_entry` and
  `find_nuclei_template` actually return the msfconsole / searchsploit / nuclei
  invocation that README and the tool descriptions have always promised. The field
  was populated on the model but dropped by the normalizer. `null` for GitHub PoCs,
  which have no canonical run command.

### Security
- **An empty `POCMAP_CACHE_DIR` / `POCMAP_POC_SOURCE_DIR` resolved to the working
  directory.** `Path("")` is `.`, and both directories are ones pocmap evicts from, so a
  blank value in a `.env` file pointed cache writes — and PoC-source eviction, which
  deletes trees — at the user's CWD. Empty/whitespace values are now treated as unset.
- **PoC-source eviction is restricted to directories pocmap created**, identified by a
  `.pocmap-fetch` marker written after a successful extraction. It previously removed
  every subdirectory of a root the operator can point anywhere.
- **Extraction is now atomic** (staging directory + rename, cleaned up on
  `BaseException`), so an interrupted fetch cannot strand a partial tree that the next
  run reuses as a complete cached copy. Cache reuse requires the marker, not mere
  directory existence.
- **Size budgets account for entries that carry no bytes.** Charging only `member.size`
  let an archive of empty files or bare directories consume real disk and inodes at zero
  accounted cost, bypassing both the per-repo and total caps. Every entry is now charged a
  minimum, and the member-count cap dropped from 20,000 to 5,000.
- **Archive-supplied permissions and ownership are stripped before extraction.** On
  Python 3.10.0–3.10.11 / 3.11.0–3.11.3, where tarfile's `data` filter is unavailable,
  the fallback would otherwise apply them — allowing an untrusted archive to plant a
  setuid file when running as root.

### Fixed
- **PoC evidence scoring was voided beneath common directory names.** Skip names
  (`build`, `dist`, `vendor`, `.venv`, `node_modules`) were matched against the
  *absolute* path, so any repository extracted under such an ancestor — including the
  `.venv` layout this project's own README recommends — had every file excluded and
  scored `unrelated` with no error. They are now matched relative to the repository root.
- **`--transport http` never started.** The CLI's spelling was passed straight to the SDK,
  which calls it `streamable-http`, so the documented HTTP transport raised
  `ValueError: Unknown transport: http`. Only `stdio` and `sse` ever worked.
- **A malformed CVE ID was reported to agents as `category: "unknown"`.**
  `ValidationError` derived from `PocMapError` but not `ValueError`, which is what
  `categorize_exception` keys `invalid_input` off — so every tool's error envelope
  contradicted the documented taxonomy for the most common caller mistake. It now
  subclasses `ValueError` as well. `NotFoundError` likewise now maps to `not_found`
  in `categorize_exception` rather than falling through to `unknown`.
- **Agent-facing docs now match the MCP server's real return shapes.** The
  `pocmap-agent` skill reference documented pre-2.3.0 shapes that no longer existed:
  `check_kev_status` (`in_kev`/`date_added`/`due_date` -> `kev_status`/
  `in_kev_catalog`/`description`/`recommendation`), `get_epss_score`
  (`percentile`/`date` -> `risk_level`/`available`/`interpretation`),
  `find_github_pocs` (`exploits` -> `total_count`/`pocs`/`sources`, the last being
  the previously undocumented per-source health block), `find_recent_exploits`
  (`results`/`metadata` -> `success`/`total`/`query`/`cves`, with each CVE nested
  under `cve_info`), `generate_html_report` (`status` is `"ok"`, not `"success"`),
  `generate_json_report`, the `Exploit`/`ReportEntry`/`RecentExploitResult` type
  summaries, the Metasploit/ExploitDB/Nuclei examples (real URLs; `language`/`stars`/
  `forks` are `null`), lowercase `LabPlatform` values, the missing `total_count` on
  `find_bug_bounty_reports`/`find_practice_labs`, and the playbook step shape
  (objects, not strings). Also corrected: `lookup_cve` returns `cvss.score` and
  `epss_score` (not `cvss.base_score`/`epss`) — the raw-model-dump shape applies only
  to `find_recent_exploits`.
- `AGENTS.md` documented `lookup_cve`'s identifier as `cve_id`; the tool returns `id`
  (`cve_id` appears only in the error envelope).
- `--notify <url>` on `latest` and `discover` was missing from the option tables in
  `README.md` and the `pocmap-agent` CLI reference.

## [2.3.0] - 2026-07-30

Accuracy release. Product discovery and GitHub PoC discovery both returned results
that were quietly wrong rather than merely incomplete; this fixes the underlying
causes. **`discover` results will shift between confidence tiers** — see *Changed*.

### Changed
- **BREAKING (behavioral): `discover` now searches by CPE, not by keyword.** Products
  are resolved through the NVD CPE dictionary (`/rest/json/cpes/2.0`) to canonical
  `vendor:product` pairs, and CVEs are fetched with `virtualMatchString`. Keyword
  search remains only as a fallback for products that cannot be resolved. The JSON
  keys are unchanged, but tier membership shifts substantially — for `nginx`, the
  result goes from `confirmed: 0, possibly: 9, not_enough_data: 41` (spanning only
  2009–2019) to `confirmed: 41` spanning 2009–2025.
- **`MetasploitClient.search` / `ExploitDBClient.search` return `list[Exploit]`**
  instead of `Exploit | None`, so CVEs with several modules or entries no longer
  report just the first. Metasploit results are ordered best-rank-first.
- **`GitHubClient.search_pocs` accepts `limit`**, applied before enrichment.

### Added
- `matched_cpes` on `ProductDiscoveryResult` (and in `discover --format json` and the
  `discover_product_cves` MCP tool): the canonical CPE prefixes a query resolved to.
  Empty when the keyword fallback ran, which `search_sources` also reports as
  `nvd_keyword_search` rather than `nvd_cpe_match`.
- `CVEInfo.affected_products` (every `(vendor, product)` pair) and `CVEInfo.cpe_matches`
  (full applicability statements including version bounds), plus the `AffectedProduct`
  and `CPEMatch` models.
- `CPEDictionaryClient` (`pocmap.clients.cpe_client`) and `NVD_CPE_API_BASE`.

### Fixed
- **Only the last CPE decided a CVE's vendor/product.** `_parse_nvd_cve` overwrote
  `vendor`/`product` on every `cpeMatch`, keeping the last. CVE-2009-2629 — whose first
  three CPEs are `f5:nginx` and whose last is `fedoraproject:fedora:12` — was recorded
  as a Fedora CVE and filed under `not_enough_data`. All pairs are now kept and matched
  against, and the scalar fields prefer the first CPE NVD marks *vulnerable*.
- **Version constraints were close to inert.** Matching read only the literal version in
  the CPE string and ignored `versionStartIncluding` / `versionEndExcluding`, where modern
  NVD entries put ranges. Against `cpe:2.3:a:apache:struts:*`, the constraints `1.x`,
  `2.x`, `7.x` and `>= 900` all matched. Constraints are now pushed to NVD via
  `versionStart`/`versionEnd`, and client-side matching is a true interval overlap.
- **Keyword results were truncated oldest-first.** NVD returns keyword hits ascending by
  date and `discover` took the first `--limit`, so any product with more than 100 hits
  could never surface a recent CVE. Results are now sorted newest-first before slicing.
- **`normalize_product` matched aliases by bare substring**, resolving
  `"Fortinet FortiOS"` to `("apple", "ios")` because `ios` occurs inside `fortios`.
  Matching is now whole-name (separator-insensitive) with known vendor phrases peeled
  off; unrecognized products defer to the CPE dictionary.
- **The TrickestCVE fallback parsed nothing and could never run.** It required `<a>`
  tags, but Trickest emits bare URLs that python-markdown does not autolink — 97 list
  items yielded 0 results. It was also unreachable whenever Nomi-sec returned HTTP 200,
  including an empty `[]`. Both sources are now parsed and unioned, deduped by repo URL,
  with CVE-index/"awesome-list" aggregators filtered out.
- **PoC language enrichment ran before `limit` was applied**, spending one GitHub API
  call per repo — 415 calls for CVE-2021-44228 against an unauthenticated budget of
  60/hour. `limit` is now applied first.
- **A throttled GitHub was reported as a missing language.** `_get_repo_info` caught
  `HTTPError`, which `RateLimitError` subclasses, so a 429 became `language="N/A"` while
  the aggregate status still said `ok` — making `--language Python` silently return
  nothing. `RateLimitError` now propagates and surfaces as `RATE_LIMITED`.
- **`find_exploitdb_entry` / `find_nuclei_template` returned `null` for any CVE with a
  Metasploit module.** The MCP adapters sliced the combined db-exploit list to `limit=1`
  *before* filtering by source, and that list is ordered `[metasploit, exploitdb, nuclei]`.
  Filtering now happens first.
- **Rich rewrote `:shortcode:` sequences in JSON and table output.** `render()` disabled
  markup and highlighting but not emoji, so `cpe:2.3:a:apple:xcode:*` was emitted as
  `cpe:2.3:a<apple emoji>xcode:*` — silent corruption that still parsed as valid JSON,
  and on Windows crashed redirected output with `UnicodeEncodeError` under cp1252.

## [2.2.0] - 2026-07-30

### Added
- **`pocmap-mcp` console script.** The MCP server now lives in `pocmap.mcp_server`
  and is exposed as `pocmap-mcp`, so Claude Desktop / MCP clients can launch it with
  `uvx --from pocmap[server] pocmap-mcp` (no local clone or absolute path). Repo-root
  `python mcp_server.py` remains a thin launcher shim.

### Security
- **Cross-host redirect credential stripping.** The manual redirect loop now drops
  credential-bearing headers (`Authorization`, `Proxy-Authorization`, `Cookie`, and the
  NVD `apiKey`) when a redirect crosses to a different origin, mirroring requests' own
  protection that `allow_redirects=False` had bypassed — so a bearer token / API key can
  no longer be replayed to a redirect target (e.g. via an open redirect).
- **CSV formula-injection hardening (CWE-1236).** String cells exported to CSV that begin
  with a spreadsheet formula character (`= + - @` / tab / CR) are prefixed with a single
  quote, so externally-sourced text (CVE descriptions, repo names) can't execute when the
  file is opened in Excel / Google Sheets. Genuine numbers are left intact.
- **HTML-report / MCP output XSS escaping.** `mcp_server` now HTML-escapes rendered CVE
  fields and guards emitted links through a `_safe_url` scheme/IPv6 check, and
  `report_service` routes hrefs through a `_safe_href` scheme guard — so attacker-adjacent
  text (descriptions, repo names, URLs) can't inject markup or a `javascript:`/`data:` URI.

### Fixed
- **SSRF host matching.** `is_safe_url()` now matches internal hosts by exact host or
  dotted-suffix instead of substring, fixing false-positive blocks of legitimate public
  hosts (e.g. the IPv6 literal `2606:4700:4700::1111`, which contains the substring `::1`;
  or `notlocalhost.example.com`). The internal-IP and DNS-resolution guards are unchanged,
  so the security floor is preserved.
- **Prioritization crash on missing scores.** `calculate_bounty_potential` /
  `prioritize_cves` no longer raise `TypeError` when an EPSS/CVSS value is `None` compared
  against `0` — `None` is normalized before comparison.
- **`report_service` UTF-8 BOM.** JSON/HTML reports are written with a `utf-8-sig` BOM so
  they open cleanly in Excel and Windows tooling.
- **bugbounty UTF-8 encoding.** The 22 bug-bounty site modules now read/write with explicit
  UTF-8 encoding, fixing mojibake on non-UTF-8 default locales (Windows).
- **Formatter rank-color dead-letter.** `formatters.py` compares the MSF rank via its enum
  value instead of `str(Enum)`, so rank colorization no longer silently falls through.
- **CLI exit-code contract.** Read commands map an upstream throttle to `UPSTREAM_ERROR` (5)
  instead of a generic error, and CVE.org no longer misreports a rate-limit as
  `NOT_FOUND` (3).
- **`recent_service` sort crash.** Sorting recent CVEs no longer raises when publication
  dates mix timezone-aware and naive datetimes.

### Changed
- **Pin `[server]` extra to `mcp>=1.2,<2`.** Fresh installs were resolving `mcp` 2.x,
  which removed `mcp.server.fastmcp` / `FastMCP` and broke the MCP server import.
  Upper-bound until the server is migrated to the v2 `MCPServer` API.
- **Offline serves stale.** In `--offline` mode an expired-but-cached entry is now served
  stale (an air-gapped run can't refresh it, so stale data beats an error); only a
  genuinely absent entry raises the offline error. Online runs still honour the TTL.

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

[Unreleased]: https://github.com/zebbern/pocmap/compare/v2.2.0...HEAD
[2.2.0]: https://github.com/zebbern/pocmap/releases/tag/v2.2.0
[2.1.0]: https://github.com/zebbern/pocmap/releases/tag/v2.1.0
[2.0.0]: https://github.com/zebbern/pocmap/releases/tag/v2.0.0
