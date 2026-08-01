# Changelog

All notable changes to PocMap are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **MCP server modularized into `pocmap.mcp`.** Implementation is under
  `src/pocmap/mcp/` (`adapter`, `errors`, `html_report`, `registration`, `server`,
  `tools/`, `resources`, `prompts`). `pocmap.mcp_server` remains the stable import
  path and `pocmap-mcp` entry point (no behaviour change).
- **Dropped unused `[async]` extra** (`aiohttp` / `aiosignal`) — nothing under
  `src/` imported it. Public API remains synchronous.
- **Docs site** via MkDocs Material (`mkdocs.yml`, `docs/`, `[docs]` extra).
  Generated MCP tool + model schema reference (`scripts/generate_mcp_docs.py`).
  GitHub Pages deploy workflow (`.github/workflows/docs.yml`).

### Added

- **Scheduled upstream URL smoke job** (`.github/workflows/upstream-urls.yml`) —
  `pytest tests/test_upstream_urls.py -m network` on weekdays + `workflow_dispatch`.
  Default PR CI stays offline.

### Fixed

- **MCP reports no longer omit third-party exploit sources or hide fetch failures.**
  `generate_json_report` / `generate_html_report` now collect exploits through
  `ExploitService.find_exploits_with_status` (same aggregation as `ReportService`, plus
  per-source `ok` / `empty` / `rate_limited` / `error`). Each entry includes a `sources`
  block; the HTML report renders that status so an empty exploit list is never a silent
  miss.
- **`find_recent_exploits` `cve_info` matches `lookup_cve`.** Results go through
  `_normalize_cve_info` (`cvss.score`, `epss_score` 0.0–1.0, `references` as a list) instead
  of a raw model dump (`cvss.base_score`, `epss` 0–100).
- **`ScopeMonitor` actually fetches recent CVEs.** `_fetch_recent_cves` used a placeholder
  that always returned `[]`, so scope matching never alerted. It now uses `RecentService`
  (`since=24h`) and raises on fetch failure instead of pretending there were no new CVEs.
  CVSS unwrapping also accepts `model_dump` dicts with `base_score`.
- **`ScopeMonitor` rejects empty scope.** `check_new_cves` / `start_monitoring` raise if
  there are no in-scope assets, so an empty alert list cannot mean "forgot to load scope".

### Documentation

- **Agent MCP contract moved out of `AGENTS.md`.** `AGENTS.md` is general agent guidelines;
  the canonical MCP/agent consumption guide is
  `.claude/skills/pocmap-agent/references/mcp_tools.md` (skill overview in
  `pocmap-agent/SKILL.md`). `CLAUDE.md`, README AI section, `add-mcp-tool`, and
  `agent-docs-consistency` retargeted accordingly.
- **`mcp_config.json` tool `output_schema` values corrected** from legacy "string" wording
  to structured objects (matches real `structuredContent` since 2.6.0).

## [2.6.7] - 2026-07-31

An audit that verified every AGENTS.md claim by actually invoking the tools. 14 discrepancies
confirmed, none refuted. The code bugs below all shared one shape: **a silent negative** — a
documented filter or field that returned "nothing" when the truth was "not checked".

### Fixed

- **`find_recent_exploits --kev-only` matched nothing, ever.** NVD's boolean query parameters
  are valueless flags; pocmap sent `hasKev=true`, NVD answered **HTTP 404**, and the error was
  swallowed into an empty result. Verified against Log4Shell's publication day: `hasKev=true`
  -> 404, `hasKev` -> 1 result.
- **`kev_status` and `epss` were never populated** in `find_recent_exploits`. `kev_status` was
  hardcoded `False` and EPSS was enriched only when `--min-epss` was passed, so `sort=epss`
  ranked on nulls and every row claimed "not in KEV" — including CVEs `check_kev_status`
  calls KEV in the same process. Both now come from the cached bulk feeds: one download per
  feed for the whole page, not one call per CVE.
- **`discover_product_cves` never enriched EPSS or KEV either**, while AGENTS.md told agents
  these entries "already carry full details (CVSS, EPSS, KEV, description)". The documented
  prioritization therefore ranked everything equally.
- **A malformed identifier was reported as a finding, not an error.** Only 3 of 13 CVE-taking
  tools validated input: `check_kev_status("CVE202144228")` returned `kev_status: false` —
  which reads as "not actively exploited" — and `cve_to_cpe`/`cpe_to_cve` returned
  `total_count: 0`, indistinguishable from a real empty answer. Validation now lives in the
  shared tool decorator, so all 13 return an `invalid_input` envelope and any tool added later
  inherits the guard. Tool schemas and annotations are unchanged.
- `PackageVulnerability.has_fix` is a `computed_field`, so it survives `model_dump()` — it was
  present via MCP but missing from the CLI's `--format json` and from the exported JSON Schema,
  which a script written against the documented shape would `KeyError` on. `export_schemas()`
  now emits serialization-mode schemas so computed fields appear.

### Documentation

`AGENTS.md` corrected where it did not match real output: `publication_date` is a display
string (`"10 Dec 2021"`), not ISO; `vendor`/`product`/`affected_products` carry the CNA's own
wording rather than lowercase CPE slugs; the normalizer also drops `ransomware_usage` and
`rejected_reason`; `generate_json_report` returns `entries` as a **list** while the
`MultiReport` Python model is a dict; `discover_product_cves` tier entries are **flat** (no
`cve_info` wrapper, so the documented `cve_info.epss_score` path raised `KeyError`);
`cpe_to_cve` needs a **version-qualified** CPE or it returns 0; `language` has two unknown
forms (`null` when un-enriched, the string `"N/A"` when enriched); and a `total_count: 0`
from `find_github_pocs` means *unknown* when `sources[]` reports `rate_limited`.

## [2.6.6] - 2026-07-31

### Fixed

- **The CVE's own reference URLs are no longer discarded.** `get_references` synthesized an
  NVD link, a CVEdetails link and a scraped GHSA link, and ignored the reference list the
  CNA actually published. For CVE-2026-26832 that meant losing the npm package page, the
  exact vulnerable source file (`src/index.js`), and the advisory writeup — the three links
  a responder would open first. All CNA references are now merged in, labelled by their
  `tags` (`Patch`, `Vendor Advisory`, `Exploit`), then by `name`, then by host.
  References sharing a label no longer overwrite one another, so two patch commits stay two
  links.

## [2.6.5] - 2026-07-31

Found by looking up CVE-2026-26832, a CRITICAL 9.8 OS command injection that pocmap
reported as affecting `n/a / n/a`.

### Fixed

- **CNA placeholder values no longer reach the user.** A CNA may file a record with literal
  `"vendor": "n/a", "product": "n/a"` — 12% of a 180-CVE sample from cvelistV5 do. pocmap
  printed that verbatim, so a critical command injection named no product at all. Those
  placeholders (`n/a`, `na`, `unknown`, `not applicable`, `-`) are now treated as absent, and
  NVD is consulted to fill the gap: CVE-2026-26832 resolves to `zapolnoch / tesseract_ocr`.
  Measured on the live sample, NVD resolves 4 of 5 such records that are not themselves
  Rejected.
- **`affected_products` is now populated.** It was always an empty list from `CVEService`,
  despite `AGENTS.md` telling agents to check it rather than the scalar `vendor`/`product`.
  It is built from every entry in the CVE.org record — free, since that record is already
  fetched — so CVE-2024-3094 now reports both `tukaani / xz` and the distributions that
  shipped it.

### Changed

- The NVD fallback costs **at most one** extra request, fires only when CVE.org actually
  left a gap, and **supplements rather than overwrites**: CVE.org's names are the ones the
  advisory uses (`Apache Software Foundation / Apache Log4j2`) where NVD carries the CPE
  slug (`apache / log4j2`). A throttled or unavailable NVD leaves the CVE.org data intact
  instead of failing the lookup.

## [2.6.4] - 2026-07-31

### Fixed

- **`--output` now writes the format `--format` asked for.** It previously always wrote a
  JSON report, so `pocmap package … --format sarif --output findings.sarif` produced a file
  that was not SARIF, and `latest --format sarif --output out/` wrote plain JSON while SARIF
  went to stdout. Three README snippets used exactly that form. `latest`, `discover` and
  `package` now honour `json`, `csv`, `md` and `sarif` on the saved file; `--format table`
  keeps writing the JSON report, since a file of box-drawing characters is not consumable.
  **Stdout is unchanged**, so existing pipelines keep working.
- README's CI snippet used `bulk --format sarif --output out/`, which writes no files by
  design (machine formats keep stdout parseable). It now redirects stdout, matching the
  already-correct `examples/ci-github-actions.yml`.

## [2.6.3] - 2026-07-31

Found by using the published package the way a new user would, from a clean install.

### Fixed

- **Every CVE.org record lookup was 404ing.** `CVE_ORG_GIT_RAW` was missing the `/cves` path
  segment (records live at `cvelistV5/cves/<year>/<batch>/`), so `get_cve_record()` silently
  fell through to the CVE AWG API fallback and `vendor`, `product`, `cwes` and
  `publication_date` came back **empty for every CVE in the catalogue** — in `pocmap lookup`,
  the `lookup_cve` MCP tool, and `generate_json_report`. README's own documented example
  output (`info.cwes -> ["CWE-77", "CWE-94"]`, `info.vendor -> "Apache"`) had not been
  reproducible. CVE-2021-44228 now returns `Apache Software Foundation / Apache Log4j2`,
  `['CWE-502', 'CWE-400', 'CWE-20']`, `10 Dec 2021`.

  It survived because every test mocks the HTTP layer, so a completely dead URL kept 895
  tests green. New `tests/test_upstream_urls.py` (`network`-marked) fetches the real URLs and
  asserts the payloads still contain the fields the parsers read.
- **`.env` was never read outside a source checkout.** It loaded only `PROJECT_ROOT/.env`,
  which for an installed package is `<venv>/Lib/.env` — a path no user writes to. The `.env`
  workflow README documents did nothing for anyone who installed from PyPI. Now discovered
  from the working directory upward.
- **The response cache was written inside the virtualenv** (`<venv>/Lib/.cache`). Under
  `uvx` — the install README recommends for the MCP server — that environment is ephemeral,
  so the "persistent" cache was created and discarded on every run. Now a platform user cache
  directory (`%LOCALAPPDATA%\pocmap\Cache`, `$XDG_CACHE_HOME/pocmap`, `~/.cache/pocmap`); a
  source checkout still uses `<repo>/.cache`.
- CVE records that name a package rather than a vendor/product pair (`packageName` +
  `collectionURL`, e.g. CVE-2024-3094) now resolve a product instead of `N/A`, and the first
  affected entry that actually names something is preferred over a blind `affected[0]`.
- `pocmap doctor` no longer calls the MCP SDK "FastMCP".

## [2.6.2] - 2026-07-31

### Fixed

- **`epss_score` no longer leaks binary float noise.** The 0-100 -> 0-1 conversion is a
  plain divide, and `99.99 / 100` is `0.9998999999999999` — which reached MCP clients
  verbatim on `lookup_cve` and `get_epss_score`. EPSS publishes 5 decimal places, so the
  result is now rounded to 5: `0.9999`. Lossless, and 12 junk digits out of an
  agent-facing field. `discover_package_cves` already rounded; all three paths now share
  one constant.

### Changed

- CI lints `tests/` as well as `src/`. The test tree had 17 standing ruff violations that
  nothing ran against; all are fixed. Two legacy script-runner suites keep a declared
  `E402` exemption because they bootstrap `sys.path` to stay runnable directly from a
  clone — imports must follow that block by construction.
- `tests/test_edge_cases.py` now asserts its `valid_cases`. They had been declared and
  never exercised, so only *rejection* of malformed CVE IDs was covered — a well-formed
  ID being wrongly rejected would have gone unnoticed.

## [2.6.1] - 2026-07-31

### Fixed

- **`generate_json_report` and `generate_html_report` failed on every call in 2.6.0.**
  The 2.6.0 structured-content change annotated all 22 tools `-> dict[str, Any]`, but
  these two still returned a JSON *string* from their `ServiceAdapter` methods. The SDK
  validates a tool's return against the schema derived from its annotation, so both
  raised `ToolError: Input should be a valid dictionary` before doing any work —
  including `generate_json_report`, which `AGENTS.md` documents as the primary entry
  point ("one call instead of seven"). Both adapters now return the object.
- The `report://{cve_id}` resource serializes that object again, since MCP resources
  are text where tools are structured.
- `_fmt_epss` no longer rounds across either endpoint. `:.1f` rendered EPSS 99.99 as
  `100.0` and 0.004 as `0.0` — in a security tool those read as "certain to be
  exploited" and "will not be exploited", and EPSS (which tops out at 99.999) said
  neither. Now `99.9` and `<0.1`; a genuine 100 still prints `100.0`.

### Changed

- `pocmap.mcp_server` is no longer exempt from `mypy --strict`. The exemption is what
  let the report-tool defect ship: 34 errors were hidden, two of them real return-type
  mismatches. All 53 source files now type-check.
- New `tests/test_mcp_tool_contract.py` calls **every** registered tool through
  `mcp.call_tool` — the real SDK path that validates returns — and asserts each yields
  a dict under an object schema. A tool added without a case here fails the suite.

## [2.6.0] - 2026-07-31

### Changed
- **MCP tools now return structured content.** All 22 tools returned a JSON
  *string*, so the SDK derived `outputSchema: {"result": {"type": "string"}}` and sent
  `structuredContent: {"result": "<json string>"}` — the payload JSON-encoded twice, behind
  a schema that described none of it. Tools now return objects, so a client gets the real
  object under an `{"type": "object"}` schema. **`content[0].text` is unchanged and still
  parses as JSON**, so a client reading the text block is unaffected.

  The schema is deliberately permissive rather than one model per tool. A tool returns
  either its success shape *or* an error envelope, and a pydantic model materializes its
  declared fields with defaults — a per-tool model would stamp `total_count: 0` onto a
  throttled lookup and turn "could not answer" into "no results", which is the exact
  false negative `tests/test_mcp_hardening.py` exists to prevent. `pocmap.models` exports 13
  JSON Schemas for the nested payloads and `AGENTS.md` documents each tool's keys.

  *Python API callers:* `pocmap.mcp_server` tool functions now return `dict[str, Any]`
  instead of `str`. Drop the `json.loads(...)` if you call them directly.

### Removed
- **TryHackMe lab discovery.** It read a room index that was never published, so every
  lookup returned "no room" — indistinguishable from a genuine answer, which is the wrong
  failure mode for a security tool. `LabPlatform.TRYHACKME` remains a valid enum value so
  third-party lab plugins can still emit it; pocmap simply no longer queries TryHackMe.
  Vulhub and HackTheBox are unaffected.


## [2.5.0] - 2026-07-31

Adds the dependency axis. Everything before this release was keyed on a CPE *product* —
right for software you deploy, but it carries no package coordinate and no fixed version,
so pocmap could not answer the most common question an agent gets asked about a repository:
*this lockfile pins version X — is that bad, and what do I upgrade to?*

Evaluated OSV.dev against the live API before building on it. It is **not** a replacement
for the NVD/CPE path: OSV rejects a bare product name outright (`nginx` → HTTP 400,
ecosystem is mandatory), so `discover` is unaffected. It is complementary — strong exactly
where the CPE path is blind.

### Added
- **`pocmap package <ecosystem> <name> [--version]` and the `discover_package_cves` MCP
  tool** (22 tools, 13 CLI commands). Finds vulnerabilities in a dependency and, uniquely,
  **the releases that fix them**. Supports all 50 OSV ecosystems — PyPI, npm, Go, Maven,
  crates.io, RubyGems, Packagist, NuGet, Hex, Pub, and distributions (Debian, Ubuntu,
  Alpine, Red Hat, Rocky Linux, SUSE, Bitnami, Wolfi, Chainguard). Needs no API key and is
  not subject to NVD's 5-requests-per-30-seconds limit. `table`/`json`/`csv`/`md`/`sarif`
  output and the usual exit-code contract.
- **Fixed versions are scoped to the queried package.** One advisory covers every package
  shipping the vulnerable code, and their fix streams differ: Log4Shell's
  `GHSA-jfh8-c2jp-5v3q` lists `2.15.0`/`2.3.1`/`2.12.2` for `log4j-core` but
  `1.9.2`/`1.10.8`/`1.11.10`/`2.0.11` for the `org.ops4j.pax.logging` repackager. A flat
  read of `affected[]` would tell a log4j-core user to "upgrade" to 1.9.2.
- **Results are ranked by exploitation risk, not CVSS** — CISA KEV first, then EPSS, then
  CVSS. EPSS and KEV come from bulk catalogues pocmap already caches, so enriching a
  100-advisory result costs two cached downloads rather than 100 API calls, and spends no
  NVD budget at all.
- **Duplicate advisories collapse.** Several databases feed OSV, so one CVE arrives more
  than once — Django 3.2.0 returns 56 records for 30 distinct CVEs, `requests` 16 for 8.
  The duplicate is usually the *poorer* record (PYSEC entries carry no CVSS), so the old
  behaviour would have shown the same vulnerability as CRITICAL in one row and UNKNOWN in
  the next. The richest record survives; identifiers and version lists are folded in.
- **CVSS 3.x base scores are computed from the vector** (`pocmap.utils.cvss`). OSV
  publishes vectors but never numbers, so results were previously unsortable. Validated
  against **7,701 CVSS 3.x vectors published by NVD with zero mismatches** on both score
  and severity band. CVSS 4.0 scores via a lookup table that is deliberately *not*
  implemented — a close-but-wrong number is worse than none in a patch-prioritisation
  tool — so a 4.0-only advisory falls back to the publisher's own rating.
- `HTTPClient.post_json_cached()`: a POST whose query lives in its body is a read, so it
  now gets the persistent cache, offline mode, throttle detection and SSRF validation that
  every GET already had. `HTTPCache.make_key()` gained an optional `body` component, folded
  in only when supplied so existing GET keys stay byte-identical.

### Fixed
- **The EPSS bulk feed had been dead, and every EPSS lookup was silently paying for it.**
  `EPSS_CSV_URL` pointed at a file in this repository that does not exist, so the bulk load
  404'd on every run and each score fell through to the per-CVE FIRST API — one HTTP
  request per CVE, on every `lookup`, `bulk`, `latest` and `discover`. Now points at
  FIRST's official gzipped feed (354k rows). Scoring 50 CVEs went from **21.2 s to
  0.016 s**.
- **EPSS and KEV lookups are indexed rather than linearly scanned.** Both are
  whole-catalogue feeds; scoring N CVEs cost N full scans of ~354k rows.
- **The EPSS CSV's leading `#model_version:` comment is no longer parsed as the header
  row**, which would have yielded garbage keys even once the feed loaded.
- **`get_text()` transparently gunzips a gzip-framed body.** `requests` only
  auto-decompresses when the server sets `Content-Encoding: gzip`; a `.gz` file served as
  `application/gzip` arrived as raw deflate bytes and would have been cached as mojibake.
- **A repository that exceeds the size cap now says so.** The cap raised an ordinary
  `HTTPError`, which the branch-retry loop swallowed before reporting *"Could not fetch
  from any of ('refs/heads/main', 'refs/heads/master', 'HEAD')"* — blaming a missing repo
  for a size limit. `kozmer/log4j-shell-poc` (1851 stars, the canonical Log4Shell PoC) is
  38.5 MB and hit this. Now raises `ArchiveTooLargeError` naming the cap and the variable.
- SARIF `helpUri` is overridable per row, so a GHSA/RUSTSEC/PYSEC advisory links to OSV
  instead of a nonexistent NVD page.
- `mcp_config.json` listed 19 tools and was missing `verify_github_pocs` and
  `get_attack_techniques`; it now matches the registered set exactly.
- **An unreachable OSV no longer reads as "no known vulnerabilities."** Everywhere else in
  pocmap an empty list means "nothing found"; on this path it means "this dependency is
  safe to ship". A 5xx, a connection failure, a redirect, or a success status with an
  unparseable body now surface as an upstream error (exit 5) instead of an all-clear.
- **Package names are matched the way their ecosystem matches them.** OSV stores the
  normalized name while callers type the one in their manifest, so `Django` — exactly how
  it appears in a `requirements.txt` — returned 30 advisories with **zero** fixed versions,
  which the docs tell you to read as "no fix published". Comparison now folds case and
  applies PEP 503's separator rule, fixing `Django`, `PyYAML`, `zope.interface` and
  every other capitalized or underscored name.
- **A distro query no longer inherits another release's fix.** Matching on the base
  ecosystem alone let a `Debian:12` query pick up a `Debian:11` entry and report its
  package version as the upgrade target. An exact release match now wins, with the base
  match kept only as the fallback that lets a bare `Ubuntu` query reach
  `Ubuntu:Pro:16.04:LTS`.
- **EPSS/KEV enrichment reports what it actually got.** A feed that failed to load left
  every advisory marked `kev_status: false` while still claiming `cisa_kev` as a source;
  an unavailable catalogue is now omitted from `search_sources`. Enrichment also reads both
  catalogues in bulk, so it makes no per-CVE API calls and works offline.
- **`--fixable-only` no longer reports a vulnerable package as clean.** Filtering every
  unfixable advisory out emptied the list and printed "No known vulnerabilities" — the
  inverse of the finding. The output now says how many were filtered out, and the JSON
  carries `fixable_only`/`filtered_out`.
- **`total_found` counts what was found, not what survived `--limit`.** A truncated run
  under-reported exposure by orders of magnitude; `returned` and `truncated` now say what
  was shown.
- An upstream failure under `--format json` emitted a plain-text line onto stdout,
  breaking `json.loads` and losing the reason; and `--output` was validated only *after*
  the document had been written to stdout. Both now fail cleanly.
- Gzip decoding is bounded, so a crafted response body cannot expand without limit.
- **The HackTheBox lab parser no longer invents machine names.** It read the first link
  under a CVE heading and took its second whitespace-delimited token, assuming every post
  is titled `HTB: <Machine>`. When the first post is a "Beyond Root" follow-up, that yields
  a machine name that does not exist and a confident link to a 404. It now matches
  `HTB: <name>` explicitly and reports nothing when no post qualifies.
- **A stale bug-bounty source no longer suppresses a live one.** Bug Bounty Hunting was
  only queried when PentesterLand missed, so a hit in one hid the other — and
  PentesterLand's feed has not moved since 2024, making the suppression permanent for older
  CVEs. Both are now queried independently.
- **A missing TryHackMe index is reported as missing.** `THM_ROOMS_URL` 404s, so that
  lookup returned `None` for every CVE, indistinguishable from "no room exists". It now
  logs a warning naming the unavailable source.
- **MCP: dropped a vacuous output schema on all 22 tools.** Because every tool is annotated
  `-> str`, the SDK derived `outputSchema: {"result": {"type": "string"}}` and wrapped the
  already-JSON payload as `structuredContent: {"result": "<json string>"}` — encoded twice,
  behind a schema describing none of it. Declaring no schema is more honest;
  `content[0].text` is unchanged. Returning real objects with per-tool schemas is the
  better end state and is tracked separately.
- **MCP: every tool now declares behavioural annotations.** Without them a host must assume
  the worst of all 22; 21 are `readOnlyHint`, the 3 playbooks are additionally closed-world,
  and only `verify_github_pocs` (which writes third-party source to disk) is not read-only.
- MCP list results carry cache hints instead of the default "already stale" `ttlMs: 0`.
  These apply once a client negotiates 2026-07-28.
- CI now tests Python 3.13, which the classifiers already advertised but nothing verified.
- `actions/upload-artifact` and `actions/download-artifact` moved off Node 20 (v4 -> v7/v8),
  which GitHub is removing from runners. `checkout@v5`/`setup-python@v6` were checked and
  are already Node 24, so they were left alone.
- `license = {text = "MIT"}` became the PEP 639 SPDX string (the table form has a removal
  date), and the paired `License ::` classifier was dropped.
- Documentation now states the protocol accurately: the SDK supports up to `2026-07-28`,
  but over STDIO an `initialize` handshake negotiates `2025-11-25` in practice.

### Security

Dependency floors are now the lowest version that is both functional **and** free of known
advisories. The old floors resolved to versions with published CVEs — verified by pointing
pocmap's own new `package` command at them:

| Dependency | Was | Now | Why |
|---|---|---|---|
| `urllib3` | `>=2.0` | `>=2.7.0` | 8 advisories at the old floor, incl. two HIGH |
| `click` | `>=8.0` | `>=8.3.3` | CVE-2026-7246 (HIGH) |
| `markdown` | `>=3.5` | `>=3.8.1` | CVE-2025-69534 (HIGH) — reachable from a fetched README |
| `jinja2` | `>=3.0` | `>=3.1.6` | CVE-2024-56201 and two older |
| `requests` | `>=2.28` | `>=2.33.0` | CVE-2026-25645 and three older |
| `python-dotenv` | `>=1.0` | `>=1.2.2` | CVE-2026-28684 |
| `pydantic` | `>=2.0` | `>=2.4.0` | CVE-2024-3772; 2.0.2 also breaks `pocmap schemas` |
| `typer` | `>=0.9` | `>=0.16` | older releases cannot parse the CLI's `Annotated[str \| None, ...]` |

`ruff` now runs the `S` (bandit) and `RUF100` rule sets. `S` is the check that would catch
a future `subprocess(shell=True)`, `yaml.load` or weak hash in a security tool; `RUF100`
found six `# noqa: S...` directives that had been inert because `S` was never enabled.

### Changed
- **`POCMAP_POC_SOURCE_MAX_MB` now defaults to 100 MB (was 20), and
  `POCMAP_POC_SOURCE_TOTAL_MAX_MB` to 1000 MB (was 500).** Real PoC repos routinely bundle
  a JRE, a vulnerable target app or a packet capture; 20 MB rejected the flagship
  Log4Shell PoC outright. The cap exists to stop a decompression bomb, not to second-guess
  repository size. The total is kept at 10x the per-repo cap so a default five-repo
  `verify_github_pocs` run cannot saturate it and evict trees it is about to re-fetch.
- `HTTPClient` accepts `retry_methods`; the default is unchanged, so the outbound webhook
  POST is still never retried automatically (a retry there would re-send a notification).

## [2.4.2] - 2026-07-30

Found by using 2.4.1 as a user would, then measuring rather than generalising. The
theme is a corrected bias: in a security tool an extra CVE is *visible and dismissible*,
a missing one is neither, so resolution now errs toward inclusion where the evidence
supports it.

### Fixed
- **Edition matching no longer depends on an enumerated list.** 2.4.1 recognised editions
  via fixed suffixes (`_server`, `_data_center`, ...), which can only ever contain the
  cases someone thought of — it missed `atlassian:jira_service_desk`,
  `jira_software_data_center` and `jira_service_management` entirely, the same class of
  false negative it was written to fix. A product is now admitted when its vendor already
  publishes an exact-name match *and* its name extends the target, so a vendor's own
  product family is covered structurally. Third-party lookalikes are still excluded:
  `redhat:kubernetes-client` is not Kubernetes, `perforce:gliffy` is not Confluence, and
  `atlassian:questions_for_confluence` shares the namespace but is an add-on.
- **A repository named for a CVE now counts as evidence.** `verify_github_pocs` matched
  only file *basenames*, so a 950-star PoC whose code sat in
  `CVE-2021-44228-PoC-.../src/main/java/log4j.java` — with the CVE named nowhere else but
  the README — scored `unverified`. The whole relative path is searched.
- **Real exploits are no longer labelled `unrelated`.** Security PoCs routinely cite the
  historical CVEs they build on; regreSSHion PoCs reference four older OpenSSH issues,
  which tripped the distinct-CVE index threshold. Two genuine exploits (494 and 380
  stars) were told they were unrelated to the CVE they exploit. Naming the CVE *in code*
  now settles the verdict before the index test, since an index never ships a code file
  for one specific CVE. The index rule is otherwise unchanged, so link lists are still
  caught. Measured over 29 fetched repos: `confirmed` rises from 48% to 72% with no new
  false positives.
- **Repositories whose default branch is neither `main` nor `master` are reachable.**
  The codeload fetcher tried those two refs only, so e.g. a repo defaulting to
  `production` failed and its PoC was silently dropped as a fetch error. `HEAD` is now
  tried last, resolving whatever the default actually is, and costs nothing for the
  common cases.

## [2.4.1] - 2026-07-30

Both fixes came out of using 2.4.0 as a user would, from PyPI, against products and CVEs
not touched during development.

### Fixed
- **Product discovery missed edition variants — a false negative.** NVD files enterprise
  software under a separate CPE product per edition, and resolution matched only the bare
  name. `discover "Confluence"` returned 19 CVEs, newest **2020**, because
  `atlassian:confluence_server` (50 CVEs) and `atlassian:confluence_data_center` (37)
  were never queried — so the 2021-2023 Confluence RCEs were invisible and the answer
  read as "you are patched". Nextcloud was worse: 189 CVEs sat under
  `nextcloud:nextcloud_server`.

  Measured across 34 real products rather than generalising from the one that surfaced
  it: **7 have edition variants**, hiding ~280 CVEs in total. The suffix list is
  deliberately narrow (`server`, `datacenter`, `cloud`, `enterprise`, `standard`,
  `professional`, `community`) — a broader first draft also swept in
  `redhat:kubernetes-client`, `f5:nginx_agent` and `atlassian:jira_core`, which are
  separate components, not editions. A false positive here would silently attribute
  another product's CVEs to this one, so widen the list only with evidence.
- **Docs told users to `export` variables the MCP server never sees.** MCP clients launch
  the server with a filtered environment — the stdio transport inherits only `HOME`,
  `LOGNAME`, `PATH`, `SHELL`, `TERM` and `USER` — so no `POCMAP_*`, `GITHUB_API_TOKEN` or
  `NVD_API_KEY` set in a shell reaches it. Following the README, `verify_github_pocs`
  would keep returning `not_enabled` with no explanation. README, `AGENTS.md` and the
  agent skill now say to use the client config's `env` block, and `AGENTS.md` tells
  agents what to suggest when a user insists the flag is set.

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
