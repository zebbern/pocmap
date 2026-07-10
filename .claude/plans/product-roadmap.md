# PocMap Product Roadmap — from "hardened tool" to "weekly-driver"

**Author:** Product Architect pass, grounded in the v2.0.0 code (`src/pocmap/`, `mcp_server.py`).
**Premise:** the foundation is done (security, `ruff`/`mypy --strict` clean, offline pytest, packaging, CI on 3.10–3.12, self-contained HTML report, single source of truth). This roadmap is about **product value and adoption** — the levers that decide whether a security professional installs this and reaches for it every week.

Every item below is a real, shippable increment that keeps the repo green (ruff 0, mypy 0, tests passing). Acceptance criteria are written so an execution agent can **verify offline** with fixtures/mocks wherever possible. Items that genuinely need live network or the user's accounts/tokens are flagged **[needs-user/network]**.

---

## What the code does today (baseline, cited)

- **CLI** (`src/pocmap/cli.py`): 9 commands — `lookup`, `bulk`, `labs`, `bugbounty`, `cpes`, `cpe2cve`, `readme`, `schemas`, `latest`, `discover`. Output is **Rich tables only** except `latest`/`discover`/`bulk`, which can write JSON/HTML **to a file** via `--output`. There is **no `--json` to stdout**, no CSV/SARIF/Markdown, no `--quiet`, and exit codes are only 0/1 with no distinction between not-found, upstream failure, and empty results. `add_completion=False` (`cli.py:66`) disables shell completion. `readme` shells out to `less` on Linux/Darwin and just prints on Windows (`cli.py:381-387`).
- **HTTP** (`src/pocmap/utils/http.py`): solid SSRF hardening + urllib3 `Retry` on 429/5xx for GET. **No persistent cache.** `settings.cache_dir` (`config.py:122`, default `.cache`) is declared but **never used**.
- **Clients** (`clients/exploit_client.py`, `clients/cveorg_client.py`): each large dataset (Metasploit `modules_metadata_base.json`, ExploitDB CSV, Nuclei `cves.json`, CISA KEV JSON, EPSS CSV) is **re-downloaded on every process** — the `_modules_db`/`_kev_cache`/`_epss_cache` fields are in-memory only, so a fresh CLI invocation refetches tens of MB. This is the single biggest latency/rate-limit cost.
- **Failure handling:** services/clients wrap sources in broad `except` blocks that return `[]`/`None`. A rate-limited GitHub (HTTP 403, *not* retried — `Retry` only lists 429/5xx) or a down NVD is **indistinguishable from "no results"** to the user.
- **Confirmed bug (offline-reproducible):** `ServiceAdapter.find_github_pocs` (`mcp_server.py:132`) calls `self._exploit.find_github_pocs(cve_id, limit=limit)`, but `ExploitService.find_github_pocs(self, cve_id)` (`exploit_service.py:88`) takes **no** `limit`. This raises `TypeError`, is swallowed by `except Exception`, and returns `[]`. It also poisons MCP `lookup_cve` enrichment (`mcp_server.py:311,358`) and report aggregation (`:1660`). GitHub PoC discovery via the **entire MCP surface is effectively dead**. The CLI is unaffected (`cli.py:147` passes only `cve`).
- **MCP** (`mcp_server.py`, ~77 KB single file): 19 tools, 3 resources, 3 prompts, and a genuinely good error taxonomy already (`category`/`retryable`/`error_type`, `mcp_server.py:795-812`). Strong base to build on, but monolithic and slow (no cache) and carries the bug above.
- **Distribution:** README says `pip install pocmap` but the package is **not on PyPI**; there is no release/publish workflow, no docs site, no `examples/`.

---

## Roadmap items

Fields per item: **id · title · why it drives adoption · scope · files touched · acceptance (how to verify, offline-first) · effort · risk · deps.**

---

### Phase 1 — Foundational / enabling

#### `FIX-GHPOC` — Repair MCP GitHub-PoC discovery (+ regression test)
- **Why:** The MCP server is pitched as the AI differentiator, yet its most-used exploit tool silently returns nothing. Fixing this is the highest value-per-line change in the repo and unblocks trustworthy MCP output.
- **Scope:** Either add an optional `limit: int | None = None` to `ExploitService.find_github_pocs` (slice results) or stop passing `limit=` from the adapter and slice in the adapter only. Prefer the former for a clean public API. Audit `mcp_server.py:311,358,1660` for the same call shape.
- **Files:** `src/pocmap/services/exploit_service.py`, `mcp_server.py`, `tests/`.
- **Acceptance (offline):** New pytest with a `ExploitService` whose `_github.search_pocs` is mocked to return N fake `Exploit`s; assert `ServiceAdapter.find_github_pocs(cve, limit=3)` returns 3 dicts (not `[]`) and that no `TypeError` is logged. `mypy`/`ruff` clean.
- **Effort:** S · **Risk:** Low · **Deps:** none.

#### `RENDER-LAYER` — Output-format abstraction + stable exit codes
- **Why:** Machine-readable, composable output is the #1 automation-adoption lever. This is the substrate every export feature (JSON/CSV/SARIF/MD) and CI use case builds on. Doing it once, centrally, prevents per-command drift.
- **Scope:** New `utils/output.py` with an `OutputFormat` enum (`table`, `json`) and a `render(result, fmt, console)` dispatcher, plus a serialization contract (each command produces a plain dict/dataclass "view model" that renderers consume). New `utils/exit_codes.py` with named codes (`OK=0`, `NO_RESULTS=0|2` decision, `NOT_FOUND=3`, `INVALID_INPUT=4`, `UPSTREAM_ERROR=5`). Add a global Typer callback option `--format/-f` and `--quiet` threaded through `main()`. Convert one command (`lookup`) as the reference implementation.
- **Files:** `src/pocmap/cli.py`, new `src/pocmap/utils/output.py`, new `src/pocmap/utils/exit_codes.py`, `tests/`.
- **Acceptance (offline):** `pocmap lookup CVE-... --format json` (with CVEService mocked) emits valid JSON to stdout and nothing else; table mode unchanged; `pocmap lookup BADID` exits `4`, a mocked not-found exits `3`. Unit tests assert exit codes via `typer.testing.CliRunner`. Document the exit-code table in README.
- **Effort:** M · **Risk:** Med (touches CLI surface; keep table output byte-stable for existing users) · **Deps:** none.

#### `HTTP-CACHE` — Persistent, TTL'd response cache (offline resilience + speed + fewer API hits)
- **Why:** Single highest-leverage feature. Turns multi-second, network-bound CLI calls into sub-second cached ones, dodges GitHub/NVD rate limits, and enables a real offline mode. `settings.cache_dir` already exists and is unused.
- **Scope:** New `utils/cache.py`: a keyed (hash of method+URL+params) on-disk store under `settings.cache_dir`, per-entry TTL, atomic writes, size cap + LRU eviction, and a `bypass`/`refresh` flag. Wire into `HTTPClient.get_json`/`get_text` (opt-in per call category so volatile endpoints can set short TTLs and large static datasets long ones). Config: `POCMAP_CACHE_ENABLED` (default on), `POCMAP_CACHE_TTL`, `POCMAP_CACHE_MAX_MB`. Never cache non-200 or error bodies.
- **Files:** new `src/pocmap/utils/cache.py`, `src/pocmap/utils/http.py`, `src/pocmap/config.py`, `tests/`.
- **Acceptance (offline):** Unit test with a fake transport: first `get_json` writes a cache file, second identical call returns without invoking transport; expired TTL triggers a refetch; corrupt cache file falls back to network gracefully; cache disabled → always fetches. Verify a `.cache` entry is created under a temp `POCMAP_CACHE_DIR`. `mypy --strict` clean (typed cache API).
- **Effort:** M · **Risk:** Med (cache-poisoning/staleness; mitigate with TTL + never caching errors) · **Deps:** none (but coordinates with `ERR-RESULT` on `utils/http.py` — sequence them).

#### `ERR-RESULT` — Reliability: distinguish "no results" from "source failed"
- **Why:** Trust. Today a rate-limited or down source looks identical to "nothing found," which quietly produces wrong security conclusions. Professionals abandon tools that lie by omission.
- **Scope:** Introduce a lightweight per-source status (e.g. an `Enum FetchStatus{OK, EMPTY, RATE_LIMITED, ERROR}` returned alongside results, or a `SourcesHealth` object collected during a lookup). Stop swallowing `TypeError`/programming errors in adapters (let them surface in tests/CI). Treat GitHub 403 with `X-RateLimit-Remaining: 0` as rate-limited (add 403 handling since urllib3 `Retry` won't). Surface a compact "sources: NVD ok, GitHub rate-limited, EPSS ok" footer in CLI (dim) and a `sources` block in JSON/MCP output. Reuse the existing MCP `category/retryable` taxonomy.
- **Files:** `src/pocmap/utils/http.py`, `src/pocmap/services/*.py`, `src/pocmap/clients/*.py`, `mcp_server.py`, `tests/`.
- **Acceptance (offline):** Mock a client to raise `HTTPError(status_code=403)` → result carries `RATE_LIMITED`, CLI footer reflects it, exit code is not "clean success masking failure"; mock empty-but-OK → `EMPTY`; mock a `TypeError` → test asserts it is NOT swallowed (regression guard for `FIX-GHPOC`-class bugs). `ruff`/`mypy` clean.
- **Effort:** M · **Risk:** Med (broad touch across services; keep changes additive) · **Deps:** `FIX-GHPOC` (shares the swallow-exception theme); serialize on `utils/http.py` after `HTTP-CACHE`.

#### `DOCTOR` — `pocmap doctor` + `pocmap cache` commands
- **Why:** The fastest path from "installed" to "working." First-run friction (missing tokens, no connectivity, silent rate limits) is where tools lose users. `doctor` makes the tool self-explain.
- **Scope:** `pocmap doctor` checks: Python version, installed optional extras (`[server]`), presence/format of `GITHUB_API_TOKEN`/`NVD_API_KEY`, cache dir writable + current size, and a connectivity probe per upstream (skipped/labelled under `--offline`). Emits a PASS/WARN/FAIL table and a nonzero exit if any FAIL. `pocmap cache info|clear|--path` reports entry count/size and clears safely (via `safe_path`).
- **Files:** `src/pocmap/cli.py` (new commands), `src/pocmap/config.py`, `src/pocmap/utils/cache.py`, `tests/`.
- **Acceptance (offline):** `doctor` logic tested with connectivity probes mocked (inject a prober): all-green exits 0; a forced FAIL exits nonzero; token-format check flags a malformed `ghp_` value; `cache info` on a seeded temp cache reports correct count/size; `cache clear` empties it. The **live** connectivity probe itself is **[needs-user/network]** but the surrounding logic is fully offline-verifiable via the injected prober.
- **Effort:** M · **Risk:** Low · **Deps:** `HTTP-CACHE` (cache status), `RENDER-LAYER` (shares `cli.py`; sequence after).

---

### Phase 2 — High-value features

#### `JSON-EVERYWHERE` — `--format json` on every command
- **Why:** Consistency is what makes a CLI scriptable. Half-JSON coverage means users can't rely on it and reach for something else.
- **Scope:** Wire the `RENDER-LAYER` dispatcher into the table-only commands: `labs`, `bugbounty`, `cpes`, `cpe2cve`, and align `latest`/`discover` (which already build JSON) to emit to **stdout** under `--format json`, keeping `--output` for files. One documented envelope shape (`{"data": ..., "sources": ..., "query": ...}`).
- **Files:** `src/pocmap/cli.py`, `src/pocmap/utils/output.py`, `tests/`.
- **Acceptance (offline):** For each command, `CliRunner` with mocked services asserts stdout parses as JSON and matches a golden fixture; table mode still renders. `--quiet --format json` prints only JSON (no banner/progress).
- **Effort:** M · **Risk:** Low · **Deps:** `RENDER-LAYER`.

#### `EXPORT-CSV-MD` — CSV and Markdown renderers
- **Why:** CSV drops straight into spreadsheets/BI; Markdown pastes into tickets, wikis, and bug-bounty reports. Both are low effort on top of `RENDER-LAYER` and materially widen who can consume output.
- **Scope:** Add `csv` and `md` to `OutputFormat`; renderer modules `renderers/csv_renderer.py`, `renderers/md_renderer.py` operating on the shared view models. Support `lookup`, `latest`, `discover`, `bulk`.
- **Files:** new `src/pocmap/utils/renderers/` (or functions in `output.py`), `src/pocmap/cli.py`, `tests/`.
- **Acceptance (offline):** Golden-file tests: mocked `latest` → CSV parses via `csv.DictReader` with the expected header row; Markdown output contains a valid table and passes a simple structural assertion. No network.
- **Effort:** S–M · **Risk:** Low · **Deps:** `RENDER-LAYER`.

#### `EXPORT-SARIF` — SARIF 2.1.0 output for CI/CD
- **Why:** SARIF is the lingua franca of code-scanning. Emitting SARIF lets `pocmap` post findings into GitHub code scanning / Azure DevOps / any SARIF-aware pipeline — a concrete reason for security teams to wire it into CI and thus use it continuously.
- **Scope:** `sarif` format for `bulk`/`discover`/`latest`: one `run` with `tool.driver` = pocmap, each CVE → a `result` (ruleId=CVE-ID, `level` mapped from CVSS severity: critical/high→error, medium→warning, low→note), `properties` carrying EPSS/KEV/exploit-count, `helpUri`→NVD. Include a rules array (deduped CWEs).
- **Files:** new `src/pocmap/utils/renderers/sarif_renderer.py`, `src/pocmap/cli.py`, `tests/`, fixture `tests/fixtures/sarif_schema*.json`.
- **Acceptance (offline):** Generate SARIF from a mocked multi-CVE report; validate against the bundled SARIF 2.1.0 JSON schema (schema check offline, no network); assert severity→level mapping and that KEV/EPSS land in `properties`. Optionally assert GitHub's `sarif` upload shape constraints (single run, ruleIds present).
- **Effort:** M · **Risk:** Med (schema fidelity) · **Deps:** `RENDER-LAYER`.

#### `STDIN-BULK-CI` — stdin piping + CI-grade `bulk`
- **Why:** `... | pocmap bulk -` is how tools compose in real pipelines; `--fail-on` turns pocmap into a CI gate ("fail the build if any in-scope dep has a KEV CVE"). Both convert pocmap from "thing I run by hand" to "thing in my automation."
- **Scope:** Accept `-` as the file arg to read CVE IDs from stdin. Give `bulk` a stdout summary table + `--format json|sarif|csv` (reusing renderers) and `--fail-on {critical,high,kev,epss>=N}` that sets a nonzero exit when matches exist. Preserve existing HTML/JSON file output.
- **Files:** `src/pocmap/cli.py`, `src/pocmap/services/report_service.py`, `tests/`.
- **Acceptance (offline):** `echo -e "CVE-A\nCVE-B" | pocmap bulk - --format json` (services mocked) returns both entries as JSON; `--fail-on kev` with a mocked KEV hit exits nonzero, without exits 0. `CliRunner` with `input=`.
- **Effort:** M · **Risk:** Low · **Deps:** `RENDER-LAYER`, `EXPORT-SARIF` (only for the sarif sub-format).

#### `WATCH-DIFF` — snapshot + diff between runs for `latest`/`discover`
- **Why:** The recurring-use hook. A daily "what's new since yesterday" (new CVEs, newly-KEV, newEPSS-jump) is exactly the weekly/daily ritual that builds habit. Directly serves AGENTS.md "Daily Threat Briefing" workflow.
- **Scope:** Persist each `latest`/`discover` result set as a snapshot under the cache dir (keyed by query). Add `--diff`/`--since-last` to compute added/removed/changed CVEs vs the previous snapshot for the same query and render the delta (new + severity/KEV/EPSS changes). Pure local computation.
- **Files:** new `src/pocmap/services/snapshot.py` (or in `recent_service.py`), `src/pocmap/cli.py`, `src/pocmap/utils/cache.py`, `tests/`.
- **Acceptance (offline):** Seed two snapshot fixtures (old/new); assert diff reports the correct added/removed/changed sets and that an unchanged run reports "no changes." No network.
- **Effort:** M · **Risk:** Low · **Deps:** `HTTP-CACHE` (dir/atomic-write infra).

#### `OFFLINE-MODE` — `--offline` / `POCMAP_OFFLINE`
- **Why:** Demoing on a plane, air-gapped assessments, and fast repeatable runs. Also makes the test suite honest and quick. Turns the cache into a first-class capability rather than an optimization.
- **Scope:** A global `--offline` flag (and env) that makes `HTTPClient` serve only from cache and raise a clear, categorized "cache miss (offline)" instead of hitting the network. `doctor`/footer clearly indicate offline. `EMPTY` vs `cache-miss` are distinct.
- **Files:** `src/pocmap/utils/http.py`, `src/pocmap/utils/cache.py`, `src/pocmap/cli.py`, `src/pocmap/config.py`, `tests/`.
- **Acceptance (offline):** With offline set and a warm cache fixture, a lookup returns cached data and makes zero transport calls; with a cold cache it surfaces a clear offline cache-miss error (categorizable) rather than a generic network error. Fully offline-verifiable.
- **Effort:** S–M · **Risk:** Low · **Deps:** `HTTP-CACHE`, `ERR-RESULT`.

---

### Phase 3 — Distribution & polish

#### `COMPLETION` — shell completion
- **Why:** Table stakes for a CLI people live in; frictionless tab-completion of commands/options is a small thing that signals "this is a real tool."
- **Scope:** Flip `add_completion=True` (or add explicit `--install-completion`/`--show-completion`) in `cli.py`; verify bash/zsh/fish/PowerShell scripts generate. Document in README + `doctor` hint.
- **Files:** `src/pocmap/cli.py`, `README.md`, `tests/`.
- **Acceptance (offline):** `pocmap --show-completion bash` (via `CliRunner`) emits a non-empty completion script; smoke test that the app still boots with completion enabled. No network.
- **Effort:** S · **Risk:** Low · **Deps:** none (independent of `RENDER-LAYER` but shares `cli.py`; merge-coordinate).

#### `PAGER-FIX` — cross-platform `readme` + polish
- **Why:** Windows is a first-class security workstation OS (this repo is developed on Win11). `readme` shelling to `less` only on Unix is a visible rough edge.
- **Scope:** Use a portable pager (`rich.console.Console.pager()` / `click.echo_via_pager`) so `readme` works on Windows; general small-polish sweep (consistent error prefixes, `--no-banner`/`--quiet` respected everywhere).
- **Files:** `src/pocmap/cli.py`, `tests/`.
- **Acceptance (offline):** `readme` with a mocked `get_readme` renders content through the portable pager path on all platforms (assert no `subprocess(["less"])` on Windows). Unit-testable.
- **Effort:** S · **Risk:** Low · **Deps:** none.

#### `RELEASE-CI` — build + release automation and PyPI publish
- **Why:** README already tells users `pip install pocmap`, but it's not published — the biggest single adoption gap. `pipx install pocmap` is how CLI tools actually get adopted.
- **Scope:** Add `python -m build` sdist+wheel + `twine check` to CI; a tag-triggered release workflow that builds, checks, and (via PyPI Trusted Publishing/OIDC) publishes; document `pipx install pocmap`. Add a wheel-install smoke job (`pip install dist/*.whl && pocmap --version`).
- **Files:** new `.github/workflows/release.yml`, `pyproject.toml` (metadata/`project.urls` review), `README.md`.
- **Acceptance:** Offline-verifiable parts: `python -m build` produces sdist+wheel, `twine check dist/*` passes, wheel-install smoke runs `pocmap --version`, workflow YAML is valid. **[needs-user/network]:** the actual PyPI publish requires the maintainer to create the PyPI project and configure Trusted Publishing / API token — route that step to the user.
- **Effort:** M · **Risk:** Med (release hygiene) · **Deps:** repo green; benefits from `DOCS-SITE`.

#### `DOCS-SITE` — hosted docs + versioned reference
- **Why:** A findable docs site (searchable, linkable) is a credibility and discoverability multiplier over a single long README. Feeds MCP/agent users who need the tool table and schemas.
- **Scope:** `mkdocs-material` site generated from README/AGENTS content + an auto-generated MCP tool reference and JSON-schema pages; GitHub Pages deploy workflow.
- **Files:** new `docs/`, `mkdocs.yml`, `.github/workflows/docs.yml`.
- **Acceptance:** Offline-verifiable: `mkdocs build --strict` succeeds with no broken links/nav. **[needs-user/network]:** GH Pages deploy needs the user to enable Pages for the repo — route that step to the user.
- **Effort:** M · **Risk:** Low · **Deps:** none (content stabilizes after Phase 2).

#### `QUICKSTART-EXAMPLES` — runnable examples + 60-second quickstart
- **Why:** Copy-paste-it-works examples are the strongest onboarding accelerant. Reduces "how do I use this" to zero.
- **Scope:** `examples/` with small runnable scripts (single lookup → JSON, bulk → SARIF in CI, `latest --diff` daily brief, MCP config snippet), a terminal GIF/asciinema, and a tightened README quickstart. Add a CI job that executes the offline-capable examples against mocks.
- **Files:** new `examples/`, `README.md`, `.github/workflows/ci.yml` (optional examples job).
- **Acceptance (offline):** Example scripts that can run against mocked services execute with exit 0 in CI; README quickstart commands match real `--help` output (guard against doc drift, akin to the existing `agent-docs-consistency` agent).
- **Effort:** S–M · **Risk:** Low · **Deps:** `JSON-EVERYWHERE`, `EXPORT-SARIF`, `WATCH-DIFF` (so examples showcase them).

---

### Phase 4 — Futures / stretch

#### `MCP-SPLIT` — modularize the 77 KB `mcp_server.py`
- **Why:** Maintainability of the differentiator. A single 77 KB file with 19 tools is where bugs like `FIX-GHPOC` hide. Splitting makes the MCP surface auditable and safe to extend (the `add-mcp-tool` skill will thank you).
- **Scope:** Refactor into a package (e.g. `mcp/tools/`, `mcp/resources.py`, `mcp/prompts.py`, `mcp/errors.py`, `mcp/adapter.py`) behind the same root `mcp_server.py` entrypoint (CLAUDE.md requires the entrypoint stays at repo root). No behavior change.
- **Files:** `mcp_server.py`, new `mcp/` package (repo root), `mcp_config.json`/`AGENTS.md` unchanged in contract, `tests/`.
- **Acceptance (offline):** A test imports the server module and asserts the tool/resource/prompt counts (19/3/3) and names are unchanged pre/post refactor; `python mcp_server.py --help` still works; `mypy`/`ruff` clean.
- **Effort:** L · **Risk:** Med (churn; mitigate with a name-inventory test written first) · **Deps:** `FIX-GHPOC`, `ERR-RESULT`.

#### `NOTIFY` — `latest --notify` to Slack/Discord
- **Why:** Push turns a tool you pull from into a service that reaches you — strong retention. The SSRF-guarded `HTTPClient.post_json` (`utils/http.py:283`) and `bugbounty/automation.py` webhook sender already exist; this wires them to a user-facing flag.
- **Scope:** `latest`/`discover --notify <webhook>` (or config) posts a compact summary of new/critical/KEV CVEs via the existing guarded `post_json`. Pairs naturally with `WATCH-DIFF` (notify only the delta) and `schedule`d runs.
- **Files:** `src/pocmap/cli.py`, `src/pocmap/services/recent_service.py`, reuse `src/pocmap/bugbounty/automation.py`, `tests/`.
- **Acceptance (offline):** With `post_json` mocked, `--notify` builds the expected payload and calls the guarded sender exactly once; an internal/blocked webhook URL is rejected by the existing SSRF guard (assert). No live webhook.
- **Effort:** S–M · **Risk:** Med (egress; must stay on the SSRF-checked path — see `security-reviewer` agent) · **Deps:** `WATCH-DIFF`.

#### `PLUGIN-SOURCES` — third-party exploit sources via entry points
- **Why:** An extension point lets the community add sources (e.g. new PoC feeds) without forking, which is how tools grow a moat. The `PluginRegistry` (`utils/registry.py`, used in `exploit_service.py:182`) is already the seam.
- **Scope:** Formalize registration via `importlib.metadata` entry points (`pocmap.exploit_sources`), document the contract (README already sketches it under "Adding New Exploit Sources"), and load registered sources at startup with the `ERR-RESULT` status contract.
- **Files:** `src/pocmap/services/exploit_service.py`, `src/pocmap/utils/registry.py`, `README.md`, `tests/`.
- **Acceptance (offline):** A test registers a dummy in-process source and asserts `find_exploits` includes its results and that a raising source degrades to `ERROR` status without killing the aggregate. No network.
- **Effort:** M · **Risk:** Low · **Deps:** `ERR-RESULT`.

#### `TUI` — interactive triage (`pocmap tui`)
- **Why:** A keyboard-driven triage view (browse `latest`, drill into a CVE, open PoCs) is a delight feature that differentiates from one-shot CLIs. Optional; only if the export/cache foundation proves demand.
- **Scope:** A small Textual app over the existing services, gated behind a `[tui]` extra so core install stays lean.
- **Files:** new `src/pocmap/tui/`, `pyproject.toml` (`[tui]` extra), `tests/`.
- **Acceptance (offline):** Textual's test harness drives a scripted session against mocked services (open list → select CVE → see detail) with no network; `import`-guarded so absence of the extra doesn't break core.
- **Effort:** L · **Risk:** Med (new dep surface) · **Deps:** `RENDER-LAYER` (view models), `HTTP-CACHE` (snappy UX).

---

## Recommended execution order (phased, with parallelization)

Legend: **∥** = can run concurrently (disjoint files); **→** = must follow (shared file or logical dep). The recurring shared-file hotspots are `cli.py` (RENDER-LAYER, JSON-EVERYWHERE, exports, DOCTOR, COMPLETION, PAGER-FIX) and `utils/http.py` (HTTP-CACHE, ERR-RESULT, OFFLINE-MODE) — fan out around those.

### Phase 1 — Foundational / enabling
1. **`FIX-GHPOC`** (S) — do first; tiny, unblocks trustworthy MCP output, independent files.
2. In parallel after step 1:
   - **`HTTP-CACHE`** (M) — files: `utils/cache.py`+`utils/http.py`+`config.py`.
   - **`RENDER-LAYER`** (M) — files: `cli.py`+`utils/output.py`+`utils/exit_codes.py`.
   - `FIX-GHPOC` ∥ `HTTP-CACHE` ∥ `RENDER-LAYER` are file-disjoint → **3-way parallel** safe.
3. **`ERR-RESULT`** (M) — **→ after `HTTP-CACHE`** (both edit `utils/http.py`); pulls in `FIX-GHPOC`'s no-swallow guard.
4. **`DOCTOR`** (M) — **→ after `HTTP-CACHE` (cache status) and `RENDER-LAYER` (`cli.py`)**.

> Phase-1 fan-out: one agent on `FIX-GHPOC`, one on `HTTP-CACHE`, one on `RENDER-LAYER`. Then `ERR-RESULT` and `DOCTOR` sequentially (they each depend on a Phase-1 module).

### Phase 2 — High-value features
All build on `RENDER-LAYER` and/or `HTTP-CACHE`. The **renderer modules are file-disjoint and parallelizable**; only the final `cli.py` wiring is a shared merge point — have one agent own the `cli.py` option-plumbing and let the renderer agents deliver self-contained modules.
5. Parallel group A (renderers, disjoint files, depend on `RENDER-LAYER`):
   - **`EXPORT-CSV-MD`** (S–M) ∥ **`EXPORT-SARIF`** (M) ∥ **`JSON-EVERYWHERE`** (M, owns the `cli.py` wiring — sequence the others' small CLI hooks behind it or merge carefully).
6. Parallel group B (cache-backed, disjoint from renderers, depend on `HTTP-CACHE`):
   - **`WATCH-DIFF`** (M) ∥ **`OFFLINE-MODE`** (S–M, also needs `ERR-RESULT`).
7. **`STDIN-BULK-CI`** (M) — **→ after `RENDER-LAYER`**; needs `EXPORT-SARIF` only for its `sarif` sub-format (degrade gracefully if run earlier).

> Phase-2 fan-out: Group A and Group B are mutually disjoint → run A and B concurrently (up to ~4 agents), then land `STDIN-BULK-CI` once renderers exist.

### Phase 3 — Distribution & polish
Mostly independent; `cli.py` items should merge-coordinate.
8. **`COMPLETION`** (S) ∥ **`PAGER-FIX`** (S) — both small `cli.py` edits; do sequentially or by one agent to avoid churn.
9. **`DOCS-SITE`** (M) ∥ **`RELEASE-CI`** (M) — fully disjoint from `cli.py` and from each other → **parallel**. Both have offline-verifiable cores; flag the **PyPI publish** and **GH Pages deploy** steps **[needs-user/network]**.
10. **`QUICKSTART-EXAMPLES`** (S–M) — **→ after Phase 2** (so examples demo real JSON/SARIF/diff features).

### Phase 4 — Futures / stretch (schedule opportunistically)
11. **`MCP-SPLIT`** (L) — after `ERR-RESULT`; write the tool-name-inventory test first, then refactor.
12. **`NOTIFY`** (S–M) — after `WATCH-DIFF`; keep strictly on the SSRF-guarded `post_json` path (run `security-reviewer`).
13. **`PLUGIN-SOURCES`** (M) — after `ERR-RESULT`.
14. **`TUI`** (L) — last; only if usage validates demand.

---

## Highest-conviction sequencing summary

- **Do now, cheap, unblocks trust:** `FIX-GHPOC` (a live MCP bug).
- **The two load-bearing foundations:** `HTTP-CACHE` (speed/offline/rate-limits) and `RENDER-LAYER` (machine output) — everything else leverages them.
- **The adoption headline features:** `EXPORT-SARIF` + `STDIN-BULK-CI` (pocmap becomes a CI gate) and `WATCH-DIFF`+`NOTIFY` (pocmap becomes a daily habit).
- **The credibility unlock:** `RELEASE-CI` so `pip/pipx install pocmap` is finally true (the one step that needs the maintainer's PyPI account).

Everything here keeps the repo green and is verifiable offline except the explicitly flagged **[needs-user/network]** steps (PyPI publish, GH Pages deploy, and the *live* connectivity probe inside `doctor` — whose surrounding logic is still offline-tested via an injected prober).
