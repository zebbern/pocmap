# CLI reference

## Recent CVE Discovery

Monitor newly published vulnerabilities and filter by severity, exploitability, and time window. Ideal for security briefings, threat intelligence feeds, and proactive vulnerability management.

### `pocmap latest`

```bash
# Recent CVEs from the last 24 hours (default)
pocmap latest

# Specify a relative time window
pocmap latest --since 7d
pocmap latest --since 30d
pocmap latest --since 1h

# Explicit date range
pocmap latest --from 2024-01-01 --to 2024-01-31

# Only CVEs with known PoCs on GitHub
pocmap latest --only-with-poc

# Only CISA KEV entries
pocmap latest --kev-only

# Minimum EPSS score filter
pocmap latest --min-epss 50.0

# Filter by severity levels (comma-separated)
pocmap latest --severity critical,high

# Sort results
pocmap latest --sort cve_date     # newest first (default)
pocmap latest --sort severity     # highest severity first
pocmap latest --sort epss         # highest EPSS first

# Limit results and save to JSON
pocmap latest --since 7d --severity critical --only-with-poc --limit 10 --output ./report.json
```

**Options:**

| Option | Description |
|--------|-------------|
| `--since` | Relative time window: `1h`, `24h`, `7d`, `30d` |
| `--from` | Start date in `YYYY-MM-DD` format (overrides `--since`) |
| `--to` | End date in `YYYY-MM-DD` format |
| `--only-with-poc` | Only return CVEs with known PoCs on GitHub |
| `--kev-only` | Only return CISA Known Exploited Vulnerabilities |
| `--min-epss` | Minimum EPSS score (0-100), e.g., `50.0` for EPSS >= 50% |
| `--severity` | Comma-separated severities: `critical`, `high`, `medium`, `low` |
| `--sort` | Sort by: `cve_date`, `severity`, or `epss` |
| `--limit` | Maximum results (1-100, default: 50) |
| `--output`, `-o` | Save JSON report to file |
| `--diff`, `--since-last` | Show only what changed since the last identical run (added/removed/changed) |
| `--notify <url>` | POST a summary of notable CVEs (critical/high or KEV) to a webhook; with `--diff`, only the delta is sent |
| `--format`, `-f` | Output format: `table` (default), `json`, `csv`, `md`, `sarif` |
| `--quiet`, `-q` | Suppress decorative output |

**Output includes:** CVE ID, description, CVSS severity/score, EPSS, KEV status, vendor, product, publication date, PoC availability, and PoC source counts.

## Product Discovery

Find all CVEs affecting a specific product without needing a CVE ID. Product names are
resolved through the **NVD CPE dictionary** to canonical `vendor:product` identifiers,
and CVEs are then fetched by CPE applicability match with the version constraint applied
by NVD itself.

### `pocmap discover`

```bash
# Discover CVEs for a product by name
pocmap discover "Apache Struts"

# With version wildcard
pocmap discover "Log4j" --version 2.x

# Exact version
pocmap discover "nginx" --version 1.20.1

# With vendor hint
pocmap discover "struts" --vendor apache --version 2.x

# Save results to JSON
pocmap discover "Apache Struts" --version 2.x --output ./struts-cves.json
```

**Options:**

| Option | Description |
|--------|-------------|
| `--version`, `-v` | Version constraint: `2.x`, `2.14.1`, `>= 2.0` |
| `--vendor` | Vendor name hint: `apache`, `microsoft`, `google` |
| `--limit` | Maximum CVEs to analyze (1-100, default: 50) |
| `--output`, `-o` | Save JSON report to file |
| `--diff`, `--since-last` | Show only what changed since the last identical run (added/removed/changed) |
| `--notify <url>` | POST a summary of notable CVEs (critical/high or KEV) to a webhook; with `--diff`, only the delta is sent |
| `--format`, `-f` | Output format: `table` (default), `json`, `csv`, `md`, `sarif` |
| `--quiet`, `-q` | Suppress decorative output |

### How a product name is resolved

1. **Alias fast path.** A small curated table maps common shorthands to canonical names
   (see below). A hit skips the dictionary lookup; a miss costs nothing.
2. **NVD CPE dictionary.** The product name is resolved to every `vendor:product` pair
   NVD files CVEs under, ranked by how many CPE entries back each pair. **All** pairs are
   searched and the results unioned, because products change hands: `nginx` resolves to
   `igor_sysoev:nginx` (0 CVEs), `nginx:nginx` (2) and `f5:nginx` (41), so taking only the
   top-ranked pair would find almost nothing. At most 5 pairs are queried (a rate-limit
   bound, not a precision one — NVD allows 5 requests/30s unauthenticated); any dropped
   pairs are logged, never silently discarded.

   **Editions and product families are included.** NVD files enterprise software under a
   separate product per edition, so a query also admits any product in the *same vendor's
   namespace* whose name extends the target: "Confluence" reaches
   `atlassian:confluence_server` and `atlassian:confluence_data_center`, "Jira" reaches
   `jira_service_desk`, `jira_software_data_center` and `jira_service_management`. A
   third party's lookalike does not — `redhat:kubernetes-client` is not Kubernetes, and
   `perforce:gliffy` is not Confluence. The bias is deliberate: an extra CVE in the list
   is visible and dismissible, a missing one is neither.
3. **Keyword fallback.** If the product cannot be resolved at all, `discover` falls back
   to NVD full-text search. This is materially weaker — it matches CVE *descriptions*, so
   it is both noisy and incomplete. The result reports which path ran:

| `search_sources` | `matched_cpes` | Meaning |
|------------------|----------------|---------|
| `nvd_cpe_match` | the resolved CPE prefixes | Authoritative applicability match |
| `nvd_keyword_search` | empty | Unresolvable product; noisy full-text fallback |

> **Rate limits.** Discovery costs one dictionary lookup plus one query per resolved pair.
> Unauthenticated NVD allows 5 requests per 30 seconds, so setting `NVD_API_KEY` is
> considerably more valuable than it used to be. Responses are cached (see
> [Caching & Offline Mode](#caching-offline-mode)), so repeat runs are cheap.

### Product Alias System

The discovery command recognizes common product aliases and abbreviations, so you don't need to know the exact canonical product name:

| Alias Input | Resolved Product |
|-------------|-----------------|
| `struts` | Apache Struts |
| `log4j`, `log4j2` | Log4j |
| `httpd`, `apache2` | Apache HTTP Server |
| `k8s`, `kube` | Kubernetes |
| `postgres`, `pgsql` | PostgreSQL |
| `es`, `elastic` | Elasticsearch |
| `nodejs`, `node` | Node.js |
| `ghe` | GitHub Enterprise |
| `ror` | Ruby on Rails |
| `wp` | WordPress |
| `ie`, `msie` | Internet Explorer |

Aliases are matched on the whole name, ignoring separators — `apache struts`,
`apache_struts` and `Apache-Struts` are equivalent — and a known vendor phrase is peeled
off first, so `"Palo Alto PAN-OS"` becomes vendor=`palo alto` + product=`pan-os`.
Matching is deliberately not substring-based: anything the table does not recognize goes
to the CPE dictionary, which covers the full NVD catalogue rather than this short list.

### Version Constraint Format

Version constraints support multiple formats for flexible version matching:

| Format | Example | Meaning |
|--------|---------|---------|
| Wildcard | `2.x` | Any version in major version 2 |
| Exact | `2.14.1` | Exactly version 2.14.1 |
| Major.Minor | `2.14` | Version 2.14.x |
| Range (>=) | `>= 2.0` | Version 2.0 and above |
| Range (<=) | `<= 1.20` | Version 1.20 and below |
| Range (>) | `> 1.0` | Above version 1.0 |
| Range (<) | `< 3.0` | Below version 3.0 |
| None (omit) | - | Any version |

Results are grouped into three confidence tiers. Matching considers **every**
`(vendor, product)` pair a CVE is filed under, not just one — a CVE typically names the
vulnerable component plus every distribution that shipped it, and judging it by a single
pair misclassifies the component the CVE is actually about:

- **Confirmed**: Vendor AND product match AND version constraint is met
- **Possibly**: Vendor OR product matches but version info is unclear
- **Not enough data**: CVE has insufficient product/version information

Version matching is an interval-overlap test that honours NVD's out-of-band range
attributes (`versionStartIncluding` / `versionEndExcluding`), which is where modern CVE
records express affected ranges — the literal version field in the CPE string is usually
just `*`.

## Dependency Vulnerabilities

`pocmap discover` answers "is the nginx we run vulnerable". `pocmap package` answers the
other half: **is the dependency we ship vulnerable, and what do we upgrade to.**

The two are keyed differently and are not interchangeable. NVD files vulnerabilities
against a CPE *product*, which is right for deployed software but carries no package
coordinate and no fix version. [OSV.dev](https://osv.dev) files them against a *package*
(`PyPI/django`, `Maven/org.apache.logging.log4j:log4j-core`) and records the releases that
fix each one. OSV needs no API key and is not bound by NVD's 5-requests-per-30-seconds
limit, so this path stays fast without `NVD_API_KEY`.

```bash
# What's wrong with the version we actually ship, and what fixes it
pocmap package PyPI django --version 3.2.0
pocmap package npm lodash --version 4.17.20
pocmap package Maven org.apache.logging.log4j:log4j-core --version 2.14.1

# Ecosystem names are case-insensitive here and normalized for you
pocmap package pypi requests --version 2.25.0
pocmap package debian:12 nginx

# Only what you can actually act on, as JSON
pocmap package PyPI django --version 3.2.0 --fixable-only --format json

# SARIF for code scanning, in a CI dependency gate
pocmap package npm lodash --version 4.17.20 --format sarif --output out/
```

```
Package Vulnerabilities: Maven/org.apache.logging.log4j:log4j-core@2.14.1
Found 7 | with a fix: 7 | no fix published: 0
Severity  CVSS   EPSS  KEV  Advisory        Fixed in
CRITICAL  10.0  100.0  yes  CVE-2021-44228  2.15.0, 2.3.1, 2.12.2
CRITICAL   9.0  100.0  yes  CVE-2021-45046  2.16.0, 2.12.2
HIGH       8.6  100.0       CVE-2021-45105  2.12.3, 2.17.0, 2.3.1
```

**Options:**

| Option | Description |
|--------|-------------|
| `--version`, `-v` | Installed version. Strongly recommended — OSV then evaluates its own affected ranges and returns only advisories that genuinely apply. |
| `--fixable-only` | Only advisories with a published fix. Applied *after* ranking and `--limit`, so it narrows the top-N by risk rather than fetching N fixable ones. |
| `--limit` | Maximum advisories (1-1000, default: 100), taken from the top of the risk ranking. |
| `--output`, `-o` | Save the JSON report to a file. |
| `--format`, `-f` | `table` (default), `json`, `csv`, `md`, `sarif`. |
| `--quiet`, `-q` | Suppress decorative output. |

**Supported ecosystems.** All 50 OSV ecosystems, including `PyPI`, `npm`, `Go`, `Maven`,
`crates.io`, `RubyGems`, `Packagist`, `NuGet`, `Hex`, `Pub`, `CRAN`, `Hackage`,
`ConanCenter`, `SwiftURL`, `vcpkg`, and the distributions `Debian`, `Ubuntu`, `Alpine`,
`Red Hat`, `Rocky Linux`, `AlmaLinux`, `SUSE`, `Wolfi`, `Chainguard` and `Bitnami`. OSV
itself is case-**sensitive** (`pypi` is rejected outright); pocmap normalizes common
spellings and aliases first, so `pypi`, `cargo`, `golang`, `composer` and `debian:12` all
resolve. A release qualifier is preserved: `alpine:v3.19` -> `Alpine:v3.19`.

### Reading the results

**Ranking is by exploitation risk, not CVSS.** Results are ordered CISA KEV first, then
EPSS, then CVSS — the top row is what is actually being exploited, which is often not the
highest-scoring entry. EPSS and KEV come from bulk catalogues pocmap already caches, so
enriching a 100-advisory result costs two cached downloads, not 100 API calls.

**Several `Fixed in` versions is normal.** Maintainers backport a fix to each supported
branch, so log4j-core is fixed in `2.3.1`, `2.12.2` *and* `2.15.0`. Take the one on your
own major version.

**An empty result is not proof of safety.** OSV returns an empty body both for a package
it has never heard of and for one with no known issues, so the two are indistinguishable
— check the spelling first. This matters most for Maven, where the name must be the full
`groupId:artifactId`; a bare `log4j-core` matches nothing and looks clean.

**Counts describe different things.** `total_found` is how many advisories were found;
`returned`/`truncated` describe what `--limit` left. `--fixable-only` never reports a
package as clean — if it empties the list, the output says how many were filtered out.

**`no fix published` means exactly that** — the advisory is real and there is no upgrade
to take, so it needs a workaround or a risk decision rather than a version bump.

**Severity source.** A CVSS 3.x vector is scored locally to a base score. CVSS 4.0 scores
via a lookup table that pocmap does not implement, so a 4.0-only advisory shows `-` for
CVSS and falls back to the publisher's own rating rather than a plausible-but-wrong number.

## Output Formats & Exit Codes

Read commands emit machine-readable output via `--format/-f`. `--format` and `--quiet/-q`
can be set globally (before the command) or per command (the local value wins).

```bash
pocmap lookup CVE-2021-44228 --format json      # structured view model to stdout
pocmap latest --since 7d --format csv           # spreadsheet-ready rows
pocmap discover "Log4j" --format md             # Markdown table for tickets/wikis
pocmap latest --since 24h --format sarif        # SARIF 2.1.0 for code scanning
pocmap -f json latest --since 7d                # global form
```

| Format | Value | Notes |
|--------|-------|-------|
| Table | `table` | Default. Rich colorized tables (human-facing). |
| JSON | `json` | JSON-serializable view model to stdout, nothing else. |
| CSV | `csv` | One row per record (`csv.DictReader`-friendly). |
| Markdown | `md` | A Markdown table for tickets/wikis. |
| SARIF | `sarif` | SARIF 2.1.0 log for CI code scanning. |

**Format support by command:**
- `lookup`, `doctor`, `cache info`, `cache clear`: `table`, `json`
- `labs`, `bugbounty`, `cpes`, `cpe2cve`: `table`, `json`, `csv`, `md`
- `latest`, `discover`: `table`, `json`, `csv`, `md`, `sarif`
- `bulk`: `table` (writes JSON + HTML files), `json`, `csv`, `sarif`

SARIF results are keyed on CVE IDs, so it is available only on the CVE-list commands
(`latest`, `discover`, `bulk`). Requesting `--format sarif` on any other command exits
`4` (invalid input) with a clear message. Severity maps to SARIF levels as
`critical`/`high` -> `error`, `medium` -> `warning`, `low` -> `note`; EPSS, KEV, exploit
count, and CVSS ride along in `result.properties`, and each CVE's NVD page is the rule `helpUri`.

### Exit-Code Contract

Every command returns a stable, documented exit code (see `src/pocmap/utils/exit_codes.py`)
so scripts and CI can react to *why* a command stopped, not just whether it succeeded:

| Code | Name | Meaning |
|------|------|---------|
| `0` | `OK` | Success — the command ran and produced output. |
| `1` | `ERROR` | Generic / unclassified error. |
| `2` | `NO_RESULTS` | Ran fine but found nothing (empty result set). |
| `3` | `NOT_FOUND` | Requested resource does not exist upstream (e.g. unknown CVE). |
| `4` | `INVALID_INPUT` | Caller input was malformed (bad CVE ID, unsafe path, bad `--fail-on`). |
| `5` | `UPSTREAM_ERROR` | An upstream data source failed (network, rate limit, 5xx, offline cache miss). |
| `6` | `POLICY_FAIL` | A `bulk --fail-on` policy condition matched (the CI gate tripped). |

These values are a public contract: existing codes are never renumbered.

## Caching & Offline Mode

PocMap keeps a **persistent, TTL'd HTTP response cache** on disk. The default is the
platform user cache directory (`%LOCALAPPDATA%\pocmap\Cache` on Windows,
`$XDG_CACHE_HOME/pocmap` or `~/.cache/pocmap` elsewhere); a source checkout uses
`<repo>/.cache` so development is self-contained. Override with `POCMAP_CACHE_DIR`.
This turns network-bound calls into sub-second cached ones, dodges GitHub/NVD rate
limits, and backs a real offline mode. Non-200 and error responses are never cached.

```bash
# Warm the cache with a normal (online) run, then work entirely offline
pocmap lookup CVE-2021-44228
pocmap --offline lookup CVE-2021-44228     # served from cache, zero network I/O

# Inspect / clear the cache
pocmap cache info                          # location, entry count, on-disk size
pocmap cache clear                         # delete every cached entry
```

In `--offline` mode (or with `POCMAP_OFFLINE=1`) HTTP GETs are served only from the
cache; a cache miss surfaces a clear offline error and exits `5` (`UPSTREAM_ERROR`)
rather than masquerading as "not found" or "no results". An **expired**-but-cached
entry is served **stale** offline (an air-gapped run cannot refresh it, so stale
data beats an error) — only a genuinely absent entry raises. Online runs are
unaffected: they still honour the TTL and refetch expired entries.

**Cache / offline configuration:**

| Variable | Default | Description |
|----------|---------|-------------|
| `POCMAP_CACHE_ENABLED` | `true` | Enable/disable the persistent HTTP cache. |
| `POCMAP_CACHE_DIR` | platform user cache | Directory for cached responses. `%LOCALAPPDATA%\pocmap\Cache` on Windows, `$XDG_CACHE_HOME/pocmap` (or `~/.cache/pocmap`) elsewhere; a source checkout uses `<repo>/.cache`. |
| `POCMAP_CACHE_TTL` | `3600` | Seconds a cached entry stays fresh. |
| `POCMAP_CACHE_MAX_MB` | `200` | On-disk cache cap (MB) before LRU eviction. |
| `POCMAP_OFFLINE` | `false` | Serve only from cache; a miss errors instead of hitting the network. |

## Diagnostics: doctor and cache

`pocmap doctor` is the fastest path from "installed" to "working". It checks the Python
version, the optional `[server]` extra, the *format* of your `GITHUB_API_TOKEN` /
`NVD_API_KEY` (never printing their values), that the cache directory is writable, and
runs a live connectivity probe against NVD and the GitHub API. It prints a PASS/WARN/FAIL
table and **exits nonzero if any check FAILs**.

```bash
pocmap doctor                  # full run with a live connectivity probe
pocmap doctor --offline        # skip the network probe (labelled SKIPPED)
pocmap doctor --format json    # machine-readable check results
```

`pocmap cache info|clear` reports and clears the response cache (see above).

## PocMap in CI

`bulk` is a composable CI gate. Point it at a CVE list (a file, or `-` to read stdin),
choose a machine format, and use `--fail-on` to fail the build on a policy match:

```bash
# Fail the build (exit 6) if any dependency CVE is in the CISA KEV catalog,
# and write a SARIF log for GitHub code scanning.
pocmap bulk cves.txt --format sarif --fail-on kev > out/pocmap.sarif

# Pipe CVE IDs straight from another tool
grep -oE 'CVE-[0-9]{4}-[0-9]+' sbom.txt | pocmap bulk - --format json --fail-on critical
```

`--fail-on` accepts `critical`, `high` (HIGH *or worse*), `kev`, or `epss>=N` (e.g.
`epss>=50` on the 0-100 EPSS scale). A match exits `6` (`POLICY_FAIL`) — distinct from a
generic error — so CI can tell a tripped gate apart from an operational failure; no match
exits `0`. A malformed `--fail-on` exits `4`. In `table` mode `bulk` preserves its
historical behaviour (writes a JSON **and** an HTML report to `--output`); the machine
formats (`json`/`csv`/`sarif`) emit a clean stdout summary and write no files, so the
stream stays parseable.

See [`examples/ci-github-actions.yml`](https://github.com/zebbern/pocmap/blob/main/examples/ci-github-actions.yml) for a ready-to-use
GitHub Actions job that runs the gate and uploads the SARIF to code scanning, and the
[`examples/`](https://github.com/zebbern/pocmap/tree/main/examples) directory for more runnable scripts.
