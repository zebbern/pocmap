# PocMap CLI Commands

Verified against `src/pocmap/cli.py`. There are **13 commands** (12 top-level plus the
`cache` sub-app with `info`/`clear`). Each takes a positional argument or options as
shown. `python -m pocmap --help` is authoritative.

Most commands hit **live external APIs** (NVD, CVE.org, CISA KEV, EPSS, GitHub,
ExploitDB, Nuclei, Vulhub, HackerOne, PentesterLand) — expect network latency and
rate limits.

**Global options** (on `pocmap` itself, before the command): `--format`/`-f`
`{table,json,csv,md,sarif}`, `--offline`, `--quiet`/`-q`, `--version`/`-v`. Read
commands also accept `--format`/`-f` and `--quiet`/`-q` locally (the local value wins).

---

## `pocmap lookup <cve>`
Look up a single CVE and show its info plus discovered PoCs.

| Flag | Description |
|------|-------------|
| `-d`, `--description` | Show the CVE description |
| `-l`, `--language <lang>` | Filter PoCs by programming language |
| `--limit <n>` | Max PoCs to display (default 10) |
| `--no-banner` | Suppress the ASCII banner |

```bash
pocmap lookup CVE-2021-44228 --description --limit 5
```

## `pocmap latest`
Find recently published CVEs with exploit intelligence.

| Flag | Description |
|------|-------------|
| `--since <1h\|24h\|7d\|30d>` | Relative time window |
| `--from <YYYY-MM-DD>` / `--to <YYYY-MM-DD>` | Explicit date range |
| `--only-with-poc` | Only CVEs with known PoCs |
| `--kev-only` | Only CISA KEV entries |
| `--min-epss <0-100>` | Minimum EPSS score (0–100 scale) |
| `--severity <critical,high,medium,low>` | Comma-separated severities |
| `--sort <cve_date\|severity\|epss>` | Sort field (default `cve_date`) |
| `--limit <n>` | Max results (default 50, max 100) |
| `-o`, `--output <file>` | Save JSON report to file |
| `--diff`, `--since-last` | Show only what changed since the last identical run |
| `--notify <url>` | POST a summary of notable CVEs (critical/high or KEV) to a webhook; with `--diff`, only the delta is sent |
| `-f`, `--format <table\|json\|csv\|md\|sarif>` | Output format (default `table`) |
| `-q`, `--quiet` | Suppress decorative output |

```bash
pocmap latest --since 24h --severity critical --kev-only
pocmap latest --since 7d --format sarif --diff
```

## `pocmap discover <product>`
Discover CVEs affecting a product by name/version. Supports aliases and `2.x` wildcards.
Results are grouped into confirmed / possibly-affected / not-enough-data.

| Flag | Description |
|------|-------------|
| `-v`, `--version <ver>` | Version filter (`2.x`, `2.14.1`, `v2.14.1`) |
| `--vendor <name>` | Vendor for disambiguation |
| `--limit <n>` | Max CVEs to analyze (default 50, max 100) |
| `-o`, `--output <file>` | Save JSON report to file |
| `--diff`, `--since-last` | Show only what changed since the last identical run |
| `--notify <url>` | POST a summary of notable CVEs (critical/high or KEV) to a webhook; with `--diff`, only the delta is sent |
| `-f`, `--format <table\|json\|csv\|md\|sarif>` | Output format (default `table`) |
| `-q`, `--quiet` | Suppress decorative output |

```bash
pocmap discover "Apache Struts" --version 2.x
```

## `pocmap package <ecosystem> <name>`
Find vulnerabilities in a **dependency** and the releases that fix them (OSV.dev; no API
key, not bound by NVD rate limits). Use for lockfiles/SBOMs. This is the only command that
returns fixed versions; it cannot answer questions about deployed products like nginx or
Confluence — use `pocmap discover` for those.

| Flag | Description |
|------|-------------|
| `-v`, `--version <ver>` | Installed version, e.g. `3.2.0`. Strongly recommended — OSV then returns only advisories that actually apply |
| `--fixable-only` | Only advisories with a published fix (applied after ranking + `--limit`) |
| `--limit <n>` | Max advisories (default 100, max 1000), taken from the top of the risk ranking |
| `-o`, `--output <file>` | Save JSON report to file |
| `-f`, `--format <table\|json\|csv\|md\|sarif>` | Output format (default `table`) |
| `-q`, `--quiet` | Suppress decorative output |

Ecosystems are case-insensitive here and normalized (`pypi` -> `PyPI`, `debian:12` ->
`Debian:12`). Maven needs the full `groupId:artifactId`. Ranked CISA KEV > EPSS > CVSS.
An empty result is *not* proof of safety — OSV returns the same empty body for an unknown
package as for a clean one.

```bash
pocmap package PyPI django --version 3.2.0
pocmap package Maven org.apache.logging.log4j:log4j-core --version 2.14.1
pocmap package npm lodash --version 4.17.20 --format sarif
```

## `pocmap bulk <file>`
Process multiple CVEs from a file (one ID per line); writes JSON and HTML reports.

| Flag | Description |
|------|-------------|
| `-o`, `--output <dir>` | Output directory for reports (default `.`) |
| `-t`, `--threads <n>` | Concurrent workers (default 10) |
| `-f`, `--format <table\|json\|csv\|sarif>` | Output format (`table` writes JSON+HTML files; machine formats emit stdout) |
| `--fail-on <critical\|high\|kev\|epss>=N>` | CI gate: exit `6` (POLICY_FAIL) if any CVE matches |

Read CVE IDs from stdin with `-` as the file argument.

```bash
pocmap bulk cves.txt --output ./reports
pocmap bulk - --format sarif --fail-on kev      # CI gate, IDs piped on stdin
```

## `pocmap labs <cve>`
Search for CTF labs / vulnerable environments (Vulhub, HackTheBox).

```bash
pocmap labs CVE-2021-44228
```

## `pocmap bugbounty <cve>`
Search for bug bounty reports related to a CVE (HackerOne, PentesterLand, etc.).

```bash
pocmap bugbounty CVE-2021-44228
```

## `pocmap cpes <cve>`
Retrieve CPE 2.3 identifiers (affected software configurations) for a CVE.

```bash
pocmap cpes CVE-2021-44228
```

## `pocmap cpe2cve <cpe>`
Retrieve CVE IDs affecting a CPE identifier.

| Flag | Description |
|------|-------------|
| `-s`, `--save <file>` | Save the CVE list to a file |

```bash
pocmap cpe2cve "cpe:2.3:o:microsoft:windows_10:1607"
```

## `pocmap readme <github-url>`
Display a GitHub repository's README (used to inspect a PoC repo before running it).
Paged portably via `click.echo_via_pager(content)`; the global `--quiet`/`-q` flag
bypasses paging and prints directly. URL must start with `https://github.com/`.

```bash
pocmap readme https://github.com/user/CVE-2021-44228-PoC
```

## `pocmap schemas`
Export JSON schemas for all data models (useful for AI-agent tool definitions).

| Flag | Description |
|------|-------------|
| `-o`, `--output <dir>` | Output directory (default `./schemas`) |

```bash
pocmap schemas --output ./schemas
```

## `pocmap doctor`
Run self-diagnostics: Python version, the `[server]` extra, `GITHUB_API_TOKEN` /
`NVD_API_KEY` *format* (never their values), cache-dir writability, and a live NVD +
GitHub connectivity probe. Prints a PASS/WARN/FAIL table and exits nonzero if any check
FAILs (`UPSTREAM_ERROR` if only connectivity failed, else `ERROR`).

| Flag | Description |
|------|-------------|
| `--offline` | Skip the live connectivity probe (labelled SKIPPED) |
| `-f`, `--format <table\|json>` | Output format (default `table`) |

```bash
pocmap doctor
pocmap doctor --offline --format json
```

## `pocmap cache info` / `pocmap cache clear`
Inspect and clear the persistent HTTP response cache (`cache` is a sub-app).
`info` reports location, entry count, and on-disk size; `clear` deletes every entry.

| Flag | Description |
|------|-------------|
| `-f`, `--format <table\|json>` | Output format (default `table`) |

```bash
pocmap cache info
pocmap cache clear
```

---

## Not real commands
Older docs referenced `pocmap report`, `pocmap checklist`, and `pocmap workflow`.
These do **not** exist in `cli.py`. Use `bulk` for reports; checklist/workflow/
playbook content is exposed via the MCP playbook tools and the `pocmap.bugbounty`
toolkit, not CLI commands.
