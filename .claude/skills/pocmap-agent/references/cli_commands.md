# PocMap CLI Commands

Verified against `src/pocmap/cli.py`. There are **10 commands**. Each takes a
positional argument or options as shown. `python -m pocmap --help` is authoritative.

Most commands hit **live external APIs** (NVD, CVE.org, CISA KEV, EPSS, GitHub,
ExploitDB, Nuclei, Vulhub, HackerOne, PentesterLand) — expect network latency and
rate limits.

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

```bash
pocmap latest --since 24h --severity critical --kev-only
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

```bash
pocmap discover "Apache Struts" --version 2.x
```

## `pocmap bulk <file>`
Process multiple CVEs from a file (one ID per line); writes JSON and HTML reports.

| Flag | Description |
|------|-------------|
| `-o`, `--output <dir>` | Output directory for reports (default `.`) |
| `-t`, `--threads <n>` | Concurrent workers (default 10) |

```bash
pocmap bulk cves.txt --output ./reports
```

## `pocmap labs <cve>`
Search for CTF labs / vulnerable environments (Vulhub, HackTheBox, TryHackMe).

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
Pipes through `less` on Linux/macOS; prints directly on Windows. URL must start with
`https://github.com/`.

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

---

## Not real commands
Older docs referenced `pocmap report`, `pocmap checklist`, and `pocmap workflow`.
These do **not** exist in `cli.py`. Use `bulk` for reports; checklist/workflow/
playbook content is exposed via the MCP playbook tools and the `pocmap.bugbounty`
toolkit, not CLI commands.
