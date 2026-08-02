# Verifying PoCs (opt-in)

The CVE indexes list repositories that *mention* a CVE, which is not the same as
repositories that exploit it — link lists, course notes and personal repos all show up.
Star count does not separate them either: a popular repo can be an index, and a genuine
one-file PoC often has zero stars.

`verify_github_pocs` downloads the top PoCs' **source** and reports what each actually
contains:

| Verdict | Meaning |
|---------|---------|
| `confirmed` | Names the CVE **in code** and ships runnable code. The only tier that claims the repo exploits the CVE. |
| `likely` | Names the CVE but has no code — a writeup. |
| `unverified` | Has code, but never names this CVE. Unproven, *not* disproven: a PoC may be named for its target instead. |
| `unrelated` | No mention, or an index — a link list, notes repo or scan dump. |

It also derives the language from file extensions, so it needs **zero** GitHub API calls.

The index test is *how many distinct CVEs the repository cites*, not how many files it
has: a PoC or a writeup is about one vulnerability, while a link list cites dozens.
Across a 55-repository sample, genuine PoCs cited at most 3 distinct CVEs and the
indexes cited 10, 22 and 118 — so the boundary sits in a wide empty gap. Citing many
CVEs only counts against a repo that also ships essentially no code, so a multi-CVE
exploit toolkit is not mistaken for a list.

```bash
export POCMAP_ALLOW_FETCH_POC_SOURCE=1     # CLI / Python API
```

> **Using the MCP server? `export` will not work.** MCP clients launch the server with a
> filtered environment — the stdio transport inherits only `HOME`, `LOGNAME`, `PATH`,
> `SHELL`, `TERM` and `USER` — so **no `POCMAP_*` variable set in your shell reaches the
> server**, and `verify_github_pocs` will keep returning `not_enabled`. Put it in your
> client config's `env` block instead (this applies to `GITHUB_API_TOKEN` and
> `NVD_API_KEY` too):
>
> ```json
> {
>   "mcpServers": {
>     "pocmap": {
>       "command": "uvx",
>       "args": ["--from", "pocmap[server]", "pocmap-mcp"],
>       "env": {
>         "POCMAP_ALLOW_FETCH_POC_SOURCE": "1",
>         "POCMAP_POC_SOURCE_DIR": "/home/you/.local/share/pocmap/poc-source",
>         "GITHUB_API_TOKEN": "ghp_xxxxxxxxxxxx"
>       }
>     }
>   }
> }
> ```

**This is off by default and must be set deliberately.** It writes third-party exploit
code to disk, which endpoint protection will often quarantine — run it on an isolated VM
or a dedicated research host. pocmap never executes, imports, or evaluates fetched
content; it only reads bytes.

The fetcher is bounded and hardened: owner/repo names are validated before they reach the
URL, transfers go through the same SSRF-guarded HTTP client as everything else (per-hop
redirect re-validation included), downloads and *extracted* sizes are both capped so a
decompression bomb cannot fill the disk, and archive members that are absolute, contain
`..`, or are symlinks/devices are dropped rather than extracted.

| Variable | Default | Description |
|----------|---------|-------------|
| `POCMAP_ALLOW_FETCH_POC_SOURCE` | `false` | Master switch. Nothing is fetched unless this is set. |
| `POCMAP_POC_SOURCE_DIR` | `<cache_dir>/poc-source` | Extraction root. |
| `POCMAP_POC_SOURCE_MAX_MB` | `100` | Per-repo cap on download and extracted size. |
| `POCMAP_POC_SOURCE_TOTAL_MAX_MB` | `1000` | Total cap; oldest fetched repos are evicted first. |

Offline mode has nothing to serve here — tarballs deliberately bypass the HTTP response
cache — so `--offline` reports that plainly instead of failing obscurely.

### Where to point `POCMAP_POC_SOURCE_DIR`

The default sits under the response cache, which is convenient but is *not* the right
place on every machine. Two things decide it: whether an on-access scanner will quarantine
the files, and whether the directory is synced anywhere.

**Windows.** Defender scans NTFS on access and will quarantine exploit source, which both
interrupts the fetch and silently corrupts any scoring that reads the files back. Either
put the directory inside WSL2 — its ext4 lives in a VHDX that Defender does not
real-time scan the way it does NTFS — or add a Defender exclusion for a dedicated path:

```powershell
# Option A: run pocmap inside WSL2 and keep the source there
#   (from your WSL shell)
export POCMAP_POC_SOURCE_DIR="$HOME/.local/share/pocmap/poc-source"

# Option B: stay on Windows and exclude one dedicated directory (admin PowerShell)
New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\pocmap\poc-source"
Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\pocmap\poc-source"
$env:POCMAP_POC_SOURCE_DIR = "$env:LOCALAPPDATA\pocmap\poc-source"
```

Exclude the narrowest path that works — one directory used only for this — never your
home directory or the whole repo.

**Linux / macOS.** No on-access scanner by default, so a per-user cache path is fine:

```bash
export POCMAP_POC_SOURCE_DIR="$HOME/.cache/pocmap/poc-source"
```

**VM or dedicated research host.** Anywhere. This is the intended environment and needs
no special handling.

**Do not point it at a synced or shared folder.** OneDrive, Dropbox, iCloud Drive and
Google Drive will upload the exploit source to cloud storage, where the provider's own
scanner may flag the account and the content may be shared further than intended. This is
easy to hit by accident on Windows, where `Documents` is frequently redirected to
OneDrive — so a repo cloned there gets a OneDrive-synced `.cache/` with it. Prefer
`%LOCALAPPDATA%` (never synced) over anything under `Documents`.

The same reasoning applies to `POCMAP_CACHE_DIR`, though it holds only API responses
rather than exploit code, so it is far less sensitive.
