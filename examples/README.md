# PocMap Examples

Runnable, copy-paste examples for the most common PocMap workflows. Every command
here matches the real CLI (`pocmap --help`); see the main
[README](../README.md) for the full reference.

> Install first (PocMap is not yet on PyPI):
> ```bash
> git clone https://github.com/zebbern/pocmap.git && cd pocmap && pip install -e .
> ```
> Once published, `pip install pocmap` (or `pipx install pocmap`) will also work.

| File | What it shows |
|------|---------------|
| [`ci-github-actions.yml`](ci-github-actions.yml) | A consumer GitHub Actions job that runs `pocmap bulk` as a CI gate: emits **SARIF 2.1.0**, uploads it to GitHub code scanning, and fails the build (`--fail-on kev`) when a CISA KEV CVE is present. |
| [`daily-brief.sh`](daily-brief.sh) | A daily threat brief: recent critical/high CVEs, showing only what changed since the last run (`latest --since 24h --diff`). |
| [`lookup-json.sh`](lookup-json.sh) | Machine-readable single-CVE lookup piped through `jq` (`lookup --format json`). |
| [`mcp-config.json`](mcp-config.json) | A ready Claude Desktop / MCP client config that launches the PocMap MCP server (`python mcp_server.py`). |

## Quick reference

```bash
# Machine-readable output on any read command
pocmap lookup CVE-2021-44228 --format json
pocmap latest --since 7d --format csv
pocmap discover "Apache Struts" --format sarif   # CVE-list commands only

# CI gate: exit 6 (POLICY_FAIL) if any CVE is in CISA KEV
pocmap bulk cves.txt --format sarif --fail-on kev

# Offline / cached runs
pocmap --offline lookup CVE-2021-44228
pocmap cache info
pocmap doctor
```

Exit codes: `0` OK, `1` ERROR, `2` NO_RESULTS, `3` NOT_FOUND, `4` INVALID_INPUT,
`5` UPSTREAM_ERROR, `6` POLICY_FAIL. See the
[exit-code contract](../README.md#output-formats--exit-codes) for details.
