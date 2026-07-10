#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# examples/lookup-json.sh
#
# Machine-readable single-CVE lookup. `pocmap lookup --format json` emits a
# structured view model to stdout (and nothing else — no banner, no spinners),
# so it pipes cleanly into `jq` and other tools.
#
# JSON shape:
#   {
#     "cve":         { "id", "description", "cvss": {"base_score","severity",...},
#                      "epss", "kev_status", "cwes", "vendor", "product", ... },
#     "github_pocs": [ { "source", "url", "title", "language", "stars", ... } ],
#     "db_exploits": [ ... ],   # metasploit / exploitdb / nuclei
#     "labs":        [ ... ]    # vulhub / hackthebox / tryhackme
#   }
#
# Usage:
#   ./lookup-json.sh                 # defaults to CVE-2021-44228
#   ./lookup-json.sh CVE-2023-38408
#
# Requires: jq (https://jqlang.github.io/jq/)
# -----------------------------------------------------------------------------
set -euo pipefail

CVE="${1:-CVE-2021-44228}"

# Full JSON document (pretty-printed by pocmap already):
pocmap lookup "$CVE" --format json > /tmp/pocmap-lookup.json

echo "== Summary =="
jq -r '
  "CVE:      \(.cve.id)",
  "Severity: \(.cve.cvss.severity // "UNKNOWN") (\(.cve.cvss.base_score // "n/a"))",
  "EPSS:     \(.cve.epss // "n/a")",
  "KEV:      \(.cve.kev_status)",
  "Vendor:   \(.cve.vendor // "n/a") / \(.cve.product // "n/a")"
' /tmp/pocmap-lookup.json

echo
echo "== Top GitHub PoCs =="
# Highest-starred first, top 5, as "stars  url".
jq -r '.github_pocs | sort_by(-(.stars // 0)) | .[:5][] | "\(.stars // 0)\t\(.url)"' \
  /tmp/pocmap-lookup.json

# One-liners you can reuse:
#   pocmap lookup CVE-2021-44228 -f json | jq '.cve.cvss.base_score'
#   pocmap lookup CVE-2021-44228 -f json | jq -r '.github_pocs[].url'
