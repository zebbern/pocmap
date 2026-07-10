#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# examples/daily-brief.sh
#
# A daily threat brief: recently published CRITICAL / HIGH CVEs, showing only
# what CHANGED since the last identical run (new CVEs, plus severity / KEV /
# EPSS movements). Great for a cron job, a login shell, or a Slack post.
#
# `--diff` (alias `--since-last`) persists a per-query snapshot under the cache
# dir and reports the delta against the previous run — pure local computation.
# The first run has no baseline, so it records one and reports everything as new.
#
# Usage:
#   ./daily-brief.sh                 # critical + high, last 24h, table output
#   FORMAT=md ./daily-brief.sh       # Markdown table (paste into a ticket/wiki)
#   SINCE=7d SEV=critical ./daily-brief.sh
# -----------------------------------------------------------------------------
set -euo pipefail

SINCE="${SINCE:-24h}"
SEV="${SEV:-critical,high}"
FORMAT="${FORMAT:-table}"

# Note: `--diff` always exits 0 (it succeeded in computing the delta), so this
# is safe under `set -e`.
pocmap latest \
  --since "$SINCE" \
  --severity "$SEV" \
  --diff \
  --format "$FORMAT"
