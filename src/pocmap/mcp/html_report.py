"""Self-contained HTML vulnerability report helpers (XSS-hardened)."""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any
from urllib.parse import urlparse


def _safe_url(url: str) -> str:
    """Return *url* only when it is an ``http(s)`` URL, else ``"#"``.

    Blocks ``javascript:``/``data:`` and other click-to-execute schemes from
    ever reaching an ``href`` in the generated HTML report. A malformed URL
    (e.g. an unbalanced IPv6 bracket ``http://[oops``) makes ``urlparse`` raise
    ``ValueError``; that degrades to ``"#"`` rather than crashing the report.
    """
    try:
        return url if urlparse(url).scheme in ("http", "https") else "#"
    except ValueError:
        return "#"


def _build_html_report(
    entries: list[dict[str, Any]],
    errors: list[dict[str, str]],
    cve_ids: list[str],
    now: datetime,
) -> str:
    """Assemble the self-contained HTML vulnerability report.

    Every externally-sourced value is ``html.escape``-d, and every ``href`` is
    routed through :func:`_safe_url`, so attacker-controlled CVE descriptions,
    repo names, or URLs cannot inject markup, scripts, or ``javascript:`` links.
    """
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '  <meta charset="UTF-8">',
        '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
        "  <title>PocMap Vulnerability Report</title>",
        "  <style>",
        "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2em; background: #f5f5f5; }",
        "    .container { max-width: 1200px; margin: 0 auto; }",
        "    h1 { color: #d32f2f; border-bottom: 2px solid #d32f2f; padding-bottom: 0.3em; }",
        "    .entry { background: white; border-radius: 8px; padding: 1.5em; margin-bottom: 1.5em; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }",
        "    .cve-header { background: #fff3f3; border-left: 4px solid #d32f2f; padding: 1em; margin-bottom: 1em; }",
        "    .cve-id { font-size: 1.5em; font-weight: bold; color: #d32f2f; }",
        "    .severity-CRITICAL { color: #d32f2f; font-weight: bold; }",
        "    .severity-HIGH { color: #f57c00; font-weight: bold; }",
        "    .severity-MEDIUM { color: #fbc02d; font-weight: bold; }",
        "    .severity-LOW { color: #388e3c; font-weight: bold; }",
        "    .section { margin-top: 1em; }",
        "    .section h3 { color: #333; border-bottom: 1px solid #ddd; padding-bottom: 0.2em; }",
        "    .exploit-item { background: #f9f9f9; padding: 0.8em; margin: 0.5em 0; border-radius: 4px; }",
        "    .source-badge { display: inline-block; padding: 0.2em 0.6em; border-radius: 4px; font-size: 0.85em; font-weight: bold; margin-right: 0.5em; }",
        "    .source-github { background: #333; color: white; }",
        "    .source-metasploit { background: #1565c0; color: white; }",
        "    .source-exploitdb { background: #d32f2f; color: white; }",
        "    .source-nuclei { background: #e65100; color: white; }",
        "    .metadata { color: #666; font-size: 0.9em; }",
        "    a { color: #1565c0; text-decoration: none; }",
        "    a:hover { text-decoration: underline; }",
        "    .score-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1em; margin: 1em 0; }",
        "    .score-card { background: #fafafa; padding: 1em; border-radius: 4px; text-align: center; }",
        "    .score-value { font-size: 1.5em; font-weight: bold; }",
        "    .poc-badge { background: #4caf50; color: white; padding: 0.1em 0.4em; border-radius: 3px; font-size: 0.8em; }",
        "    .lab-box { background: #e3f2fd; padding: 0.5em 1em; border-radius: 4px; margin: 0.3em 0; }",
        "    .source-status-list { list-style: none; padding: 0; margin: 0.5em 0; }",
        "    .source-status-list li { padding: 0.35em 0; color: #444; font-size: 0.95em; }",
        "    .source-status { font-weight: bold; }",
        "    .source-status-ok { color: #2e7d32; }",
        "    .source-status-empty { color: #616161; }",
        "    .source-status-rate_limited { color: #ef6c00; }",
        "    .source-status-error { color: #c62828; }",
        "  </style>",
        "</head>",
        "<body>",
        '  <div class="container">',
        "    <h1>PocMap Vulnerability Report</h1>",
        f"    <p class=\"metadata\">Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}</p>",
        f"    <p class=\"metadata\">Total CVEs: {len(cve_ids)} | Successful: {len(entries)} | Errors: {len(errors)}</p>",
    ]

    for entry in entries:
        cve = entry["cve_info"]
        cvss = cve.get("cvss", {})
        sev = html.escape((cvss.get("severity") or "UNKNOWN").upper())
        parts.append('    <div class="entry">')
        parts.append('      <div class="cve-header">')
        parts.append(f'        <div class="cve-id">{html.escape(str(cve.get("id", "N/A")))}</div>')
        parts.append(f'        <p>{html.escape(str(cve.get("description", "No description")))}</p>')
        parts.append('      </div>')

        # Score grid
        parts.append('      <div class="score-grid">')
        if cvss.get("score") is not None:
            parts.append('        <div class="score-card">')
            parts.append(f'          <div>CVSS v{html.escape(str(cvss.get("version", "?")))}</div>')
            parts.append(
                f'          <div class="score-value severity-{sev}">'
                f'{html.escape(str(cvss["score"]))}</div>'
            )
            parts.append(f'          <div class="severity-{sev}">{sev}</div>')
            parts.append('        </div>')
        epss = cve.get("epss_score")
        if epss is not None:
            parts.append('        <div class="score-card">')
            parts.append('          <div>EPSS</div>')
            parts.append(f'          <div class="score-value">{epss:.4f}</div>')
            parts.append('        </div>')
        parts.append('        <div class="score-card">')
        parts.append('          <div>KEV Status</div>')
        kev = "IN KEV" if cve.get("kev_status") else "Not in KEV"
        parts.append(f'          <div class="score-value">{kev}</div>')
        parts.append('        </div>')
        parts.append('      </div>')

        # Exploits
        if entry["exploits"]:
            parts.append('      <div class="section">')
            parts.append(f'        <h3>Exploits & PoCs ({len(entry["exploits"])})</h3>')
            for ex in entry["exploits"]:
                src = html.escape(str(ex.get("source", "unknown")).lower())
                parts.append('        <div class="exploit-item">')
                parts.append(
                    f'          <span class="source-badge source-{src}">{src.upper()}</span>'
                )
                parts.append(f'          <strong>{html.escape(str(ex.get("title", "Untitled")))}</strong>')
                if ex.get("language"):
                    parts.append(
                        f'          <span class="metadata"> | {html.escape(str(ex["language"]))}</span>'
                    )
                if ex.get("stars"):
                    parts.append(
                        f'          <span class="metadata"> | Stars: {html.escape(str(ex["stars"]))}</span>'
                    )
                href = html.escape(_safe_url(ex.get("url", "#")))
                parts.append(
                    f'          <br><a href="{href}" target="_blank">'
                    f'{html.escape(str(ex.get("url", "")))}</a>'
                )
                parts.append('        </div>')
            parts.append('      </div>')

        # Per-source fetch status — empty ≠ rate-limited ≠ error (no silent miss).
        sources = entry.get("sources") or []
        if sources:
            parts.append('      <div class="section">')
            parts.append('        <h3>Source Status</h3>')
            parts.append('        <ul class="source-status-list">')
            for src in sources:
                name = html.escape(str(src.get("source", "?")))
                status = html.escape(str(src.get("status", "?")))
                count = src.get("count")
                count_s = f" · count {html.escape(str(count))}" if count is not None else ""
                detail = src.get("detail")
                detail_s = f" — {html.escape(str(detail))}" if detail else ""
                parts.append(
                    f'          <li><span class="source-status source-status-{status}">'
                    f"{name}: {status}</span>{count_s}{detail_s}</li>"
                )
            parts.append("        </ul>")
            parts.append("      </div>")

        # Labs
        if entry["labs"]:
            parts.append('      <div class="section">')
            parts.append(f'        <h3>Practice Labs ({len(entry["labs"])})</h3>')
            for lab in entry["labs"]:
                platform = html.escape(str(lab.get("platform", "?")).upper())
                href = html.escape(_safe_url(lab.get("url", "#")))
                name = html.escape(str(lab.get("name", "Unknown")))
                parts.append(
                    f'        <div class="lab-box"><strong>[{platform}]</strong> '
                    f'<a href="{href}">{name}</a></div>'
                )
            parts.append('      </div>')

        # BB Reports
        if entry["bb_reports"]:
            parts.append('      <div class="section">')
            parts.append(f'        <h3>Bug Bounty Reports ({len(entry["bb_reports"])})</h3>')
            for r in entry["bb_reports"]:
                poc = ' <span class="poc-badge">PoC</span>' if r.get("has_poc") else ""
                source = html.escape(str(r.get("source", "?")).upper())
                href = html.escape(_safe_url(r.get("url", "#")))
                title = html.escape(str(r.get("title", "Untitled")))
                parts.append(
                    f'        <p><strong>[{source}]</strong>{poc} '
                    f'<a href="{href}">{title}</a></p>'
                )
            parts.append('      </div>')

        parts.append('    </div>')

    # Errors section
    if errors:
        parts.append('    <div class="entry" style="background: #fff8e1; border-left: 4px solid #f57c00;">')
        parts.append(f'      <h3>Errors ({len(errors)})</h3>')
        parts.append('      <p class="metadata">The following CVEs could not be processed:</p>')
        parts.append('      <ul>')
        for err in errors:
            cve_id = html.escape(str(err["cve_id"]))
            msg = html.escape(str(err["error"]))
            parts.append(f'        <li><strong>{cve_id}</strong>: {msg}</li>')
        parts.append('      </ul>')
        parts.append('    </div>')

    parts.extend(["  </div>", "</body>", "</html>"])
    return "\n".join(parts)

