"""
Encoding regression tests for the bugbounty package file I/O.

These guard against the Windows cp1252-vs-UTF-8 bug: text-mode ``open()`` without
an explicit ``encoding=`` uses the platform default (cp1252 on the primary dev/CI
platform), which raises ``UnicodeEncodeError`` or writes mojibake for the non-ASCII
characters common in CVE text (em-dashes, curly quotes, accented vendor names,
check marks). Every writer/reader in the package now pins ``encoding="utf-8"`` so
this text round-trips intact regardless of the host's locale.

Offline and unmarked: runs in the default ``pytest`` suite.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pocmap.bugbounty.prioritization import export_prioritized_list
from pocmap.bugbounty.templates import HackerOneTemplate

# A mix of non-ASCII: em-dash, curly quotes, accented letters, and a code point
# (U+2713 CHECK MARK) that is NOT representable in cp1252 — so a default-encoding
# write on Windows raises UnicodeEncodeError, proving the fix is load-bearing.
NON_ASCII = "Café — “RCE” achieved ✓ 日本"


def test_hackerone_render_to_file_roundtrips_non_ascii(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """render_to_file() must write UTF-8 so non-ASCII survives a UTF-8 read-back."""
    # render_to_file() runs paths through safe_path() (base_dir=cwd), so operate
    # from within tmp_path and use a relative filename.
    monkeypatch.chdir(tmp_path)

    template = HackerOneTemplate()
    template.render_to_file(
        "report.md",
        cve_id="CVE-2021-44228",
        executive_summary=NON_ASCII,
        impact_description=NON_ASCII,
    )

    content = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert NON_ASCII in content


def test_export_prioritized_list_markdown_roundtrips_non_ascii(tmp_path: Path) -> None:
    """export_prioritized_list() (markdown) must write UTF-8 cleanly."""
    out = tmp_path / "prioritized.md"

    cves = [
        {
            "id": "CVE-2021-44228",
            # Non-ASCII rides through the rendered markdown table via the
            # severity column.
            "severity": NON_ASCII,
            "cvss_score": 10.0,
            "epss": 0.97,
            "kev": True,
            "priority_score": 99.9,
        }
    ]

    export_prioritized_list(cves, str(out), format="markdown")

    content = out.read_text(encoding="utf-8")
    assert NON_ASCII in content
