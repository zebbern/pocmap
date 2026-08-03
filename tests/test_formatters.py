"""Native pytest tests for the Rich console formatters (offline).

Covers the ``model -> rich.table.Table`` formatters in
:mod:`pocmap.utils.formatters`. Each formatter is rendered through a
recording :class:`rich.console.Console` and the exported text / styled
segments are asserted against substrings the code actually emits.

The headline case is a regression guard for the Metasploit rank color:
``format_exploit_table`` must color an ``MSFRank.EXCELLENT`` rank with
``spring_green2`` (its entry in ``_MSF_RANK_COLORS``) rather than falling
through to the ``white`` default — the bug that ``str(Enum).lower()``
introduced on Python 3.11+/3.12.

Everything runs from in-memory pydantic fixtures; no network or disk I/O.
"""

from __future__ import annotations

from rich.console import Console

from pocmap.models import (
    BugBountyReport,
    BugBountySource,
    CVEInfo,
    Exploit,
    ExploitSource,
    LabEnvironment,
    LabPlatform,
    MSFRank,
    RecentExploitResult,
)
from pocmap.utils.formatters import (
    _MSF_RANK_COLORS,
    format_bb_table,
    format_exploit_table,
    format_lab_table,
    format_recent_cves_table,
)


def _render_text(table: object) -> str:
    """Render a Rich renderable to plain text (styles stripped)."""
    # ``force_terminal`` keeps width=200 on Windows where record mode otherwise
    # collapses to a narrow legacy console and truncates CVE / severity cells.
    console = Console(width=200, record=True, force_terminal=True)
    console.print(table)
    return console.export_text()


def _color_names_for(table: object, needle: str) -> set[str]:
    """Return the set of style color names on segments containing ``needle``."""
    console = Console(width=200)
    colors: set[str] = set()
    for segment in console.render(table):
        if needle in segment.text and segment.style and segment.style.color:
            name = segment.style.color.name
            if name is not None:
                colors.add(name)
    return colors


def test_excellent_rank_is_colored_not_white() -> None:
    """Regression: an EXCELLENT Metasploit rank renders in spring_green2, not white."""
    expected = _MSF_RANK_COLORS["excellent"]
    assert expected == "spring_green2"

    ex = Exploit(
        source=ExploitSource.METASPLOIT,
        url="https://example.test",
        title="x",
        rank=MSFRank.EXCELLENT,
    )
    table = format_exploit_table([ex])

    colors = _color_names_for(table, "excellent")
    assert expected in colors, f"expected rank cell colored {expected!r}, got {colors!r}"
    assert "white" not in colors

    # The rank value is present in the plain-text render.
    assert "excellent" in _render_text(table)


def test_exploit_table_none_fields_fall_back() -> None:
    """Missing stars/forks/language/rank render as N/A."""
    ex = Exploit(source=ExploitSource.GITHUB, url="https://example.test/repo", title="repo")
    text = _render_text(format_exploit_table([ex]))
    assert "N/A" in text
    assert "github" in text
    assert "repo" in text


def test_lab_table_renders_with_na_fallback() -> None:
    """format_lab_table renders and shows N/A for a missing name."""
    labs = [
        LabEnvironment(platform=LabPlatform.VULHUB, name=None, url="https://example.test/lab"),
        LabEnvironment(
            platform=LabPlatform.HACKTHEBOX, name="Box One", url="https://example.test/box"
        ),
    ]
    text = _render_text(format_lab_table(labs))
    assert "vulhub" in text
    assert "hackthebox" in text
    assert "Box One" in text
    assert "N/A" in text


def test_bb_table_has_poc_tristate() -> None:
    """BugBountyReport has_poc True/False/None render as Yes/No/N/A."""
    reports = [
        BugBountyReport(
            source=BugBountySource.HACKERONE, url="https://example.test/1", has_poc=True, title="a"
        ),
        BugBountyReport(
            source=BugBountySource.PENTESTERLAND,
            url="https://example.test/2",
            has_poc=False,
            title="b",
        ),
        BugBountyReport(
            source=BugBountySource.OTHER, url="https://example.test/3", has_poc=None, title=None
        ),
    ]
    text = _render_text(format_bb_table(reports))
    assert "Yes" in text
    assert "No" in text
    assert "N/A" in text
    assert "hackerone" in text


def test_recent_cves_table_renders_with_na_fallback() -> None:
    """format_recent_cves_table renders and shows N/A for missing vendor/product."""
    results = [
        RecentExploitResult(
            cve_info=CVEInfo(id="CVE-2021-44228", vendor=None, product=None),
            has_poc=False,
            poc_sources=[],
        ),
    ]
    text = _render_text(format_recent_cves_table(results))
    assert "CVE-2021-44228" in text
    assert "N/A" in text
    assert "UNKNOWN" in text
