"""Tests for scoring a fetched PoC repository (fully offline, synthetic trees).

The property that matters is **no false ``confirmed``**: that tier is the only
one claiming a repository actually exploits the CVE, so a link list or a set of
course notes reaching it would be worse than no verdict at all. The cases below
are modelled on repositories the real CVE indexes return for CVE-2023-38408.
"""

from __future__ import annotations

from pathlib import Path

from pocmap.utils.poc_evidence import analyze

CVE = "CVE-2023-38408"


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# confirmed: the CVE is named in code, and there is code
# ---------------------------------------------------------------------------

def test_cve_named_in_a_code_filename_is_confirmed(tmp_path: Path) -> None:
    _tree(tmp_path, {"CVE-2023-38408.sh": "#!/bin/sh\necho pwn\n", "README.md": "poc"})
    ev = analyze(tmp_path, CVE)
    assert ev.verdict == "confirmed"
    assert ev.mentions_cve_in_code is True
    assert ev.language == "Shell"


def test_cve_named_inside_code_contents_is_confirmed(tmp_path: Path) -> None:
    _tree(tmp_path, {"exploit.py": "# exploit for CVE-2023-38408\nimport os\n"})
    ev = analyze(tmp_path, CVE)
    assert ev.verdict == "confirmed"
    assert ev.language == "Python"


def test_underscored_and_unseparated_spellings_match(tmp_path: Path) -> None:
    """Repos write cve_2023_38408 and CVE202338408 too."""
    for spelling in ("cve_2023_38408", "CVE202338408", "CVE 2023 38408"):
        d = tmp_path / spelling.replace(" ", "_")
        _tree(d, {"exploit.py": f"# {spelling}\n"})
        assert analyze(d, CVE).mentions_cve is True, spelling


def test_a_different_cve_does_not_match(tmp_path: Path) -> None:
    _tree(tmp_path, {"exploit.py": "# exploit for CVE-2021-44228\n"})
    ev = analyze(tmp_path, CVE)
    assert ev.mentions_cve is False
    assert ev.verdict == "unverified"  # has code, just unproven for THIS cve


def test_bare_year_does_not_false_match(tmp_path: Path) -> None:
    _tree(tmp_path, {"notes.py": "# written in 2023, 38408 downloads\n"})
    assert analyze(tmp_path, CVE).mentions_cve is False


# ---------------------------------------------------------------------------
# The false-positive cases that motivated the in-code signal
# ---------------------------------------------------------------------------

def test_doc_heavy_index_repo_is_not_confirmed(tmp_path: Path) -> None:
    """Modelled on ARESHAmohanad/THM: 100+ notes citing many CVEs, no exploit.

    It names the CVE and has a stray code file, which under a naive
    "mentions it + has code" rule scored `confirmed`.
    """
    files = {f"notes/day{i}.md": "tryhackme notes" for i in range(103)}
    files["README.md"] = f"room list incl. {CVE}"
    files["config.yml"] = "theme: dark"
    _tree(tmp_path, files)

    ev = analyze(tmp_path, CVE)
    assert ev.mentions_cve is True
    assert ev.mentions_cve_in_code is False
    assert ev.verdict == "unrelated"


def test_awesome_list_is_flagged_as_an_index(tmp_path: Path) -> None:
    """What makes it an index is citing many CVEs, not the file count."""
    cited = ", ".join(f"CVE-2021-{40000 + i}" for i in range(30))
    _tree(tmp_path, {"README.md": f"awesome security links: {CVE}, {cited}"})

    ev = analyze(tmp_path, CVE)
    assert ev.distinct_cves >= 30
    assert ev.looks_like_an_index is True
    assert ev.verdict == "unrelated"


def test_scan_dump_citing_a_hundred_cves_is_unrelated(tmp_path: Path) -> None:
    """Modelled on a real result: an nmap output dump citing 118 CVEs.

    It has no code and two docs, so a doc-count rule left it as ``likely`` —
    i.e. "a writeup about this CVE", which it is not.
    """
    body = "\n".join(f"| CVE-2023-{10000 + i} | 7.5 |" for i in range(118))
    _tree(tmp_path, {"scan.md": f"{CVE}\n{body}", "README.md": "nmap results"})

    ev = analyze(tmp_path, CVE)
    assert ev.verdict == "unrelated"


def test_a_multi_cve_toolkit_with_real_code_is_not_an_index(tmp_path: Path) -> None:
    """Citing many CVEs is only an index signal when there is no code.

    An exploit toolkit legitimately references a whole family of CVEs.
    """
    files = {f"exploits/cve_2021_{40000 + i}.py": f"# CVE-2021-{40000 + i}\n" for i in range(20)}
    files["exploits/target.py"] = f"# {CVE}\nrun()\n"
    _tree(tmp_path, files)

    ev = analyze(tmp_path, CVE)
    assert ev.distinct_cves >= 20
    assert ev.looks_like_an_index is False
    assert ev.verdict == "confirmed"


def test_writeup_collection_with_scripts_is_still_an_index(tmp_path: Path) -> None:
    """Modelled on momenbasel/htb-writeups: 236 CVEs, 71 docs, 9 code files.

    A writeup collection often carries helper scripts, so an absolute
    code-file ceiling misses it. Documentation outnumbering code several times
    over is the signal that it is a collection rather than a toolkit.
    """
    files = {f"machines/box{i}.md": f"writeup citing CVE-2020-{10000 + i}" for i in range(71)}
    files.update({f"scripts/helper{i}.py": "import os" for i in range(9)})
    _tree(tmp_path, files)

    ev = analyze(tmp_path, CVE)
    assert ev.code_files == 9  # above the absolute ceiling...
    assert ev.looks_like_an_index is True  # ...but docs dominate
    assert ev.verdict == "unrelated"


def test_code_dominant_repo_is_never_an_index(tmp_path: Path) -> None:
    """Security tooling with docs alongside it must not be swept up."""
    files = {f"src/mod{i}.py": f"# CVE-2020-{10000 + i}\nrun()" for i in range(40)}
    files.update({f"docs/page{i}.md": "docs" for i in range(30)})
    _tree(tmp_path, files)

    ev = analyze(tmp_path, CVE)
    assert ev.distinct_cves >= 5
    assert ev.looks_like_an_index is False


def test_single_cve_writeup_is_not_swept_up_as_an_index(tmp_path: Path) -> None:
    """A multi-page writeup about one CVE must stay `likely`."""
    files = {f"notes/part{i}.md": f"analysis of {CVE}" for i in range(8)}
    files["README.md"] = f"deep dive on {CVE}"
    _tree(tmp_path, files)

    ev = analyze(tmp_path, CVE)
    assert ev.distinct_cves == 1
    assert ev.looks_like_an_index is False
    assert ev.verdict == "likely"


def test_cve_only_in_readme_of_a_code_repo_is_unverified(tmp_path: Path) -> None:
    """Documentation alone does not prove the code exploits the CVE."""
    _tree(tmp_path, {"README.md": f"mentions {CVE}", "main.go": "package main"})
    ev = analyze(tmp_path, CVE)
    assert ev.mentions_cve is True
    assert ev.mentions_cve_in_code is False
    assert ev.verdict == "unverified"


def test_writeup_with_no_code_is_likely_not_confirmed(tmp_path: Path) -> None:
    _tree(tmp_path, {"README.md": f"my analysis of {CVE}"})
    ev = analyze(tmp_path, CVE)
    assert ev.verdict == "likely"
    assert ev.code_files == 0


# ---------------------------------------------------------------------------
# Mechanics
# ---------------------------------------------------------------------------

def test_vcs_and_vendored_trees_are_skipped(tmp_path: Path) -> None:
    _tree(tmp_path, {
        ".git/config": f"url = {CVE}",
        "node_modules/pkg/index.js": f"// {CVE}",
        "README.md": "nothing here",
    })
    ev = analyze(tmp_path, CVE)
    assert ev.mentions_cve is False
    assert ev.code_files == 0


def test_skip_dirs_are_matched_relative_to_root_not_absolute(tmp_path: Path) -> None:
    """Regression: an ancestor named build/.venv voided the entire scan.

    Skip names were matched against the absolute path, so any repo extracted
    beneath a directory called ``build``, ``dist``, ``vendor`` or ``.venv``
    (what this project's README recommends for a virtualenv) had every file
    excluded and scored ``unrelated`` with no error.
    """
    for ancestor in ("build", ".venv", "dist", "vendor", "node_modules"):
        root = tmp_path / ancestor / "owner__repo"
        root.mkdir(parents=True)
        (root / "CVE-2023-38408.sh").write_text("#!/bin/sh\necho poc\n")

        ev = analyze(root, CVE)
        assert ev.code_files == 1, f"scan voided under ancestor {ancestor!r}"
        assert ev.verdict == "confirmed", f"scan voided under ancestor {ancestor!r}"

    # ...while the same names *inside* the repo are still skipped.
    root = tmp_path / "clean" / "repo"
    (root / "build").mkdir(parents=True)
    (root / "build" / "artifact.py").write_text(f"# {CVE}")
    assert analyze(root, CVE).code_files == 0


def test_fetch_marker_is_not_counted_as_repository_content(tmp_path: Path) -> None:
    _tree(tmp_path, {".pocmap-fetch": "", "exploit.py": f"# {CVE}"})
    ev = analyze(tmp_path, CVE)
    assert ev.code_files == 1
    assert ev.doc_files == 0


def test_dominant_language_wins_by_bytes(tmp_path: Path) -> None:
    _tree(tmp_path, {
        "tiny.rb": "# rb",
        "exploit.py": f"# {CVE}\n" + ("x = 1\n" * 500),
    })
    assert analyze(tmp_path, CVE).language == "Python"


def test_missing_directory_yields_a_default_not_an_error(tmp_path: Path) -> None:
    ev = analyze(tmp_path / "does-not-exist", CVE)
    assert ev.verdict == "unverified"
    assert ev.total_bytes == 0


def test_undecodable_bytes_do_not_crash_the_scan(tmp_path: Path) -> None:
    p = tmp_path / "payload.bin"
    p.write_bytes(b"\xff\xfe\x00" + CVE.encode() + b"\x80\x81")
    ev = analyze(tmp_path, CVE)
    assert ev.mentions_cve is True


def test_matched_paths_are_capped(tmp_path: Path) -> None:
    _tree(tmp_path, {f"f{i}.py": f"# {CVE}" for i in range(12)})
    assert len(analyze(tmp_path, CVE).matched_paths) == 5
