"""Score a fetched PoC repository on what its source actually contains.

The indexes behind ``find_github_pocs`` list repositories that *mention* a CVE,
which is not the same as repositories that exploit it — TrickestCVE lists in
particular carry personal repos, course notes and link collections that merely
name-drop the ID. Star count does not separate them either: a popular repo can
be a link list, and a genuine one-file PoC often has zero stars.

Reading the source does separate them, on two independent signals:

* **Does the CVE ID appear** anywhere in the code, filenames or docs?
* **Is there executable code at all**, or only documentation?

Neither is conclusive alone — a PoC can be named for its target rather than the
CVE, and a good writeup is documentation — so they are reported separately and
combined into a coarse verdict the caller can override.

This module only ever *reads* bytes. Nothing here executes, imports, or
evaluates fetched content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Extensions that indicate runnable exploit code, mapped to a display language.
# Deliberately not exhaustive: an unknown extension counts as code (it is not
# documentation), it just does not name a language.
_CODE_LANGUAGES: dict[str, str] = {
    ".py": "Python", ".rb": "Ruby", ".go": "Go", ".rs": "Rust",
    ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".java": "Java", ".kt": "Kotlin", ".cs": "C#", ".php": "PHP",
    ".js": "JavaScript", ".ts": "TypeScript", ".sh": "Shell", ".bash": "Shell",
    ".ps1": "PowerShell", ".pl": "Perl", ".lua": "Lua", ".swift": "Swift",
    ".yaml": "YAML", ".yml": "YAML", ".jsp": "JSP", ".asp": "ASP",
    ".sql": "SQL", ".html": "HTML", ".htm": "HTML", ".xml": "XML",
}

# Documentation / project scaffolding: present in almost every repo and never
# evidence of an exploit on its own.
_DOC_EXTENSIONS = frozenset({".md", ".rst", ".txt", ".pdf", ".png", ".jpg",
                             ".jpeg", ".gif", ".svg", ".webp", ".mp4"})
_DOC_FILENAMES = frozenset({"license", "licence", "notice", "authors",
                            "contributing", "code_of_conduct", ".gitignore",
                            ".gitattributes"})

# Bytes read per file when searching for the CVE ID. PoC files are small; this
# bounds the work on a repo that also ships a large binary or dataset.
_SCAN_BYTES = 256 * 1024

# Any CVE ID, for counting how many distinct ones a repository cites.
_ANY_CVE_RE = re.compile(r"CVE[-_ ]?(\d{4})[-_ ]?(\d{4,7})", re.IGNORECASE)

# Citing this many different CVEs marks a repository as an index. Calibrated on
# a 55-repo sample: genuine PoCs topped out at 3 distinct CVEs, while the
# indexes cited 10, 22 and 118 — so the boundary sits in a wide empty gap.
_INDEX_CVE_THRESHOLD = 5

# ...but only when the repo is not code-driven. A toolkit that exploits many
# CVEs cites many CVEs too, and it is not an index. "Not code-driven" means
# either almost no code at all, or documentation outnumbering it several times
# over — a writeup collection can still carry scripts (one real example: 236
# CVEs cited across 71 docs and 9 code files), so an absolute code-file ceiling
# is too tight to catch it.
_INDEX_MAX_CODE_FILES = 2
_INDEX_DOC_TO_CODE_RATIO = 4

# Counting stops here; the exact total beyond it does not change any decision.
_MAX_DISTINCT_CVES = 200

# Skip version control internals and vendored dependency trees.
_SKIP_DIRS = frozenset({".git", ".github", "node_modules", "vendor",
                        "__pycache__", ".venv", "venv", "dist", "build"})

# Bookkeeping written by the fetcher; not part of the repository's content.
_SKIP_FILES = frozenset({".pocmap-fetch"})


@dataclass
class PoCEvidence:
    """What a repository's source says about whether it is a real PoC.

    Attributes:
        distinct_cves: How many *different* CVE IDs the repository cites. The
            sharpest index signal available: a PoC or a writeup is about one
            vulnerability, while a link list, a scan dump or a notes repo cites
            dozens. Measured over a 55-repo sample, genuine PoCs cited at most 3
            and the indexes cited 10, 22 and 118.
        mentions_cve: The CVE ID appears anywhere in the repository.
        mentions_cve_in_code: The CVE ID appears in a *code* file's name or
            contents. This is the load-bearing signal — a link-list repo cites
            hundreds of CVEs in its README, so "mentioned somewhere" alone
            cannot distinguish a PoC from an index.
        code_files: Count of files that look like runnable code.
        doc_files: Count of documentation/asset files.
        language: Dominant language inferred from extensions, if any.
        total_bytes: Total size of the scanned files.
        verdict: ``confirmed`` / ``likely`` / ``unverified`` / ``unrelated``.
        matched_paths: Up to a few paths where the CVE ID was found.
    """

    mentions_cve: bool = False
    mentions_cve_in_code: bool = False
    distinct_cves: int = 0
    code_files: int = 0
    doc_files: int = 0
    language: str | None = None
    total_bytes: int = 0
    verdict: str = "unverified"
    matched_paths: list[str] = field(default_factory=list)

    @property
    def looks_like_an_index(self) -> bool:
        """Whether this is a list/notes repo rather than a PoC or a writeup.

        Primary signal is :attr:`distinct_cves`; sheer documentation volume is
        the secondary one, kept at a high bar so an ordinary multi-page writeup
        is not swept up. Both require the repo to carry almost no code — a
        genuine multi-CVE exploit toolkit cites many CVEs *and* ships code, and
        must not be filed as an index.
        """
        code_driven = (
            self.code_files > _INDEX_MAX_CODE_FILES
            and self.doc_files < self.code_files * _INDEX_DOC_TO_CODE_RATIO
        )
        if code_driven:
            return False
        return self.distinct_cves >= _INDEX_CVE_THRESHOLD or self.doc_files >= 25

    def to_dict(self) -> dict[str, object]:
        """JSON-serializable view for the MCP layer."""
        return {
            "mentions_cve": self.mentions_cve,
            "mentions_cve_in_code": self.mentions_cve_in_code,
            "code_files": self.code_files,
            "doc_files": self.doc_files,
            "language": self.language,
            "total_bytes": self.total_bytes,
            "verdict": self.verdict,
            "matched_paths": self.matched_paths,
        }


def _is_doc(path: Path) -> bool:
    """Whether *path* is documentation or a project-scaffolding file."""
    suffix = path.suffix.lower()
    if suffix in _DOC_EXTENSIONS:
        return True
    return path.stem.lower() in _DOC_FILENAMES or path.name.lower() in _DOC_FILENAMES


def _iter_files(root: Path) -> list[Path]:
    """Every scannable file under *root*, skipping VCS and vendored trees.

    Skip names are matched against the path *relative to root*. Matching the
    absolute path instead meant any ancestor directory named ``build``,
    ``dist``, ``vendor`` or ``.venv`` — all ordinary, and ``.venv`` is what this
    project's own README recommends — silently excluded every file, so each
    repository scored ``unrelated`` with no error.
    """
    out: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:  # pragma: no cover - rglob yields paths under root
            continue
        if any(part in _SKIP_DIRS for part in relative.parts):
            continue
        if path.name in _SKIP_FILES:
            continue
        out.append(path)
    return out


def analyze(root: Path, cve_id: str) -> PoCEvidence:
    """Score the extracted repository at *root* as evidence for *cve_id*.

    Args:
        root: Directory holding the extracted source.
        cve_id: The CVE this repository is claimed to exploit.

    Returns:
        A :class:`PoCEvidence` summary. A missing or empty directory yields the
        default ``unverified`` verdict rather than raising.
    """
    evidence = PoCEvidence()
    if not root.exists():
        return evidence

    # Match the CVE ID tolerantly: repos write CVE-2023-38408, cve_2023_38408
    # and CVE202338408. Anchored on the year+number so "2023" alone never hits.
    parts = cve_id.upper().split("-")
    if len(parts) == 3:
        pattern = re.compile(
            rf"CVE[-_ ]?{re.escape(parts[1])}[-_ ]?{re.escape(parts[2])}\b", re.IGNORECASE
        )
    else:  # pragma: no cover - validators reject this shape upstream
        pattern = re.compile(re.escape(cve_id), re.IGNORECASE)

    language_bytes: dict[str, int] = {}
    all_cves: set[tuple[str, str]] = set()

    for path in _iter_files(root):
        try:
            size = path.stat().st_size
        except OSError:  # pragma: no cover - race with eviction
            continue
        evidence.total_bytes += size

        is_doc = _is_doc(path)
        if is_doc:
            evidence.doc_files += 1
        else:
            evidence.code_files += 1
            language = _CODE_LANGUAGES.get(path.suffix.lower())
            if language:
                language_bytes[language] = language_bytes.get(language, 0) + size

        try:
            # Bounded read, not read-then-slice: the latter pulls the whole
            # file into memory first, so the documented cap would not hold.
            with path.open("rb") as fh:
                blob = fh.read(_SCAN_BYTES)
        except OSError:  # pragma: no cover - unreadable file
            blob = b""
        # Decode leniently: exploit payloads are frequently not valid UTF-8.
        text = f"{path.name}\n{blob.decode('utf-8', errors='ignore')}"

        # Filenames are evidence too: "CVE-2023-38408.sh" says a lot.
        found = bool(pattern.search(text))

        if len(all_cves) < _MAX_DISTINCT_CVES:
            for match in _ANY_CVE_RE.finditer(text):
                all_cves.add((match.group(1), match.group(2)))

        if found:
            evidence.mentions_cve = True
            if not is_doc:
                evidence.mentions_cve_in_code = True
            _remember(evidence, root, path)

    if language_bytes:
        evidence.language = max(language_bytes.items(), key=lambda kv: kv[1])[0]

    evidence.distinct_cves = len(all_cves)
    evidence.verdict = _verdict(evidence)
    return evidence


def _remember(evidence: PoCEvidence, root: Path, path: Path) -> None:
    """Record where the CVE ID was found, capped for payload size."""
    if len(evidence.matched_paths) < 5:
        evidence.matched_paths.append(path.relative_to(root).as_posix())


def _verdict(evidence: PoCEvidence) -> str:
    """Combine the signals into a coarse, overridable verdict.

    * ``confirmed``  — the CVE is named *in code*, and there is code to run.
      This is the only tier that claims the repo exploits the CVE.
    * ``likely``     — a small, doc-shaped repo that names the CVE: a writeup.
    * ``unverified`` — has code, but the CVE is only named in documentation (or
      not at all). It may still be a PoC named for its target rather than the
      ID, so this is "unproven", not "disproven".
    * ``unrelated``  — no mention, or an index/link-list shape. These are the
      ``awesome-list`` and course-notes repos that pollute the CVE indexes.

    The in-code requirement is what stops a link list scoring ``confirmed``: an
    index cites hundreds of CVEs in its README while shipping no exploit for any
    of them.
    """
    if evidence.looks_like_an_index:
        # An index cites this CVE the same way it cites hundreds of others;
        # that is not a writeup about it.
        return "unrelated"
    if evidence.mentions_cve_in_code and evidence.code_files:
        return "confirmed"
    if evidence.mentions_cve and not evidence.code_files:
        return "likely"
    if evidence.code_files:
        return "unverified"
    return "unrelated"
