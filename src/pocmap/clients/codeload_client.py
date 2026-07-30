"""Opt-in fetcher for GitHub PoC repository source, via codeload tarballs.

Why this exists
---------------
``find_github_pocs`` can only ever return *links*: the indexes it reads
(Nomi-sec, TrickestCVE) list repositories that mention a CVE, which is not the
same as repositories that exploit it. Trickest lists in particular are full of
personal repos that merely name-drop the CVE. Reading the source is the only
way to tell a real PoC from a lead.

``codeload.github.com`` serves repository tarballs and is not metered by the
REST API rate limit, so this also sidesteps the 60-requests/hour unauthenticated
budget that makes per-repo API enrichment expensive.

Safety posture
--------------
This downloads and unpacks **untrusted third-party exploit code**, so it is:

* **Off unless explicitly enabled** — ``POCMAP_ALLOW_FETCH_POC_SOURCE=1``. Never
  inferred from another setting. Endpoint protection commonly quarantines
  exploit source, so the operator has to opt in knowingly (an isolated VM or
  research host is the intended environment).
* **Never executed.** Files are written to disk and read as bytes. Nothing in
  pocmap runs, imports, or evaluates fetched content.
* **Routed through** :class:`~pocmap.utils.http.HTTPClient`, so the SSRF guard,
  per-hop redirect re-validation and DNS-rebinding check all apply — a raw
  ``urllib.request.urlopen`` would bypass every one of them.
* **Bounded** on the download, on the extracted size (a small ``.tar.gz`` can
  expand to gigabytes), on member count, and on total on-disk usage.
* **Traversal-proof**: extraction uses tarfile's ``data`` filter where
  available, plus an independent per-member path check, so neither ``../``
  members nor absolute paths, symlinks or device nodes can escape the target.
"""

from __future__ import annotations

import io
import logging
import re
import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pocmap.config import settings
from pocmap.utils.http import HTTPClient, HTTPError, OfflineError
from pocmap.utils.paths import safe_path

logger = logging.getLogger(__name__)

CODELOAD_BASE = "https://codeload.github.com"

# GitHub owner/repo grammar. These names arrive from third-party indexes and
# anyone can create a repository, so they are untrusted input interpolated into
# a URL path: without this, ``owner="a/../../evil"`` would redirect the fetch.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")

# Default branch varies by repo and codeload has no "default branch" alias.
# Refs to try, in order. ``HEAD`` resolves whatever the repository's default
# branch actually is, so it covers the ones that use neither convention —
# Karmakstylez/CVE-2024-6387 defaults to "production" and was unreachable
# without it. It is last so the common cases still take one request.
_REFS = ("refs/heads/main", "refs/heads/master", "HEAD")

# Guards a tarball with a huge number of tiny entries, which exhausts inodes
# and wall-clock rather than bytes.
_MAX_MEMBERS = 5_000

# Minimum accounted cost per archive entry. A file of 0 bytes still consumes a
# disk block and an inode, so charging only ``member.size`` lets an archive of
# empty entries bypass both the per-repo and the total budget.
_MIN_ENTRY_COST = 4096

# Written into a completed extraction. Its presence means "pocmap created this
# and finished writing it" — it gates both cache reuse and eviction, so a
# partially written or foreign directory is never mistaken for either.
_MARKER = ".pocmap-fetch"

# Extraction happens here, then renames onto the destination.
_STAGING_SUFFIX = ".partial"

_BYTES_PER_MB = 1024 * 1024


class PoCSourceDisabledError(RuntimeError):
    """Raised when fetching is attempted without the operator opting in."""


@dataclass(frozen=True)
class FetchedSource:
    """A PoC repository unpacked on disk.

    Attributes:
        owner: GitHub owner/organization.
        repo: Repository name.
        path: Directory the source was extracted into.
        branch: Branch that resolved (``main``/``master``), or ``None`` when cached.
        bytes_extracted: Total extracted size, in bytes.
        cached: Whether this call reused an already-fetched copy.
    """

    owner: str
    repo: str
    path: Path
    branch: str | None
    bytes_extracted: int
    cached: bool


def parse_repo_url(url: str) -> tuple[str, str] | None:
    """Extract a validated ``(owner, repo)`` from a GitHub repository URL.

    Returns *None* for anything that is not a plain ``github.com/owner/repo``
    URL, or whose components fail :data:`_NAME_RE`. Rejecting here is what keeps
    attacker-controlled names out of the request path.
    """
    if not url.startswith(("https://github.com/", "http://github.com/")):
        return None
    tail = url.split("github.com/", 1)[1].strip("/")
    parts = tail.split("/")
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]
    if not _NAME_RE.match(owner) or not _NAME_RE.match(repo):
        return None
    return owner, repo


class CodeloadClient:
    """Downloads and unpacks GitHub repository tarballs.

    Args:
        http_client: Optional HTTP client (must be SSRF-guarded).
        dest_root: Override for the extraction root (defaults to
            ``settings.poc_source_dir``).

    Example::

        client = CodeloadClient()
        src = client.fetch("kali-mx", "CVE-2023-38408")   # needs the opt-in flag
        print(src.path, src.bytes_extracted)
    """

    def __init__(
        self,
        http_client: HTTPClient | None = None,
        dest_root: Path | None = None,
    ) -> None:
        self._client = http_client or HTTPClient(headers=settings.default_headers)
        self._dest_root = Path(dest_root) if dest_root else Path(settings.poc_source_dir)

    # -- Public API --

    @staticmethod
    def is_enabled() -> bool:
        """Whether the operator opted in to writing PoC source to disk."""
        return bool(settings.allow_fetch_poc_source)

    def fetch(self, owner: str, repo: str, *, force: bool = False) -> FetchedSource:
        """Download and extract ``owner/repo`` into the source directory.

        Args:
            owner: GitHub owner/organization.
            repo: Repository name.
            force: Re-fetch even if a copy already exists.

        Returns:
            A :class:`FetchedSource` describing what is on disk.

        Raises:
            PoCSourceDisabledError: ``POCMAP_ALLOW_FETCH_POC_SOURCE`` is not set.
            ValueError: *owner*/*repo* is not a valid GitHub name.
            OfflineError: Offline mode is active (there is no tarball cache).
            HTTPError: No branch resolved, or the transfer/extraction failed.
        """
        if not self.is_enabled():
            raise PoCSourceDisabledError(
                "Fetching PoC source is disabled. Set POCMAP_ALLOW_FETCH_POC_SOURCE=1 "
                "to allow pocmap to write third-party exploit code to disk "
                "(intended for an isolated VM or research host)."
            )
        if not _NAME_RE.match(owner) or not _NAME_RE.match(repo):
            raise ValueError(f"Invalid GitHub owner/repo: {owner!r}/{repo!r}")
        if settings.offline:
            # Tarballs deliberately bypass the HTTP response cache, so there is
            # nothing to serve offline. Say that plainly instead of failing
            # somewhere less obvious.
            raise OfflineError(
                f"offline: PoC source for {owner}/{repo} is not cached "
                "(tarballs are not stored in the HTTP cache)"
            )

        dest = self._dest_for(owner, repo)
        # Reuse only a *completed* extraction: the marker is written last, so a
        # directory without it is a partial or foreign tree, not a cached copy.
        if (dest / _MARKER).exists() and not force:
            return FetchedSource(
                owner=owner,
                repo=repo,
                path=dest,
                branch=None,
                bytes_extracted=_dir_size(dest),
                cached=True,
            )
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)

        self._enforce_total_budget()

        max_bytes = settings.poc_source_max_mb * _BYTES_PER_MB
        last_error: Exception | None = None
        for ref in _REFS:
            url = f"{CODELOAD_BASE}/{owner}/{repo}/tar.gz/{ref}"
            try:
                blob = self._download(url, max_bytes)
            except HTTPError as exc:
                last_error = exc
                continue
            branch = ref.rsplit("/", 1)[-1] if ref.startswith("refs/") else ref
            written = self._extract(blob, dest, max_bytes)
            logger.info(
                "Fetched PoC source %s/%s@%s -> %s (%d bytes)",
                owner, repo, branch, dest, written,
            )
            return FetchedSource(
                owner=owner,
                repo=repo,
                path=dest,
                branch=branch,
                bytes_extracted=written,
                cached=False,
            )

        raise HTTPError(
            f"Could not fetch {owner}/{repo} from any of {_REFS}: {last_error}"
        )

    def fetch_url(self, repo_url: str, *, force: bool = False) -> FetchedSource:
        """Convenience wrapper around :meth:`fetch` taking a repository URL."""
        parsed = parse_repo_url(repo_url)
        if parsed is None:
            raise ValueError(f"Not a GitHub repository URL: {repo_url!r}")
        return self.fetch(*parsed, force=force)

    # -- Internals --

    def _dest_for(self, owner: str, repo: str) -> Path:
        """Resolve the extraction directory, refusing to escape the root."""
        self._dest_root.mkdir(parents=True, exist_ok=True)
        # Both components already match _NAME_RE; safe_path is the belt-and-
        # braces check that the join stays inside the root.
        return Path(safe_path(f"{owner}__{repo}", str(self._dest_root)))

    def _download(self, url: str, max_bytes: int) -> bytes:
        """Stream *url* into memory, aborting past *max_bytes*."""
        resp = self._client.get(url, stream=True, timeout=settings.http_timeout)
        if resp.status_code != 200:
            raise HTTPError(f"HTTP {resp.status_code} for {url}", status_code=resp.status_code)

        buf = bytearray()
        for chunk in resp.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            buf.extend(chunk)
            if len(buf) > max_bytes:
                resp.close()
                raise HTTPError(
                    f"Archive exceeds {max_bytes // _BYTES_PER_MB} MB cap: {url}"
                )
        return bytes(buf)

    def _extract(self, blob: bytes, dest: Path, max_bytes: int) -> int:
        """Unpack *blob* into *dest*, enforcing the extraction budget.

        Unpacks into a sibling staging directory and renames on success, so an
        interrupted run can never leave a partial tree at *dest* — :meth:`fetch`
        treats an existing marked directory as a complete cached copy, and a
        truncated one would be scored as authoritative.

        The compressed size passing the download cap says nothing about the
        unpacked size, so members are measured *before* extraction and the
        running total is checked against the same cap.
        """
        staging = dest.with_name(dest.name + _STAGING_SUFFIX)
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True, exist_ok=True)
        written = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
                members = []
                for i, member in enumerate(tar):
                    if i >= _MAX_MEMBERS:
                        raise HTTPError(f"Archive has more than {_MAX_MEMBERS} entries")
                    # Only regular files and directories. Symlinks, hardlinks,
                    # FIFOs and devices are dropped: a symlink is the classic
                    # way out of an extraction root even when paths look sane.
                    if not (member.isfile() or member.isdir()):
                        continue
                    if not _member_is_contained(member.name):
                        logger.warning("Skipping unsafe archive member: %r", member.name)
                        continue
                    # Charge every entry a minimum: an archive of empty files or
                    # bare directories costs real disk blocks and inodes that a
                    # pure ``member.size`` sum would account as zero, leaving
                    # both the per-repo and total budgets unenforced.
                    written += max(member.size, _MIN_ENTRY_COST) if member.isfile() else _MIN_ENTRY_COST
                    if written > max_bytes:
                        raise HTTPError(
                            f"Archive expands beyond {max_bytes // _BYTES_PER_MB} MB cap"
                        )
                    # Strip archive-supplied permissions and ownership. The
                    # ``data`` filter does this itself, but the fallback path on
                    # older 3.10/3.11 patch releases applies them — which on a
                    # root-run process means an attacker-controlled archive can
                    # plant a setuid binary.
                    member.mode = 0o755 if member.isdir() else 0o644
                    member.uid = member.gid = 0
                    member.uname = member.gname = ""
                    members.append(member)
                _extractall(tar, staging, members)
            staging.replace(dest)
            (dest / _MARKER).write_text("", encoding="utf-8")
        except tarfile.TarError as exc:
            shutil.rmtree(staging, ignore_errors=True)
            raise HTTPError(f"Malformed archive: {exc}") from exc
        except BaseException:
            # BaseException, not Exception: a Ctrl-C during extraction is the
            # most likely way to strand a partial tree.
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return written

    def _enforce_total_budget(self) -> None:
        """Evict oldest fetched repos until the total cap has headroom.

        Only directories carrying :data:`_MARKER` are considered. This method
        deletes trees, and the destination root is operator-configurable, so it
        must never assume everything under that root belongs to pocmap — a
        misconfigured or shared directory would otherwise have its contents
        removed on a routine fetch.
        """
        cap = settings.poc_source_total_max_mb * _BYTES_PER_MB
        if not self._dest_root.exists():
            return
        entries = [
            p for p in self._dest_root.iterdir() if p.is_dir() and (p / _MARKER).exists()
        ]
        total = sum(_dir_size(p) for p in entries)
        if total <= cap:
            return
        for path in sorted(entries, key=lambda p: p.stat().st_mtime):
            if total <= cap:
                break
            freed = _dir_size(path)
            shutil.rmtree(path, ignore_errors=True)
            total -= freed
            logger.info("Evicted fetched PoC source %s (%d bytes)", path.name, freed)

    def close(self) -> None:
        """Release the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> CodeloadClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _member_is_contained(name: str) -> bool:
    """Whether an archive member path stays inside the extraction root.

    Pure string inspection — never touches the filesystem. Member names are
    POSIX-ish but can still carry Windows drive letters or backslashes when the
    archive was built on Windows, so both separators are considered.
    """
    if "\x00" in name or name.startswith(("/", "\\")):
        return False
    parts = name.replace("\\", "/").split("/")
    if any(part == ".." for part in parts):
        return False
    head = parts[0]
    has_drive = len(head) >= 2 and head[1] == ":"
    return not has_drive


def _extractall(tar: tarfile.TarFile, dest: Path, members: list[tarfile.TarInfo]) -> None:
    """Extract *members* using the ``data`` filter when the runtime has it.

    ``filter=`` landed in Python 3.12 and was backported to 3.10.12 / 3.11.4;
    pocmap supports 3.10+, so older patch releases fall back to the explicit
    per-member containment check already applied by the caller.
    """
    if hasattr(tarfile, "data_filter"):
        tar.extractall(dest, members=members, filter="data")  # noqa: S202 - filtered
    else:  # pragma: no cover - only on <3.10.12 / <3.11.4
        logger.debug("tarfile data filter unavailable; relying on member validation")
        tar.extractall(dest, members=members)  # noqa: S202 - members pre-validated


def _dir_size(path: Path) -> int:
    """Total size in bytes of everything under *path*."""
    if not path.exists():
        return 0
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
