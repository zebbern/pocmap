"""Security and behaviour tests for the opt-in PoC source fetcher (offline).

This component downloads and unpacks **untrusted third-party archives**, so the
guards are the feature. Every test here is an attack or an abuse case:

  * fetching is refused unless the operator opted in;
  * attacker-controlled owner/repo names cannot escape the URL path;
  * ``../`` members, absolute paths, drive letters, symlinks and device nodes
    cannot escape the extraction root;
  * an oversized download is aborted, and a decompression bomb is stopped on
    the *extracted* size (which the download cap cannot see);
  * a failed extraction leaves nothing behind to be mistaken for a cached copy.

Fully offline: the HTTP client is a ``MagicMock`` and every archive is built
in-memory.
"""

from __future__ import annotations

import io
import tarfile
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

import pocmap.clients.codeload_client as codeload_mod
from pocmap.clients.codeload_client import (
    CodeloadClient,
    PoCSourceDisabledError,
    parse_repo_url,
)
from pocmap.config import settings
from pocmap.utils.http import HTTPError, OfflineError


def _patch_settings(monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> None:
    """Rebind the module's ``settings`` to a modified frozen copy.

    ``Settings`` is ``frozen=True, slots=True``, so it cannot be mutated
    attribute-wise; this mirrors the approach in ``test_offline.py``.
    """
    monkeypatch.setattr(codeload_mod, "settings", replace(settings, **overrides))


@pytest.fixture
def enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Opt in, as ``POCMAP_ALLOW_FETCH_POC_SOURCE=1`` would."""
    _patch_settings(monkeypatch, allow_fetch_poc_source=True, offline=False)


def _tar_bytes(entries: dict[str, bytes], *, kind: str = "file") -> bytes:
    """Build an in-memory .tar.gz from ``{name: content}``."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in entries.items():
            if kind == "symlink":
                info = tarfile.TarInfo(name)
                info.type = tarfile.SYMTYPE
                info.linkname = content.decode()
                tar.addfile(info)
            elif kind == "device":
                info = tarfile.TarInfo(name)
                info.type = tarfile.CHRTYPE
                tar.addfile(info)
            else:
                info = tarfile.TarInfo(name)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _client(tmp_path: Path, blob: bytes | Exception, status: int = 200) -> CodeloadClient:
    http = MagicMock()

    def fake_get(url: str, **_: Any) -> Any:
        if isinstance(blob, Exception):
            raise blob
        resp = MagicMock()
        resp.status_code = status
        resp.iter_content.return_value = [blob[i : i + 1024] for i in range(0, len(blob), 1024)]
        return resp

    http.get.side_effect = fake_get
    return CodeloadClient(http_client=http, dest_root=tmp_path / "poc-source")


# ---------------------------------------------------------------------------
# The opt-in gate
# ---------------------------------------------------------------------------

def test_fetch_is_refused_unless_explicitly_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Writing exploit code to disk must never be inferred from other settings."""
    _patch_settings(monkeypatch, allow_fetch_poc_source=False)
    client = _client(tmp_path, _tar_bytes({"repo/poc.py": b"x"}))

    with pytest.raises(PoCSourceDisabledError) as excinfo:
        client.fetch("owner", "repo")
    assert "POCMAP_ALLOW_FETCH_POC_SOURCE" in str(excinfo.value)


def test_disabled_gate_is_checked_before_any_network_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_settings(monkeypatch, allow_fetch_poc_source=False)
    http = MagicMock()
    client = CodeloadClient(http_client=http, dest_root=tmp_path)

    with pytest.raises(PoCSourceDisabledError):
        client.fetch("owner", "repo")
    http.get.assert_not_called()


def test_offline_mode_reports_clearly_instead_of_fetching(
    tmp_path: Path, enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tarballs bypass the HTTP cache, so there is nothing to serve offline."""
    _patch_settings(monkeypatch, allow_fetch_poc_source=True, offline=True)
    client = _client(tmp_path, _tar_bytes({"repo/poc.py": b"x"}))

    with pytest.raises(OfflineError):
        client.fetch("owner", "repo")


# ---------------------------------------------------------------------------
# Untrusted owner/repo names must not reach the URL path
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "owner,repo",
    [
        ("a/../../evil", "repo"),
        ("owner", "../../../etc/passwd"),
        ("owner", "repo/../../x"),
        ("", "repo"),
        ("owner", ""),
        ("own er", "repo"),
        ("owner", "re\x00po"),
        ("-leading-dash-is-not-a-github-name", "repo"),
    ],
)
def test_invalid_names_are_rejected_before_the_request(
    tmp_path: Path, enabled: None, owner: str, repo: str
) -> None:
    http = MagicMock()
    client = CodeloadClient(http_client=http, dest_root=tmp_path)

    with pytest.raises(ValueError):
        client.fetch(owner, repo)
    http.get.assert_not_called()


@pytest.mark.parametrize(
    "url",
    [
        "https://gitlab.com/owner/repo",
        "https://github.com/owner",
        "https://evil.com/github.com/o/r",
        "ftp://github.com/owner/repo",
        "https://github.com/a b/repo",
    ],
)
def test_parse_repo_url_rejects_non_github_and_malformed(url: str) -> None:
    assert parse_repo_url(url) is None


def test_parse_repo_url_accepts_normal_forms() -> None:
    assert parse_repo_url("https://github.com/kali-mx/CVE-2023-38408") == (
        "kali-mx",
        "CVE-2023-38408",
    )
    assert parse_repo_url("https://github.com/o/r.git") == ("o", "r")
    assert parse_repo_url("https://github.com/o/r/tree/main") == ("o", "r")


# ---------------------------------------------------------------------------
# Extraction cannot escape the destination
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "member",
    ["../escaped.py", "repo/../../escaped.py", "/abs/escaped.py", "C:/escaped.py"],
)
def test_traversal_members_are_dropped(tmp_path: Path, enabled: None, member: str) -> None:
    blob = _tar_bytes({member: b"pwned", "repo/ok.py": b"safe"})
    client = _client(tmp_path, blob)

    src = client.fetch("owner", "repo")

    root = tmp_path / "poc-source"
    escaped = list(tmp_path.rglob("escaped.py"))
    assert not escaped, f"member {member!r} escaped to {escaped}"
    assert (src.path / "repo" / "ok.py").exists()
    assert src.path.is_relative_to(root)


def test_symlink_members_are_dropped(tmp_path: Path, enabled: None) -> None:
    """A symlink is the classic escape even when its own path looks fine."""
    blob = _tar_bytes({"repo/link": b"/etc/passwd"}, kind="symlink")
    client = _client(tmp_path, blob)

    src = client.fetch("owner", "repo")
    assert not (src.path / "repo" / "link").exists()


def test_device_members_are_dropped(tmp_path: Path, enabled: None) -> None:
    blob = _tar_bytes({"repo/dev": b""}, kind="device")
    client = _client(tmp_path, blob)

    src = client.fetch("owner", "repo")
    assert not (src.path / "repo" / "dev").exists()


# ---------------------------------------------------------------------------
# Size budgets
# ---------------------------------------------------------------------------

def test_oversized_download_is_aborted(
    tmp_path: Path, enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_settings(monkeypatch, allow_fetch_poc_source=True, poc_source_max_mb=1)
    client = _client(tmp_path, b"\x00" * (2 * 1024 * 1024))

    with pytest.raises(HTTPError, match="exceeds"):
        client.fetch("owner", "repo")


def test_decompression_bomb_is_stopped_on_extracted_size(
    tmp_path: Path, enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The download cap cannot see this: 8 MB of zeros gzips to a few KB."""
    _patch_settings(monkeypatch, allow_fetch_poc_source=True, poc_source_max_mb=1)
    bomb = _tar_bytes({"repo/big.bin": b"\x00" * (8 * 1024 * 1024)})
    assert len(bomb) < 1024 * 1024, "fixture should be small when compressed"
    client = _client(tmp_path, bomb)

    with pytest.raises(HTTPError, match="expands beyond"):
        client.fetch("owner", "repo")


def test_failed_extraction_leaves_no_partial_tree(
    tmp_path: Path, enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A half-unpacked dir would be treated as a complete cached copy."""
    _patch_settings(monkeypatch, allow_fetch_poc_source=True, poc_source_max_mb=1)
    bomb = _tar_bytes({"repo/big.bin": b"\x00" * (8 * 1024 * 1024)})
    client = _client(tmp_path, bomb)

    with pytest.raises(HTTPError):
        client.fetch("owner", "repo")
    assert not (tmp_path / "poc-source" / "owner__repo").exists()


def test_malformed_archive_is_reported_not_crashed(tmp_path: Path, enabled: None) -> None:
    client = _client(tmp_path, b"this is not a gzip stream at all")

    with pytest.raises(HTTPError, match="Could not fetch|Malformed"):
        client.fetch("owner", "repo")


# ---------------------------------------------------------------------------
# Normal operation
# ---------------------------------------------------------------------------

def test_successful_fetch_extracts_and_reports_size(tmp_path: Path, enabled: None) -> None:
    blob = _tar_bytes({"repo/exploit.py": b"print('poc')\n", "repo/README.md": b"# poc"})
    client = _client(tmp_path, blob)

    src = client.fetch("owner", "repo")

    assert src.cached is False
    assert src.branch == "main"
    assert src.bytes_extracted > 0
    assert (src.path / "repo" / "exploit.py").read_bytes() == b"print('poc')\n"


def test_second_fetch_reuses_the_extracted_copy(tmp_path: Path, enabled: None) -> None:
    blob = _tar_bytes({"repo/exploit.py": b"x"})
    client = _client(tmp_path, blob)

    first = client.fetch("owner", "repo")
    second = client.fetch("owner", "repo")

    assert first.cached is False
    assert second.cached is True
    assert second.path == first.path


def test_falls_back_to_master_when_main_is_missing(tmp_path: Path, enabled: None) -> None:
    blob = _tar_bytes({"repo/exploit.py": b"x"})
    http = MagicMock()
    calls: list[str] = []

    def fake_get(url: str, **_: Any) -> Any:
        calls.append(url)
        if "refs/heads/main" in url:
            raise HTTPError("404", status_code=404)
        resp = MagicMock()
        resp.status_code = 200
        resp.iter_content.return_value = [blob]
        return resp

    http.get.side_effect = fake_get
    client = CodeloadClient(http_client=http, dest_root=tmp_path / "poc-source")

    src = client.fetch("owner", "repo")
    assert src.branch == "master"
    assert any("refs/heads/main" in u for u in calls)


# ---------------------------------------------------------------------------
# Eviction must never touch anything pocmap did not create
# ---------------------------------------------------------------------------

def test_eviction_only_removes_directories_pocmap_created(
    tmp_path: Path, enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: eviction rmtree'd every subdirectory of the root.

    The root is operator-configurable, and an empty ``POCMAP_POC_SOURCE_DIR``
    used to resolve to the CWD — so a routine fetch could delete the user's
    working-directory subtrees.
    """
    root = tmp_path / "poc-source"
    root.mkdir(parents=True)
    precious = root / "my-important-work"
    precious.mkdir()
    (precious / "thesis.txt").write_bytes(b"\x00" * (900 * 1024))

    _patch_settings(monkeypatch, allow_fetch_poc_source=True, poc_source_total_max_mb=1)
    client = _client(tmp_path, _tar_bytes({"repo/x.py": b"x"}))
    client.fetch("owner", "repo")

    assert precious.exists(), "eviction deleted a directory pocmap did not create"
    assert (precious / "thesis.txt").exists()


def test_empty_dir_env_var_does_not_resolve_to_cwd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``Path("")`` is the CWD; an empty env value must mean 'unset'."""
    from pocmap.config import _build_settings

    monkeypatch.setenv("POCMAP_POC_SOURCE_DIR", "")
    monkeypatch.setenv("POCMAP_CACHE_DIR", "")
    built = _build_settings()

    assert Path(built.poc_source_dir).resolve() != Path.cwd()
    assert Path(built.cache_dir).resolve() != Path.cwd()


# ---------------------------------------------------------------------------
# Budgets must account for entries that carry no bytes
# ---------------------------------------------------------------------------

def test_archive_of_empty_entries_is_still_capped(
    tmp_path: Path, enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Zero-byte files consume inodes and blocks that ``member.size`` misses."""
    _patch_settings(monkeypatch, allow_fetch_poc_source=True, poc_source_max_mb=1)
    blob = _tar_bytes({f"repo/empty{i}": b"" for i in range(400)})
    client = _client(tmp_path, blob)

    with pytest.raises(HTTPError, match="expands beyond"):
        client.fetch("owner", "repo")


def test_member_count_is_capped(tmp_path: Path, enabled: None) -> None:
    blob = _tar_bytes({f"repo/f{i}.txt": b"x" for i in range(6000)})
    client = _client(tmp_path, blob)

    with pytest.raises(HTTPError, match="more than|expands beyond"):
        client.fetch("owner", "repo")


# ---------------------------------------------------------------------------
# A partial tree must never be reused as a cached copy
# ---------------------------------------------------------------------------

def test_unmarked_directory_is_not_treated_as_cached(
    tmp_path: Path, enabled: None
) -> None:
    """A tree without the completion marker is partial or foreign, not cached."""
    root = tmp_path / "poc-source"
    stale = root / "owner__repo"
    stale.mkdir(parents=True)
    (stale / "truncated.py").write_text("half a file")

    client = _client(tmp_path, _tar_bytes({"repo/exploit.py": b"complete"}))
    src = client.fetch("owner", "repo")

    assert src.cached is False
    assert not (src.path / "truncated.py").exists()
    assert (src.path / "repo" / "exploit.py").exists()


def test_completed_fetch_writes_a_marker(tmp_path: Path, enabled: None) -> None:
    client = _client(tmp_path, _tar_bytes({"repo/exploit.py": b"x"}))
    src = client.fetch("owner", "repo")
    assert (src.path / ".pocmap-fetch").exists()


def test_no_staging_directory_survives_a_successful_fetch(
    tmp_path: Path, enabled: None
) -> None:
    client = _client(tmp_path, _tar_bytes({"repo/exploit.py": b"x"}))
    client.fetch("owner", "repo")
    assert not list((tmp_path / "poc-source").glob("*.partial"))


def test_archive_permissions_are_normalized(tmp_path: Path, enabled: None) -> None:
    """The <3.10.12 fallback applies archive modes; setuid must not survive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("repo/suid")
        info.size = 2
        info.mode = 0o4755  # setuid
        info.uid = info.gid = 0
        tar.addfile(info, io.BytesIO(b"hi"))
    client = _client(tmp_path, buf.getvalue())

    src = client.fetch("owner", "repo")
    mode = (src.path / "repo" / "suid").stat().st_mode
    assert not mode & 0o4000, "setuid bit survived extraction"


def test_falls_back_to_head_for_a_non_standard_default_branch(
    tmp_path: Path, enabled: None
) -> None:
    """Not every repo defaults to main or master.

    Karmakstylez/CVE-2024-6387 (187 stars) defaults to `production` and was
    unreachable, surfacing as a fetch error that silently dropped a real PoC.
    `HEAD` resolves whatever the default actually is.
    """
    blob = _tar_bytes({"repo/exploit.py": b"x"})
    http = MagicMock()
    tried: list[str] = []

    def fake_get(url: str, **_: Any) -> Any:
        tried.append(url.rsplit("/tar.gz/", 1)[-1])
        if not url.endswith("/HEAD"):
            raise HTTPError("404", status_code=404)
        resp = MagicMock()
        resp.status_code = 200
        resp.iter_content.return_value = [blob]
        return resp

    http.get.side_effect = fake_get
    client = CodeloadClient(http_client=http, dest_root=tmp_path / "poc-source")

    src = client.fetch("owner", "repo")
    assert src.branch == "HEAD"
    assert tried == ["refs/heads/main", "refs/heads/master", "HEAD"]


def test_head_is_tried_last_so_common_repos_cost_one_request(
    tmp_path: Path, enabled: None
) -> None:
    http = MagicMock()
    tried: list[str] = []
    blob = _tar_bytes({"repo/exploit.py": b"x"})

    def fake_get(url: str, **_: Any) -> Any:
        tried.append(url.rsplit("/tar.gz/", 1)[-1])
        resp = MagicMock()
        resp.status_code = 200
        resp.iter_content.return_value = [blob]
        return resp

    http.get.side_effect = fake_get
    client = CodeloadClient(http_client=http, dest_root=tmp_path / "poc-source")

    assert client.fetch("owner", "repo").branch == "main"
    assert tried == ["refs/heads/main"]


def test_total_budget_evicts_oldest_first(
    tmp_path: Path, enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "poc-source"
    root.mkdir(parents=True)
    for i, name in enumerate(("old__a", "new__b")):
        d = root / name
        d.mkdir()
        (d / "f.bin").write_bytes(b"\x00" * (600 * 1024))
        # Only marked (pocmap-created) directories are eviction candidates.
        (d / ".pocmap-fetch").write_text("")
        # Deterministic ordering: "old__a" is older.
        import os
        os.utime(d, (1000 + i, 1000 + i))

    _patch_settings(monkeypatch, allow_fetch_poc_source=True, poc_source_total_max_mb=1)
    client = _client(tmp_path, _tar_bytes({"repo/x.py": b"x"}))
    client.fetch("owner", "repo")

    assert not (root / "old__a").exists()
    assert (root / "new__b").exists()
