"""Native pytest regression tests for the shared path-safety guard.

Locks in ``pocmap.utils.paths.safe_path`` — the single source of truth for the
path-traversal / null-byte check used by report + template writers. These are
REAL asserts (the guard was previously only exercised by copies), so a
regression that weakens the check will fail CI.

Fully offline: no file is ever created; only path *strings* are validated.
"""

from __future__ import annotations

import os

import pytest

from pocmap.utils.paths import safe_path


def test_traversal_relative_escape_raises() -> None:
    with pytest.raises(ValueError, match="traversal"):
        safe_path("../../../etc/passwd")


def test_null_byte_raises() -> None:
    with pytest.raises(ValueError, match="[Nn]ull byte"):
        safe_path("file\x00.txt")


def test_plain_relative_name_returns_absolute_under_base() -> None:
    base = os.getcwd()
    result = safe_path("report.md")
    assert os.path.isabs(result)
    assert result.startswith(base + os.sep)
    assert result == os.path.join(base, "report.md")


def test_explicit_base_dir_is_honored(tmp_path) -> None:
    base = str(tmp_path)
    result = safe_path("report.md", base_dir=base)
    assert result == os.path.join(os.path.abspath(base), "report.md")


def test_escaping_explicit_base_dir_raises(tmp_path) -> None:
    base = str(tmp_path / "base")
    os.makedirs(base, exist_ok=True)
    with pytest.raises(ValueError, match="traversal"):
        safe_path("../x", base_dir=base)


def test_sibling_prefix_escape_is_blocked(tmp_path) -> None:
    """A sibling dir that shares the base as a *prefix* must not slip through.

    base=.../base, filepath='../basement/x' resolves to .../basement/x which
    is NOT inside .../base even though it starts with the same characters.
    """
    base = str(tmp_path / "base")
    os.makedirs(base, exist_ok=True)
    with pytest.raises(ValueError, match="traversal"):
        safe_path("../basement/x", base_dir=base)


def test_absolute_path_outside_base_raises(tmp_path) -> None:
    base = str(tmp_path / "base")
    os.makedirs(base, exist_ok=True)
    outside = "C:\\Windows\\system32" if os.name == "nt" else "/etc/passwd"
    with pytest.raises(ValueError, match="traversal"):
        safe_path(outside, base_dir=base)


def test_base_equals_target_returns_base(tmp_path) -> None:
    base = str(tmp_path)
    result = safe_path(".", base_dir=base)
    assert result == os.path.abspath(base)


def test_nested_subdir_resolves_under_base(tmp_path) -> None:
    base = str(tmp_path)
    result = safe_path("sub/report.md", base_dir=base)
    assert result.startswith(os.path.abspath(base) + os.sep)
    assert result == os.path.join(os.path.abspath(base), "sub", "report.md")
