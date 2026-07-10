"""Path-safety helpers shared across the toolkit.

Single source of truth for filesystem path validation. Consolidates the
previously duplicated ``_safe_path`` implementations from
``pocmap.bugbounty.automation`` and ``pocmap.bugbounty.templates``.

Example::

    from pocmap.utils.paths import safe_path

    dest = safe_path("report.md")            # -> absolute path under CWD
    safe_path("../../etc/passwd")            # -> raises ValueError
    safe_path("file\\x00.txt")               # -> raises ValueError
"""

from __future__ import annotations

import os


def safe_path(filepath: str, base_dir: str | None = None) -> str:
    """Validate *filepath* against path-traversal and null-byte attacks.

    Args:
        filepath: The (possibly user/CVE-derived) path to validate.
        base_dir: Directory the resolved path must stay within.
                  Defaults to the current working directory.

    Returns:
        The absolute, normalized path when it is safe.

    Raises:
        ValueError: If *filepath* contains a null byte, or if the resolved
            target escapes *base_dir* (path traversal).
    """
    if "\x00" in filepath:
        raise ValueError(f"Null byte detected in path: {filepath!r}")
    base = os.path.abspath(base_dir or os.getcwd())
    target = os.path.abspath(os.path.join(base, filepath))
    # Ensure target is within base directory
    if not target.startswith(base + os.sep) and target != base:
        raise ValueError(f"Path traversal detected: {filepath}")
    return target
