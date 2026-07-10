#!/usr/bin/env python
"""PreToolUse guard: block reads/writes to secrets and cache files.

pocmap loads API tokens from a repo-root ``.env`` (POCMAP_GITHUB_API_TOKEN /
GITHUB_API_TOKEN / POCMAP_NVD_API_KEY / NVD_API_KEY) and writes fetched vuln
data under ``.cache/``. Editing, reading, or diffing those files risks leaking
live credentials into the transcript. This hook denies the tool call for a
small set of sensitive paths.

Wired as a PreToolUse hook for Edit|Write|MultiEdit|Read in
.claude/settings.json. Exit 2 = block (reason on stderr); exit 0 = allow.
Fails open on any internal error so a hook bug can never brick editing.
"""
from __future__ import annotations

import json
import sys
from pathlib import PurePath


def _is_sensitive(raw_path: str) -> str | None:
    """Return a human reason if the path is sensitive, else None."""
    if not raw_path:
        return None
    p = PurePath(raw_path.replace("\\", "/"))
    name = p.name.lower()
    parts = {seg.lower() for seg in p.parts}

    # Any .env file: .env, .env.local, .env.production, secrets.env, ...
    if name == ".env" or name.startswith(".env") or name.endswith(".env"):
        return f"{p.name} may contain POCMAP_/NVD/GITHUB API tokens"
    # The project cache directory (see config.py: cache_dir = PROJECT_ROOT/.cache)
    if ".cache" in parts:
        return "files under .cache/ hold fetched vulnerability data, not source"
    # Common credential material
    if name in {"credentials", "credentials.json", "secrets.json", "id_rsa", ".netrc"}:
        return f"{p.name} is a credential file"
    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # fail open: never block on a parse error
    file_path = payload.get("tool_input", {}).get("file_path", "")
    reason = _is_sensitive(file_path)
    if reason:
        tool = payload.get("tool_name", "tool")
        sys.stderr.write(
            f"Blocked {tool} on '{file_path}': {reason}. "
            "If you truly need it, ask the user to act on this file manually.\n"
        )
        return 2  # block the tool call
    return 0


if __name__ == "__main__":
    sys.exit(main())
