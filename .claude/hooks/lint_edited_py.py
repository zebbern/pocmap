#!/usr/bin/env python
"""PostToolUse hook: auto-fix lint on edited Python, type-check if available.

pocmap configures ruff (line-length 100; rules E,F,W,I,N,UP,B,C4,SIM) and
mypy --strict in pyproject.toml, but nothing runs them automatically. This
hook runs them on the single file that was just edited.

Design choices:
  * Non-blocking: always exits 0. Lint findings are advisory (printed to
    stderr); they never stop the session.
  * ``ruff check --fix`` only (safe autofixes). It does NOT run ``ruff format``,
    to avoid imposing a formatter the project hasn't opted into.
  * Each tool is skipped silently if not installed (mypy is commonly absent
    from the active env here), so the hook degrades gracefully.

Wired as a PostToolUse hook for Edit|Write|MultiEdit in .claude/settings.json.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


def _run(tool: str, args: list[str]) -> None:
    exe = shutil.which(tool)
    if not exe:
        return
    try:
        proc = subprocess.run(
            [exe, *args],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as exc:  # noqa: BLE001 - advisory hook, never fatal
        sys.stderr.write(f"[{tool}] skipped: {exc}\n")
        return
    out = (proc.stdout + proc.stderr).strip()
    if out and proc.returncode != 0:
        sys.stderr.write(f"[{tool}] {out}\n")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    file_path = payload.get("tool_input", {}).get("file_path", "")
    if not file_path or not file_path.endswith(".py"):
        return 0
    if not Path(file_path).exists():
        return 0

    _run("ruff", ["check", "--fix", file_path])
    _run("mypy", [file_path])
    return 0


if __name__ == "__main__":
    sys.exit(main())
