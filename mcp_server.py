#!/usr/bin/env python3
"""Repo-root launcher for the PocMap MCP server.

The real implementation lives in ``pocmap.mcp_server``. This shim keeps
``python mcp_server.py`` working in a git checkout, including one that has not
been ``pip install``-ed: it puts ``src/`` on ``sys.path`` first, so a bare clone
needs only the ``mcp`` SDK rather than a full install.

Everything else — transports, host/port, flags — is handled by
``pocmap.mcp_server.main``, so this file has no options of its own::

    python mcp_server.py                        # STDIO (default)
    python mcp_server.py --transport sse
    python mcp_server.py --transport http --port 9000

Installed users should prefer the ``pocmap-mcp`` console script.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Prefer the checkout's own src/ over any installed copy, so running from a
# clone tests the code in front of you. Harmless when pocmap is installed.
_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from pocmap.mcp_server import main  # noqa: E402  (must follow the sys.path bootstrap)

if __name__ == "__main__":
    main()
