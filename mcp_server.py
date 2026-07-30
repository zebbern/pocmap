#!/usr/bin/env python3
"""Repo-root launcher for the PocMap MCP server.

The real implementation lives in ``pocmap.mcp_server`` (installed with the
package). This shim keeps ``python mcp_server.py`` working for local checkouts.
"""

from __future__ import annotations

from pocmap.mcp_server import main

if __name__ == "__main__":
    main()
