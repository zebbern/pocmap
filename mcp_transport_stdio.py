#!/usr/bin/env python3
"""PocMap AI MCP Server - STDIO Transport for Claude Desktop Integration.

This script runs the MCP server over STDIO, which is the standard transport
for Claude Desktop and other MCP clients that communicate via standard input/output.

Usage:
    python mcp_transport_stdio.py

For Claude Desktop, add this to your claude_desktop_config.json:
    {
        "mcpServers": {
            "pocmap": {
                "command": "python",
                "args": ["/path/to/pocmap/mcp_transport_stdio.py"]
            }
        }
    }

The server will read JSON-RPC messages from stdin and write responses to stdout.
All logging is directed to stderr to avoid interfering with the protocol.
"""

from __future__ import annotations

import logging
import sys
import os

# Ensure the server directory is on the path
_SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

# Also ensure src/ is on path for the real pocmap package
_SRC_DIR = os.path.join(_SERVER_DIR, "src")
if os.path.exists(_SRC_DIR) and _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

# Send all logging to stderr so stdout is clean for MCP protocol
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pocmap-stdio")


def main():
    """Run the MCP server with STDIO transport."""
    logger.info("PocMap MCP STDIO Transport starting...")

    try:
        import mcp_server
        logger.info("Starting MCP server with STDIO transport")
        mcp_server.mcp.run(transport="stdio")
    except KeyboardInterrupt:
        logger.info("Shutting down (KeyboardInterrupt)")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
