#!/usr/bin/env python3
"""PocMap AI MCP Server - SSE (Server-Sent Events) Transport.

This script runs the MCP server over SSE transport, enabling remote access
via HTTP. The SSE transport provides:
- Real-time bidirectional communication over HTTP
- Support for multiple concurrent client connections
- Compatibility with browser-based and remote MCP clients
- A built-in Starlette/FastAPI application with health endpoints

Usage:
    python mcp_transport_sse.py                # Run on 127.0.0.1:8000
    python mcp_transport_sse.py --host 0.0.0.0 # Bind to all interfaces
    python mcp_transport_sse.py --port 9000    # Run on port 9000
    python mcp_transport_sse.py --debug        # Enable debug logging

The server exposes:
    GET  /sse      - SSE endpoint for MCP communication
    POST /messages - Message endpoint for sending commands
    GET  /health   - Health check endpoint

Environment Variables:
    POCMAP_HOST - Server host (overrides --host)
    POCMAP_PORT - Server port (overrides --port)
    POCMAP_DEBUG - Set to "1" to enable debug logging
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

# Ensure the server directory is on the path
_SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

# Also ensure src/ is on path for the real pocmap package
_SRC_DIR = os.path.join(_SERVER_DIR, "src")
if os.path.exists(_SRC_DIR) and _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pocmap-sse")


def main():
    """Run the MCP server with SSE transport."""
    parser = argparse.ArgumentParser(
        description="PocMap AI MCP Server - SSE Transport",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python mcp_transport_sse.py                    # Default: 127.0.0.1:8000
  python mcp_transport_sse.py --host 0.0.0.0     # Bind to all interfaces
  python mcp_transport_sse.py --port 9000        # Custom port
  python mcp_transport_sse.py --debug            # Debug logging
        """,
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("POCMAP_HOST", "127.0.0.1"),
        help="Host to bind to (default: 127.0.0.1, env: POCMAP_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("POCMAP_PORT", "8000")),
        help="Port to bind to (default: 8000, env: POCMAP_PORT)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=os.environ.get("POCMAP_DEBUG", "") == "1",
        help="Enable debug logging (env: POCMAP_DEBUG=1)",
    )
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info(f"PocMap MCP SSE Transport starting on {args.host}:{args.port}")

    try:
        import mcp_server as ms

        ms.mcp.host = args.host
        ms.mcp.port = args.port

        logger.info(f"SSE endpoint: http://{args.host}:{args.port}/sse")
        logger.info(f"Message endpoint: http://{args.host}:{args.port}/messages/")
        logger.info("Press Ctrl+C to stop")

        ms.mcp.run(transport="sse")

    except KeyboardInterrupt:
        logger.info("Shutting down (KeyboardInterrupt)")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
