"""MCPServer instance, lifespan, and CLI entry point."""

from __future__ import annotations

import argparse
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.lowlevel.server import CacheHint  # type: ignore[attr-defined]
from mcp.server.mcpserver import MCPServer

from pocmap import __version__
from pocmap.mcp.adapter import ServiceAdapter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pocmap-mcp")

_svc = ServiceAdapter()


@asynccontextmanager
async def app_lifespan(server: MCPServer) -> AsyncIterator[dict[str, Any]]:
    """Manage application lifecycle."""
    logger.info("PocMap MCP Server starting up...")
    yield {"services": _svc}
    logger.info("PocMap MCP Server shutting down...")
    _svc.close()


mcp = MCPServer(
    "PocMap",
    instructions=(
        "You are an AI security assistant with access to the PocMap toolkit. "
        "You can look up CVE details from NVD, CVE.org, CISA KEV, and EPSS sources; "
        "find exploits and PoCs from GitHub, Metasploit, ExploitDB, and Nuclei; "
        "discover bug bounty reports from HackerOne and PentesterLand; "
        "find practice labs on Vulhub and HackTheBox; "
        "convert between CVEs and CPEs; and generate vulnerability reports. "
        "Always verify CVE IDs are in the correct format (CVE-YYYY-NNNN+) before querying. "
        "When a user asks about a vulnerability, provide comprehensive context including "
        "CVSS scores, EPSS scores, KEV status, available exploits, and practice environments."
    ),
    lifespan=app_lifespan,
    # Bind address is no longer constructor state: the 2026-07-28 protocol core
    # is stateless, so host/port belong to the transport and are passed to
    # ``run()`` by :func:`main`. STDIO (the default) takes neither.
    version=__version__,
    # Every list here is fixed at import — 22 tools, 3 prompts and 3 resource
    # templates registered by decorator, with no runtime mutation and no
    # list_changed notification anywhere. Without a hint the SDK advertises
    # ttlMs 0, i.e. "already stale", so a client re-fetches an unchanging list
    # on every reconnect. "public" because the lists do not vary by caller.
    #
    # These take effect only once a client negotiates 2026-07-28. Over STDIO
    # today the ``initialize`` handshake settles on 2025-11-25 (verified), so
    # the hints are currently inert — declared now so the behaviour is right
    # the moment a client speaks the newer revision.
    cache_hints={
        "tools/list": CacheHint(ttl_ms=3_600_000, scope="public"),
        "prompts/list": CacheHint(ttl_ms=3_600_000, scope="public"),
        "resources/templates/list": CacheHint(ttl_ms=3_600_000, scope="public"),
    },
)

def main() -> None:
    """Run the MCP server with the specified transport."""
    parser = argparse.ArgumentParser(
        description="PocMap AI MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pocmap-mcp                                     # STDIO transport (default)
  pocmap-mcp --transport sse                     # SSE transport on port 8000
  pocmap-mcp --transport http                    # Streamable HTTP transport
  pocmap-mcp --host 0.0.0.0 --port 9000 --transport sse
        """,
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "http"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to for SSE/HTTP transports (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to for SSE/HTTP transports (default: 8000)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("Starting PocMap MCP Server with %s transport", args.transport)

    # ``--transport http`` is the user-facing spelling; the SDK calls it
    # "streamable-http". Passing the CLI value straight through raised
    # ``ValueError: Unknown transport: http``, so the documented HTTP transport
    # never actually started.
    transport = "streamable-http" if args.transport == "http" else args.transport

    if transport == "stdio":
        # STDIO has no bind address; passing host/port would be a TypeError.
        mcp.run(transport="stdio")
    elif transport == "sse":
        mcp.run(transport="sse", host=args.host, port=args.port)
    else:
        mcp.run(transport="streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
