"""Entry point: `python -m forensic_mcp [--http | --stdio]` (default --http), or
`python -m forensic_mcp validate` (analyst-only, interactive terminal, outside MCP)."""
from __future__ import annotations

import argparse
import sys

import anyio

from .config import load_config
from .server import build_server


def main(argv: list[str] | None = None) -> int:
    """Parse the transport flag and start the server."""
    p = argparse.ArgumentParser(prog="forensic_mcp")
    p.add_argument("command", nargs="?", choices=["validate"],
                   help="validate = analyst validation of findings (interactive terminal only)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--http", action="store_true", help="Streamable HTTP on http_host:http_port")
    g.add_argument("--stdio", action="store_true", help="stdio transport (local MCP clients)")
    args = p.parse_args(argv)
    cfg = load_config()
    if args.command == "validate":
        from .validation import run_cli  # never imported by the MCP server

        return run_cli(cfg)
    mcp = build_server(cfg)
    if args.stdio:
        anyio.run(mcp.run_stdio_async)
    else:
        from .web import serve

        serve(mcp, cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
