"""HTTP app: MCP streamable HTTP at /mcp, bearer-token middleware, /health and a home page."""
from __future__ import annotations

import hmac
import html
import json
import os
import secrets
from pathlib import Path
from typing import Any, Awaitable, Callable

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response

from .config import Config

PUBLIC_GET_PATHS = {"/health", "/"}
Scope = dict[str, Any]
ASGIApp = Callable[[Scope, Callable[[], Awaitable[dict]], Callable[[dict], Awaitable[None]]],
                   Awaitable[None]]


def load_or_create_token(path: Path) -> str:
    """Read the API token, creating it (0600, token_urlsafe(32)) on first start."""
    path = Path(path)
    if path.exists():
        token = path.read_text(encoding="utf-8").strip()
        if token:
            return token
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    token = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token + "\n")
    os.chmod(path, 0o600)
    return token


class BearerAuth:
    """ASGI middleware: every request needs `Authorization: Bearer <token>`,
    except GET /health and GET /. Lifespan events pass through."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app = app
        self.token = token.encode()

    async def __call__(self, scope: Scope, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if (scope["type"] == "http" and scope.get("method") == "GET"
                and scope.get("path") in PUBLIC_GET_PATHS):
            return await self.app(scope, receive, send)
        if scope["type"] == "http" and self._authorized(scope):
            return await self.app(scope, receive, send)
        if scope["type"] != "http":  # websocket or unknown: refuse
            await send({"type": "websocket.close", "code": 1008})
            return
        body = json.dumps({"error": "unauthorized"}).encode()
        await send({"type": "http.response.start", "status": 401, "headers": [
            (b"content-type", b"application/json"), (b"www-authenticate", b"Bearer"),
            (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    def _authorized(self, scope: Scope) -> bool:
        for name, value in scope.get("headers", []):
            if name == b"authorization" and value[:7].lower() == b"bearer ":
                return hmac.compare_digest(value[7:].strip(), self.token)
        return False


def _home_page(mcp: MCPServer, tools: list[tuple[str, str]]) -> str:
    items = "".join(f"<li><code>{html.escape(n)}</code> — {html.escape(d)}</li>"
                    for n, d in tools)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>forensic-mcp</title>
<style>body{{font-family:system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem}}
code{{background:#eee;padding:0 .25rem}}</style></head><body>
<h1>{html.escape(mcp.name)}</h1>
<p>MCP endpoint: <code>http://localhost:8000/mcp</code> (Streamable HTTP,
header <code>Authorization: Bearer &lt;token&gt;</code>).</p>
<h2>Tools</h2><ul>{items}</ul></body></html>"""


def build_app(mcp: MCPServer, cfg: Config) -> BearerAuth:
    """Starlette MCP app wrapped in the bearer-token middleware."""
    token = load_or_create_token(cfg.api_token_file)

    @mcp.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    @mcp.custom_route("/", methods=["GET"])
    async def home(request: Request) -> Response:
        tools = [(t.name, (t.description or "").split("\n")[0]) for t in await mcp.list_tools()]
        return HTMLResponse(_home_page(mcp, tools))

    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=list(cfg.allowed_hosts),
        allowed_origins=list(cfg.allowed_origins))
    app = mcp.streamable_http_app(streamable_http_path="/mcp", transport_security=security)
    return BearerAuth(app, token)


def serve(mcp: MCPServer, cfg: Config) -> None:
    """Run the HTTP app with uvicorn on cfg.http_host:cfg.http_port."""
    import uvicorn

    uvicorn.run(build_app(mcp, cfg), host=cfg.http_host, port=cfg.http_port)
