"""Fast-track tests: vol3 engine (fake stub), MCP tools in memory, HTTP auth."""
import json
import stat

import pytest
from mcp import Client
from starlette.testclient import TestClient

from forensic_mcp import results, safety, server, web
from forensic_mcp.engines import volatility3

pytestmark = pytest.mark.anyio
SHA = "a" * 64


async def _run(cfg, plugin, pid=None):
    path = volatility3.image_path(cfg, "mem.raw")
    return await volatility3.run(cfg, path, plugin, pid, SHA)


async def test_plugins_parsed_and_resolved(cfg) -> None:
    plugins = await volatility3.list_plugins(cfg)
    assert "windows.netscan.NetScan" in plugins and len(plugins) == 9
    assert plugins["windows.malfind.Malfind"]["deprecated"]
    assert await volatility3.version(cfg) == "2.28.2"
    r = volatility3.resolve_plugin
    assert r("windows.pslist", plugins) == "windows.pslist.PsList"
    assert r("netscan", plugins) == "windows.netscan.NetScan"
    assert r("windows.malfind", plugins) == "windows.malware.malfind.Malfind"
    for bad in ("pslist", "nope", "windows.pslist;id", "-l"):
        with pytest.raises(ValueError):
            r(bad, plugins)


async def test_run_flattens_children_with_depth(cfg) -> None:
    out = await _run(cfg, "windows.pstree")
    assert out["row_count"] == 4 and out["exit_code"] == 0
    rows = results.query(out["dir"])["rows"]
    assert [(x["_row"], x["PID"], x["depth"]) for x in rows] == [
        (1, 4, 0), (2, 252, 1), (3, 340, 2), (4, 500, 0)]
    meta = json.loads((out["dir"] / "meta.json").read_text())
    assert meta["tool_version"] == "2.28.2" and meta["input_sha256"] == SHA
    assert meta["argv"][-1] == "windows.pstree.PsTree" and "-o" in meta["argv"]


async def test_run_pid_and_jail(cfg) -> None:
    out = await _run(cfg, "windows.pslist", pid=3496)
    rows = results.query(out["dir"])["rows"]
    assert out["row_count"] == 1 and rows[0]["ImageFileName"] == "UWkpjFjDzM.exe"
    with pytest.raises(safety.SafetyError):
        volatility3.image_path(cfg, "../tools.toml")
    with pytest.raises(ValueError):
        await _run(cfg, "windows.pslist", pid=-1)


async def test_big_int_addresses_are_exact_hex(cfg) -> None:
    d = (await _run(cfg, "windows.pslist"))["dir"]
    first = results.query(d)["rows"][0]
    assert first["Offset(V)"] == "0xfffffa800577ba10"  # not 18446738026487330000
    assert first["Threads"] == 87 and first["PID"] == 4  # small ints stay ints
    raw = (d / "rows.jsonl").read_text()
    assert '"0xfffffa800577ba10"' in raw and "18446738026487331344" not in raw
    for wanted in ("0xfffffa800577ba10", "0xFFFFFA800577BA10", str(0xFFFFFA800577BA10)):
        q = results.query(d, column="Offset(V)", equals=wanted)
        assert [r["PID"] for r in q["rows"]] == [4], wanted
    assert results.query(d, column="Offset(V)", equals="18446738026487330000")["matched"] == 0
    s = results.query(d, sort_by="Offset(V)", sort_desc=True, limit=1)
    assert s["rows"][0]["PID"] == 4  # hex sorted numerically (0x...ba10 > 0x...b060)


async def test_mcp_lists_tools_and_runs(cfg) -> None:
    mcp = server.build_server(cfg)
    async with Client(mcp) as client:
        names = sorted(t.name for t in (await client.list_tools()).tools)
        assert names == sorted(server.TOOL_NAMES)
        r = await client.call_tool("memory_run", {"path": "mem.raw", "plugin": "netscan"})
        # fake stub fails on netscan: reported as a result with exit code + stderr, not a crash
        assert not r.is_error and r.structured_content["exit_code"] == 1
        assert "unsupported plugin" in r.structured_content["stderr_tail"]
        r = await client.call_tool("memory_run", {"path": "mem.raw", "plugin": "windows.pslist"})
        rid = r.structured_content["result_id"]
        q = await client.call_tool("query_results", {"result_id": rid, "contains": "uwkp"})
        assert q.structured_content["row_count"] == 1
        assert q.structured_content["rows"][0]["_row"] == 2
        ev = await client.call_tool("list_evidence", {})
        assert ev.structured_content["rows"][0]["path"] == "mem.raw"
        bad = await client.call_tool("list_evidence", {"subdir": "../"})
        assert bad.is_error


def test_http_auth_health_and_home(cfg) -> None:
    cfg.allowed_origins = [*cfg.allowed_origins, "http://localhost:3000"]
    app = web.build_app(server.build_server(cfg), cfg)
    token = cfg.api_token_file.read_text().strip()
    assert stat.S_IMODE(cfg.api_token_file.stat().st_mode) == 0o600 and len(token) >= 40
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "t", "version": "0"}}}
    hdrs = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    with TestClient(app, base_url="http://localhost:8000") as c:
        assert c.get("/health").status_code == 200
        home = c.get("/")
        assert home.status_code == 200 and "memory_run" in home.text
        assert c.post("/mcp", json=init, headers=hdrs).status_code == 401
        assert c.post("/mcp", json=init, headers={**hdrs, "Authorization": "Bearer nope"}
                      ).status_code == 401
        auth = {**hdrs, "Authorization": f"Bearer {token}"}
        ok = c.post("/mcp", json=init, headers=auth)
        assert ok.status_code == 200, ok.text
        # hosts/origins come from config: unlisted Host or Origin refused even with a token
        evil_host = c.post("/mcp", json=init, headers={**auth, "Host": "evil.example:8000"})
        assert evil_host.status_code in (400, 421)
        evil_origin = c.post("/mcp", json=init, headers={**auth, "Origin": "http://evil.example"})
        assert evil_origin.status_code in (400, 403)
        webui = c.post("/mcp", json=init, headers={**auth, "Origin": "http://localhost:3000"})
        assert webui.status_code == 200
    # token is reused on restart
    assert web.load_or_create_token(cfg.api_token_file) == token
