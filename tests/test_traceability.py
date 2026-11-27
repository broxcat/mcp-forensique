"""ET-04 / objective 3 (100 % of calls traced), audit 27/11/2026 P1."""
import asyncio

import pytest
from mcp import Client
from mcp.server.mcpserver.exceptions import ToolError

from forensic_mcp import audit, results, server
from forensic_mcp.ops import Engine

pytestmark = pytest.mark.anyio


def _events(cfg, type_=None):
    return [e for e in audit.iter_events(cfg.audit_file) if type_ in (None, e["type"])]


# ---- sealing inside the journaled try ------------------------------------------------------
async def test_sealing_failure_is_journaled_and_the_result_refused(cfg, monkeypatch) -> None:
    def broken(d):
        raise OSError("cannot read result file")

    monkeypatch.setattr(results, "manifest", broken)
    async with Client(server.build_server(cfg)) as c:
        r = await c.call_tool("vol3_run", {"path": "mem.raw", "plugin": "windows.pslist"})
        assert r.is_error
        call = _events(cfg, "tool_call")[-1]
        assert call["outcome"] == "tool_error"
        assert call["error"].startswith("result sealing failed: OSError")
        assert call["result_id"] and "result_manifest" not in call
        assert f"audit_id {call['audit_id']}" in r.content[0].text
        monkeypatch.undo()  # the real manifest again: the unsealed result stays refused
        q = await c.call_tool("query_results", {"result_id": call["result_id"]})
    assert q.is_error and _events(cfg, "tool_call")[-1]["outcome"] == "refused"
    assert audit.verify_report(cfg.audit_file)["ok"]


# ---- start journaled before the tool runs ---------------------------------------------------
class Killed(BaseException):
    """Stands for a process killed mid-call: no handler of Engine.call runs."""


async def test_every_call_is_paired_with_an_earlier_start(cfg) -> None:
    async with Client(server.build_server(cfg)) as c:
        await c.call_tool("tool_status", {})
        await c.call_tool("vol3_run", {"path": "mem.raw", "plugin": "windows.pslist"})
        await c.call_tool("vol3_run", {"path": "mem.raw", "plugin": "banners"})       # tool_error
        await c.call_tool("vol3_run", {"path": "../tools.toml", "plugin": "pslist"})  # refused
    starts = {e["audit_id"]: e for e in _events(cfg, "tool_call_started")}
    calls = [e for e in _events(cfg, "tool_call") if e["actor"]["kind"] == "llm"]
    assert [e["outcome"] for e in calls] == ["ok", "ok", "tool_error", "refused"]
    for call in calls:
        start = starts[call["started_audit_id"]]
        assert start["tool"] == call["tool"] and start["audit_id"] < call["audit_id"]
    assert len(starts) == len(calls) and audit.unfinished_calls(cfg.audit_file) == []
    report = audit.verify_report(cfg.audit_file)  # schema includes the new event type
    assert report["ok"], report


async def test_start_is_on_disk_while_the_tool_runs_and_survives_a_kill(cfg) -> None:
    eng, seen = Engine(cfg), []

    async def op(params, conf=None):
        seen.append(_events(cfg)[-1])  # what an observer finds DURING the run
        raise Killed()

    eng.op_tool_status = op
    with pytest.raises(Killed):
        await eng.call("tool_status", {})
    assert seen[0]["type"] == "tool_call_started" and seen[0]["tool"] == "tool_status"
    assert not _events(cfg, "tool_call")  # nothing could write the end...
    left = audit.unfinished_calls(cfg.audit_file)  # ...but the call is not lost
    assert [e["audit_id"] for e in left] == [seen[0]["audit_id"]]
    assert audit.verify_report(cfg.audit_file)["ok"]


async def test_cancelled_call_is_journaled_as_interrupted(cfg) -> None:
    eng = Engine(cfg)

    async def op(params, conf=None):
        raise asyncio.CancelledError()

    eng.op_tool_status = op
    with pytest.raises(asyncio.CancelledError):
        await eng.call("tool_status", {})
    call = _events(cfg, "tool_call")[-1]
    assert call["outcome"] == "tool_error" and call["error"] == "interrupted (CancelledError)"
    assert audit.unfinished_calls(cfg.audit_file) == []


async def test_no_journal_means_no_execution(cfg, monkeypatch) -> None:
    eng, ran = Engine(cfg), []

    async def op(params, conf=None):
        ran.append(True)

    eng.op_tool_status = op

    def broken(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(audit, "append", broken)
    with pytest.raises(ToolError, match="journal unavailable"):
        await eng.call("tool_status", {})
    assert ran == []


async def test_tool_status_counts_unfinished_calls(cfg) -> None:
    audit.append(cfg.audit_file, "tool_call_started", {"kind": "llm"}, tool="x", params={})
    async with Client(server.build_server(cfg)) as c:
        notes = (await c.call_tool("tool_status", {})).structured_content["notes"]
    # the orphan start above + this tool_status call itself, still running when it counts
    assert "2 journaled call(s) started without an end (still running or interrupted)" in notes
    assert len(audit.unfinished_calls(cfg.audit_file)) == 1  # once tool_status has ended
