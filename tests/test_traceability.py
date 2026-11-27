"""ET-04 / objective 3 (100 % of calls traced), audit 27/11/2026 P1."""
import pytest
from mcp import Client

from forensic_mcp import audit, results, server

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
