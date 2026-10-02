"""4.4: record_finding cross-check details, findings in cloud mode, paging (EF-04), and the
ET-09 rule "at least one test per exposed tool"."""
import re
from pathlib import Path

import pytest
from mcp import Client

from forensic_mcp import audit, schemas, server
from forensic_mcp.findings_ops import value_matches

pytestmark = pytest.mark.anyio
TESTS = Path(__file__).parent


async def _call(cfg, tool, args):
    async with Client(server.build_server(cfg)) as c:
        r = await c.call_tool(tool, args)
    assert not r.is_error, r.content[0].text
    assert schemas.errors(schemas.output_validator(), r.structured_content) == []
    return r.structured_content


def test_value_matches() -> None:
    assert value_matches("powershell.exe", "PowerShell.EXE") == "exact"
    assert value_matches("0xfffffa800577ba10", str(0xFFFFFA800577BA10)) == "numeric"
    assert value_matches(443, "443") in ("exact", "numeric")
    assert value_matches("2019-03-22 05:31:55 UTC+0000", "2019-03-22T05:31:55Z") == "time"
    assert value_matches("2026-10-06T14:32:07.0000000+00:00", "2026-10-06T14:32:07Z") == "time"
    long_cell = "powershell.exe -NoP -W Hidden -f C:\\Users\\Public\\upd.ps1 " + "x" * 40
    assert value_matches(long_cell, "C:\\Users\\Public\\upd.ps1") == "partial"
    assert value_matches("203.0.113.10", "203.0.113") is None  # no partial on short cells
    assert value_matches("2026-10-06T14:32:07Z", "2026-10-06T14:35:00Z") is None


async def test_findings_cite_tokens_in_cloud_mode_and_journal_real_values(cfg) -> None:
    case = Path(cfg.evidence_root) / "WS-042"
    case.mkdir()
    (case / "mem.raw").write_bytes(b"\1" * 64)
    (case / "case.toml").write_text('case = "WS-042"\nclassification = "internal"\n'
                                    'hosts = ["WS-042"]\n')
    cfg.llm_mode = "cloud"
    r = await _call(cfg, "vol_cmdline", {"path": "WS-042/mem.raw"})
    row = r["rows"][0]
    assert row["UserName"] == "USER_1"
    f = await _call(cfg, "record_finding", {
        "kind": "fact", "text": "USER_1 ran PowerShell on HOST_1", "confidence": "medium",
        "citations": [{"result_id": r["result_id"], "row": row["_row"], "field": "UserName",
                       "value": "USER_1"}]})
    assert "à valider" in f["summary"]
    sug = [e for e in audit.iter_events(cfg.audit_file) if e["type"] == "suggestion"][-1]
    assert sug["citations"][0]["value"] == "alice" and sug["text"] == "alice ran PowerShell on WS-042"


async def test_listing_paging_with_next_call(cfg) -> None:
    p1 = await _call(cfg, "tool_status", {"limit": 2})
    assert [r["_row"] for r in p1["rows"]] == [1, 2] and p1["row_count"] > 2
    assert p1["page"]["next_call"] == {"tool": "tool_status", "args": {"offset": 2, "limit": 2}}
    p2 = await _call(cfg, "tool_status", p1["page"]["next_call"]["args"])
    assert [r["_row"] for r in p2["rows"]] == [3, 4]
    last = await _call(cfg, "tool_status", {"offset": p1["row_count"] - 1})
    assert last["page"]["next_offset"] is None and last["page"]["next_call"] is None


async def test_paging_keeps_filters(cfg) -> None:
    (Path(cfg.evidence_root) / "Security.evtx").write_bytes(b"evtx")
    ev = await _call(cfg, "evtx_query", {"path": "Security.evtx", "event_ids": [4624, 4104, 4698],
                                         "limit": 1})
    nc = ev["page"]["next_call"]
    assert nc["tool"] == "evtx_query" and nc["args"]["event_ids"] == [4624, 4104, 4698]
    nxt = await _call(cfg, nc["tool"], nc["args"])
    assert nxt["rows"][0]["_row"] != ev["rows"][0]["_row"] and nxt["row_count"] == 3
    q = await _call(cfg, "vol_pslist", {"path": "mem.raw"})
    qq = await _call(cfg, "query_results", {"result_id": q["result_id"], "contains": "exe",
                                            "limit": 1})
    assert qq["page"]["next_call"]["args"]["contains"] == "exe"
    plain = await _call(cfg, "vol_pslist", {"path": "mem.raw"})
    assert plain["page"]["next_call"] is None or plain["page"]["next_call"]["tool"] == "query_results"


async def test_size_bound_keeps_next_call_aligned(cfg) -> None:
    cfg.max_response_kb = 2
    r = await _call(cfg, "vol_pslist", {"path": "mem.raw"})
    assert r["truncated"] and r["page"]["next_offset"] == len(r["rows"])
    assert r["page"]["next_call"] == {"tool": "query_results", "args": {
        "result_id": r["result_id"], "offset": len(r["rows"]), "limit": r["page"]["limit"]}}


def test_every_exposed_tool_has_a_test() -> None:
    """ET-09: each MCP tool name appears as a called tool in at least one test file."""
    sources = "\n".join(p.read_text(encoding="utf-8") for p in TESTS.rglob("test_*.py")
                        if p.name != Path(__file__).name)
    sources += Path(__file__).read_text(encoding="utf-8").split("def test_every_exposed")[0]
    missing = [t for t in server.TOOL_NAMES if not re.search(rf'"{t}"', sources)]
    assert missing == [], f"tools without a test: {missing}"
    assert len(server.TOOL_NAMES) == 38
