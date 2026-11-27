"""Cloud policy on findings (audit 27/11/2026, WS-042 replay): a refusal concerns the faulty
element, never the whole collection. A finding without provenance (no citation, unknown
result_id) gets a fixed-text rejection with reason codes in cloud mode and is masked in
list_findings; list_findings, sitrep_draft and report_export keep working; no real value
(IP, host, user, case name) reaches the cloud client."""
import json
from pathlib import Path

import pytest
from mcp import Client

from forensic_mcp import audit, server
from forensic_mcp.findings_ops import MASKED_TEXT

pytestmark = pytest.mark.anyio
REAL = ("alice", "WS-042", "203.0.113.10", "10.0.0.5")
MARK = "SECRET-MARK-7f3a"  # free text typed by the model, must never be echoed back


def _internal_case(cfg) -> str:
    d = Path(cfg.evidence_root) / "WS-042"
    d.mkdir()
    (d / "mem.raw").write_bytes(b"\1" * 4096)
    (d / "case.toml").write_text('case = "WS-042"\nclassification = "internal"\n'
                                 'hosts = ["WS-042"]\nusers = ["alice"]\n')
    return "WS-042/mem.raw"


async def test_unprovenanced_findings_are_rejected_masked_and_never_block(cfg) -> None:
    path = _internal_case(cfg)
    cfg.llm_mode = "cloud"
    shown = []
    async with Client(server.build_server(cfg)) as c:
        async def call(tool, args):
            r = await c.call_tool(tool, args)
            text = r.content[0].text + json.dumps(r.structured_content, ensure_ascii=False)
            shown.append(text)
            assert not r.is_error, (tool, r.content[0].text)
            return r.structured_content

        res = await call("vol3_run", {"path": path, "plugin": "windows.cmdline"})
        row = res["rows"][0]
        field = next(k for k, v in row.items() if k != "_row" and isinstance(v, str) and v)
        ok = await call("record_finding", {
            "kind": "fact", "text": f"{row[field]} seen", "confidence": "high", "attack": [],
            "citations": [{"result_id": res["result_id"], "row": row["_row"], "field": field,
                           "value": row[field]}]})
        assert "à valider" in ok["summary"]
        uncited = await call("record_finding", {"kind": "hypothesis", "text": f"{MARK} lateral",
                                                "citations": [], "confidence": "low", "attack": []})
        assert uncited["summary"] == "F-0002 REJECTED: no citation [no_citation]"
        assert "reason codes: no_citation" in uncited["notes"]
        bad = await call("record_finding", {
            "kind": "fact", "text": f"{MARK} invented", "confidence": "low", "attack": [],
            "citations": [{"result_id": "nope", "row": 1, "field": "PID", "value": 1}]})
        assert bad["summary"] == "F-0003 REJECTED: invalid citation [unknown_result_id]"
        assert bad["rows"] == [{"_row": 1, "citation": 1, "check": "unknown_result_id"}]

        listing = await call("list_findings", {})  # never refused because of F-0002 / F-0003
        by_id = {r["finding_id"]: r for r in listing["rows"]}
        assert [by_id[f]["status"] for f in ("F-0001", "F-0002", "F-0003")] == [
            "à valider", "rejeté par le serveur", "rejeté par le serveur"]
        assert by_id["F-0002"]["text"] == by_id["F-0003"]["text"] == MASKED_TEXT
        assert by_id["F-0001"]["text"] != MASKED_TEXT
        assert "2 sans provenance (texte masqué)" in listing["summary"]
        await call("sitrep_draft", {"case": "WS-042", "audience": "technique"})
        await call("report_export", {"final": False, "title": "brouillon"})

    leaked = sorted({s for s in (*REAL, MARK) for t in shown if s.lower() in t.lower()})
    assert leaked == [], leaked
    events = list(audit.iter_events(cfg.audit_file))
    assert [e["status"] for e in events if e["type"] == "suggestion"] == [
        "à valider", "rejected_by_server", "rejected_by_server"]
    assert MARK in json.dumps([e["text"] for e in events if e["type"] == "suggestion"])  # kept locally
    rf = [e for e in events if e["type"] == "tool_call" and e["tool"] == "record_finding"]
    assert MARK in json.dumps([e["params"] for e in rf])  # the journal keeps the real request
    assert all(e["outcome"] == "ok" for e in events if e["type"] == "tool_call")
    assert audit.verify_report(cfg.audit_file)["ok"]


async def test_local_mode_still_returns_the_detailed_rejection(cfg) -> None:
    async with Client(server.build_server(cfg)) as c:
        r = await c.call_tool("record_finding", {"kind": "hypothesis", "text": "x happened",
                                                 "citations": [], "confidence": "low", "attack": []})
    s = r.structured_content
    assert not r.is_error and s["summary"].startswith("F-0001 REJECTED by the cross-check: no citation")
    assert "reason codes: no_citation" in s["notes"]
