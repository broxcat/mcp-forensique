"""Golden test (CLAUDE.md §10, milestone M4): the reference conversation on WS-042, end to end
through the MCP server, on fixtures. The server computes the facts; record_finding accepts the
true statements and rejects the false ones."""
from pathlib import Path

import pytest
from mcp import Client

from forensic_mcp import audit, schemas, server

pytestmark = pytest.mark.anyio
HERE = Path(__file__).parent
FAKEBIN = HERE.parent / "fakebin"
MEM, EVTX = "WS-042/memory/ws042.raw", "WS-042/kape/Security.evtx"


@pytest.fixture
def ws042(cfg):
    root = Path(cfg.evidence_root) / "WS-042"
    for rel in ("memory/ws042.raw", "kape/Security.evtx"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(b"fixture " + rel.encode())
    (root / "case.toml").write_text('case = "WS-042"\nclassification = "lab"\n')
    tools = Path(cfg.tools_file)
    text = tools.read_text().replace(str(FAKEBIN / "vol"), str(HERE / "vol"))
    tools.write_text(text)  # scenario vol stub; EvtxECmd stays the fake EZ stub
    return cfg


async def test_reference_conversation(ws042) -> None:
    async with Client(server.build_server(ws042)) as c:
        async def call(tool, args):
            r = await c.call_tool(tool, args)
            assert not r.is_error, (tool, r.content[0].text)
            s = r.structured_content
            assert schemas.errors(schemas.output_validator(), s) == [], tool
            return s

        # "Par où on commence ?" -> vol_pslist, vol_pstree
        ps = await call("vol_pslist", {"path": MEM})
        rid_ps = ps["result_id"]
        rows = {r["PID"]: r for r in ps["rows"]}
        office = {a["rule_id"]: a for a in ps["anomalies"]}["office_spawns_shell"]
        assert office["attack"] == ["T1566.001", "T1204.002", "T1059"]
        assert office["rows"] == [rows[4312]["_row"]] and rows[4312]["PPID"] == 2980
        assert {"tool": "vol_cmdline", "args": {"pid": 4312},
                "why": "command line of the process started by Office"} in ps["next_steps"]
        tree = await call("vol_pstree", {"path": MEM})
        assert [(r["PID"], r["depth"]) for r in tree["rows"]][-1] == (4312, 2)

        # "Oui, et ses connexions réseau." -> vol_cmdline pid=4312, vol_netscan
        cmd = await call("vol_cmdline", {"path": MEM, "pid": 4312})
        enc = {a["rule_id"]: a for a in cmd["anomalies"]}["encoded_powershell"]
        assert enc["attack"] == ["T1059.001", "T1027"]
        assert "http://203.0.113.10/a.ps1" in cmd["decoded"][0]["text"]
        assert {"type": "ip", "value": "203.0.113.10"} in [
            {k: i[k] for k in ("type", "value")} for i in cmd["iocs"]]
        net = await call("vol_netscan", {"path": MEM})
        c2 = next(r for r in net["rows"] if r["ForeignAddr"] == "203.0.113.10")
        by_rule = {a["rule_id"]: a for a in net["anomalies"]}
        assert by_rule["ioc_match"]["rows"] == [c2["_row"]] == [3]
        assert by_rule["external_connection"]["severity"] == "high"

        # "Il y a de la persistance ?" -> evtx_query 4698, 7045
        per = await call("evtx_query", {"path": EVTX, "preset": "persistence"})
        task = next(r for r in per["rows"] if r["EventId"] == 4698)
        assert task["PayloadData1"].endswith("UpdateSvc")

        # timeline in UTC: PowerShell 14:30:07, then the scheduled task 2 minutes later
        tl = await call("timeline", {"case": "WS-042", "around": "2026-10-06T14:31:00Z",
                                     "window_minutes": 5})
        seq = [(r["time_utc"], r["event"], r["detail"]) for r in tl["rows"]]
        ps_start = next(i for i, e in enumerate(seq) if "powershell.exe PID 4312" in e[2])
        task_ev = next(i for i, e in enumerate(seq) if e[1] == "event 4698")
        assert seq[ps_start][0] == "2026-10-06T14:30:07Z" and seq[task_ev][0] == "2026-10-06T14:32:07Z"
        assert ps_start < task_ev and seq == sorted(seq, key=lambda e: e[0])

        # The statements: true ones accepted ("à valider"), false ones rejected
        def cite(res, row, field, value):
            return {"result_id": res["result_id"], "row": row["_row"], "field": field,
                    "value": value}

        true = [
            ("fact", "powershell.exe (PID 4312) was started by WINWORD.EXE (PID 2980)",
             [cite(ps, rows[4312], "PPID", 2980), cite(ps, rows[2980], "ImageFileName", "WINWORD.EXE")],
             ["T1566.001", "T1059.001"]),
            ("fact", "The encoded command downloads http://203.0.113.10/a.ps1",
             [cite(cmd, cmd["rows"][-1], "decoded", "http://203.0.113.10/a.ps1")], ["T1027"]),
            ("fact", "PID 4312 has an established connection to 203.0.113.10:443",
             [cite(net, c2, "ForeignAddr", "203.0.113.10"), cite(net, c2, "ForeignPort", "443"),
              cite(net, c2, "PID", 4312)], []),
            ("fact", "Scheduled task UpdateSvc created at 2026-10-06T14:32:07Z",
             [cite(per, task, "TimeCreated", "2026-10-06T14:32:07Z"),
              cite(per, task, "PayloadData1", "TaskName: \\UpdateSvc")], []),
            ("recommendation", "Block 203.0.113.10 at the proxy (à valider)",
             [cite(net, c2, "ForeignAddr", "203.0.113.10")], []),
        ]
        false = [
            ("fact", "PID 4312 connected to 185.1.2.3", [cite(net, c2, "ForeignAddr", "185.1.2.3")], []),
            ("fact", "The PowerShell PID is 4444", [cite(ps, rows[4312], "PID", 4444)], []),
            ("fact", "UpdateSvc created at 14:35:00",
             [cite(per, task, "TimeCreated", "2026-10-06T14:35:00Z")], []),
            ("hypothesis", "Lateral movement happened", [], []),
            ("fact", "Credentials were dumped", [cite(ps, rows[490], "PID", 490)], ["T1003.001"]),
            ("fact", "Row 999 says so", [{**cite(ps, rows[4], "PID", 4), "row": 999}], []),
            ("fact", "Unknown result", [{**cite(ps, rows[4], "PID", 4), "result_id": "nope"}], []),
        ]
        for kind, text, cits, attack in true:
            f = await call("record_finding", {"kind": kind, "text": text, "citations": cits,
                                              "confidence": "high", "attack": attack})
            assert "à valider" in f["summary"], (text, f["summary"])
        reasons = []
        for kind, text, cits, attack in false:
            f = await call("record_finding", {"kind": kind, "text": text, "citations": cits,
                                              "confidence": "medium", "attack": attack})
            assert "REJECTED" in f["summary"], text
            reasons.append(f["summary"])
        assert "185.1.2.3" in reasons[0] and "not found" in reasons[0]
        assert "no citation" in reasons[3] and "T1003.001" in reasons[4]
        assert "row 999 does not exist" in reasons[5] and "unknown result_id" in reasons[6]
        listing = await call("list_findings", {})
        statuses = [r["status"] for r in listing["rows"]]
        assert statuses == ["à valider"] * len(true) + ["rejected_by_server"] * len(false)
        pending = await call("list_findings", {"status": "à valider", "limit": 2})
        assert pending["row_count"] == len(true) and pending["page"]["next_call"] == {
            "tool": "list_findings", "args": {"status": "à valider", "offset": 2, "limit": 2}}

    # traceability: every call journaled, chain intact, every suggestion journaled
    events = list(audit.iter_events(ws042.audit_file))
    calls = [e for e in events if e["type"] == "tool_call"]
    # 6 analysis calls (pslist, pstree, cmdline, netscan, evtx_query, timeline) + findings + 2 lists
    assert len(calls) == 6 + len(true) + len(false) + 2 and all(e["outcome"] == "ok" for e in calls)
    assert len([e for e in events if e["type"] == "suggestion"]) == len(true) + len(false)
    assert audit.verify_report(ws042.audit_file)["ok"]
