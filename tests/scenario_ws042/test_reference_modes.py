"""Reference conversation WS-042 replayed per data policy (audit 27/11/2026, P1): cloud is the
production default, so the cross-check of IOCs / timestamps, the artefact citations and the
"à valider" status must also hold on PSEUDONYMISED data.

The "client" below only uses what it is shown: evidence paths from list_evidence, values
copied from the returned rows (tokens in cloud + internal). The oracle `seen()` turns each
real expected value into what that client should see, using the server-side mapping.
The original golden test (test_reference_conversation.py) is left unchanged."""
import json
from pathlib import Path

import pytest
from mcp import Client

from forensic_mcp import audit, schemas, server
from forensic_mcp.redact import Case, Pseudonymizer

pytestmark = pytest.mark.anyio
HERE = Path(__file__).parent
FAKEBIN = HERE.parent / "fakebin"
REAL = ("203.0.113.10", "WS-042", "10.0.0.42", "alice")  # must never reach a cloud client
MODES = {  # id: (llm_mode, classification, pseudonymised output expected)
    "local-lab": ("local", "lab", False),
    "cloud-lab": ("cloud", "lab", False),
    "cloud-internal": ("cloud", "internal", True),
}


@pytest.fixture(params=list(MODES))
def mode(request, cfg):
    llm_mode, classification, pseudo = MODES[request.param]
    root = Path(cfg.evidence_root) / "WS-042"
    for rel in ("memory/ws042.raw", "kape/Security.evtx"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(b"fixture " + rel.encode())
    (root / "case.toml").write_text(f'case = "WS-042"\nclassification = "{classification}"\n'
                                    'hosts = ["WS-042"]\nusers = ["alice"]\n')
    tools = Path(cfg.tools_file)
    tools.write_text(tools.read_text().replace(str(FAKEBIN / "vol"), str(HERE / "vol")))
    cfg.llm_mode = llm_mode
    return cfg, pseudo


async def test_reference_conversation_per_policy(mode) -> None:
    cfg, pseudo = mode
    shown: list[str] = []  # every text the client received

    def seen(real: str) -> str:
        """What this client should see for a real value."""
        if not pseudo:
            return real
        store = Path(cfg.output_root) / ".pseudo" / "WS-042.json"
        return Pseudonymizer(store, Case("WS-042", "internal", ["WS-042"], ["alice"])).text(real)

    async with Client(server.build_server(cfg)) as c:
        async def call(tool, args):
            r = await c.call_tool(tool, args)
            if r.is_error:  # cloud hides the detail from the client: show the journal's
                last = [e for e in audit.iter_events(cfg.audit_file) if e["type"] == "tool_call"][-1]
                pytest.fail(f"{tool} {args!r}: {r.content[0].text} | journal: {last.get('error')}")
            s = r.structured_content
            assert schemas.errors(schemas.output_validator(), s) == [], tool
            shown.extend([r.content[0].text, json.dumps(s, ensure_ascii=False)])
            return s

        listing = await call("list_evidence", {})
        path = {Path(x["path"]).name: x["path"] for x in listing["rows"]}
        mem, evtx = path["ws042.raw"], path["Security.evtx"]
        case_seen = next(x["case"] for x in listing["rows"] if x["path"] == mem)

        ps = await call("vol_pslist", {"path": mem})
        rows = {r["PID"]: r for r in ps["rows"]}
        office = {a["rule_id"]: a for a in ps["anomalies"]}["office_spawns_shell"]
        assert office["attack"] == ["T1566.001", "T1204.002", "T1059"]
        assert office["rows"] == [rows[4312]["_row"]] and rows[4312]["PPID"] == 2980
        tree = await call("vol_pstree", {"path": mem})
        assert [(r["PID"], r["depth"]) for r in tree["rows"]][-1] == (4312, 2)

        cmd = await call("vol_cmdline", {"path": mem, "pid": 4312})
        enc = {a["rule_id"]: a for a in cmd["anomalies"]}["encoded_powershell"]
        assert enc["attack"] == ["T1059.001", "T1027"]
        assert seen("http://203.0.113.10/a.ps1") in cmd["decoded"][0]["text"]
        assert {"type": "ip", "value": seen("203.0.113.10")} in [
            {k: i[k] for k in ("type", "value")} for i in cmd["iocs"]]
        net = await call("vol_netscan", {"path": mem})
        c2 = next(r for r in net["rows"] if r["ForeignAddr"] == seen("203.0.113.10"))
        by_rule = {a["rule_id"]: a for a in net["anomalies"]}
        assert by_rule["ioc_match"]["rows"] == [c2["_row"]] == [3]
        assert by_rule["external_connection"]["severity"] == "high"

        per = await call("evtx_query", {"path": evtx, "preset": "persistence"})
        task = next(r for r in per["rows"] if r["EventId"] == 4698)
        assert task["PayloadData1"].endswith("UpdateSvc")

        tl = await call("timeline", {"case": case_seen, "around": "2026-10-06T14:31:00Z",
                                     "window_minutes": 5})
        seq = [(r["time_utc"], r["event"], r["detail"]) for r in tl["rows"]]
        ps_start = next(i for i, e in enumerate(seq) if "powershell.exe PID 4312" in e[2])
        task_ev = next(i for i, e in enumerate(seq) if e[1] == "event 4698")
        assert seq[ps_start][0] == "2026-10-06T14:30:07Z" and seq[task_ev][0] == "2026-10-06T14:32:07Z"
        assert ps_start < task_ev and seq == sorted(seq, key=lambda e: e[0])

        def cite(res, row, field, value):
            return {"result_id": res["result_id"], "row": row["_row"], "field": field,
                    "value": value}

        decoded_url = seen("http://203.0.113.10/a.ps1")
        true = [  # values exactly as the client sees them
            ("fact", "powershell.exe (PID 4312) was started by WINWORD.EXE (PID 2980)",
             [cite(ps, rows[4312], "PPID", 2980), cite(ps, rows[2980], "ImageFileName", "WINWORD.EXE")],
             ["T1566.001", "T1059.001"]),
            ("fact", f"The encoded command downloads {decoded_url}",
             [cite(cmd, cmd["rows"][-1], "decoded", decoded_url)], ["T1027"]),
            ("fact", f"PID 4312 has an established connection to {c2['ForeignAddr']}:443",
             [cite(net, c2, "ForeignAddr", c2["ForeignAddr"]), cite(net, c2, "ForeignPort", "443"),
              cite(net, c2, "PID", 4312)], []),
            ("fact", "Scheduled task UpdateSvc created at 2026-10-06T14:32:07Z",
             [cite(per, task, "TimeCreated", "2026-10-06T14:32:07Z"),
              cite(per, task, "PayloadData1", "TaskName: \\UpdateSvc")], []),
            ("recommendation", f"Block {c2['ForeignAddr']} at the proxy (à valider)",
             [cite(net, c2, "ForeignAddr", c2["ForeignAddr"])], []),
        ]
        false = [
            ("fact", "PID 4312 connected to 185.1.2.3", [cite(net, c2, "ForeignAddr", "185.1.2.3")], []),
            ("fact", "The PowerShell PID is 4444", [cite(ps, rows[4312], "PID", 4444)], []),
            ("fact", "UpdateSvc created at 14:35:00",
             [cite(per, task, "TimeCreated", "2026-10-06T14:35:00Z")], []),
            ("hypothesis", "Lateral movement happened", [], []),
        ]
        for kind, text, cits, attack in true:
            f = await call("record_finding", {"kind": kind, "text": text, "citations": cits,
                                              "confidence": "high", "attack": attack})
            assert "à valider" in f["summary"], (text, f["summary"])
        for kind, text, cits, attack in false:
            f = await call("record_finding", {"kind": kind, "text": text, "citations": cits,
                                              "confidence": "medium", "attack": attack})
            assert "REJECTED" in f["summary"], (text, f["summary"])
        statuses = [r["status"] for r in (await call("list_findings", {}))["rows"]]
        assert statuses == ["à valider"] * len(true) + ["rejeté par le serveur"] * len(false)

    if pseudo:  # nothing real reached the cloud client...
        leaked = sorted({s for s in REAL for t in shown if s.lower() in t.lower()})
        assert leaked == [], leaked
    events = list(audit.iter_events(cfg.audit_file))
    calls = [e for e in events if e["type"] == "tool_call"]
    assert all(e["outcome"] == "ok" for e in calls), [e.get("error") for e in calls]
    # ...while the journal keeps the real values (accepted IP citation restored)
    accepted = [e for e in events if e["type"] == "suggestion" and e.get("status") != "rejected_by_server"]
    assert any(cit.get("value") == "203.0.113.10" for e in accepted for cit in e["citations"])
    assert audit.verify_report(cfg.audit_file)["ok"]
