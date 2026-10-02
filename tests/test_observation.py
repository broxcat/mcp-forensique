"""5.3: kind="observation" = a verified absence of trace in a cited result (EF-10, EF-11,
anti-hallucination). The server checks the absence itself, writes the statement, copies the
notes; the observation is "à valider" and appears in the report."""
from pathlib import Path

import pytest
from mcp import Client

from forensic_mcp import audit, schemas, server, validation

pytestmark = pytest.mark.anyio


async def _call(c, tool, args):
    r = await c.call_tool(tool, args)
    if r.is_error:
        return r.content[0].text
    assert schemas.errors(schemas.output_validator(), r.structured_content) == []
    return r.structured_content


def _obs(rid, field, value, **kw):
    return {"kind": "observation", "confidence": "medium", "text": kw.pop("text", "absence"),
            "citations": [{"result_id": rid, "row": kw.pop("row", 0), "field": field,
                           "value": value}], **kw}


async def test_observation_verified_by_the_server(cfg) -> None:
    async with Client(server.build_server(cfg)) as c:
        ps = await _call(c, "vol_pslist", {"path": "mem.raw"})
        rid = ps["result_id"]
        empty = await _call(c, "query_results", {"result_id": rid, "contains": "zz-no-such-zz"})
        assert empty["row_count"] == 0 and empty["result_id"] == rid
        ok_call = await _call(c, "record_finding", _obs(rid, "audit_id", empty["audit_id"],
                                                        text="Aucun processus zz-no-such-zz"))
        ok_col = await _call(c, "record_finding", _obs(rid, "ImageFileName", "mimikatz.exe"))
        bad = {
            "rows": _obs(rid, "audit_id", ps["audit_id"]),          # that call returned rows
            "present": _obs(rid, "ImageFileName", "System"),        # the value is there
            "all": _obs(rid, "*", None),                            # the result is not empty
            "unknown": _obs("20990101-000000-nope-000000", "*", None),
            "other_call": _obs(rid, "audit_id", 999),
            "row": _obs(rid, "audit_id", empty["audit_id"], row=1),
            "attack": _obs(rid, "audit_id", empty["audit_id"], attack=["T1053.005"]),
        }
        out = {k: await _call(c, "record_finding", v) for k, v in bad.items()}
        draft = await _call(c, "report_export", {})
    for r in (ok_call, ok_col):
        assert "à valider" in r["summary"], r["summary"]
        assert any("NOT absence of the behaviour" in n for n in r["notes"])
    for k, r in out.items():
        assert "REJECTED" in r["summary"], (k, r["summary"])
    assert "returned" in out["rows"]["summary"] and "present" in out["present"]["summary"]
    assert "unknown result_id" in out["unknown"]["summary"]
    assert "no ATT&CK ID" in out["attack"]["summary"]
    sug = [e for e in audit.iter_events(cfg.audit_file) if e["type"] == "suggestion"]
    first = sug[0]
    assert first["kind"] == "observation" and first["status"] == "à valider"
    assert first["observation"]["statements"][0].startswith("Aucune ligne renvoyée par query_results")
    calls = {e["audit_id"]: e for e in audit.iter_events(cfg.audit_file) if e["type"] == "tool_call"}
    assert calls[empty["audit_id"]]["row_count"] == 0  # journaled since 5.3
    assert calls[ps["audit_id"]]["row_count"] == ps["row_count"]
    assert audit.verify_report(cfg.audit_file)["ok"]  # schema-valid journal
    report = (Path(cfg.output_root) / draft["result_id"] / "report.md").read_text(encoding="utf-8")
    assert "Observation (absence de trace dans le résultat cité" in report
    assert "Aucune ligne de" in report and "mimikatz.exe" in report
    # the analyst's re-check re-verifies the absence
    f = [x for x in validation.load_findings(cfg.audit_file, with_citations=True)
         if x["finding_id"] == first["finding_id"]][0]
    assert validation.recheck(cfg, f)[0]["check"] == "ok"


async def test_observation_on_an_empty_evtx_preset_copies_the_notes(cfg) -> None:
    """The real case: an empty preset on a SHARED parse result (rows exist), cited by the
    audit_id of the empty call; the server copies the 'log / audit policy required' notes."""
    from test_disk import SAMPLES
    root = Path(cfg.evidence_root) / "WS-042"
    for rel in SAMPLES.values():
        if not rel.endswith("/"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(b"fake " + rel.encode())
    (root / "case.toml").write_text('case = "WS-042"\nclassification = "lab"\n')
    async with Client(server.build_server(cfg)) as c:
        rdp = await _call(c, "evtx_query", {"path": "WS-042/logs/Security.evtx", "preset": "rdp"})
        assert rdp["row_count"] == 0
        all_rows = await _call(c, "record_finding", _obs(rdp["result_id"], "*", None))
        ok = await _call(c, "record_finding", _obs(rdp["result_id"], "audit_id", rdp["audit_id"],
                                                   text="Aucun événement RDP dans Security.evtx"))
    assert "REJECTED" in all_rows["summary"]  # the parse itself has rows: '*' is refused
    assert "à valider" in ok["summary"]
    assert any("4778 (Security, log present): requires" in n for n in ok["notes"])
    obs = [e for e in audit.iter_events(cfg.audit_file) if e["type"] == "suggestion"][-1]
    assert "'preset': 'rdp'" in obs["observation"]["statements"][0]
    assert any("log ABSENT from the input" in n for n in obs["observation"]["notes"])
