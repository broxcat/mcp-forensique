"""Option A (Windows-only EZ tools): registry export, TTY stdin, ez_import checks, srum_query."""
import asyncio
import json
import sys
from pathlib import Path

import pytest
from mcp import Client

from export_helpers import jsonl, make_export
from forensic_mcp import audit, runner, schemas, server
from forensic_mcp.engines.ez_registry import registry_json_text

pytestmark = pytest.mark.anyio
ROOT = Path(__file__).resolve().parents[1]
PF = [{"ExecutableName": "PSEXESVC.EXE", "LastRun": "2026-10-06T14:35:00.0000000+00:00"}]


@pytest.fixture
def case(cfg):
    pf = Path(cfg.evidence_root) / "WS-042" / "kape" / "prefetch"
    pf.mkdir(parents=True)
    (pf / "PSEXESVC.EXE-AD70946C.pf").write_bytes(b"MAM\x04 compressed")
    (pf / "CALC.EXE-3FBEF7FD.pf").write_bytes(b"MAM\x04 other")
    (Path(cfg.evidence_root) / "WS-042" / "case.toml").write_text(
        'case = "WS-042"\nclassification = "lab"\n')
    return cfg


async def _call(cfg, tool, args):
    async with Client(server.build_server(cfg)) as c:
        r = await c.call_tool(tool, args)
    if r.is_error:
        return r.content[0].text
    assert schemas.errors(schemas.output_validator(), r.structured_content) == []
    return r.structured_content


def _export(cfg, tool="PECmd", **kw):
    return make_export(cfg.evidence_root, "WS-042", tool, "WS-042/kape/prefetch",
                       {"20261006_PECmd_Output.json": jsonl(PF)}, **kw)


def test_registry_json_for_the_windows_script_is_in_sync() -> None:
    on_disk = (ROOT / "rules" / "ez_registry.json").read_text(encoding="utf-8")
    assert on_disk == registry_json_text(), "run scripts/export_ez_registry.py"
    reg = json.loads(on_disk)
    assert {n for n, t in reg["tools"].items() if t["runtime"] == "windows_only"} == {
        "PECmd", "SQLECmd", "WxTCmd", "SrumECmd", "SumECmd"}


def test_runner_tty_stdin(tmp_path: Path) -> None:
    code = "import sys; print(sys.stdin.isatty())"
    for tty, expected in ((False, "False"), (True, "True")):
        r = asyncio.run(runner.run_process([sys.executable, "-c", code], tmp_path / "o",
                                           tmp_path / "e", 10, tty_stdin=tty))
        assert r.exit_code == 0 and (tmp_path / "o").read_text().strip() == expected


async def test_ez_import_verifies_normalises_and_journals(case) -> None:
    exp = _export(case)
    r = await _call(case, "ez_import", {"tool": "PECmd", "path": exp})
    assert r["row_count"] == 1 and r["rows"][0]["_row"] == 1
    assert r["rows"][0]["ExecutableName"] == "PSEXESVC.EXE" and r["engine"].startswith("PECmd")
    assert r["evidence"]["path"] == exp and r["notes"][0].startswith("imported from Windows")
    ev = [e for e in audit.iter_events(case.audit_file) if e["type"] == "imported_from_windows"]
    assert len(ev) == 1 and ev[0]["tool_version"] == "1.5.1.0"
    assert ev[0]["input_path"] == "WS-042/kape/prefetch" and ev[0]["result_id"] == r["result_id"]
    assert audit.verify_report(case.audit_file)["ok"]  # the new event type passes the schema
    again = await _call(case, "ez_import", {"tool": "PECmd", "path": exp + "/manifest.json"})
    assert "import reused" in again["summary"] and again["result_id"] == r["result_id"]


async def test_ez_import_refusals(case) -> None:
    root = Path(case.evidence_root)
    out_mod = _export(case, stamp="20261006T150001Z")
    (root / out_mod / "out" / "20261006_PECmd_Output.json").write_bytes(b"{}\n")
    in_mod = _export(case, stamp="20261006T150002Z")
    wrong_tool = _export(case, stamp="20261006T150003Z")
    bad_name = _export(case, stamp="20261006T150004Z",
                       outputs=[{"file": "../../../tools.toml", "sha256": "0" * 64}])
    bad_fmt = _export(case, stamp="20261006T150005Z", format="other/1")
    missing_in = make_export(root, "WS-042", "PECmd", "WS-042/kape/prefetch",
                             {"x.json": jsonl(PF)}, stamp="20261006T150006Z",
                             input={"path": "WS-042/kape/gone", "kind": "folder", "sha256": "0" * 64})
    results = {}
    for name, args in (("out", {"tool": "PECmd", "path": out_mod}),
                       ("tool", {"tool": "SQLECmd", "path": wrong_tool}),
                       ("name", {"tool": "PECmd", "path": bad_name}),
                       ("fmt", {"tool": "PECmd", "path": bad_fmt}),
                       ("missing", {"tool": "PECmd", "path": missing_in}),
                       ("nomanifest", {"tool": "PECmd", "path": "WS-042/kape/prefetch"}),
                       ("outside", {"tool": "PECmd", "path": "../tools.toml"})):
        results[name] = await _call(case, "ez_import", args)
    (root / "WS-042" / "kape" / "prefetch" / "NEW.EXE-00000000.pf").write_bytes(b"added later")
    results["input"] = await _call(case, "ez_import", {"tool": "PECmd", "path": in_mod})
    assert "modified" in results["out"] and "not 'SQLECmd'" in results["tool"]
    assert "invalid output name" in results["name"] and "unknown export format" in results["fmt"]
    assert "cannot verify" in results["missing"] and "no manifest.json" in results["nomanifest"]
    assert "EVIDENCE_DIR" in results["outside"] and "digest mismatch" in results["input"]
    calls = [e for e in audit.iter_events(case.audit_file) if e["type"] == "tool_call"]
    assert [e["outcome"] for e in calls] == ["refused"] * 8
    assert not [e for e in audit.iter_events(case.audit_file) if e["type"] == "imported_from_windows"]


async def test_ez_import_crash_on_windows_is_a_tool_error(case) -> None:
    exp = _export(case, stamp="20261006T150007Z", stdout_tail="Unhandled exception: boom")
    r = await _call(case, "ez_import", {"tool": "PECmd", "path": exp})
    assert "TOOL ERROR" in r["notes"][0]
    last = [e for e in audit.iter_events(case.audit_file) if e["type"] == "tool_call"][-1]
    assert last["outcome"] == "tool_error" and "Unhandled exception" in last["error"]


async def test_srum_query_reads_the_import_with_a_table_filter(case) -> None:
    sru = Path(case.evidence_root) / "WS-042" / "kape" / "SRUDB.dat"
    sru.write_bytes(b"ese")
    exp = make_export(case.evidence_root, "WS-042", "SrumECmd", "WS-042/kape/SRUDB.dat", {
        "SrumECmd_NetworkUsages_Output.csv":
            b"Timestamp,ExeInfo,BytesSent\n2026-10-06 14:40:00,\\device\\upd.exe,123456\n"
            b"2026-10-01 08:00:00,\\device\\chrome.exe,10\n",
        "SrumECmd_AppResourceUseInfo_Output.csv":
            b"Timestamp,ExeInfo,ForegroundCycleTime\n2026-10-06 14:41:00,\\device\\upd.exe,9\n"})
    net = await _call(case, "srum_query", {"path": exp, "app_contains": "upd.exe",
                                           "table": "network_usage"})
    assert net["row_count"] == 1 and net["rows"][0]["BytesSent"] == "123456"
    win = await _call(case, "srum_query", {"path": exp, "start": "2026-10-06T00:00:00Z"})
    assert win["row_count"] == 2
    raw = await _call(case, "srum_query", {"path": "WS-042/kape/SRUDB.dat"})
    assert "does not run on Linux" in raw
