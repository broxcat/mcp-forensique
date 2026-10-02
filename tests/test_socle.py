"""Task 4.1 (socle) tests: contract, journal, replay, evidence, bounds, markers, annotations,
classification + pseudonymisation, cleanup. One test (at least) per item."""
import asyncio
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from mcp import Client

from export_helpers import jsonl, make_export
from forensic_mcp import audit, config, contract, evidence, results, runner, safety, schemas, server

pytestmark = pytest.mark.anyio


async def _call(cfg, tool, args):
    async with Client(server.build_server(cfg)) as c:
        return await c.call_tool(tool, args)


def _events(cfg, type_=None):
    return [e for e in audit.iter_events(cfg.audit_file) if type_ in (None, e["type"])]


def _case(cfg, classification, name="WS-042"):
    d = Path(cfg.evidence_root) / name
    d.mkdir()
    (d / "mem.raw").write_bytes(b"\1" * 4096)
    (d / "case.toml").write_text(f'case = "{name}"\nclassification = "{classification}"\n'
                                 f'hosts = ["{name}"]\n')
    return f"{name}/mem.raw"


# ---- output contract (ET-03, EF-04, EF-10) --------------------------------------------------
async def test_every_tool_response_matches_contract(cfg) -> None:
    pf, sq, sr = (make_export(cfg.evidence_root, "LAB", t, "mem.raw", {f"{t}.json": jsonl([{"x": 1}])},
                              stamp=f"2026100{i}T000000Z")
                  for i, t in enumerate(("PECmd", "SQLECmd", "SrumECmd")))
    async with Client(server.build_server(cfg)) as c:
        run = await c.call_tool("vol3_run", {"path": "mem.raw", "plugin": "windows.pslist"})
        rid, aid = run.structured_content["result_id"], run.structured_content["audit_id"]
        m = {"path": "mem.raw"}
        calls = [("tool_status", {}), ("list_evidence", {}), ("register_evidence", m),
                 ("verify_evidence", m), ("vol_list_plugins", {"contains": "win"}),
                 ("vol_pslist", m), ("vol_pstree", m), ("vol_cmdline", m), ("vol_netscan", m),
                 ("vol_malfind", m), ("vol_dlllist", m), ("vol_printkey", {**m, "key": "Run"}),
                 ("vol2_list_plugins", {}), ("vol2_imageinfo", m),
                 ("vol2_run", {**m, "plugin": "pslist", "profile": "Win7SP1x64"}),
                 ("ez_list_tools", {}), ("ez_run", {**m, "tool": "bstrings"}),
                 ("evtx_query", {**m, "preset": "persistence"}), ("mft_search", m),
                 ("timeline", {"around": "2026-10-06T14:31:00Z"}),
                 ("prefetch_query", {"path": pf}), ("browser_history", {"path": sq}),
                 ("srum_query", {"path": sr}), ("ez_import", {"tool": "PECmd", "path": pf}),
                 ("shimcache_query", m),
                 ("amcache_query", m), ("lnk_query", m), ("jumplist_query", m),
                 ("recyclebin_query", m), ("disk_info", m),
                 ("disk_list", {**m, "partition_offset": 206848}),
                 ("disk_extract", {**m, "partition_offset": 206848, "targets": ["mft"]}),
                 ("disk_extract_file", {**m, "partition_offset": 206848, "inodes": [0]}),
                 ("query_results", {"result_id": rid, "limit": 1}), ("list_results", {}),
                 ("replay", {"audit_id": aid}),
                 ("record_finding", {"kind": "fact", "text": "System is PID 4", "confidence": "high",
                                     "citations": [{"result_id": rid, "row": 1, "field": "PID",
                                                    "value": 4}]}),
                 ("list_findings", {}), ("report_export", {}), ("checklist_status", {})]
        seen = {"vol3_run"}
        for tool, args in calls:
            r = await c.call_tool(tool, args)
            assert not r.is_error, (tool, r.content[0].text)
            assert schemas.errors(schemas.output_validator(), r.structured_content) == [], tool
            seen.add(tool)
        assert seen == set(server.TOOL_NAMES)
        page = (await c.call_tool("query_results", {"result_id": rid, "limit": 1})).structured_content
        assert page["rows"][0]["_row"] == 1 and page["page"]["next_offset"] == 1
        assert page["raw_output"]["container"] == f"/output/{rid}/"


async def test_response_size_is_bounded(cfg) -> None:
    cfg.max_response_kb = 1  # the full 2-row response is ~1.3 KiB
    r = await _call(cfg, "vol3_run", {"path": "mem.raw", "plugin": "windows.cmdline"})
    s = r.structured_content
    assert s["truncated"] and s["row_count"] == 3
    assert contract.size_kb(s) <= 1 or s["rows"] == []
    assert s["page"]["next_offset"] == len(s["rows"]) < 3
    assert schemas.errors(schemas.output_validator(), s) == []


# ---- audit journal (ET-04, objective 3) -----------------------------------------------------
async def test_every_call_is_journaled_ok_refused_failed(cfg) -> None:
    async with Client(server.build_server(cfg)) as c:
        await c.call_tool("vol3_run", {"path": "mem.raw", "plugin": "windows.pslist"})
        failed = await c.call_tool("vol3_run", {"path": "mem.raw", "plugin": "banners"})
        refused = await c.call_tool("vol3_run", {"path": "../tools.toml", "plugin": "pslist"})
    calls = _events(cfg, "tool_call")
    assert [e["outcome"] for e in calls] == ["ok", "tool_error", "refused"]
    assert calls[1]["error"] == "exit code 1" and calls[1]["exit_code"] == 1
    assert failed.structured_content["audit_id"] == calls[1]["audit_id"]
    assert refused.is_error and f"audit_id {calls[2]['audit_id']}" in refused.content[0].text
    assert "EVIDENCE_DIR" in refused.content[0].text  # tells the analyst where to put evidence
    assert calls[0]["output_sha256"] and calls[0]["evidence_sha256"] and calls[0]["argv"]
    report = audit.verify_report(cfg.audit_file)
    assert report["ok"] and report["lines"] == len(_events(cfg)), report


def test_concurrent_appends_keep_the_chain(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"

    def write(i: int) -> None:
        audit.append(log, "crisis_event", {"kind": "server"}, time_utc="2026-10-06T10:15:00Z",
                     kind="event", description=f"e{i}", owner="t", source="test")

    with ThreadPoolExecutor(8) as pool:
        list(pool.map(write, range(100)))
    assert audit.verify_audit(log) == (True, 100)
    assert [e["audit_id"] for e in audit.iter_events(log)] == list(range(1, 101))


def test_verify_detects_schema_and_sequence_errors(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    audit.append(log, "validation", {"kind": "llm"}, finding_id="F-0001", decision="validated")
    r = audit.verify_report(log)
    assert not r["ok"] and r["reason"].startswith("schema")  # the LLM can never validate


async def test_replay_reruns_and_compares(cfg) -> None:
    async with Client(server.build_server(cfg)) as c:
        run = await c.call_tool("vol3_run", {"path": "mem.raw", "plugin": "windows.pstree"})
        aid = run.structured_content["audit_id"]
        rep = await c.call_tool("replay", {"audit_id": aid})
        assert rep.structured_content["rows"][0]["match"] is True
        bad = await c.call_tool("replay", {"audit_id": rep.structured_content["audit_id"]})
        assert bad.is_error and "not a replayable" in bad.content[0].text
    last = [e for e in _events(cfg, "tool_call") if e["tool"] == "replay"][0]
    assert last["replay_of"] == aid and last["replay_match"] is True


# ---- evidence registration and verification (EF-05, chain of evidence) ---------------------
async def test_registration_before_analysis_and_change_detected(cfg) -> None:
    img = Path(cfg.evidence_root) / "mem.raw"
    await _call(cfg, "vol3_run", {"path": "mem.raw", "plugin": "windows.info"})
    reg, call = _events(cfg, "evidence_registered")[0], _events(cfg, "tool_call")[0]
    assert reg["audit_id"] < call["audit_id"] and reg["sha256"] == results.sha256_file(img)
    assert call["evidence_sha256"] == reg["sha256"]
    assert not (Path(cfg.output_root) / ".cache").exists()  # no plain hash cache any more
    with open(img, "ab") as fh:
        fh.write(b"tampered")
    r = await _call(cfg, "vol3_run", {"path": "mem.raw", "plugin": "windows.info"})
    assert r.is_error and "changed since registration" in r.content[0].text
    assert _events(cfg, "tool_call")[-1]["outcome"] == "refused"
    v = await _call(cfg, "verify_evidence", {"path": "mem.raw"})
    assert v.structured_content["rows"][0]["matches_registration"] is False
    assert v.structured_content["evidence"]["verified"] == evidence.CHANGED
    assert _events(cfg, "evidence_verified")[-1]["matches_registration"] is False


# ---- runner output bound (ET-02) ------------------------------------------------------------
def test_runner_bounds_output(tmp_path: Path) -> None:
    argv = [sys.executable, "-c", "import sys\nwhile True: sys.stdout.write('x' * 65536)"]
    r = asyncio.run(runner.run_process(argv, tmp_path / "o", tmp_path / "e", 30,
                                       max_output_bytes=200_000))
    assert r.output_exceeded and not r.timed_out and r.duration < 10
    assert (tmp_path / "o").stat().st_size + (tmp_path / "e").stat().st_size <= 200_000


async def test_tool_output_bound_is_journaled(cfg) -> None:
    cfg.max_output_mb = 1
    r = await _call(cfg, "vol3_run", {"path": "mem.raw", "plugin": "windows.cmdline", "pid": 9999})
    assert not r.is_error
    last = _events(cfg, "tool_call")[-1]
    assert last["outcome"] == "tool_error" and last["error"] == "output over 1 MB"


# ---- prompt injection: EVIDENCE DATA markers ------------------------------------------------
async def test_text_is_wrapped_and_injection_stays_data(cfg) -> None:
    r = await _call(cfg, "vol3_run", {"path": "mem.raw", "plugin": "windows.cmdline"})
    text = r.content[0].text
    assert text.startswith(contract.BEGIN) and text.endswith(contract.END)
    assert text.count(contract.END) == 1 and text.count("<<<") == 2  # data cannot close it
    args = r.structured_content["rows"][0]["Args"]
    assert "ignore previous instructions" in args and "<<<END EVIDENCE DATA>>>" in args
    assert [e["tool"] for e in _events(cfg, "tool_call")] == ["vol3_run"]


# ---- human validation: read / journal / action annotations ----------------------------------
async def test_tools_are_annotated_and_actions_only_on_demand(cfg) -> None:
    async with Client(server.build_server(cfg)) as c:
        tools = {t.name: t.annotations for t in (await c.list_tools()).tools}
    assert set(tools) == set(server.TOOL_CLASSES)
    on_demand = {n for n, c in server.TOOL_CLASSES.items() if c == "action_on_demand"}
    assert on_demand == {"vol_malfind", "vol3_run", "vol2_run", "replay", "disk_extract",
                         "disk_extract_file"}
    for name, ann in tools.items():
        cls = server.TOOL_CLASSES[name]
        assert cls in ("read", "journal", "action_on_demand"), name
        assert ann.read_only_hint is (cls == "read") and ann.destructive_hint is False, name


# ---- confidential data: classification + pseudonymisation -----------------------------------
async def test_client_case_refused_in_cloud_mode(cfg) -> None:
    path = _case(cfg, "client")
    cfg.llm_mode = "cloud"
    r = await _call(cfg, "vol3_run", {"path": path, "plugin": "windows.cmdline"})
    assert r.is_error and "classified 'client'" in r.content[0].text
    assert _events(cfg, "tool_call")[-1]["outcome"] == "refused"
    assert not _events(cfg, "evidence_registered")  # refused before hashing
    listing = (await _call(cfg, "list_evidence", {})).structured_content
    assert [x["path"] for x in listing["rows"]] == ["mem.raw"] and "1 withheld" in listing["summary"]
    cfg.llm_mode = "local"
    assert not (await _call(cfg, "vol3_run", {"path": path, "plugin": "windows.cmdline"})).is_error


async def test_internal_case_pseudonymised_in_cloud_mode(cfg) -> None:
    path = _case(cfg, "internal")
    cfg.llm_mode = "cloud"
    secrets_ = ("alice", "WS-042", "203.0.113.10", "10.0.0.5")
    async with Client(server.build_server(cfg)) as c:
        r = await c.call_tool("vol3_run", {"path": path, "plugin": "windows.cmdline"})
        out = json.dumps(r.structured_content) + r.content[0].text
        assert not [s for s in secrets_ if s.lower() in out.lower()], out
        for tok in ("USER_1", "HOST_1", "IP_EXT_1", "IP_INT_1"):
            assert tok in out
        rid = r.structured_content["result_id"]
        raw = (Path(cfg.output_root) / rid / "rows.jsonl").read_text()
        assert "alice" in raw and "203.0.113.10" in raw  # disk keeps the real evidence
        q = await c.call_tool("query_results", {"result_id": rid, "contains": "IP_EXT_1"})
        assert q.structured_content["row_count"] == 1  # tokens accepted as inputs
        again = await c.call_tool("vol3_run", {"path": "HOST_1/mem.raw", "plugin": "windows.cmdline"})
        assert again.structured_content["rows"][0]["UserName"] == "USER_1"  # stable tokens
    assert _events(cfg, "tool_call")[-1]["params"]["path"] == path  # journal keeps real values


async def test_lab_case_and_local_mode_stay_raw(cfg) -> None:
    path = _case(cfg, "lab")
    cfg.llm_mode = "cloud"
    r = await _call(cfg, "vol3_run", {"path": path, "plugin": "windows.cmdline"})
    assert r.structured_content["rows"][0]["UserName"] == "alice"


# ---- cleanup approved in decision 5 ---------------------------------------------------------
def test_removed_legacy_items(tmp_path: Path) -> None:
    f = tmp_path / "c.toml"
    f.write_text("max_upload_gb = 64\n")
    with pytest.raises(ValueError, match="max_upload_gb"):
        config.load_config(f)
    assert not hasattr(safety, "validate_args") and not hasattr(safety, "FORBIDDEN_FLAGS")
    assert not hasattr(results, "sha256_cached") and not hasattr(results, "summarize")
