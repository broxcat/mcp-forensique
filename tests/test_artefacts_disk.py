"""Task 4.3b shortcuts (one test per tool) and 4.3c disk-image tools, with fake stubs."""
import stat
from pathlib import Path

import pytest
from mcp import Client
from mcp.types import ElicitResult

from forensic_mcp import audit, safety, schemas, server

pytestmark = pytest.mark.anyio
IMG = "WS-042/disk/ws042.E01"


@pytest.fixture
def case(cfg):
    root = Path(cfg.evidence_root) / "WS-042"
    for rel in ("prefetch/PSEXESVC.EXE-AD70946C.pf", "History", "SYSTEM", "Amcache.hve",
                "Recent/invoice.docm.lnk", "Recent/1b4dd67f29cb1962.automaticDestinations-ms",
                "RecycleBin/$IABC123.txt", "disk/ws042.E01", "disk/nopart.raw"):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"fake " + rel.encode())
    (root / "case.toml").write_text('case = "WS-042"\nclassification = "lab"\n')
    return cfg


async def _approve(context, params):
    return ElicitResult(action="accept", content={"approve": True, "analyst": "L. Plancke"})


async def _call(cfg, tool, args, elicit=None):
    async with Client(server.build_server(cfg), elicitation_callback=elicit) as c:
        r = await c.call_tool(tool, args)
    if r.is_error:
        return r.content[0].text
    assert schemas.errors(schemas.output_validator(), r.structured_content) == []
    return r.structured_content


def _events(cfg, type_):
    return [e for e in audit.iter_events(cfg.audit_file) if e["type"] == type_]


# ---- typed shortcuts (one test each) --------------------------------------------------------
async def test_prefetch_query(case) -> None:
    r = await _call(case, "prefetch_query", {"path": "WS-042/prefetch",
                                             "executable_contains": "psexe",
                                             "start": "2026-10-06T00:00:00Z"})
    assert r["row_count"] == 1 and r["rows"][0]["ExecutableName"] == "PSEXESVC.EXE"
    assert r["rows"][0]["_row"] == 1 and "--json" in _events(case, "tool_call")[-1]["argv"]


async def test_browser_history(case) -> None:
    r = await _call(case, "browser_history", {"path": "WS-042/History", "url_contains": "203.0.113"})
    assert r["row_count"] == 1 and r["rows"][0]["URL"] == "http://203.0.113.10/a.ps1"
    win = await _call(case, "browser_history", {"path": "WS-042/History",
                                                "start": "2026-10-01T00:00:00Z",
                                                "end": "2026-10-02T00:00:00Z"})
    assert win["row_count"] == 1 and "parse reused" in win["summary"]


async def test_shimcache_query(case) -> None:
    r = await _call(case, "shimcache_query", {"path": "WS-042/SYSTEM", "executed_only": True})
    assert r["row_count"] == 1 and r["rows"][0]["Path"].endswith("upd.exe")
    argv = _events(case, "tool_call")[-1]["argv"]
    assert argv[argv.index("-f") + 1].endswith("WS-042/SYSTEM")  # never the live registry
    folder = await _call(case, "shimcache_query", {"path": "WS-042/prefetch"})
    assert "takes -f" in folder


async def test_amcache_query(case) -> None:
    r = await _call(case, "amcache_query", {"path": "WS-042/Amcache.hve", "sha1": "ab" * 20})
    assert r["row_count"] == 1 and r["rows"][0]["Name"] == "upd.exe"
    bad = await _call(case, "amcache_query", {"path": "WS-042/Amcache.hve", "sha1": "xyz"})
    assert "40 hex" in bad


async def test_lnk_query(case) -> None:
    r = await _call(case, "lnk_query", {"path": "WS-042/Recent/invoice.docm.lnk",
                                        "target_contains": "invoice"})
    assert r["row_count"] == 1 and r["rows"][0]["LocalPath"].endswith("invoice.docm")


async def test_jumplist_query(case) -> None:
    r = await _call(case, "jumplist_query", {
        "path": "WS-042/Recent/1b4dd67f29cb1962.automaticDestinations-ms",
        "start": "2026-10-06T14:30:00Z", "end": "2026-10-06T14:40:00Z"})
    assert r["row_count"] == 1 and r["rows"][0]["Path"].endswith("upd.exe")


async def test_recyclebin_query(case) -> None:
    r = await _call(case, "recyclebin_query", {"path": "WS-042/RecycleBin", "name_contains": "secret"})
    assert r["row_count"] == 1 and r["rows"][0]["DeletedOn"] == "2026-10-06 14:50:00"


# ---- disk images (4.3c) ---------------------------------------------------------------------
async def test_disk_info(case) -> None:
    r = await _call(case, "disk_info", {"path": IMG})
    assert [x["start_sector"] for x in r["rows"]][-1] == 206848
    assert any("512-byte sectors" in n for n in r["notes"])
    none = await _call(case, "disk_info", {"path": "WS-042/disk/nopart.raw"})
    assert none["row_count"] == 0 and "partition_offset=0" in none["notes"][-1]


async def test_disk_list(case) -> None:
    r = await _call(case, "disk_list", {"path": IMG, "partition_offset": 206848,
                                        "path_contains": "prefetch"})
    assert r["row_count"] == 2 and {x["deleted"] for x in r["rows"]} == {True, False}
    dele = await _call(case, "disk_list", {"path": IMG, "partition_offset": 206848, "deleted": True})
    assert dele["row_count"] == 1 and "parse" not in dele["summary"]
    bad = await _call(case, "disk_list", {"path": IMG, "partition_offset": 0})
    assert isinstance(bad, dict) and bad["exit_code"] == 1


async def test_disk_extract_hashes_journals_and_chains(case) -> None:
    r = await _call(case, "disk_extract", {"path": IMG, "partition_offset": 206848,
                                           "targets": ["mft", "usnjrnl", "prefetch", "evtx"]})
    paths = {x["source_path"]: x for x in r["rows"]}
    assert set(paths) == {"$MFT", "$Extend/$UsnJrnl:$J", "Windows/Prefetch/PSEXESVC.EXE-AD70946C.pf",
                          "Windows/System32/winevt/Logs/Security.evtx"}  # deleted .pf skipped
    pf = paths["Windows/Prefetch/PSEXESVC.EXE-AD70946C.pf"]
    rid = r["result_id"]
    assert pf["path"] == f"@{rid}/Windows/Prefetch/PSEXESVC.EXE-AD70946C.pf"
    f = Path(case.output_root) / rid / "extracted" / "Windows/Prefetch/PSEXESVC.EXE-AD70946C.pf"
    assert stat.S_IMODE(f.stat().st_mode) == 0o444 and len(pf["sha256"]) == 64
    assert (Path(case.output_root) / rid / "extracted" / "$Extend" / "$UsnJrnl_$J").exists()
    reg = [e for e in _events(case, "evidence_registered") if e["path"] == pf["path"]][0]
    assert reg["inode"] == "1204-128-1" and reg["source_image"] == IMG and reg["sha256"] == pf["sha256"]
    chained = await _call(case, "prefetch_query", {"path": pf["path"]})
    assert chained["evidence"]["path"] == pf["path"] and chained["row_count"] >= 1
    ev = await _call(case, "evtx_query", {"path": f"@{rid}/Windows/System32/winevt/Logs/Security.evtx",
                                          "preset": "persistence"})
    assert ev["row_count"] == 2
    assert audit.verify_audit(case.audit_file)[0]


async def test_disk_extract_sam_security_needs_confirmation(case) -> None:
    args = {"path": IMG, "partition_offset": 206848, "targets": ["sam_security"]}
    refused = await _call(case, "disk_extract", args)
    assert "not confirmed" in refused
    ok = await _call(case, "disk_extract", args, _approve)
    assert [x["source_path"] for x in ok["rows"]] == ["Windows/System32/config/SAM"]
    assert [e["decision"] for e in _events(case, "action_confirmed")] == ["denied", "approved"]


async def test_second_jail_root_only_accepts_extractions(case) -> None:
    r = await _call(case, "disk_extract", {"path": IMG, "partition_offset": 206848,
                                           "targets": ["mft"]})
    rid = r["result_id"]
    out = case.output_root
    assert safety.jail_input(f"@{rid}/$MFT", case.evidence_root, out).name == "$MFT"
    for bad in (f"@{rid}/../meta.json", "@20261002-000000-vol3_windows.pslist-abcdef/x",
                "@../../etc/passwd", f"@{rid}"[:-1] + "0/$MFT"):
        with pytest.raises(safety.SafetyError):
            safety.jail_input(bad, case.evidence_root, out)
    refused = await _call(case, "mft_search", {"path": f"@{rid}/../rows.jsonl"})
    assert "outside the extraction" in refused
