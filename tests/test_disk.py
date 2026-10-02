"""Task 4.3: Eric Zimmerman registry, ez_run (one test per tool), evtx_query, mft_search,
timeline — with the fake `ez` stub."""
from pathlib import Path

import pytest
from mcp import Client

from forensic_mcp import audit, schemas, server
from forensic_mcp.engines import zimmerman

pytestmark = pytest.mark.anyio
FORBIDDEN = zimmerman.FORBIDDEN | {"--dr"}  # + MFTECmd --dr (writes resident files)
OPTIONS = {"RECmd": {"batch": "Kroll_Batch.reb"}}  # RECmd needs batch or key
# (tool, evidence path relative to WS-042/, kind) — one artefact per tool
SAMPLES = {
    "EvtxECmd": "logs/Security.evtx", "MFTECmd": "C/$MFT",
    "PECmd": "C/Windows/prefetch/CALC.EXE-3FBEF7FD.pf",
    "RECmd": "C/Windows/System32/config/SYSTEM",
    "AmcacheParser": "C/Windows/AppCompat/Programs/Amcache.hve",
    "AppCompatCacheParser": "C/Windows/System32/config/SYSTEM",
    "LECmd": "Users/alice/Recent/a.lnk",
    "JLECmd": "Users/alice/Recent/AutomaticDestinations/1b4dd67f29cb1962.automaticDestinations-ms",
    "SBECmd": "Users/alice/", "SrumECmd": "C/Windows/System32/sru/SRUDB.dat",
    "SQLECmd": "Users/alice/Chrome/History", "WxTCmd": "Users/alice/ActivitiesCache.db",
    "RBCmd": "C/$Recycle.Bin/$IABC123.txt",
    "RecentFileCacheParser": "C/Windows/AppCompat/Programs/RecentFileCache.bcf",
    "SumECmd": "C/Windows/System32/LogFiles/Sum/", "bstrings": "C/Windows/System32/config/SYSTEM",
    "rla": "C/Windows/System32/config/SYSTEM"}


@pytest.fixture
def case(cfg):
    root = Path(cfg.evidence_root) / "WS-042"
    for rel in [*SAMPLES.values(), "Users/alice/NTUSER.DAT",
                "C/Windows/System32/LogFiles/Sum/Current.mdb", "logs/System.evtx"]:
        p = root / rel
        if rel.endswith("/"):
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"fake " + rel.encode())
    (root / "case.toml").write_text('case = "WS-042"\nclassification = "lab"\n')
    return cfg


async def _call(cfg, tool, args):
    async with Client(server.build_server(cfg)) as c:
        r = await c.call_tool(tool, args)
    if r.is_error:
        return r.content[0].text
    assert schemas.errors(schemas.output_validator(), r.structured_content) == []
    return r.structured_content


def _last_call(cfg):
    return [e for e in audit.iter_events(cfg.audit_file) if e["type"] == "tool_call"][-1]


def test_registry_has_17_tools_and_every_flag_is_in_the_saved_help() -> None:
    assert len(zimmerman.REGISTRY) == 17 and "Hasher" not in zimmerman.REGISTRY  # no Linux build
    assert zimmerman.verify_registry() == []
    for name, t in zimmerman.REGISTRY.items():
        used = {*t.inputs, *t.fixed, t.output, *(o.flag for o in t.options.values())}
        assert not used & FORBIDDEN, name
        assert {o.kind for o in t.options.values()} <= {
            "bool", "int", "ids", "date", "enum_batch", "regpath", "evidence_path"}, name
    assert "-o" not in {o.flag for o in zimmerman.REGISTRY["PECmd"].options.values()}
    json_tools = {"EvtxECmd", "MFTECmd", "PECmd", "LECmd", "JLECmd", "RecentFileCacheParser",
                  "SQLECmd", "RECmd"}
    assert {n for n, t in zimmerman.REGISTRY.items() if t.output == "--json"} == json_tools


def test_verify_registry_catches_an_invented_flag(monkeypatch) -> None:
    fake = zimmerman.Tool(("-f",), "x", {"bad": zimmerman.Opt("--no-such-flag", "bool", "x")})
    monkeypatch.setitem(zimmerman.REGISTRY, "EvtxECmd", fake)
    assert zimmerman.verify_registry() == ["EvtxECmd --no-such-flag"]


WINDOWS_ONLY = {"PECmd", "SQLECmd", "WxTCmd", "SrumECmd", "SumECmd"}


@pytest.mark.parametrize("tool", sorted(set(SAMPLES) - WINDOWS_ONLY))
async def test_ez_run_each_tool(case, tool) -> None:
    r = await _call(case, "ez_run", {"tool": tool, "path": "WS-042/" + SAMPLES[tool],
                                     "options": OPTIONS.get(tool)})
    assert isinstance(r, dict), r
    assert r["row_count"] >= 1 and r["engine"].startswith(tool)
    argv = _last_call(case)["argv"]
    assert ("-d" if SAMPLES[tool].endswith("/") else "-f") in argv
    assert zimmerman.output_flag(tool, argv) in argv and not set(argv) & FORBIDDEN
    assert r["exit_code"] == 0


@pytest.mark.parametrize("tool", sorted(WINDOWS_ONLY))
async def test_windows_only_tools_are_refused_not_run(case, tool) -> None:
    assert set(zimmerman.windows_only()) == WINDOWS_ONLY
    before = {p.name for p in Path(case.output_root).glob("*") if p.is_dir()}
    r = await _call(case, "ez_run", {"tool": tool, "path": "WS-042/" + SAMPLES[tool]})
    assert isinstance(r, str) and "does not run on Linux" in r
    assert "scripts/run_ez_windows.ps1" in r and "ez_import" in r
    assert _last_call(case)["outcome"] == "refused"
    after = {p.name for p in Path(case.output_root).glob("*") if p.is_dir()}
    assert not [n for n in after - before if n.startswith(("20", "ez_"))]  # nothing executed


async def test_ez_run_output_shapes(case) -> None:
    amc = await _call(case, "ez_run", {"tool": "AmcacheParser", "path": "WS-042/" + SAMPLES["AmcacheParser"]})
    assert {row["_file"] for row in amc["rows"]} == {"Amcache_ProgramEntries.csv",
                                                   "Amcache_UnassociatedFileEntries.csv"}
    kn = await _call(case, "ez_run", {"tool": "RECmd", "path": "WS-042/" + SAMPLES["RECmd"],
                                      "options": {"key": "Microsoft\\Windows\\CurrentVersion\\Run"}})
    assert kn["rows"][0]["ValueName"] == "UpdateSvc"  # --kn -> JSON
    assert "--json" in _last_call(case)["argv"] and "--csv" not in _last_call(case)["argv"]
    bs = await _call(case, "ez_run", {"tool": "bstrings", "path": "WS-042/" + SAMPLES["bstrings"],
                                      "options": {"min_length": 5}})
    assert bs["rows"][1]["string"] == "http://203.0.113.10/a.ps1"
    rla = await _call(case, "ez_run", {"tool": "rla", "path": "WS-042/" + SAMPLES["rla"]})
    assert rla["rows"][0]["file"] == "SYSTEM"


async def test_ez_typed_options_and_refusals(case) -> None:
    hive = "WS-042/" + SAMPLES["RECmd"]
    ok = await _call(case, "ez_run", {"tool": "RECmd", "path": hive,
                                      "options": {"batch": "Kroll_Batch.reb"}})
    argv = _last_call(case)["argv"]
    assert argv[argv.index("--bn") + 1].endswith("BatchExamples/Kroll_Batch.reb") and ok["row_count"]
    assert "--csv" in argv and "--json" not in argv  # batch -> CSV
    bad = [await _call(case, "ez_run", args) for args in (
        {"tool": "RECmd", "path": hive, "options": {"batch": "../../etc/passwd"}},
        {"tool": "RECmd", "path": hive, "options": {"sync": True}},
        {"tool": "RECmd", "path": hive, "options": {"key": "--sync"}},
        {"tool": "EvtxECmd", "path": "WS-042/logs/Security.evtx", "options": {"event_ids": [70000]}},
        {"tool": "MFTECmd", "path": "WS-042/C/$MFT", "options": {"mft_path": "../tools.toml"}},
        {"tool": "SBECmd", "path": "WS-042/Users/alice/NTUSER.DAT"},
        {"tool": "PECmd", "path": "../tools.toml"})]
    assert "unknown RECmd batch" in bad[0] and "no option 'sync'" in bad[1]
    assert "must be a registry path" in bad[2] and "event IDs" in bad[3]
    assert "outside evidence root" in bad[4] and "takes -d" in bad[5]
    assert "EVIDENCE_DIR" in bad[6]
    outcomes = [e["outcome"] for e in audit.iter_events(case.audit_file) if e["type"] == "tool_call"]
    assert outcomes[-7:] == ["refused"] * 7
    ids = await _call(case, "ez_run", {"tool": "EvtxECmd", "path": "WS-042/logs/Security.evtx",
                                       "options": {"event_ids": [4624, 4698],
                                                   "start": "2026-10-06T14:00:00Z"}})
    argv = _last_call(case)["argv"]
    assert argv[argv.index("--inc") + 1] == "4624,4698" and ids["row_count"] == 2
    assert argv[argv.index("--sd") + 1] == "2026-10-06 14:00:00.0000000"


async def test_ez_run_on_a_folder_registers_every_file(case) -> None:
    r = await _call(case, "ez_run", {"tool": "EvtxECmd", "path": "WS-042/logs"})
    reg = [e["path"] for e in audit.iter_events(case.audit_file) if e["type"] == "evidence_registered"]
    assert set(reg) == {"WS-042/logs/Security.evtx", "WS-042/logs/System.evtx"}
    assert r["evidence"]["path"] == "WS-042/logs" and len(r["evidence"]["sha256"]) == 64


async def test_silent_failure_is_a_tool_error_not_zero_rows(case) -> None:
    p = Path(case.evidence_root) / "WS-042" / "silent.lnk"
    p.write_bytes(b"x")
    r = await _call(case, "ez_run", {"tool": "LECmd", "path": "WS-042/silent.lnk"})
    assert r["row_count"] == 0 and r["exit_code"] == 0
    assert "silent failure" in r["notes"][0] and "does NOT mean 'not present'" in r["notes"][0]
    last = _last_call(case)
    assert last["outcome"] == "tool_error" and "input from stdin or file" in last["error"]


async def test_crash_with_exit_0_and_empty_file_is_a_tool_error(case) -> None:
    p = Path(case.evidence_root) / "WS-042" / "crash.lnk"
    p.write_bytes(b"x")
    r = await _call(case, "lnk_query", {"path": "WS-042/crash.lnk"})
    assert r["row_count"] == 0 and "TOOL ERROR" in r["notes"][0]
    last = _last_call(case)
    assert last["outcome"] == "tool_error" and "SQLite.Interop.dll" in last["error"]
    listing = await _call(case, "ez_list_tools", {})
    issues = {x["tool"] for x in listing["rows"] if x["known_issue"]}
    assert issues == WINDOWS_ONLY  # bstrings runs on Linux with a TTY stdin
    rows = {x["tool"]: x for x in listing["rows"]}
    assert rows["PECmd"]["runtime"] == "windows_only"
    assert rows["PECmd"]["how_to_run"].startswith("exécuter sous Windows")
    assert rows["bstrings"]["runtime"] == "linux"


async def test_ez_list_tools(case) -> None:
    r = await _call(case, "ez_list_tools", {})
    assert r["row_count"] == 17 and "(all present)" in r["summary"]
    recmd = next(x for x in r["rows"] if x["tool"] == "RECmd")
    assert "batch choices: Kroll_Batch.reb" in recmd["options"]


async def test_evtx_query_presets_inc_then_reuse(case) -> None:
    p = "WS-042/logs/Security.evtx"
    per = await _call(case, "evtx_query", {"path": p, "preset": "persistence"})
    assert [r["EventId"] for r in per["rows"]] == [4698, 7045]  # int in real JSON
    assert per["rows"][0]["PayloadData1"].endswith("UpdateSvc")
    assert "--inc" in _last_call(case)["argv"]          # IDs filtered by EvtxECmd itself
    full = await _call(case, "evtx_query", {"path": p, "contains": "alice"})
    assert full["row_count"] == 1 and full["rows"][0]["EventId"] == 4624
    again = await _call(case, "evtx_query", {"path": p, "preset": "execution", "limit": 1})
    assert "parse reused" in again["summary"] and again["page"]["next_offset"] is None
    win = await _call(case, "evtx_query", {"path": p, "start": "2026-10-06T14:30:00Z",
                                           "end": "2026-10-06T14:35:00Z"})
    assert [r["EventId"] for r in win["rows"]] == [4104, 4698]


async def test_evtx_empty_preset_explains_requirements(case) -> None:
    r = await _call(case, "evtx_query", {"path": "WS-042/logs/Security.evtx", "preset": "rdp"})
    assert r["row_count"] == 0 and "'No event' is not 'no activity'" in r["notes"][0]
    joined = " ".join(r["notes"])
    assert "4778 (Security, log present): requires Audit Other Logon/Logoff Events" in joined
    assert "1149 (Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational, " \
           "log ABSENT from the input)" in joined


async def test_mft_search(case) -> None:
    exe = await _call(case, "mft_search", {"path": "WS-042/C/$MFT", "extension": "exe"})
    assert exe["row_count"] == 1 and exe["rows"][0]["FileName"] == "upd.exe"
    pub = await _call(case, "mft_search", {"path": "WS-042/C/$MFT", "path_contains": "users\\public",
                                           "start": "2026-10-06T14:00:00Z",
                                           "end": "2026-10-06T15:00:00Z"})
    assert pub["row_count"] == 1 and "parse reused" in pub["summary"]
    none = await _call(case, "mft_search", {"path": "WS-042/C/$MFT", "start": "2030-01-01T00:00:00Z"})
    assert none["row_count"] == 0
    bad = await _call(case, "mft_search", {"path": "WS-042/C/$MFT", "time_field": "Nope"})
    assert isinstance(bad, str)


async def test_timeline_merges_memory_evtx_mft_in_utc(case) -> None:
    await _call(case, "vol_pslist", {"path": "mem.raw"})
    await _call(case, "evtx_query", {"path": "WS-042/logs/Security.evtx"})
    await _call(case, "mft_search", {"path": "WS-042/C/$MFT"})
    t = await _call(case, "timeline", {"around": "2026-10-06T14:31:00Z", "window_minutes": 5})
    seq = [(r["time_utc"], r["source"], r["event"]) for r in t["rows"]]
    assert seq == [
        ("2026-10-06T14:28:00Z", "evtx", "event 4624"),
        ("2026-10-06T14:29:00Z", "memory", "process_start"),
        ("2026-10-06T14:30:00Z", "memory", "process_start"),
        ("2026-10-06T14:30:05Z", "evtx", "event 4104"),
        ("2026-10-06T14:31:00Z", "mft", "file_created"),
        ("2026-10-06T14:31:00Z", "mft", "file_modified"),
        ("2026-10-06T14:32:07Z", "evtx", "event 4698")]
    assert all(r["source_result_id"] and r["source_row"] >= 1 for r in t["rows"])
    only_case = await _call(case, "timeline", {"case": "WS-042", "around": "2026-10-06T14:31:00Z",
                                               "window_minutes": 5})
    assert "memory" not in {r["source"] for r in only_case["rows"]}  # mem.raw is outside WS-042
    bad = await _call(case, "timeline", {"around": "yesterday"})
    assert "ISO-8601" in bad
