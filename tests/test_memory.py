"""Task 4.2: one test per memory tool (fake vol / fake vol2), typed options, sensitive plugins."""
import pytest
from mcp import Client
from mcp.types import ElicitResult

from forensic_mcp import audit, schemas, server
from forensic_mcp.engines import volatility2

pytestmark = pytest.mark.anyio
M = {"path": "mem.raw"}


async def _approve(context, params):
    return ElicitResult(action="accept", content={"approve": True, "analyst": "L. Plancke"})


async def _decline(context, params):
    return ElicitResult(action="decline")


async def _calls(cfg, calls, elicit=None):
    """Run calls in one session; return structured contents (or the error text)."""
    out = []
    async with Client(server.build_server(cfg), elicitation_callback=elicit) as c:
        for tool, args in calls:
            r = await c.call_tool(tool, args)
            if r.is_error:
                out.append(r.content[0].text)
            else:
                assert schemas.errors(schemas.output_validator(), r.structured_content) == []
                out.append(r.structured_content)
    return out


def _events(cfg, type_):
    return [e for e in audit.iter_events(cfg.audit_file) if e["type"] == type_]


def _rules(payload):
    return {a["rule_id"]: a for a in payload["anomalies"]}


async def test_vol_pslist_flags_office_shell_with_attack(cfg) -> None:
    (r,) = await _calls(cfg, [("vol_pslist", M)])
    a = _rules(r)["office_spawns_shell"]
    row = next(x for x in r["rows"] if x["PID"] == 4312)
    assert a["rows"] == [row["_row"]] and a["attack"] == ["T1566.001", "T1204.002", "T1059"]
    assert "WINWORD.EXE" in a["explanation"].upper() or "winword" in a["explanation"]
    assert {"tool": "vol_cmdline", "args": {"pid": 4312},
            "why": "command line of the process started by Office"} in r["next_steps"]


async def test_vol_pstree_passes_pid(cfg) -> None:
    (r,) = await _calls(cfg, [("vol_pstree", {**M, "pid": 4})])
    assert r["row_count"] == 4 and "--pid" in _events(cfg, "tool_call")[-1]["argv"]


async def test_vol_cmdline_decodes_and_extracts_iocs(cfg) -> None:
    (r,) = await _calls(cfg, [("vol_cmdline", M)])
    dec = r["decoded"][0]
    assert "http://203.0.113.10/a.ps1" in dec["text"] and dec["layers"] == 1
    assert {"type": "url", "value": "http://203.0.113.10/a.ps1", "_row": dec["_row"],
            "source": "decoded"} in r["iocs"]
    assert _rules(r)["encoded_powershell"]["attack"] == ["T1059.001", "T1027"]


async def test_vol_netscan_pid_filter_and_ioc_match(cfg) -> None:
    pslist, cmd, net = await _calls(cfg, [("vol_pslist", M), ("vol_cmdline", M),
                                          ("vol_netscan", {**M, "pid": 4312})])
    assert net["row_count"] == 1 and net["rows"][0]["ForeignAddr"] == "203.0.113.10"
    rules = _rules(net)
    assert rules["ioc_match"]["rows"] == [net["rows"][0]["_row"]]
    assert rules["external_connection"]["severity"] == "high"  # owner flagged by pslist
    assert "--pid" not in _events(cfg, "tool_call")[-1]["argv"]  # netscan has no --pid option


async def test_vol_malfind_dump_needs_named_confirmation(cfg) -> None:
    (plain,) = await _calls(cfg, [("vol_malfind", M)])
    assert plain["row_count"] == 1
    (refused,) = await _calls(cfg, [("vol_malfind", {**M, "dump": True})])  # no elicitation
    assert "not confirmed" in refused
    (declined,) = await _calls(cfg, [("vol_malfind", {**M, "dump": True})], _decline)
    assert "not confirmed" in declined
    (ok,) = await _calls(cfg, [("vol_malfind", {**M, "dump": True})], _approve)
    assert "--dump" in _events(cfg, "tool_call")[-1]["argv"]
    decisions = [e["decision"] for e in _events(cfg, "action_confirmed")]
    assert decisions == ["denied", "denied", "approved"]
    assert _events(cfg, "action_confirmed")[-1]["actor"] == {"kind": "analyst", "name": "L. Plancke"}
    assert len(_events(cfg, "action_request")) == 3
    assert audit.verify_audit(cfg.audit_file)[0]


async def test_vol_dlllist_learns_image_path(cfg) -> None:
    (r,) = await _calls(cfg, [("vol_dlllist", {**M, "pid": 4312})])
    assert r["rows"][0]["Path"].endswith("powershell.exe") and r["anomalies"] == []


async def test_vol_printkey_typed_key(cfg) -> None:
    ok, bad = await _calls(cfg, [("vol_printkey", {**M, "key": "Software\\Run"}),
                                 ("vol_printkey", {**M, "key": "--plugin-dirs=/tmp"})])
    assert ok["rows"][0]["Name"] == "UpdateSvc"
    argv = [e["argv"] for e in _events(cfg, "tool_call") if e["outcome"] == "ok"][0]
    assert argv[-2:] == ["--key", "Software\\Run"]
    assert "invalid" in bad


async def test_vol3_run_any_plugin_typed_options_only(cfg) -> None:
    info, bad_opt, bad_name = await _calls(cfg, [
        ("vol3_run", {**M, "plugin": "windows.info"}),
        ("vol3_run", {**M, "plugin": "windows.cmdline", "offset": "0x10"}),
        ("vol3_run", {**M, "plugin": "windows.info;id"})])
    assert info["row_count"] == 1
    assert "has no --offset option" in bad_opt and "invalid plugin name" in bad_name


async def test_vol3_sensitive_plugin_refused_then_approved(cfg) -> None:
    (refused,) = await _calls(cfg, [("vol3_run", {**M, "plugin": "windows.registry.hashdump"})])
    assert "not confirmed" in refused
    assert not _events(cfg, "evidence_registered")  # refused before touching the evidence
    (ok,) = await _calls(cfg, [("vol3_run", {**M, "plugin": "hashdump"})], _approve)
    assert ok["rows"][0]["User"] == "Administrator"
    outcomes = [e["outcome"] for e in _events(cfg, "tool_call")]
    assert outcomes == ["refused", "ok"]


async def test_vol_list_plugins_flags_sensitive(cfg) -> None:
    (r,) = await _calls(cfg, [("vol_list_plugins", {"contains": "hash"})])
    assert r["rows"][0]["sensitive"] is True and r["row_count"] == 1


async def test_vol2_list_plugins_and_profiles(cfg) -> None:
    (r,) = await _calls(cfg, [("vol2_list_plugins", {})])
    by = {x["name"]: x for x in r["rows"]}
    assert by["hashdump"]["sensitive"] and by["procdump"]["refused_needs_dump_dir"]
    assert "Win7SP1x64" in r["summary"]


async def test_vol2_imageinfo_is_cached(cfg) -> None:
    first, second = await _calls(cfg, [("vol2_imageinfo", M), ("vol2_imageinfo", M)])
    assert first["summary"].startswith("Suggested profiles: Win7SP1x64")
    assert second["summary"].endswith("(cached)") and second["result_id"] == first["result_id"]


async def test_vol2_run_json_text_fallback_and_refusals(cfg) -> None:
    ps, cmd, prof, dump, cred = await _calls(cfg, [
        ("vol2_run", {**M, "plugin": "pslist", "profile": "Win7SP1x64", "pid": 4}),
        ("vol2_run", {**M, "plugin": "cmdline", "profile": "Win7SP1x64"}),
        ("vol2_run", {**M, "plugin": "pslist", "profile": "Win99"}),
        ("vol2_run", {**M, "plugin": "procdump", "profile": "Win7SP1x64"}),
        ("vol2_run", {**M, "plugin": "hashdump", "profile": "Win7SP1x64"})])
    assert ps["row_count"] == 1 and ps["rows"][0]["Offset(V)"] == hex(18446738026458983216)
    assert ps["rows"][0]["Name"] == "System"
    assert cmd["rows"][1]["line"].startswith("System pid")  # text fallback, one row per line
    assert "unknown vol2 profile" in prof and "--dump-dir" in dump and "not confirmed" in cred
    for e in _events(cfg, "tool_call"):
        assert not any(a.split("=")[0] in volatility2.FORBIDDEN for a in e["argv"])
    assert "--pid=4" in _events(cfg, "tool_call")[0]["argv"]


def test_vol2_engine_never_passes_forbidden_options() -> None:
    with pytest.raises(ValueError):
        volatility2.check_plugin("dumpfiles", {"dumpfiles": "x"})
    assert {"--plugins", "-w", "--write", "-D", "--dump-dir"} <= volatility2.FORBIDDEN


async def test_vol2_engine_rejects_forbidden_option(cfg) -> None:
    with pytest.raises(ValueError, match="forbidden"):
        await volatility2.run(cfg, cfg.evidence_root / "mem.raw", "pslist", "Win7SP1x64",
                              ["--plugins=/tmp"], "a" * 64)


async def test_replay_of_typed_tool(cfg) -> None:
    (r,) = await _calls(cfg, [("vol_pslist", M)])
    (rep,) = await _calls(cfg, [("replay", {"audit_id": r["audit_id"]})])
    assert rep["rows"][0]["match"] is True
