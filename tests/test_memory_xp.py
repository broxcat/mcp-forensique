"""Task 6.5: gaps found on a Windows XP image (Bob.vmem) — vol3 cannot read XP, registry key
with vol2, one string in the memory of one process, one memory region extracted and hashed."""
import hashlib
from pathlib import Path

import pytest
from mcp import Client
from mcp.types import ElicitResult

from forensic_mcp import audit, memory_ops, schemas, server
from forensic_mcp.engines import volatility2

pytestmark = pytest.mark.anyio
XP = {"path": "xp.vmem"}
V2 = {"path": "mem.raw", "profile": "WinXPSP2x86"}


async def _approve(context, params):
    return ElicitResult(action="accept", content={"approve": True, "analyst": "L. Plancke"})


async def _calls(cfg, calls, elicit=None):
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


# ---- 1. Windows XP image: vol3 says what to do instead of a raw symbol error ------------------
async def test_vol3_tools_on_an_xp_image_point_to_vol2(cfg) -> None:
    (Path(cfg.evidence_root) / "xp.vmem").write_bytes(b"\0" * 4096)
    (first,) = await _calls(cfg, [("vol_pslist", XP)])
    assert first["summary"].startswith("Windows XP / 2003 image detected")
    assert "vol2_run (plugin pslist)" in first["summary"] and first["row_count"] == 0
    assert first["notes"][0] == first["summary"] and first["exit_code"] == 1
    assert first["next_steps"] == [{"tool": "vol2_imageinfo", "args": XP,
                                    "why": "vol2 profile of this image"}]
    call = _events(cfg, "tool_call")[-1]
    assert call["outcome"] == "tool_error" and "Windows XP" in call["error"]
    # once vol2_imageinfo has named a legacy profile, the hint gives the exact call
    cache = Path(cfg.output_root) / ".toolcache" / "vol2_imageinfo.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text('{"%s": {"result_id": "x", "profiles": ["WinXPSP2x86", "WinXPSP3x86"]}}'
                     % first["evidence"]["sha256"])
    net, generic = await _calls(cfg, [("vol_netscan", XP),
                                      ("vol3_run", {**XP, "plugin": "windows.info"})])
    assert "vol2 profile WinXPSP2x86" in net["summary"]
    assert net["next_steps"] == [{
        "tool": "vol2_run", "args": {**XP, "plugin": "connscan", "profile": "WinXPSP2x86"},
        "why": "same question with Volatility 2, which supports this image"}]
    assert "Use vol2_run with profile WinXPSP2x86" in generic["summary"]


async def test_a_supported_image_gets_no_xp_hint(cfg) -> None:
    (r,) = await _calls(cfg, [("vol_pslist", {"path": "mem.raw"})])
    assert "XP" not in r["summary"] and "notes" not in r


# ---- 5. vol2_run: typed registry key ----------------------------------------------------------
async def test_vol2_run_typed_registry_key(cfg) -> None:
    key = "Microsoft\\Windows\\CurrentVersion\\Run"
    ok, flag, ctrl, nokey = await _calls(cfg, [
        ("vol2_run", {**V2, "plugin": "printkey", "key": key}),
        ("vol2_run", {**V2, "plugin": "printkey", "key": "--plugins=/tmp"}),
        ("vol2_run", {**V2, "plugin": "printkey", "key": "Run\nx"}),
        ("vol2_run", {**V2, "plugin": "pslist", "key": key})])
    assert ok["rows"][0]["KeyName"] == "Run" and ok["row_count"] == 1
    assert f"--key={key}" in _events(cfg, "tool_call")[0]["argv"]
    assert "key must be a registry path" in flag and "key must be a registry path" in ctrl
    assert "vol2 pslist has no --key option" in nokey
    assert [e["outcome"] for e in _events(cfg, "tool_call")] == ["ok"] + ["refused"] * 3


# ---- 2. one string in the memory of one process -----------------------------------------------
async def test_vol2_yarascan_one_string_one_process(cfg) -> None:
    text, hexa, wide, other = await _calls(cfg, [
        ("vol2_yarascan", {**V2, "pid": 1752, "text": "http://"}),
        ("vol2_yarascan", {**V2, "pid": 1752, "hex_bytes": "68 74 74 70"}),
        ("vol2_yarascan", {**V2, "pid": 1752, "text": "http://", "wide": True,
                           "case_insensitive": True}),
        ("vol2_yarascan", {**V2, "pid": 4, "text": "http://"})])
    row = text["rows"][0]
    assert text["row_count"] == 1 and row["PID"] == 1752 and row["Address"] == "0x1a38102"
    assert row["Text"] == "http://203.0.113.10/a.pdf.." and row["Data"].startswith("68747470")
    assert hexa["rows"][0]["Text"] == row["Text"]
    assert wide["rows"][0]["Text"] == "http://203.0.113.10/a.pdf"
    assert other["row_count"] == 0 and "not that it never existed" in other["notes"][1]
    argv = [e["argv"] for e in _events(cfg, "tool_call")]
    assert "--pid=1752" in argv[0] and "--yara-rules=http://" in argv[0]
    assert "--yara-rules={ 68 74 74 70 }" in argv[1]
    assert "--wide" in argv[2] and "--case" in argv[2] and "--wide" not in argv[0]
    for a in argv:  # never a rule file, never a dump directory
        assert not any(x.split("=")[0] in ("--yara-file", "-y", "--dump-dir", "-D") for x in a)


async def test_vol2_yarascan_refuses_free_patterns(cfg) -> None:
    bad = [{"text": "/evil.*/"}, {"text": "{ 00 }"}, {"text": "ab"}, {"text": "a\nb c"},
           {"text": "x" * 129}, {"hex_bytes": "zz"}, {"text": "abc", "hex_bytes": "00 01"}, {}]
    out = await _calls(cfg, [("vol2_yarascan", {**V2, "pid": 4, **b}) for b in bad]
                       + [("vol2_yarascan", {**V2, "pid": 4, "text": "abc", "profile": "Win99"})])
    assert all(isinstance(o, str) and "refused (audit_id" in o for o in out), out
    assert all(e["outcome"] == "refused" and e["argv"] == [] for e in _events(cfg, "tool_call"))


def test_yara_string_cannot_leave_its_quotes() -> None:
    """vol2 builds `$a = "<text>"`: a quote or a backslash must stay inside the string."""
    assert memory_ops.yara_string('a" condition: true } rule x { condition: true', None) == (
        'a\\" condition: true } rule x { condition: true')
    assert memory_ops.yara_string("C:\\Temp\\a.exe", None) == "C:\\\\Temp\\\\a.exe"
    assert memory_ops.yara_string("end\\", None) == "end\\\\"
    assert memory_ops.yara_string(None, "4D5A90") == "{ 4d 5a 90 }"


# ---- 3. extract one memory region -> hash -> journal ------------------------------------------
async def test_mem_extract_vad_needs_a_named_analyst(cfg) -> None:
    args = {**V2, "pid": 1752, "address": "0x1f0000"}
    (refused,) = await _calls(cfg, [("mem_extract_vad", args)])
    assert "not confirmed" in refused
    assert not _events(cfg, "evidence_registered")  # refused before touching the evidence
    assert not list(Path(cfg.output_root).glob("*/extracted/*"))
    assert [e["type"] for e in audit.iter_events(cfg.audit_file)] == [
        "action_request", "action_confirmed", "tool_call"]


async def test_mem_extract_vad_vol2_hashes_and_registers(cfg) -> None:
    args = {**V2, "pid": 1752, "address": "0x1f0000"}
    ok, none, whole = await _calls(cfg, [
        ("mem_extract_vad", args), ("mem_extract_vad", {**args, "address": "0x7f0000"}),
        ("mem_extract_vad", {**args, "address": "everything"})], _approve)
    row = ok["rows"][0]
    digest = hashlib.sha256(b"%PDF" + b"\0" * 4092).hexdigest()
    assert ok["row_count"] == 1 and row["sha256"] == digest and row["size"] == 4096
    assert row["path"] == f"@{ok['result_id']}/pid1752_vad_0x001f0000-0x001f0fff.dmp"
    assert (row["vad_start"], row["vad_end"]) == ("0x001f0000", "0x001f0fff")
    assert "NOT the hash of the file on disk" in ok["notes"][0]
    f = Path(cfg.output_root) / ok["result_id"] / "extracted" / row["path"].split("/")[1]
    assert f.read_bytes()[:4] == b"%PDF" and not f.stat().st_mode & 0o222
    reg = [e for e in _events(cfg, "evidence_registered") if e["path"] == row["path"]][0]
    assert reg["sha256"] == digest and reg["audit_id"] == row["registration_audit_id"]
    assert reg["source_sha256"] == ok["evidence"]["sha256"] and reg["pid"] == 1752
    conf = _events(cfg, "action_confirmed")[0]
    assert conf["decision"] == "approved" and conf["actor"] == {"kind": "analyst",
                                                                "name": "L. Plancke"}
    call = [e for e in _events(cfg, "tool_call") if e["tool"] == "mem_extract_vad"]
    dump_dirs = [a for a in call[0]["argv"] if a.startswith("--dump-dir=")]
    assert dump_dirs == [f"--dump-dir={Path(cfg.output_root) / ok['result_id'] / 'extracted'}"]
    assert "--pid=1752" in call[0]["argv"] and "--base=0x1f0000" in call[0]["argv"]
    assert call[0]["outcome"] == "ok" and call[0]["result_id"] == ok["result_id"]
    # an address that is not a VAD start: nothing written, said plainly, journaled as an error
    assert none["row_count"] == 0 and none["summary"].startswith("nothing extracted")
    assert call[1]["outcome"] == "tool_error" and "nothing extracted" in call[1]["error"]
    assert "address must be" in whole and call[2]["outcome"] == "refused"
    # the extracted region is usable as a registered input of the other tools
    (ev,) = await _calls(cfg, [("verify_evidence", {"path": row["path"]})])
    assert ev["evidence"]["sha256"] == digest and "unchanged" in ev["summary"]


async def test_mem_extract_vad_vol3(cfg) -> None:
    (ok,) = await _calls(cfg, [("mem_extract_vad", {"path": "mem.raw", "pid": 4312,
                                                    "address": "0x1f0800"})], _approve)
    row = ok["rows"][0]
    assert ok["engine"].startswith("volatility3") and row["size"] == 4096
    assert row["sha256"] == hashlib.sha256(b"MZ" + b"\x90" * 4094).hexdigest()
    assert row["path"] == f"@{ok['result_id']}/pid4312_vad_0x1f0000-0x1f0fff.dmp"
    argv = _events(cfg, "tool_call")[-1]["argv"]
    assert argv[-7:] == ["--pid", "4312", "--address", str(0x1F0800), "--maxsize",
                         str(cfg.max_output_mb * 1024 * 1024), "--dump"]


async def test_vol2_run_still_refuses_dump_plugins_and_dump_dir(cfg) -> None:
    (r,) = await _calls(cfg, [("vol2_run", {**V2, "plugin": "vaddump", "pid": 1752})], _approve)
    assert "--dump-dir" in r and "forbidden" in r
    with pytest.raises(ValueError, match="forbidden"):
        await volatility2.run(cfg, cfg.evidence_root / "mem.raw", "pslist", "WinXPSP2x86",
                              ["--dump-dir=/tmp/x"], "a" * 64)
