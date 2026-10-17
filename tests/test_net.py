"""Task 6.7 (extension EXT-03): network-capture tools. The typed-parameter, path-jail and
journal rules are checked with the fake tshark/capinfos stubs; the last test runs the REAL
tshark on a real .pcap built by tests/pcap_fixture.py (skipped when tshark is not installed).
"""
import json
import shutil
import stat
from pathlib import Path

import pytest
from mcp import Client
from mcp.types import ElicitResult

from forensic_mcp import audit, config, safety, schemas, server
from forensic_mcp.engines import tshark
from pcap_fixture import write_test_pcap

pytestmark = pytest.mark.anyio
PCAP = "WS-042/network/ws042.pcap"
# Fake capture: 5 packets (DNS query/answer, HTTP request/response, TLS ClientHello), the field
# names being the real tshark ones (the stub prints whatever the server asks for with -e).
FAKE_PACKETS = [
    {"frame.number": 1, "frame.time_epoch": "1792161000.000000", "frame.len": 85,
     "frame.protocols": "eth:ethertype:ip:udp:dns", "ip.src": "192.168.56.101",
     "ip.dst": "192.168.56.1", "udp.srcport": 50000, "udp.dstport": 53,
     "dns.flags.response": 0, "dns.qry.name": "c2.example.test", "dns.qry.type": 1},
    {"frame.number": 2, "frame.time_epoch": "1792161000.050000", "frame.len": 101,
     "frame.protocols": "eth:ethertype:ip:udp:dns", "ip.src": "192.168.56.1",
     "ip.dst": "192.168.56.101", "udp.srcport": 53, "udp.dstport": 50000,
     "dns.flags.response": 1, "dns.qry.name": "c2.example.test", "dns.qry.type": 1,
     "dns.a": "203.0.113.10", "dns.flags.rcode": 0},
    {"frame.number": 3, "frame.time_epoch": "1792161001.000000", "frame.len": 160,
     "frame.protocols": "eth:ethertype:ip:tcp:http", "ip.src": "192.168.56.101",
     "ip.dst": "203.0.113.10", "tcp.srcport": 49800, "tcp.dstport": 80,
     "http.request.method": "GET", "http.host": "c2.example.test",
     "http.request.uri": "/a.ps1", "http.request.full_uri": "http://c2.example.test/a.ps1",
     "http.user_agent": "Mozilla/5.0 (lab)"},
    {"frame.number": 4, "frame.time_epoch": "1792161001.200000", "frame.len": 140,
     "frame.protocols": "eth:ethertype:ip:tcp:http", "ip.src": "203.0.113.10",
     "ip.dst": "192.168.56.101", "tcp.srcport": 80, "tcp.dstport": 49800,
     "http.response.code": 200, "http.content_type": "application/octet-stream",
     "http.content_length": 5},
    {"frame.number": 5, "frame.time_epoch": "1792161002.000000", "frame.len": 180,
     "frame.protocols": "eth:ethertype:ip:tcp:tls", "ip.src": "192.168.56.101",
     "ip.dst": "203.0.113.10", "tcp.srcport": 49802, "tcp.dstport": 443,
     "tls.handshake.type": 1, "tls.handshake.version": "0x0303",
     "tls.handshake.ciphersuite": "0x1301",
     "tls.handshake.extensions_server_name": "c2.example.test",
     "tls.handshake.ja3": "771,4865,0"},
]


@pytest.fixture
def case(cfg):
    root = Path(cfg.evidence_root) / "WS-042"
    (root / "network").mkdir(parents=True)
    (root / "network" / "ws042.pcap").write_text(json.dumps({"packets": FAKE_PACKETS}),
                                                 encoding="utf-8")
    (root / "network" / "broken.pcap").write_text(json.dumps({"packets": []}), encoding="utf-8")
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


def _last_call(cfg):
    return _events(cfg, "tool_call")[-1]


# ---- the engine: flags, fields, filter building (no tool run) -------------------------------
def test_every_flag_the_server_can_pass_is_in_the_saved_help() -> None:
    assert tshark.verify_flags() == []
    assert not tshark.USED_TSHARK & tshark.FORBIDDEN   # capinfos letters mean other things
    assert tshark.SERVER_ONLY == {"-w", "-G"}
    assert len(tshark.all_fields()) >= 25


def test_verify_flags_catches_an_invented_flag(monkeypatch) -> None:
    monkeypatch.setattr(tshark, "USED_TSHARK", frozenset({"--no-such-flag"}))
    assert "tshark --no-such-flag" in tshark.verify_flags()


def test_filter_is_built_from_typed_values_only() -> None:
    f = tshark.build_filter("packets", ip="203.0.113.10", port=443, proto="tcp",
                            start="2026-10-16T14:30:00Z", end="2026-10-16T14:31:00Z")
    assert f == ("ip.addr == 203.0.113.10 && (tcp.port == 443 || udp.port == 443) && tcp && "
                 "frame.time_epoch >= 1792161000.000000 && "
                 "frame.time_epoch <= 1792161060.000000")
    assert tshark.build_filter("dns", ip="2001:db8::1") == \
        "(dns) && ipv6.addr == 2001:db8::1"
    assert tshark.build_filter("packets") == ""


@pytest.mark.parametrize("kw", [
    {"ip": "203.0.113.10 || ip.addr == 10.0.0.1"},   # filter injection through the address
    {"ip": "evil.example"}, {"ip": "203.0.113.999"},
    {"port": 0}, {"port": 70000}, {"port": True}, {"port": "443 || tcp.port == 22"},
    {"proto": "frame.len > 0"}, {"proto": "icmp6"},
    {"start": "yesterday"}, {"end": "2026-13-45"}])
def test_a_value_outside_the_type_is_refused(kw) -> None:
    with pytest.raises(ValueError):
        tshark.build_filter("packets", **kw)


def test_forbidden_options_never_reach_the_tool(cfg) -> None:
    for flag in ("-X", "-z", "-o", "-i", "-k", "--export-objects"):
        with pytest.raises(ValueError, match="forbidden"):
            tshark.check_argv(["tshark", "-r", "x.pcap", flag, "value"])
    with pytest.raises(ValueError, match="-w is only used"):
        tshark.check_argv(["tshark", "-r", "x.pcap", "-w", "/evidence/overwrite.pcap"])
    argv = tshark.extract_argv(cfg, Path("/evidence/x.pcap"), "tcp", Path("/output/r/e/f.pcapng"))
    assert argv[-2:] == ["-w", "/output/r/e/f.pcapng"] and "-n" in argv


def test_read_argv_has_no_name_resolution_and_one_field_per_column(cfg) -> None:
    argv = tshark.read_argv(cfg, Path("/evidence/x.pcap"), "dns", "(dns)")
    assert "-n" in argv and argv.count("-e") == len(tshark.VIEWS["dns"].fields)
    assert ["-Y", "(dns)"] == argv[argv.index("-Y"):argv.index("-Y") + 2]
    assert "-E" in argv and "separator=/t" in argv


# ---- the six tools on the fake stubs --------------------------------------------------------
async def test_pcap_info(case) -> None:
    r = await _call(case, "pcap_info", {"path": PCAP})
    row = r["rows"][0]
    assert row["packets"] == 5 and row["encapsulation"] == "Ethernet"
    assert row["first_packet_utc"] == "2026-10-16T14:30:00Z"
    assert row["last_packet_utc"] == "2026-10-16T14:30:02Z"
    assert "65535" in " ".join(r["notes"])          # snapshot length warning
    ev = _last_call(case)
    assert ev["outcome"] == "ok" and ev["tool"] == "pcap_info"
    assert ev["evidence_sha256"] and "capinfos" in " ".join(ev["argv"])


async def test_pcap_conversations_are_aggregated_by_the_server(case) -> None:
    r = await _call(case, "pcap_conversations", {"path": PCAP})
    assert r["row_count"] == 3                       # DNS pair folded, HTTP, TLS
    http = [c for c in r["rows"] if c["dst_port"] == 80 or c["src_port"] == 80][0]
    assert http["packets"] == 2 and http["bytes"] == 300
    assert http["packets_a_to_b"] == 1 and http["packets_b_to_a"] == 1
    assert http["first_utc"] == "2026-10-16T14:30:01Z"
    dns = [c for c in r["rows"] if c["transport"] == "udp"][0]
    assert dns["packets"] == 2 and "dns" in dns["protocols"]
    assert "-z" not in " ".join(_last_call(case)["argv"])   # computed here, not by tshark


async def test_pcap_dns_query_filters_text_server_side(case) -> None:
    r = await _call(case, "pcap_dns_query", {"path": PCAP, "query_name_contains": "C2.EXAMPLE"})
    assert r["row_count"] == 2 and r["rows"][0]["query_name"] == "c2.example.test"
    answer = [row for row in r["rows"] if row.get("answer_a")][0]
    assert answer["answer_a"] == "203.0.113.10" and answer["time_utc"].endswith("Z")
    argv = " ".join(_last_call(case)["argv"])
    assert "C2.EXAMPLE" not in argv and "-Y (dns)" in argv   # no caller text in the argv
    empty = await _call(case, "pcap_dns_query", {"path": PCAP, "query_name_contains": "absent"})
    assert empty["row_count"] == 0 and "does not prove" in " ".join(empty["notes"])


async def test_pcap_http_objects(case) -> None:
    r = await _call(case, "pcap_http_objects", {"path": PCAP, "uri_contains": ".ps1"})
    assert r["row_count"] == 1
    row = r["rows"][0]
    assert row["host"] == "c2.example.test" and row["uri"] == "/a.ps1"
    assert row["full_uri"] == "http://c2.example.test/a.ps1" and row["frame"] == 3
    assert "no file is carved" in " ".join(r["notes"])
    both = await _call(case, "pcap_http_objects", {"path": PCAP})
    assert both["row_count"] == 2 and both["rows"][1]["response_code"] == 200


async def test_pcap_tls_info(case) -> None:
    r = await _call(case, "pcap_tls_info", {"path": PCAP, "server_name_contains": "example"})
    assert r["row_count"] == 1 and r["rows"][0]["server_name"] == "c2.example.test"
    assert r["rows"][0]["ja3"] == "771,4865,0" and r["rows"][0]["dst_port"] == 443
    assert "stays encrypted" in " ".join(r["notes"])


async def test_typed_filters_reach_the_display_filter(case) -> None:
    await _call(case, "pcap_conversations", {"path": PCAP, "ip": "203.0.113.10", "port": 80,
                                             "proto": "tcp", "start": "2026-10-16T14:30:00Z"})
    argv = _last_call(case)["argv"]
    filt = argv[argv.index("-Y") + 1]
    assert filt == ("ip.addr == 203.0.113.10 && (tcp.port == 80 || udp.port == 80) && tcp && "
                    "frame.time_epoch >= 1792161000.000000")
    bad = await _call(case, "pcap_conversations", {"path": PCAP, "ip": "not-an-ip"})
    assert "refused" in bad and _last_call(case)["outcome"] == "refused"


async def test_a_capture_outside_the_evidence_root_is_refused(case) -> None:
    for path in ("../outside.pcap", "/etc/passwd", "@20261017-120000-vol3_run-abcdef/x.pcap"):
        out = await _call(case, "pcap_info", {"path": path})
        assert "refused" in out, path
        assert _last_call(case)["outcome"] == "refused"


async def test_an_unreadable_capture_is_a_tool_error(case) -> None:
    out = await _call(case, "pcap_dns_query", {"path": "WS-042/network/broken.pcap"})
    assert out["row_count"] == 0 and "damaged or corrupt" in " ".join(out["notes"])
    assert _last_call(case)["outcome"] == "tool_error"


# ---- net_extract_pcap: confirmed, hashed, registered, reusable ------------------------------
async def test_net_extract_pcap_needs_a_filter_and_a_confirmation(case) -> None:
    out = await _call(case, "net_extract_pcap", {"path": PCAP}, _approve)
    assert "at least one filter" in out
    out = await _call(case, "net_extract_pcap", {"path": PCAP, "ip": "203.0.113.10"})
    assert "confirmation" in out.lower() or "refused" in out      # no elicitation support
    assert _last_call(case)["outcome"] == "refused"


async def test_net_extract_pcap_registers_the_copy_as_evidence(case) -> None:
    r = await _call(case, "net_extract_pcap", {"path": PCAP, "ip": "203.0.113.10"}, _approve)
    row = r["rows"][0]
    assert row["packets"] == 3 and row["path"].startswith("@") and row["sha256"]
    assert row["path"].endswith("ws042_filtered.pcapng")
    copy = safety.jail_input(row["path"], case.evidence_root, case.output_root)
    assert copy.is_file() and not stat.S_IMODE(copy.stat().st_mode) & 0o222   # read-only
    reg = _events(case, "evidence_registered")[-1]
    assert reg["sha256"] == row["sha256"] and reg["display_filter"] == "ip.addr == 203.0.113.10"
    assert [e["type"] for e in audit.iter_events(case.audit_file)].count("action_confirmed") == 1
    # the copy is itself an input of the pcap_* tools
    again = await _call(case, "pcap_info", {"path": row["path"]})
    assert again["rows"][0]["packets"] == 3


# ---- end to end on a real capture with the real tshark --------------------------------------
REAL = shutil.which("tshark")


@pytest.mark.skipif(not REAL, reason="tshark is not installed (image before task 6.7)")
async def test_real_tshark_on_a_real_pcap(tmp_path, cfg) -> None:
    real = config.Config(**{**cfg.__dict__, "tshark_dir": Path(REAL).parent,
                            "tshark_prefix": []})
    facts = write_test_pcap(Path(real.evidence_root) / "WS-042/network/real.pcap")
    (Path(real.evidence_root) / "WS-042" / "case.toml").write_text(
        'case = "WS-042"\nclassification = "lab"\n')
    path = "WS-042/network/real.pcap"

    info = await _call(real, "pcap_info", {"path": path})
    assert info["rows"][0]["packets"] == facts["packets"]
    assert info["rows"][0]["first_packet_utc"] == facts["first_utc"]

    dns = await _call(real, "pcap_dns_query", {"path": path})
    assert dns["row_count"] == 2
    assert all(row["query_name"] == facts["domain"] for row in dns["rows"])
    assert [row for row in dns["rows"] if row.get("answer_a")][0]["answer_a"] == facts["server"]

    http = await _call(real, "pcap_http_objects", {"path": path, "uri_contains": ".ps1"})
    assert http["row_count"] == 1 and http["rows"][0]["uri"] == facts["uri"]
    assert http["rows"][0]["host"] == facts["domain"]

    tls = await _call(real, "pcap_tls_info", {"path": path})
    assert tls["row_count"] == 1 and tls["rows"][0]["server_name"] == facts["domain"]

    conv = await _call(real, "pcap_conversations", {"path": path})
    assert conv["row_count"] == 3 and sum(c["packets"] for c in conv["rows"]) == 5
    external = [c for c in conv["rows"] if facts["server"] in (c["src"], c["dst"])]
    assert len(external) == 2 and sum(c["packets"] for c in external) == 3

    window = await _call(real, "pcap_conversations",
                         {"path": path, "ip": facts["server"], "start": "2026-10-16T14:30:01Z"})
    assert window["row_count"] == 2

    out = await _call(real, "net_extract_pcap", {"path": path, "ip": facts["server"]}, _approve)
    assert out["rows"][0]["packets"] == 3
    copy = safety.jail_input(out["rows"][0]["path"], real.evidence_root, real.output_root)
    assert copy.read_bytes()[:4] in (b"\n\r\r\n", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")
    again = await _call(real, "pcap_tls_info", {"path": out["rows"][0]["path"]})
    assert again["row_count"] == 1


@pytest.mark.skipif(not REAL, reason="tshark is not installed (image before task 6.7)")
def test_every_field_used_exists_in_the_real_tshark(tmp_path) -> None:
    import subprocess
    known = {line.split("\t")[2] for line in subprocess.run(
        [REAL, "-G", "fields"], capture_output=True, text=True, check=True).stdout.splitlines()
        if line.startswith("F") and len(line.split("\t")) > 2}
    assert not [f for f in tshark.all_fields() if f not in known]
