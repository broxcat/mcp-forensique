"""Analyzers applied by the server to memory results (CLAUDE.md §10): the rule table
rules/process_rules.yaml, encoded-PowerShell decoding and IOC extraction.

A per-image context (output_root/.analysis/<evidence sha256>.json) keeps the process table,
flagged PIDs and extracted IOCs across calls, so a cmdline or netscan result can be judged
with the parent names seen in pslist. Output: anomalies[], next_steps[], iocs[], decoded[].
"""
from __future__ import annotations

import fcntl
import ipaddress
import json
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Iterator

import yaml

from . import decode
from .redact import INTERNAL_NETS

RULES_FILE = Path(__file__).resolve().parents[2] / "rules" / "process_rules.yaml"
PROCESS_LISTS = {"pslist", "pstree", "psscan"}
FAMILIES = PROCESS_LISTS | {"cmdline", "dlllist", "netscan", "netstat", "connections", "connscan"}
MAX_ROWS = 50_000
PID, PPID = ("PID", "Pid", "pid"), ("PPID", "Ppid", "ppid")
NAME = ("ImageFileName", "Name", "Process", "Owner")
ARGS, EXIT = ("Args", "CommandLine", "Command line"), ("ExitTime", "Exit")
FOREIGN, FPORT, STATE = ("ForeignAddr", "Foreign Address"), ("ForeignPort",), ("State",)


@lru_cache(maxsize=None)
def rules() -> dict[str, Any]:
    """The rule table (data), with rules indexed by id."""
    data = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
    data["by_id"] = {r["id"]: r for r in data["rules"]}
    return data


def family(plugin: str) -> str:
    """windows.pslist.PsList -> pslist; vol2 'pslist' -> pslist."""
    parts = plugin.lower().split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _get(row: dict[str, Any], names: tuple[str, ...]) -> Any:
    return next((row[n] for n in names if row.get(n) not in (None, "")), None)


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def exe_path(args: str | None) -> str | None:
    """Image path from a command line ("C:\\x y\\a.exe" arg, or C:\\a.exe arg)."""
    if not args:
        return None
    a = args.strip()
    p = a[1:].split('"', 1)[0] if a.startswith('"') else a.split(" ", 1)[0]
    return p if (":\\" in p or p.startswith("\\")) else None


def _public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local
                or any(addr in n for n in INTERNAL_NETS if n.version == addr.version))


def _distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


@contextmanager
def _context(output_root: Path, sha: str) -> Iterator[dict[str, Any]]:
    f = Path(output_root) / ".analysis" / f"{sha}.json"
    f.parent.mkdir(parents=True, exist_ok=True)
    with open(f.with_suffix(".lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        ctx = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
        ctx.setdefault("procs", {}), ctx.setdefault("flagged", {}), ctx.setdefault("iocs", {})
        yield ctx
        f.write_text(json.dumps(ctx, indent=1), encoding="utf-8")


class _Out:
    def __init__(self) -> None:
        self.anomalies: list[dict[str, Any]] = []
        self.next_steps: dict[str, dict[str, Any]] = {}
        self.iocs: dict[str, dict[str, Any]] = {}
        self.decoded: list[dict[str, Any]] = []

    def flag(self, rule_id: str, rows: list[int], pid: int | None, severity: str | None = None,
             attack: list[str] | None = None, **fmt: Any) -> None:
        r = rules()["by_id"][rule_id]
        self.anomalies.append({"rule_id": rule_id, "severity": severity or r["severity"],
                               "attack": list(r["attack"] if attack is None else attack),
                               "rows": sorted(set(rows)),
                               "explanation": r["explanation"].format(pid=pid, **fmt)})
        for step in r.get("next_steps", []) if pid is not None else []:
            args = {k: (pid if v == "{pid}" else v) for k, v in step["args"].items()}
            key = json.dumps([step["tool"], args], sort_keys=True)
            self.next_steps.setdefault(key, {"tool": step["tool"], "args": args,
                                             "why": step["why"]})


def analyze(output_root: Path, evidence_sha: str, plugin: str,
            rows: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Apply the rule table to one result. Returns anomalies, next_steps, iocs, decoded."""
    fam, out = family(plugin), _Out()
    if fam not in FAMILIES:
        return {"anomalies": [], "next_steps": [], "iocs": [], "decoded": []}
    data = [r for _, r in zip(range(MAX_ROWS), rows)]
    with _context(output_root, evidence_sha) as ctx:
        _learn(ctx, fam, data)
        if fam in PROCESS_LISTS | {"cmdline", "dlllist"}:
            _process_rules(ctx, fam, data, out)
        if fam == "cmdline":
            _encoded(ctx, data, out)
        if fam in {"netscan", "netstat", "connections", "connscan"}:
            _network(ctx, data, out)
        for a in out.anomalies:
            for row in data:
                if row["_row"] in a["rows"] and _int(_get(row, PID)) is not None:
                    ctx["flagged"].setdefault(str(_int(_get(row, PID))), [])
                    if a["rule_id"] not in ctx["flagged"][str(_int(_get(row, PID)))]:
                        ctx["flagged"][str(_int(_get(row, PID)))].append(a["rule_id"])
    return {"anomalies": out.anomalies, "next_steps": list(out.next_steps.values()),
            "iocs": list(out.iocs.values()), "decoded": out.decoded}


def _learn(ctx: dict[str, Any], fam: str, data: list[dict[str, Any]]) -> None:
    seen: set[str] = set()
    for row in data:
        pid = _int(_get(row, PID))
        if pid is None:
            continue
        p = ctx["procs"].setdefault(str(pid), {})
        if fam in PROCESS_LISTS:
            name, ppid = _get(row, NAME), _int(_get(row, PPID))
            if name:
                p["name"] = str(name)
            if ppid is not None:
                p["ppid"] = ppid
            p["exited"] = bool(_get(row, EXIT))
        elif fam == "cmdline":
            if _get(row, NAME):
                p.setdefault("name", str(_get(row, NAME)))
            path = exe_path(_get(row, ARGS))
            if path:
                p["path"] = path
        elif fam == "dlllist" and str(pid) not in seen and row.get("Path"):
            p["path"] = str(row["Path"])  # first module of a process = its image
        seen.add(str(pid))


def _process_rules(ctx: dict[str, Any], fam: str, data: list[dict[str, Any]], out: _Out) -> None:
    t, procs = rules(), ctx["procs"]
    office, shells = set(t["office_parents"]), set(t["shells"])
    counts: dict[str, list[dict[str, Any]]] = {}
    done: set[tuple[str, int]] = set()
    for row in data:
        pid = _int(_get(row, PID))
        if pid is None or (("row", pid) in done):
            continue
        done.add(("row", pid))
        p = procs.get(str(pid), {})
        name = str(p.get("name") or _get(row, NAME) or "").lower()
        ppid = p.get("ppid")
        parent = str(procs.get(str(ppid), {}).get("name", "")).lower() if ppid is not None else ""
        rows = [row["_row"]]
        if name in shells and parent in office:
            out.flag("office_spawns_shell", rows, pid, name=name, ppid=ppid, parent_name=parent)
        exp = t["expected_parents"].get(name)
        if exp and parent and parent not in exp:
            out.flag("system_process_wrong_parent", rows, pid, name=name, ppid=ppid,
                     parent_name=parent, expected=" or ".join(exp))
        if len(name) >= 5 and name not in t["system_binaries"] + t["masquerade_exclude"]:
            for sysname in t["system_binaries"]:
                ref = sysname[:len(name)] if len(name) == 14 else sysname  # vol3 cuts at 14
                d = _distance(name, ref)
                if 1 <= d <= 2 and len(sysname) >= 7:
                    out.flag("masquerade_name", rows, pid, name=name, expected=sysname, count=d)
                    break
        _path_rule(p.get("path"), name, pid, rows, out)
        if fam in PROCESS_LISTS and not p.get("exited"):
            counts.setdefault(name, []).append(row)
    for name in t["singletons"]:
        live = counts.get(name, [])
        if len(live) > 1:
            out.flag("duplicate_singleton", [r["_row"] for r in live], _int(_get(live[-1], PID)),
                     name=name, count=len(live))


def _path_rule(path: str | None, name: str, pid: int, rows: list[int], out: _Out) -> None:
    if not path:
        return
    t, low = rules(), path.lower().replace("/", "\\")
    for prefix in ("\\??\\", "\\\\?\\"):  # NT object-manager / Win32 long-path prefixes
        low = low[len(prefix):] if low.startswith(prefix) else low
    base = low.rsplit("\\", 1)[-1]
    if base in t["system_binaries"] or name in t["system_binaries"]:
        dirs = t["system_dir_exceptions"].get(base, t["system_dirs"])
        if not any(low.startswith(d) for d in dirs):
            out.flag("unusual_path", rows, pid,
                     attack=rules()["by_id"]["unusual_path"]["attack_system_name"],
                     name=base, path=path)
            return
    if low.endswith(".exe") and any(d in low for d in t["suspicious_dirs"]):
        out.flag("unusual_path", rows, pid, name=base, path=path)


def _encoded(ctx: dict[str, Any], data: list[dict[str, Any]], out: _Out) -> None:
    for row in data:
        args, pid = _get(row, ARGS), _int(_get(row, PID))
        name = str(_get(row, NAME) or "").lower()
        if not args or not ("powershell" in name or "pwsh" in name or "powershell" in args.lower()):
            continue
        dec = decode.decode_powershell(str(args))
        if dec is None:
            continue
        field = next(n for n in ARGS if row.get(n) == args)
        out.decoded.append({"_row": row["_row"], "field": field, **dec})
        out.flag("encoded_powershell", [row["_row"]], pid, decoded=dec["text"][:200])
        for ioc in decode.extract_iocs(dec["text"]):
            out.iocs.setdefault(ioc["value"], {**ioc, "_row": row["_row"], "source": "decoded"})
            ctx["iocs"].setdefault(ioc["value"], ioc["type"])


def _network(ctx: dict[str, Any], data: list[dict[str, Any]], out: _Out) -> None:
    iocs = ctx["iocs"]
    for row in data:
        state = str(_get(row, STATE) or "")
        foreign = str(_get(row, FOREIGN) or "")
        ip = foreign.rsplit(":", 1)[0] if foreign.count(":") == 1 else foreign  # vol2 "ip:port"
        pid = _int(_get(row, PID))
        name = str(_get(row, NAME) or "")
        port = _get(row, FPORT)
        shown = f"{ip}:{port}" if port is not None else foreign
        if ip in iocs:
            out.flag("ioc_match", [row["_row"]], pid, name=name, foreign=shown, ioc=ip)
        if state.upper() == "ESTABLISHED" and _public(ip):
            other = set(ctx["flagged"].get(str(pid), [])) - {"external_connection", "ioc_match"}
            flagged = bool(other) or ip in iocs
            out.flag("external_connection", [row["_row"]], pid, severity="high" if flagged else None,
                     name=name, foreign=shown, state=state)
