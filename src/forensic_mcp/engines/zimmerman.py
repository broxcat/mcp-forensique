"""Eric Zimmerman CLI tools (EF-02, EF-03, Décision J3): ONE registry describing the 17 tools.

Every flag below comes from docs/tool_help/<tool>.txt; verify_registry() checks it. Only typed
options are accepted (rule 8). Never passed: --sync (network, rewrites maps), --vss / -l (live
system), --maps / --appIds / -w / -b / --fs / --fr (load external files), --saveTo / --dumpTo /
-o (PECmd) / --blobdir / --dd / --dr (write outside the result folder), --json/--xml/--html.
"""
from __future__ import annotations

import csv
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import results, runner
from ..config import Config, load_tools

HELP_DIR = Path(__file__).resolve().parents[3] / "docs" / "tool_help"
STR_RE = re.compile(r"^[^-\x00-\x1f][^\x00-\x1f]{0,511}$")
WORD_RE = re.compile(r"^[\w .$-]{1,64}$")


@dataclass(frozen=True)
class Opt:
    """One typed option: kind in bool, int, str, ids, words, date, enum_batch, evidence_path."""

    flag: str
    kind: str
    help: str


@dataclass(frozen=True)
class Tool:
    """Registry entry."""

    inputs: tuple[str, ...]                 # "-f" and/or "-d"
    artefacts: str                          # accepted artefact types (documentation)
    options: dict[str, Opt] = field(default_factory=dict)
    fixed: tuple[str, ...] = ()             # always passed
    output: str = "--csv"                   # "--csv" dir, "-o" file (bstrings), "--out" dir (rla)
    known_issue: str = ""                   # verified problem, shown by ez_list_tools


B, I, S = "bool", "int", "str"
REGISTRY: dict[str, Tool] = {
    "EvtxECmd": Tool(("-f", "-d"), "*.evtx (file or folder)", {
        "event_ids": Opt("--inc", "ids", "Event IDs to keep"),
        "exclude_ids": Opt("--exc", "ids", "Event IDs to drop"),
        "start": Opt("--sd", "date", "UTC start (ISO-8601)"),
        "end": Opt("--ed", "date", "UTC end (ISO-8601)")}),
    "MFTECmd": Tool(("-f",), "$MFT, $J, $Boot, $SDS, $I30", {
        "mft_path": Opt("-m", "evidence_path", "$MFT used to resolve parent paths of a $J"),
        "short_names": Opt("--sn", B, "include DOS 8.3 names"),
        "all_timestamps": Opt("--at", B, "all 0x30 timestamps"),
        "recover_slack": Opt("--rs", B, "recover slack space of FILE records")}),
    "PECmd": Tool(("-f", "-d"), "*.pf prefetch", {
        "keywords": Opt("-k", "words", "keywords to highlight")}, fixed=("-q",)),
    "RECmd": Tool(("-f", "-d"), "registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, "
                  "UsrClass.dat, Amcache.hve) + .LOG1/.LOG2", {
        "batch": Opt("--bn", "enum_batch", "batch file shipped with RECmd, e.g. Kroll_Batch.reb"),
        "key": Opt("--kn", S, "key path to display"),
        "value": Opt("--vn", S, "value name (with key)"),
        "search_all": Opt("--sa", S, "search keys, values, data and slack"),
        "search_key": Opt("--sk", S, "search key names"),
        "search_value_name": Opt("--sv", S, "search value names"),
        "search_data": Opt("--sd", S, "search value data"),
        "regex": Opt("--regex", B, "treat --sk/--sv/--sd as a regex"),
        "allow_missing_logs": Opt("--nl", B, "accept dirty hives without transaction logs")}),
    "AmcacheParser": Tool(("-f",), "Amcache.hve", {
        "include_programs": Opt("-i", B, "include file entries for Programs entries"),
        "ignore_logs": Opt("--nl", B, "ignore transaction logs for dirty hives")}),
    "AppCompatCacheParser": Tool(("-f",), "SYSTEM hive (ShimCache)", {
        "control_set": Opt("-c", I, "ControlSet to parse (default: all)"),
        "sort_desc": Opt("-t", B, "sort last modified descending"),
        "ignore_logs": Opt("--nl", B, "ignore transaction logs for dirty hives")}),
    "LECmd": Tool(("-f", "-d"), "*.lnk", {
        "removable_only": Opt("-r", B, "only lnk files pointing to removable drives"),
        "all_files": Opt("--all", B, "process all files, not only *.lnk")}, fixed=("-q",)),
    "JLECmd": Tool(("-f", "-d"), "*.automaticDestinations-ms, *.customDestinations-ms", {
        "all_files": Opt("--all", B, "process all files"),
        "lnk_details": Opt("--ld", B, "more information about lnk files"),
        "lnk_full": Opt("--fd", B, "full information about lnk files")}, fixed=("-q",)),
    "SBECmd": Tool(("-d",), "folder with NTUSER.DAT / UsrClass.dat (ShellBags)", {
        "dedupe": Opt("--dedupe", B, "remove duplicate hives"),
        "allow_missing_logs": Opt("--nl", B, "accept dirty hives without logs")}),
    "SrumECmd": Tool(("-f", "-d"), "SRUDB.dat (+ SOFTWARE hive)", {
        "software_hive": Opt("-r", "evidence_path", "SOFTWARE hive (recommended)")}),
    "SQLECmd": Tool(("-f", "-d"), "SQLite databases: browser history (Chromium, Firefox, Edge), "
                    "Windows databases", {
        "hunt": Opt("--hunt", B, "identify SQLite files by header, not by name"),
        "dedupe": Opt("--dedupe", B, "deduplicate files by SHA-1")}, fixed=("--noblob",)),
    "WxTCmd": Tool(("-f",), "ActivitiesCache.db (Windows Timeline)"),
    "RBCmd": Tool(("-f", "-d"), "Recycle Bin $I* files, INFO2", fixed=("-q",)),
    "RecentFileCacheParser": Tool(("-f",), "RecentFileCache.bcf", fixed=("-q",)),
    "SumECmd": Tool(("-d",), "folder with SystemIdentity.mdb, Current.mdb, {GUID}.mdb (UAL)"),
    "bstrings": Tool(("-f", "-d"), "any file (strings)", {
        "min_length": Opt("-m", I, "minimum string length"),
        "max_length": Opt("-x", I, "maximum string length"),
        "search": Opt("--ls", S, "only strings containing this text"),
        "regex": Opt("--lr", S, "only strings matching this regex (or a built-in name, see -p)")},
        fixed=("-q", "-s"), output="-o",
        known_issue="2026.5.0 on Linux prints 'input from stdin or file' and processes nothing "
                    "(-f, -d or stdin; verified 02/10/2026): calls end as tool_error"),
    "rla": Tool(("-f", "-d"), "dirty registry hives + transaction logs (replays the logs)", {
        "copy_all": Opt("--ca", B, "copy clean hives too")}, output="--out"),
}


def verify_registry() -> list[str]:
    """Flags of the registry missing from docs/tool_help (rule 6). Empty list = all present."""
    missing = []
    for name, t in REGISTRY.items():
        text = (HELP_DIR / f"{name}.txt").read_text(encoding="utf-8", errors="replace")
        flags = {*t.inputs, *t.fixed, t.output, *(o.flag for o in t.options.values())}
        missing += [f"{name} {f}" for f in sorted(flags) if not re.search(
            rf"(^|[\s,]){re.escape(f)}(\s|,|$)", text, re.M)]
    return missing


def ez_cmd(cfg: Config, tool: str) -> list[str]:
    """Launch argv prefix of an EZ tool from tools.toml."""
    if tool not in REGISTRY:
        raise ValueError(f"unknown EZ tool {tool!r} (see ez_list_tools)")
    cmd = load_tools(cfg.tools_file).get(tool)
    if not cmd:
        raise RuntimeError(f"{tool} is not available in tools.toml (run scripts/check_tools.py)")
    return cmd


def batch_files(cfg: Config) -> dict[str, Path]:
    """RECmd batch files shipped with the tool ({name: path})."""
    dll = Path(ez_cmd(cfg, "RECmd")[-1])
    return {p.name: p for p in sorted(dll.parent.glob("BatchExamples/*.reb"))}


def ez_date(value: str) -> str:
    """ISO-8601 (UTC) -> EZ default format 'yyyy-MM-dd HH:mm:ss.fffffff'."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f") + "0"


def build_options(cfg: Config, tool: str, options: dict[str, Any] | None,
                  jail: Any) -> list[str]:
    """Typed options -> argv. `jail(path) -> Path` resolves evidence paths. Unknown options,
    wrong types and unsafe strings are refused."""
    spec = REGISTRY[tool]
    argv: list[str] = []
    for name, value in (options or {}).items():
        if value is None or value is False:
            continue
        opt = spec.options.get(name)
        if opt is None:
            raise ValueError(f"{tool} has no option {name!r}; allowed: {sorted(spec.options)}")
        k = opt.kind
        if k == "bool":
            if value is not True:
                raise ValueError(f"{name} must be a boolean")
            argv.append(opt.flag)
            continue
        if k == "int":
            if isinstance(value, bool) or not isinstance(value, int) or not -1 <= value <= 10**6:
                raise ValueError(f"{name} must be an integer")
            text = str(value)
        elif k == "ids":
            if not isinstance(value, list) or not value or not all(
                    isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 65535 for v in value):
                raise ValueError(f"{name} must be a non-empty list of event IDs (0-65535)")
            text = ",".join(str(v) for v in value)
        elif k == "words":
            if not isinstance(value, list) or not all(isinstance(v, str) and WORD_RE.match(v)
                                                      for v in value):
                raise ValueError(f"{name} must be a list of simple words")
            text = ",".join(value)
        elif k == "date":
            text = ez_date(str(value))
        elif k == "enum_batch":
            files = batch_files(cfg)
            if value not in files:
                raise ValueError(f"unknown RECmd batch {value!r}; choices: {sorted(files)}")
            text = str(files[value])
        elif k == "evidence_path":
            text = str(jail(str(value)))
        else:  # str
            if not isinstance(value, str) or not STR_RE.match(value):
                raise ValueError(f"{name} must be a string (no leading '-', no control chars)")
            text = value
        argv += [opt.flag, text]
    return argv


def _csv_to_rows(d: Path) -> int:
    """Every CSV of the result -> rows.jsonl (one stream, `_csv` = source file)."""
    n = 0
    with open(d / "rows.jsonl", "w", encoding="utf-8") as out:
        for p in sorted((d / "out").rglob("*.csv")):
            with open(p, newline="", encoding="utf-8-sig", errors="replace") as fh:
                for row in csv.DictReader(fh):
                    out.write(json.dumps({"_csv": p.name, **row}, ensure_ascii=False) + "\n")
                    n += 1
    return n


def _lines_to_rows(src: Path, d: Path, key: str = "line") -> int:
    n = 0
    with open(d / "rows.jsonl", "w", encoding="utf-8") as out:
        if src.exists():
            for line in src.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    out.write(json.dumps({key: line}, ensure_ascii=False) + "\n")
                    n += 1
    return n


async def run(cfg: Config, tool: str, path: Path, options: list[str],
              evidence_sha256: str) -> dict[str, Any]:
    """Run one EZ tool on a jailed file or folder; CSV (or text) -> rows.jsonl."""
    spec = REGISTRY[tool]
    flag = "-d" if path.is_dir() else "-f"
    if flag not in spec.inputs:
        raise ValueError(f"{tool} takes {' or '.join(spec.inputs)} "
                         f"({'a folder' if spec.inputs == ('-d',) else 'a file'}): {spec.artefacts}")
    rid, d = results.new_result(cfg.output_root, f"ez_{tool}")
    out = d / "out"
    out.mkdir()
    target = {"--csv": out, "-o": out / "strings.txt", "--out": out}[spec.output]
    argv = [*ez_cmd(cfg, tool), flag, str(path), *options, spec.output, str(target), *spec.fixed]
    start = time.time()
    rr = await runner.run_process(argv, d / "stdout.txt", d / "stderr.txt", cfg.timeout_seconds,
                                  max_output_bytes=cfg.max_output_mb * 1024 * 1024)
    console_mode = tool == "RECmd" and "--bn" not in options
    if spec.output == "-o":
        n = _lines_to_rows(out / "strings.txt", d, "string")
    elif any(out.rglob("*.csv")):
        n = _csv_to_rows(d)
    elif spec.output == "--out":
        files = sorted(p for p in out.rglob("*") if p.is_file())
        (d / "rows.jsonl").write_text("".join(json.dumps(
            {"file": str(p.relative_to(out)), "size": p.stat().st_size}) + "\n" for p in files))
        n = len(files)
    elif console_mode:  # RECmd --kn / --sa…: results only on the console, one row per line
        n = _lines_to_rows(d / "stdout.txt", d)
    else:
        n = _lines_to_rows(out / "none", d)  # nothing produced: empty rows.jsonl
    produced = any(out.rglob("*"))
    silent = rr.exit_code == 0 and not produced and not console_mode and spec.output != "--out"
    error = ("exit code 0 but no output written (silent failure): "
             + (d / "stdout.txt").read_text(errors="replace")[-300:].strip()) if silent else ""
    results.write_meta(
        d, tool=tool, plugin=tool, argv=argv, tool_version=None, input_path=str(path),
        input_sha256=evidence_sha256, start=start, end=time.time(),
        duration=round(rr.duration, 2), exit_code=rr.exit_code, timed_out=rr.timed_out,
        output_exceeded=rr.output_exceeded, row_count=n, error=error or None)
    return {"result_id": rid, "dir": d, "plugin": tool, "argv": argv, "exit_code": rr.exit_code,
            "timed_out": rr.timed_out, "output_exceeded": rr.output_exceeded,
            "duration": round(rr.duration, 2), "row_count": n, "error": error,
            "stderr_tail": (d / "stderr.txt").read_text(errors="replace")[-2000:]}
