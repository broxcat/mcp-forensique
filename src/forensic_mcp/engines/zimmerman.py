"""Eric Zimmerman CLI tools (EF-02, EF-03, Décision J3, task 4.3b): ONE registry of the CLI tools.

Source of truth for every flag: docs/tool_help/<Tool>.txt (real help of the binary), checked by
verify_registry(). Options are a nominative, typed list per tool (bool, int, enum, list of
ints, UTC date; a strictly validated registry path for RECmd --kn/--vn; a jailed evidence path
for MFTECmd -m / SrumECmd -r). Never passed: --sync --vss --maps --saveTo --dumpTo --dd --do
-o (PECmd) --appIds --fs/--fr, -l (live), -w/-b (external files), --blobdir, --csvf/--jsonf/
--html/--xml/--dt, and no caller-chosen output path: the server picks the result folder.
Output: --json for EvtxECmd, MFTECmd, PECmd, LECmd, JLECmd, RecentFileCacheParser, SQLECmd and
RECmd --kn; --csv for the others (RECmd --bn included). All results are normalised to
rows.jsonl (stable _row). Hasher has no Linux (.NET 9) build: not in the registry (§11).
"""
from __future__ import annotations

import csv
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .. import results, runner
from ..config import Config, load_tools

HELP_DIR = Path(__file__).resolve().parents[3] / "docs" / "tool_help"
# Seen on Linux (02/10/2026): crashes / refusals that still exit 0 (SQLECmd, WxTCmd, SrumECmd,
# SumECmd). Any of these in the output = tool_error, never "0 rows".
CRASH_MARKERS = ("unhandled exception", "unable to load shared library",
                 "non-windows platforms not supported")
SQLITE_ISSUE = ("Linux: crashes with 'Unable to load shared library SQLite.Interop.dll' (Windows-only "
                "native SQLite; exit 0, empty output; verified 02/10/2026): calls end as tool_error")
ESE_ISSUE = ("Linux: 'Non-Windows platforms not supported due to the need to load ESI specific "
             "Windows libraries! Exiting...' (exit 0, no output; verified 02/10/2026)")
# Registry path for RECmd --kn / --vn: never starts with '-' (it would be read as an option).
REGPATH_RE = re.compile(r"^[A-Za-z0-9_.{}()$&@#+][A-Za-z0-9_ .{}()$&@#+-]*"
                        r"(\\[A-Za-z0-9_ .{}()$&@#+-]+)*$")
FORBIDDEN = {"--sync", "--vss", "--maps", "--saveTo", "--dumpTo", "--dd", "--do", "--appIds",
             "--fs", "--fr", "-fs", "-fr", "-l", "-w", "-b", "--blobdir", "--csvf", "--jsonf",
             "--html", "--xml", "--dt", "--pretty"}


@dataclass(frozen=True)
class Opt:
    """One typed option: kind in bool, int, ids, date, enum_batch, regpath, evidence_path."""

    flag: str
    kind: str
    help: str


@dataclass(frozen=True)
class Tool:
    """Registry entry."""

    inputs: tuple[str, ...]                 # "-f" and/or "-d"
    artefacts: str
    options: dict[str, Opt] = field(default_factory=dict)
    fixed: tuple[str, ...] = ()
    output: str = "--csv"                   # "--json" / "--csv" dir, "-o" file, "--out" dir
    known_issue: str = ""


B, I = "bool", "int"
REGISTRY: dict[str, Tool] = {
    "EvtxECmd": Tool(("-f", "-d"), "*.evtx (file or folder)", {
        "event_ids": Opt("--inc", "ids", "Event IDs to keep"),
        "exclude_ids": Opt("--exc", "ids", "Event IDs to drop"),
        "start": Opt("--sd", "date", "UTC start (ISO-8601)"),
        "end": Opt("--ed", "date", "UTC end (ISO-8601)")}, output="--json"),
    "MFTECmd": Tool(("-f",), "$MFT, $J, $Boot, $SDS, $I30", {
        "mft_path": Opt("-m", "evidence_path", "$MFT used to resolve parent paths of a $J"),
        "short_names": Opt("--sn", B, "include DOS 8.3 names"),
        "all_timestamps": Opt("--at", B, "all 0x30 timestamps"),
        "recover_slack": Opt("--rs", B, "recover slack space of FILE records")}, output="--json"),
    "PECmd": Tool(("-f", "-d"), "*.pf prefetch", fixed=("-q",), output="--json",
                  known_issue="Linux: 'Non-Windows platforms not supported due to the need to load "
                              "decompression specific Windows libraries! Exiting...' at start-up, "
                              "for every input (Win7 SCCA too; verified 02/10/2026)"),
    "RECmd": Tool(("-f", "-d"), "registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, "
                  "UsrClass.dat, Amcache.hve) + .LOG1/.LOG2; needs batch OR key", {
        "batch": Opt("--bn", "enum_batch", "batch file shipped with RECmd (CSV output)"),
        "key": Opt("--kn", "regpath", "key path, e.g. Microsoft\\Windows\\CurrentVersion\\Run (JSON)"),
        "value": Opt("--vn", "regpath", "value name under key"),
        "allow_missing_logs": Opt("--nl", B, "accept dirty hives without transaction logs")},
        output="--json"),
    "AmcacheParser": Tool(("-f",), "Amcache.hve", {
        "include_programs": Opt("-i", B, "include file entries for Programs entries"),
        "ignore_logs": Opt("--nl", B, "ignore transaction logs for dirty hives")}),
    "AppCompatCacheParser": Tool(("-f",), "SYSTEM hive (ShimCache); -f mandatory, never the "
                                 "live registry", {
        "control_set": Opt("-c", I, "ControlSet to parse (default: all)"),
        "sort_desc": Opt("-t", B, "sort last modified descending"),
        "ignore_logs": Opt("--nl", B, "ignore transaction logs for dirty hives")}),
    "LECmd": Tool(("-f", "-d"), "*.lnk", {
        "removable_only": Opt("-r", B, "only lnk files pointing to removable drives"),
        "all_files": Opt("--all", B, "process all files, not only *.lnk")},
        fixed=("-q",), output="--json"),
    "JLECmd": Tool(("-f", "-d"), "*.automaticDestinations-ms, *.customDestinations-ms", {
        "all_files": Opt("--all", B, "process all files"),
        "lnk_details": Opt("--ld", B, "more information about lnk files"),
        "lnk_full": Opt("--fd", B, "full information about lnk files")},
        fixed=("-q",), output="--json"),
    "SBECmd": Tool(("-d",), "folder with NTUSER.DAT / UsrClass.dat (ShellBags)", {
        "dedupe": Opt("--dedupe", B, "remove duplicate hives"),
        "allow_missing_logs": Opt("--nl", B, "accept dirty hives without logs")}),
    "SrumECmd": Tool(("-f", "-d"), "SRUDB.dat (+ SOFTWARE hive)", {
        "software_hive": Opt("-r", "evidence_path", "SOFTWARE hive (recommended)")},
        known_issue=ESE_ISSUE),
    "SQLECmd": Tool(("-f", "-d"), "SQLite databases (browser history: Chromium, Firefox, Edge; "
                    "Windows databases)", {
        "hunt": Opt("--hunt", B, "identify SQLite files by header, not by name"),
        "dedupe": Opt("--dedupe", B, "deduplicate files by SHA-1")},
        fixed=("--noblob",), output="--json", known_issue=SQLITE_ISSUE),
    "WxTCmd": Tool(("-f",), "ActivitiesCache.db (Windows Timeline)", known_issue=SQLITE_ISSUE),
    "RBCmd": Tool(("-f", "-d"), "Recycle Bin $I* files, INFO2", fixed=("-q",)),
    "RecentFileCacheParser": Tool(("-f",), "RecentFileCache.bcf", fixed=("-q",), output="--json"),
    "SumECmd": Tool(("-d",), "folder with SystemIdentity.mdb, Current.mdb, {GUID}.mdb (UAL)",
                    known_issue=ESE_ISSUE),
    "bstrings": Tool(("-f", "-d"), "any file (strings)", {
        "min_length": Opt("-m", I, "minimum string length"),
        "max_length": Opt("-x", I, "maximum string length")}, fixed=("-q", "-s"), output="-o",
        known_issue="2026.5.0 on Linux prints 'input from stdin or file' and processes nothing "
                    "(-f, -d or stdin; verified 02/10/2026): calls end as tool_error"),
    "rla": Tool(("-f", "-d"), "dirty registry hives + transaction logs (replays the logs)", {
        "copy_all": Opt("--ca", B, "copy clean hives too")}, output="--out"),
}


def output_flag(tool: str, options: list[str]) -> str:
    """RECmd: CSV for a batch (--bn), JSON for a key (--kn); others from the registry."""
    return "--csv" if tool == "RECmd" and "--bn" in options else REGISTRY[tool].output


def verify_registry() -> list[str]:
    """Registry flags missing from docs/tool_help (rule 6). Empty list = all present."""
    missing = []
    for name, t in REGISTRY.items():
        text = (HELP_DIR / f"{name}.txt").read_text(encoding="utf-8", errors="replace")
        flags = {*t.inputs, *t.fixed, t.output, *(o.flag for o in t.options.values())}
        flags |= {"--csv"} if name == "RECmd" else set()
        missing += [f"{name} {f}" for f in sorted(flags) if not re.search(
            rf"(^|[\s,]){re.escape(f)}(\s|,|$)", text, re.M)]
    return missing


def ez_cmd(cfg: Config, tool: str) -> list[str]:
    """Launch argv prefix of an EZ tool from tools.toml."""
    if tool not in REGISTRY:
        raise ValueError(f"unknown EZ tool {tool!r} (see ez_list_tools)")
    cmd = load_tools(cfg.tools_file).get(tool)
    if not cmd:
        raise RuntimeError(f"{tool} is not available in tools.toml (run scripts/check_tools_18.py)")
    return cmd


def batch_files(cfg: Config) -> dict[str, Path]:
    """RECmd batch files shipped with the tool ({name: path})."""
    dll = Path(ez_cmd(cfg, "RECmd")[-1])
    return {p.name: p for p in sorted(dll.parent.glob("BatchExamples/*.reb"))}


def ez_date(value: str) -> str:
    """ISO-8601 (UTC) -> EZ default format 'yyyy-MM-dd HH:mm:ss.fffffff'."""
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f") + "0"


def build_options(cfg: Config, tool: str, options: dict[str, Any] | None, jail: Any) -> list[str]:
    """Typed options -> argv; unknown options, wrong types and unsafe values are refused."""
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
        elif k == "date":
            text = ez_date(str(value))
        elif k == "enum_batch":
            files = batch_files(cfg)
            if value not in files:
                raise ValueError(f"unknown RECmd batch {value!r}; choices: {sorted(files)}")
            text = str(files[value])
        elif k == "regpath":
            if not isinstance(value, str) or len(value) > 512 or not REGPATH_RE.match(value):
                raise ValueError(f"{name} must be a registry path (letters, digits, spaces, "
                                 "._{}()$&@#+- separated by \\)")
            text = value
        else:  # evidence_path
            text = str(jail(str(value)))
        argv += [opt.flag, text]
    if tool == "RECmd" and "--bn" not in argv and "--kn" not in argv:
        raise ValueError("RECmd needs `batch` (CSV) or `key` (JSON)")
    if tool == "RECmd" and "--vn" in argv and "--kn" not in argv:
        raise ValueError("RECmd `value` needs `key`")
    return argv


def iter_json_records(p: Path) -> Iterator[dict[str, Any]]:
    """Records of an EZ JSON file, whatever its shape: one object per line (seen on real
    EvtxECmd), a JSON array, or one object. UTF-8 BOM tolerated."""
    with open(p, encoding="utf-8-sig", errors="replace") as fh:
        first = ""
        for line in fh:
            if line.strip():
                first = line.strip()
                break
        if not first:
            return
        if first.startswith("{") and first.endswith("}"):  # one object per line
            yield json.loads(first)
            for line in fh:
                if line.strip():
                    yield json.loads(line)
            return
    # an array or a pretty-printed object: whole-file parse
    doc = json.loads(p.read_text(encoding="utf-8-sig", errors="replace"))
    for item in (doc if isinstance(doc, list) else [doc]):
        yield item if isinstance(item, dict) else {"value": item}


def _to_rows(d: Path, kind: str) -> int:
    """CSV / JSON files of out/ -> rows.jsonl (one stream; `_file` = source file)."""
    n = 0
    with open(d / "rows.jsonl", "w", encoding="utf-8") as out:
        for p in sorted((d / "out").rglob(f"*.{kind}")):
            if kind == "csv":
                fh = open(p, newline="", encoding="utf-8-sig", errors="replace")
                records: Iterator[dict[str, Any]] = csv.DictReader(fh)
            else:
                fh, records = None, iter_json_records(p)
            for rec in records:
                out.write(json.dumps({"_file": p.name, **rec}, ensure_ascii=False,
                                     default=str) + "\n")
                n += 1
            if fh:
                fh.close()
    return n


async def run(cfg: Config, tool: str, path: Path, options: list[str],
              evidence_sha256: str) -> dict[str, Any]:
    """Run one EZ tool on a jailed file or folder; output -> rows.jsonl."""
    spec = REGISTRY[tool]
    flag = "-d" if path.is_dir() else "-f"
    if flag not in spec.inputs:
        raise ValueError(f"{tool} takes {' or '.join(spec.inputs)} "
                         f"({'a folder' if spec.inputs == ('-d',) else 'a file'}): {spec.artefacts}")
    rid, d = results.new_result(cfg.output_root, f"ez_{tool}")
    out = d / "out"
    out.mkdir()
    oflag = output_flag(tool, options)
    target = out / "strings.txt" if oflag == "-o" else out
    argv = [*ez_cmd(cfg, tool), flag, str(path), *options, oflag, str(target), *spec.fixed]
    if tool == "AppCompatCacheParser" and "-f" not in argv:
        raise ValueError("AppCompatCacheParser without -f would read the host registry: refused")
    start = time.time()
    rr = await runner.run_process(argv, d / "stdout.txt", d / "stderr.txt", cfg.timeout_seconds,
                                  max_output_bytes=cfg.max_output_mb * 1024 * 1024)
    if oflag == "-o":
        lines = target.read_text(errors="replace").splitlines() if target.exists() else []
        (d / "rows.jsonl").write_text("".join(json.dumps({"string": s}, ensure_ascii=False) + "\n"
                                              for s in lines if s.strip()), encoding="utf-8")
        n = sum(1 for s in lines if s.strip())
    elif oflag == "--out":
        files = sorted(p for p in out.rglob("*") if p.is_file())
        (d / "rows.jsonl").write_text("".join(json.dumps(
            {"file": str(p.relative_to(out)), "size": p.stat().st_size}) + "\n" for p in files))
        n = len(files)
    else:
        n = _to_rows(d, oflag.lstrip("-"))
    produced = any(p.is_file() for p in out.rglob("*"))
    console = ((d / "stdout.txt").read_text(errors="replace")
               + (d / "stderr.txt").read_text(errors="replace"))
    crash = next((ln.strip() for ln in console.splitlines()
                  if any(m in ln.lower() for m in CRASH_MARKERS)), "")
    silent = rr.exit_code == 0 and not produced and oflag != "--out"
    error = (f"tool crashed or refused to run (exit code {rr.exit_code}): {crash[:300]}" if crash
             else "exit code 0 but no output written (silent failure): "
             + console[-300:].strip() if silent else "")
    results.write_meta(
        d, tool=tool, plugin=tool, argv=argv, tool_version=None, input_path=str(path),
        input_sha256=evidence_sha256, start=start, end=time.time(), output_format=oflag,
        duration=round(rr.duration, 2), exit_code=rr.exit_code, timed_out=rr.timed_out,
        output_exceeded=rr.output_exceeded, row_count=n, error=error or None)
    return {"result_id": rid, "dir": d, "plugin": tool, "argv": argv, "exit_code": rr.exit_code,
            "timed_out": rr.timed_out, "output_exceeded": rr.output_exceeded,
            "duration": round(rr.duration, 2), "row_count": n, "error": error,
            "stderr_tail": (d / "stderr.txt").read_text(errors="replace")[-2000:]}
