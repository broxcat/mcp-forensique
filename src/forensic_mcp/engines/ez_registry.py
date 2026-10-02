"""Registry of the Eric Zimmerman CLI tools (single source of truth, Décision J3, task 4.3b).

Every flag comes from docs/tool_help/<Tool>.txt (verify_registry, rule 6). `runtime`:
"linux" = runs in the container; "windows_only" = verified not to run on Linux (cause in
`known_issue`): never started in the container, run on Windows with scripts/run_ez_windows.ps1
then imported with ez_import. The same registry is exported to rules/ez_registry.json for that
script (registry_json / scripts/export_ez_registry.py; a test keeps both in sync).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HELP_DIR = Path(__file__).resolve().parents[3] / "docs" / "tool_help"
# Seen on Linux (02/10/2026): crashes / refusals that still exit 0. Any of these in the output
# = tool_error, never "0 rows" (kept as a safety net for the tools that do run on Linux).
CRASH_MARKERS = ("unhandled exception", "unable to load shared library",
                 "non-windows platforms not supported")
# Root causes verified 02/10/2026 on the real binaries (CLAUDE.md §11).
SQLITE_ISSUE = ("Windows only: uses System.Data.SQLite, whose native SQLite.Interop.dll is not "
                "shipped for Linux (crash 'Unable to load shared library SQLite.Interop.dll', "
                "exit 0, empty output)")
ESE_ISSUE = ("Windows only: explicit OS check (IsOSPlatform) at start-up, then 'Non-Windows "
             "platforms not supported…' — the ESE database needs Windows' esent.dll (exit 0)")
PECMD_ISSUE = ("Windows only: explicit OS check (IsOSPlatform) at start-up for every input, "
               "'…decompression specific Windows libraries' (Win8+ prefetch is compressed with "
               "the Windows decompression API; exit 0)")
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
    runtime: str = "linux"                  # "linux" | "windows_only"
    tty_stdin: bool = False                 # needs a TTY on stdin (else reads stdin)


B, I, W = "bool", "int", "windows_only"
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
                  known_issue=PECMD_ISSUE, runtime=W),
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
        known_issue=ESE_ISSUE, runtime=W),
    "SQLECmd": Tool(("-f", "-d"), "SQLite databases (browser history: Chromium, Firefox, Edge; "
                    "Windows databases)", {
        "hunt": Opt("--hunt", B, "identify SQLite files by header, not by name"),
        "dedupe": Opt("--dedupe", B, "deduplicate files by SHA-1")},
        fixed=("--noblob",), output="--json", known_issue=SQLITE_ISSUE, runtime=W),
    "WxTCmd": Tool(("-f",), "ActivitiesCache.db (Windows Timeline)", known_issue=SQLITE_ISSUE,
                   runtime=W),
    "RBCmd": Tool(("-f", "-d"), "Recycle Bin $I* files, INFO2", fixed=("-q",)),
    "RecentFileCacheParser": Tool(("-f",), "RecentFileCache.bcf", fixed=("-q",), output="--json"),
    "SumECmd": Tool(("-d",), "folder with SystemIdentity.mdb, Current.mdb, {GUID}.mdb (UAL)",
                    known_issue=ESE_ISSUE, runtime=W),
    "bstrings": Tool(("-f", "-d"), "any file (strings)", {
        "min_length": Opt("-m", I, "minimum string length"),
        "max_length": Opt("-x", I, "maximum string length")}, fixed=("-q", "-s"), output="-o",
        tty_stdin=True),  # checks Console.IsInputRedirected: with /dev/null it reads stdin
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


def windows_only() -> list[str]:
    """Tools that must run on Windows (scripts/run_ez_windows.ps1) and be imported."""
    return sorted(n for n, t in REGISTRY.items() if t.runtime == "windows_only")


def registry_json() -> dict[str, Any]:
    """The registry as JSON, for scripts/run_ez_windows.ps1 (rules/ez_registry.json)."""
    return {"format": "forensic-mcp/ez-registry/1", "forbidden": sorted(FORBIDDEN),
            "regpath_pattern": REGPATH_RE.pattern, "tools": {
                name: {"runtime": t.runtime, "inputs": list(t.inputs), "output": t.output,
                       "fixed": list(t.fixed), "artefacts": t.artefacts,
                       "known_issue": t.known_issue,
                       "options": {k: {"flag": o.flag, "kind": o.kind, "help": o.help}
                                   for k, o in t.options.items()}}
                for name, t in REGISTRY.items()}}


def registry_json_text() -> str:
    """Canonical text of rules/ez_registry.json."""
    return json.dumps(registry_json(), indent=1, ensure_ascii=False) + "\n"
