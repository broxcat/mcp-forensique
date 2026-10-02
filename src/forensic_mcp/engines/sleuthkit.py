"""The Sleuth Kit (task 4.3c, Décision J3): disk images read as files — raw/dd, E01 (libewf),
VMDK, VHD — never mounted (the container has no capabilities and no FUSE).

Flags come from docs/tool_help/{mmls,fls,icat}.txt (rule 6): mmls <image>; fls -r -p -o <sector>
<image>; icat -o <sector> <image> <inode>. Image and file-system types are auto-detected.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .. import runner
from ..config import Config

_MMLS = re.compile(r"^(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$")
# "r/r 1234-128-1:\tWindows/x" ; deleted: "r/r * 1234-128-1(realloc):\tpath"
_FLS = re.compile(r"^(\S)/(\S)\s+(\*\s+)?([0-9]+(?:-[0-9]+-[0-9]+)?)(\(realloc\))?:\t(.*)$")
INODE_RE = re.compile(r"^[0-9]+(-[0-9]+-[0-9]+)?$")

# Fixed extraction targets (KAPE-like), regexes on the fls full path ('/' separators,
# case-insensitive). "sam_security" holds credential material: human confirmation needed.
TARGETS: dict[str, list[str]] = {
    "mft": [r"\$MFT"],
    "usnjrnl": [r"\$Extend/\$UsnJrnl:\$J"],
    "logfile": [r"\$LogFile"],
    "registry_system": [r"Windows/System32/config/(SYSTEM|SOFTWARE)(\.LOG1|\.LOG2)?"],
    "sam_security": [r"Windows/System32/config/(SAM|SECURITY)(\.LOG1|\.LOG2)?"],
    "ntuser": [r"Users/[^/]+/NTUSER\.DAT(\.LOG1|\.LOG2)?"],
    "usrclass": [r"Users/[^/]+/AppData/Local/Microsoft/Windows/UsrClass\.dat(\.LOG1|\.LOG2)?"],
    "amcache": [r"Windows/AppCompat/Programs/Amcache\.hve(\.LOG1|\.LOG2)?"],
    "recentfilecache": [r"Windows/AppCompat/Programs/RecentFileCache\.bcf"],
    "evtx": [r"Windows/System32/winevt/Logs/[^/]+\.evtx"],
    "prefetch": [r"Windows/Prefetch/[^/]+\.pf"],
    "srum": [r"Windows/System32/sru/SRUDB\.dat"],
    "jumplists": [r"Users/[^/]+/AppData/Roaming/Microsoft/Windows/Recent/"
                  r"(Automatic|Custom)Destinations/[^/]+"],
    "lnk": [r"Users/[^/]+/AppData/Roaming/Microsoft/Windows/Recent/[^/]+\.lnk",
            r"Users/[^/]+/Desktop/[^/]+\.lnk"],
    "recyclebin": [r"\$Recycle\.Bin/[^/]+/\$I[^/]+"],
    "browser": [r"Users/[^/]+/AppData/Local/(Google/Chrome|Microsoft/Edge)/User Data/[^/]+/History",
                r"Users/[^/]+/AppData/Roaming/Mozilla/Firefox/Profiles/[^/]+/places\.sqlite"],
    "activities": [r"Users/[^/]+/AppData/Local/ConnectedDevicesPlatform/[^/]+/ActivitiesCache\.db"],
    "sum": [r"Windows/System32/LogFiles/Sum/[^/]+\.mdb"],
    "scheduled_tasks": [r"Windows/System32/Tasks/.+"],
}
SENSITIVE_TARGETS = {"sam_security"}
_COMPILED = {k: [re.compile(f"^{p}$", re.I) for p in v] for k, v in TARGETS.items()}


def cmd(cfg: Config, tool: str) -> list[str]:
    """Launch argv of a Sleuth Kit tool."""
    if tool not in ("mmls", "fls", "icat"):
        raise ValueError(f"unknown Sleuth Kit tool {tool!r}")
    return [*cfg.sleuthkit_prefix, str(Path(cfg.sleuthkit_dir) / tool)]


def parse_mmls(text: str) -> list[dict[str, Any]]:
    """Rows of the mmls table (sectors)."""
    rows = []
    for line in text.splitlines():
        m = _MMLS.match(line.strip())
        if m:
            rows.append({"slot": int(m.group(1)), "partition": m.group(2),
                         "start_sector": int(m.group(3)), "end_sector": int(m.group(4)),
                         "length_sectors": int(m.group(5)), "description": m.group(6).strip()})
    return rows


def parse_fls_line(line: str) -> dict[str, Any] | None:
    """One `fls -r -p` line -> {name_type, meta_type, deleted, inode, realloc, path}."""
    m = _FLS.match(line.rstrip("\n"))
    if not m:
        return None
    return {"name_type": m.group(1), "meta_type": m.group(2), "deleted": bool(m.group(3)),
            "inode": m.group(4), "realloc": bool(m.group(5)), "path": m.group(6)}


def match_targets(path: str, targets: list[str]) -> str | None:
    """Name of the first target whose pattern matches this fls path."""
    for t in targets:
        if any(rx.match(path) for rx in _COMPILED[t]):
            return t
    return None


def safe_relpath(path: str) -> Path:
    """fls path -> relative path inside the extraction folder (no '..', ADS ':' -> '_')."""
    parts = [p.replace(":", "_") for p in path.split("/") if p not in ("", ".", "..")]
    if not parts:
        raise ValueError(f"empty path from fls: {path!r}")
    return Path(*parts)


async def run_to_file(cfg: Config, argv: list[str], stdout: Path, stderr: Path,
                      max_mb: int) -> runner.RunResult:
    """Run a Sleuth Kit command with timeout and an output bound (ET-02)."""
    return await runner.run_process(argv, stdout, stderr, cfg.timeout_seconds,
                                    max_output_bytes=max_mb * 1024 * 1024)
