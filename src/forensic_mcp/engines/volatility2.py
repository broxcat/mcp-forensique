"""Volatility 2.6 engine (Décision J3).

Plugins and profiles come from `vol2 --info`; plugin options from `vol2 <plugin> -h` minus the
global options of `vol2 -h`. The caller only maps typed parameters to those options. Never
passed: --plugins (loads arbitrary Python), -w/--write (write support), -D/--dump-dir (writes
files); plugins that only produce output with -D are refused.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any

from .. import results, runner
from ..config import Config, load_tools
from .volatility3 import safe_value

FORBIDDEN = {"--plugins", "-w", "--write", "-D", "--dump-dir"}
PRINTING_DUMPS = {"hashdump", "lsadump", "cachedump"}  # print to stdout, no -D needed
NEEDS_DUMP_DIR = {"evtlogs", "screenshot"}
_SECTION = re.compile(r"^(\S.*)\n-{3,}$", re.M)
_ENTRY = re.compile(r"^(\S+)\s+- (.*)$")
_LONG_OPT = re.compile(r"--[a-z][\w-]*")
_cache: dict[str, Any] = {}


def vol2_cmd(cfg: Config) -> list[str]:
    """Launch argv prefix for vol2 from tools.toml."""
    cmd = load_tools(cfg.tools_file).get("vol2")
    if not cmd:
        raise RuntimeError("vol2 is not available in tools.toml (run scripts/check_tools.py)")
    return cmd


async def _capture(argv: list[str], timeout: float = 300) -> str:
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        stdin=asyncio.subprocess.DEVNULL, cwd="/tmp")
    out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    return out.decode(errors="replace")


def parse_info(text: str) -> dict[str, dict[str, str]]:
    """Sections of `vol2 --info` ({"Profiles": {...}, "Plugins": {...}, ...})."""
    sections: dict[str, dict[str, str]] = {}
    marks = list(_SECTION.finditer(text))
    for i, m in enumerate(marks):
        body = text[m.end(): marks[i + 1].start() if i + 1 < len(marks) else len(text)]
        entries = {}
        for line in body.splitlines():
            e = _ENTRY.match(line.strip())
            if e:
                entries[e.group(1)] = e.group(2).strip()
        sections[m.group(1).strip()] = entries
    return sections


async def info(cfg: Config) -> dict[str, dict[str, str]]:
    """Profiles and plugins of the installed vol2 (cached)."""
    if "info" not in _cache:
        _cache["info"] = parse_info(await _capture([*vol2_cmd(cfg), "--info"]))
    return _cache["info"]


def _long_options(text: str) -> set[str]:
    """Long option names from the first column of optparse help lines."""
    return {o for line in text.splitlines() if line.startswith("  -")
            for o in _LONG_OPT.findall(re.split(r"\s{2,}", line.strip(), maxsplit=1)[0])}


async def plugin_options(cfg: Config, plugin: str) -> set[str]:
    """Long options specific to a plugin (its -h minus the global -h), cached."""
    if "globals" not in _cache:
        _cache["globals"] = _long_options(await _capture([*vol2_cmd(cfg), "-h"]))
    key = f"opts:{plugin}"
    if key not in _cache:
        _cache[key] = _long_options(await _capture([*vol2_cmd(cfg), plugin, "-h"])) - _cache["globals"]
    return _cache[key]


def check_plugin(plugin: str, plugins: dict[str, str]) -> str:
    """Validate a plugin name against --info; refuse plugins that need -D/--dump-dir."""
    if plugin not in plugins:
        raise ValueError(f"unknown vol2 plugin: {plugin!r} (see vol2_list_plugins)")
    if plugin in NEEDS_DUMP_DIR or ("dump" in plugin and plugin not in PRINTING_DUMPS):
        raise ValueError(f"vol2 plugin {plugin} only writes files with -D/--dump-dir, which is "
                         "forbidden; use the vol3 equivalent")
    return plugin


def _rows_from_json(doc: Any) -> list[dict[str, Any]]:
    cols, rows = doc.get("columns", []), doc.get("rows", [])
    return [{c: safe_value(v) for c, v in zip(cols, r)} for r in rows]


async def run(cfg: Config, path: Path, plugin: str, profile: str | None, options: list[str],
              evidence_sha256: str, tool: str = "vol2") -> dict[str, Any]:
    """Run a validated vol2 plugin: JSON output, text fallback (one row per line).
    `profile` is None only for imageinfo."""
    for opt in options:
        if opt.split("=", 1)[0] in FORBIDDEN:
            raise ValueError(f"forbidden vol2 option {opt}")
    rid, d = results.new_result(cfg.output_root, f"{tool}_{plugin}")
    prof = [f"--profile={profile}"] if profile else []
    base = [*vol2_cmd(cfg), "-f", str(path), *prof, plugin, *options]
    argv = [*base, "--output=json", f"--output-file={d / 'out.json'}"]
    start, limit = time.time(), cfg.max_output_mb * 1024 * 1024
    rr = await runner.run_process(argv, d / "stdout.txt", d / "stderr.txt", cfg.timeout_seconds,
                                  max_output_bytes=limit)
    rows: list[dict[str, Any]] | None = None
    try:
        rows = _rows_from_json(json.loads((d / "out.json").read_text(errors="replace")))
    except (OSError, ValueError, AttributeError):
        rows = None
    if rows is None and not (rr.timed_out or rr.output_exceeded):  # plugin without JSON output
        argv = [*base, "--output=text", f"--output-file={d / 'out.txt'}"]
        rr = await runner.run_process(argv, d / "stdout.txt", d / "stderr.txt",
                                      cfg.timeout_seconds, max_output_bytes=limit)
        out = d / "out.txt"
        text = out.read_text(errors="replace") if out.exists() else ""
        rows = [{"line": ln} for ln in text.splitlines() if ln.strip()]
    with open(d / "rows.jsonl", "w", encoding="utf-8") as fh:
        for row in rows or []:
            fh.write(json.dumps(row, default=str) + "\n")
    results.write_meta(
        d, tool=tool, plugin=plugin, profile=profile, argv=argv, tool_version="2.6",
        input_path=str(path), input_sha256=evidence_sha256, start=start, end=time.time(),
        duration=round(rr.duration, 2), exit_code=rr.exit_code, timed_out=rr.timed_out,
        output_exceeded=rr.output_exceeded, row_count=len(rows or []))
    return {"result_id": rid, "dir": d, "plugin": plugin, "argv": argv, "version": "2.6",
            "exit_code": rr.exit_code, "timed_out": rr.timed_out,
            "output_exceeded": rr.output_exceeded, "duration": round(rr.duration, 2),
            "row_count": len(rows or []),
            "stderr_tail": (d / "stderr.txt").read_text(errors="replace")[-2000:]}


def parse_imageinfo(rows: list[dict[str, Any]]) -> list[str]:
    """Suggested profiles from imageinfo rows or lines."""
    for r in rows:  # JSON: {"Suggested Profile(s)": "A, B"}; text: {"line": "... : A, B"}
        text = " ".join(f"{k} : {v}" if k != "line" else str(v) for k, v in r.items()
                        if k != "_row")
        m = re.search(r"Suggested Profile\(s\)\s*:?\s*(.+)", text)
        if m:
            return [p.strip().split(" ")[0] for p in m.group(1).split(",") if p.strip()]
    return []
