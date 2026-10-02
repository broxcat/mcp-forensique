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

from .ez_registry import (CRASH_MARKERS, FORBIDDEN, HELP_DIR, REGISTRY, REGPATH_RE,  # noqa: F401
                          Opt, Tool, output_flag, registry_json, verify_registry, windows_only)


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
    if spec.runtime == "windows_only":
        raise ValueError(f"{tool} does not run on Linux ({spec.known_issue}). Run it on Windows "
                         "with scripts/run_ez_windows.ps1, then import the export with ez_import.")
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
                                  max_output_bytes=cfg.max_output_mb * 1024 * 1024,
                                  tty_stdin=spec.tty_stdin)
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
