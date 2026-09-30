"""Volatility 3 engine (fast-track minimal version).

No free-form extra args: only the typed `pid` option is passed (global options placed after the
plugin name are still honoured by vol3, see CLAUDE.md Phase 3 findings).
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any, Iterator

from .. import results, runner, safety
from ..config import Config, load_tools

_PLUGIN_LINE = re.compile(r"^ {4}([a-z]\w*(?:\.\w+)+)(?:\s+(.*))?$")
_VERSION = re.compile(r"Volatility 3 Framework\s+([\w.]+)")
_cache: dict[tuple[str, ...], dict[str, Any]] = {}


def vol_cmd(cfg: Config) -> list[str]:
    """Launch argv prefix for vol3 from tools.toml."""
    cmd = load_tools(cfg.tools_file).get("vol3")
    if not cmd:
        raise RuntimeError("vol3 is not available in tools.toml (run scripts/check_tools.py)")
    return cmd


def parse_help(text: str) -> dict[str, Any]:
    """Parse `vol -h` output into {version, plugins: {name: {description, deprecated}}}."""
    plugins: dict[str, dict[str, Any]] = {}
    current: str | None = None
    in_plugins = False
    for line in text.splitlines():
        if line.strip() == "PLUGIN":
            in_plugins = True
            continue
        if not in_plugins:
            continue
        if line and not line.startswith(" "):
            break  # end of the plugin list ("The following plugins could not be loaded...")
        m = _PLUGIN_LINE.match(line)
        if m:
            current = m.group(1)
            plugins[current] = {"description": (m.group(2) or "").strip()}
        elif current and line.strip():
            plugins[current]["description"] += " " + line.strip()
    for info in plugins.values():
        info["deprecated"] = "(deprecated)" in info["description"]
    v = _VERSION.search(text)
    return {"version": v.group(1) if v else "unknown", "plugins": plugins}


async def _help(cfg: Config) -> dict[str, Any]:
    cmd = vol_cmd(cfg)
    key = tuple(cmd)
    if key not in _cache:
        proc = await asyncio.create_subprocess_exec(
            *cmd, "-h", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        _cache[key] = parse_help(out.decode(errors="replace"))
    return _cache[key]


async def list_plugins(cfg: Config) -> dict[str, dict[str, Any]]:
    """All vol3 plugins of the installed version (cached)."""
    return (await _help(cfg))["plugins"]


async def version(cfg: Config) -> str:
    """Installed vol3 version string."""
    return (await _help(cfg))["version"]


def resolve_plugin(name: str, plugins: dict[str, dict[str, Any]]) -> str:
    """Map a short or namespaced name to the installed plugin (prefers non-deprecated)."""
    q = name.strip().lower()
    if not re.fullmatch(r"[a-z0-9_.]+", q):
        raise ValueError(f"invalid plugin name: {name!r}")
    matches = []
    for full in plugins:
        low = full.lower()
        module = low.rsplit(".", 1)[0]
        parts = module.split(".")
        if q == low:
            return full
        if q == module or ("." in q and q.split(".")[0] == parts[0]
                           and q.split(".")[-1] == parts[-1]):
            matches.append(full)
        elif "." not in q and parts[-1] == q:
            matches.append(full)
    preferred = [m for m in matches if not plugins[m]["deprecated"]] or matches
    if len(preferred) == 1:
        return preferred[0]
    if not preferred:
        raise ValueError(f"unknown vol3 plugin: {name!r} (see memory_list_plugins)")
    raise ValueError(f"ambiguous plugin {name!r}: {sorted(preferred)}")


MAX_SAFE_INT = 2**53 - 1  # above this, JSON clients (JS doubles) silently round integers


def safe_value(v: Any) -> Any:
    """Render ints beyond the JSON-safe range (64-bit addresses) as "0x..." hex strings."""
    if isinstance(v, int) and not isinstance(v, bool) and abs(v) > MAX_SAFE_INT:
        return hex(v)
    return v


def flatten(nodes: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Depth-first rows from vol3 JSON: `__children` removed, `depth` column added,
    unsafe big integers rendered as hex strings."""
    stack = [(n, 0) for n in reversed(nodes)]
    while stack:
        node, depth = stack.pop()
        row = {k: safe_value(v) for k, v in node.items() if k != "__children"}
        row["depth"] = depth
        yield row
        stack.extend((c, depth + 1) for c in reversed(node.get("__children") or []))


def _write_rows(d: Path) -> int:
    """Convert stdout.txt (vol3 JSON) into rows.jsonl; returns the row count (0 if not JSON)."""
    count = 0
    try:
        data = json.loads((d / "stdout.txt").read_text(encoding="utf-8", errors="replace"))
    except ValueError:
        data = []
    with open(d / "rows.jsonl", "w", encoding="utf-8") as fh:
        for row in flatten(data if isinstance(data, list) else []):
            fh.write(json.dumps(row, default=str) + "\n")
            count += 1
    return count


async def run(cfg: Config, image: str, plugin: str, pid: int | None = None) -> dict[str, Any]:
    """Run one vol3 plugin on an evidence image; returns the result summary."""
    path = safety.jail_path(image, cfg.evidence_root)
    if not path.is_file():
        raise FileNotFoundError(f"not a file: {image}")
    if pid is not None and (not isinstance(pid, int) or pid < 0):
        raise ValueError("pid must be a non-negative integer")
    full = resolve_plugin(plugin, await list_plugins(cfg))
    rid, d = results.new_result(cfg.output_root, "vol3_" + full.rsplit(".", 1)[0])
    files = d / "files"
    files.mkdir()
    argv = [*vol_cmd(cfg), "-q", "-r", "json", "-f", str(path), "-o", str(files), full]
    if pid is not None:
        argv += ["--pid", str(pid)]
    start = time.time()
    rr, digest = await asyncio.gather(
        runner.run_process(argv, d / "stdout.txt", d / "stderr.txt", cfg.timeout_seconds),
        asyncio.to_thread(results.sha256_cached, path, cfg.output_root))
    row_count = _write_rows(d)
    results.write_meta(
        d, tool="vol3", plugin=full, argv=argv, tool_version=await version(cfg),
        input_path=str(path), input_sha256=digest, start=start, end=time.time(),
        duration=round(rr.duration, 2), exit_code=rr.exit_code, timed_out=rr.timed_out,
        row_count=row_count)
    summary = results.summarize(d, n=cfg.max_rows_returned, max_cell_chars=cfg.max_cell_chars)
    return {**summary, "plugin": full, "exit_code": rr.exit_code, "timed_out": rr.timed_out,
            "duration": round(rr.duration, 2)}
