"""ez_import (option A for the Windows-only EZ tools, Décision J3): read an export produced on
Windows by scripts/run_ez_windows.ps1 under the evidence root, verify it, normalise it.

Checks: manifest format; tool in the registry; every output file present with its SHA-256;
the input still under the evidence root with the same content digest (file: SHA-256; folder:
SHA-256 over sorted "relative/path\\0sha256\\n" lines — the same scheme in the PowerShell
script). The import is journaled as `imported_from_windows` (tool, version, hashes)."""
from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterator

from . import audit, contract, evidence, results, safety
from .engines import zimmerman
from .engines.ez_registry import CRASH_MARKERS, registry_json_text

FORMAT = "forensic-mcp/ez-windows-export/1"
NAME_RE = re.compile(r"^[A-Za-z0-9_. $()\[\]{}-]{1,200}$")


def content_digest(path: Path) -> str:
    """File: SHA-256. Folder: SHA-256 over sorted 'rel/path\\0sha256\\n' of its files (dot
    files and case.toml skipped), rel paths with '/', ordinal sort."""
    if path.is_file():
        return results.sha256_file(path)
    lines = []
    for p in path.rglob("*"):
        rel = p.relative_to(path)
        if p.is_file() and p.name != "case.toml" and not any(x.startswith(".") for x in rel.parts):
            lines.append(f"{rel.as_posix()}\0{results.sha256_file(p)}\n")
    return hashlib.sha256("".join(sorted(lines)).encode("utf-8")).hexdigest()


def _records(p: Path) -> Iterator[dict[str, Any]]:
    if p.suffix.lower() == ".json":
        yield from zimmerman.iter_json_records(p)
    else:
        with open(p, newline="", encoding="utf-8-sig", errors="replace") as fh:
            yield from csv.DictReader(fh)


class ImportOps:
    """Mixed into ops.Engine (uses cfg, actor, _policy, _restore_path, _page, _ez_outcome)."""

    def _export_dir(self, params: dict[str, Any]) -> Path:
        p = safety.jail_path(self._restore_path(str(params["path"])), self.cfg.evidence_root)
        p = p.parent if p.name == "manifest.json" else p
        if not (p / "manifest.json").is_file():
            raise FileNotFoundError(f"no manifest.json in {params['path']}: not an export of "
                                    "scripts/run_ez_windows.ps1")
        return p

    async def _imported(self, tool: str, folder: Path) -> dict[str, Any]:
        """Verify and normalise one export (cached per manifest SHA-256)."""
        raw = (folder / "manifest.json").read_bytes()
        man = json.loads(raw.decode("utf-8-sig"))
        msha = hashlib.sha256(raw).hexdigest()
        if man.get("format") != FORMAT:
            raise ValueError(f"unknown export format {man.get('format')!r} (expected {FORMAT})")
        if man.get("tool") != tool or tool not in zimmerman.REGISTRY:
            raise ValueError(f"export is from {man.get('tool')!r}, not {tool!r}")
        cache = Path(self.cfg.output_root) / ".toolcache" / "ez_import.json"
        known = json.loads(cache.read_text(encoding="utf-8")) if cache.exists() else {}
        d0 = Path(self.cfg.output_root) / known.get(msha, "-")
        if known.get(msha) and (d0 / "rows.jsonl").exists():
            m = results.read_meta(d0)
            return {"result_id": d0.name, "dir": d0, "plugin": tool, "argv": m["argv"],
                    "exit_code": m["exit_code"], "timed_out": False, "output_exceeded": False,
                    "row_count": m["row_count"], "stderr_tail": "", "cached": True,
                    "error": m.get("error") or "", "notes": m.get("notes", [])}
        files = []
        for o in man.get("outputs") or []:
            name = str(o.get("file", ""))
            parts = name.replace("\\", "/").split("/")
            if not parts or not all(NAME_RE.match(x) and x not in (".", "..") for x in parts):
                raise safety.SafetyError(f"invalid output name in manifest: {name!r}")
            f = folder / "out" / Path(*parts)
            if not f.is_file() or results.sha256_file(f) != o.get("sha256"):
                raise safety.SafetyError(f"export output {name} missing or modified "
                                         "(SHA-256 differs from the manifest)")
            files.append(f)
        inp = man.get("input") or {}
        src = safety.jail_path(str(inp.get("path", "")), self.cfg.evidence_root)
        if not src.exists():
            raise FileNotFoundError(f"input {inp.get('path')} of the export is not under the "
                                    "evidence root: cannot verify it")
        if content_digest(src) != inp.get("sha256"):
            raise safety.SafetyError(f"input {inp.get('path')} differs from the one the export "
                                     "was made from (content digest mismatch)")
        notes = [f"imported from Windows: {tool} {man.get('tool_version')} run "
                 f"{man.get('started_utc')}; manifest sha256 {msha[:16]}…"]
        if hashlib.sha256(registry_json_text().encode()).hexdigest() != man.get("registry_sha256"):
            notes.append("export made with another version of rules/ez_registry.json")
        console = str(man.get("stdout_tail", "")) + str(man.get("stderr_tail", ""))
        crash = next((ln for ln in console.splitlines()
                      if any(k in ln.lower() for k in CRASH_MARKERS)), "")
        error = f"tool failed on Windows: {crash[:300]}" if crash else (
            "no output file in the export" if not files else "")
        rid, d = results.new_result(self.cfg.output_root, f"ez_import_{tool}")
        n = 0
        with open(d / "rows.jsonl", "w", encoding="utf-8") as out:
            for f in files:
                for rec in _records(f):
                    out.write(json.dumps({"_file": f.name, **rec}, ensure_ascii=False,
                                         default=str) + "\n")
                    n += 1
        argv = [str(a) for a in man.get("argv") or []]
        results.write_meta(d, tool=tool, plugin=tool, argv=argv, tool_version=man.get("tool_version"),
                           input_path=str(src), input_sha256=inp.get("sha256"),
                           export_path=str(folder), manifest_sha256=msha,
                           exit_code=man.get("exit_code"), row_count=n, error=error or None,
                           notes=notes, imported=True)
        audit.append(self.cfg.audit_file, "imported_from_windows", self.actor, tool=tool,
                     tool_version=man.get("tool_version"),
                     export_path=evidence.relpath(self.cfg, folder), manifest_sha256=msha,
                     input_path=evidence.relpath(self.cfg, src), input_sha256=inp.get("sha256"),
                     outputs=[{"file": f.name, "sha256": o["sha256"]}
                              for f, o in zip(files, man.get("outputs") or [])],
                     argv=argv, exit_code=man.get("exit_code"),
                     started_utc=man.get("started_utc"), result_id=rid)
        known[msha] = rid
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(known, indent=1), encoding="utf-8")
        return {"result_id": rid, "dir": d, "plugin": tool, "argv": argv,
                "exit_code": man.get("exit_code"), "timed_out": False, "output_exceeded": False,
                "row_count": n, "stderr_tail": str(man.get("stderr_tail", ""))[-2000:],
                "cached": False, "error": error, "notes": notes}

    async def op_ez_import(self, params: dict[str, Any], conf: Any = None) -> Any:
        tool = str(params["tool"])
        if tool not in zimmerman.REGISTRY:
            raise ValueError(f"unknown EZ tool {tool!r} (see ez_list_tools)")
        folder = self._export_dir(params)
        real, path, ps, ev = self._ez_input({**params, "path": params["path"]})
        r = await self._imported(tool, folder)
        q = self._page(r["dir"], limit=params.get("limit") or 50, offset=params.get("offset") or 0)
        summary = f"{r['row_count']} rows imported from a Windows run of {tool}" + (
            " (import reused)" if r.get("cached") else "")
        return self._ez_outcome("ez_import", params, real, ps, ev, r, q, summary, r["notes"])
