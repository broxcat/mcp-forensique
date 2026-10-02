"""Disk-artefact operations (EF-02, EF-03, Décision J3): ez_list_tools, ez_run (any of the 17 EZ
tools with typed options), evtx_query (presets), mft_search, timeline. Parse once, then filter
the parsed rows on the server (streaming)."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from . import contract, evidence, results, safety, timeline
from .engines import zimmerman
from .timeline import to_utc

# Bumped when the parse output changes (4.3b: CSV -> JSON) so older cached parses are not reused.
PARSE_FORMAT = "rows-v2-json"
PRESETS_FILE = Path(__file__).resolve().parents[2] / "rules" / "evtx_presets.yaml"
EVTX_COLUMNS = ["TimeCreated", "EventId", "Channel", "Computer", "UserName", "RemoteHost",
                "MapDescription", "PayloadData1", "PayloadData2", "PayloadData3",
                "ExecutableInfo", "SourceFile"]
MFT_TIME_FIELDS = ["Created0x10", "LastModified0x10", "LastRecordChange0x10", "LastAccess0x10",
                   "Created0x30", "LastModified0x30", "LastRecordChange0x30", "LastAccess0x30"]
MFT_COLUMNS = ["EntryNumber", "SequenceNumber", "InUse", "ParentPath", "FileName", "Extension",
               "FileSize", "IsDirectory", "SI<FN", "uSecZeros", "Copied", *MFT_TIME_FIELDS[:4]]


@lru_cache(maxsize=None)
def presets() -> dict[str, Any]:
    """EVTX presets (rules/evtx_presets.yaml)."""
    return yaml.safe_load(PRESETS_FILE.read_text(encoding="utf-8"))["presets"]


def _window(start: str | None, end: str | None) -> tuple[Any, Any]:
    lo, hi = (to_utc(start) if start else None), (to_utc(end) if end else None)
    if (start and lo is None) or (end and hi is None):
        raise ValueError("start / end must be ISO-8601 times (UTC if no offset)")
    return lo, hi


def _in_window(value: Any, lo: Any, hi: Any) -> bool:
    if lo is None and hi is None:
        return True
    t = to_utc(value)
    return t is not None and (lo is None or t >= lo) and (hi is None or t <= hi)


class EzOps:
    """Mixed into ops.Engine (uses cfg, actor, _policy, _restore_path, _page, _listing)."""

    def _ez_input(self, params: dict[str, Any]) -> tuple[dict[str, Any], Path, Any, dict]:
        real = {**params, "path": self._restore_path(str(params["path"]))}
        path = safety.jail_input(real["path"], self.cfg.evidence_root, self.cfg.output_root)
        if not path.exists():
            raise FileNotFoundError(f"not found under the evidence root: {params['path']}")
        ps = self._policy(path if path.is_file() else path / "_")
        if ps:
            real = {**ps.restore(real), "path": real["path"]}
        ev = (evidence.check_dir_before_use(self.cfg, path, self.actor) if path.is_dir()
              else evidence.check_before_use(self.cfg, path, self.actor))
        return real, path, ps, ev

    def _jail(self, p: str) -> Path:
        path = safety.jail_input(self._restore_path(p), self.cfg.evidence_root,
                                  self.cfg.output_root)
        if not path.is_file():
            raise FileNotFoundError(f"not a file under the evidence root: {p}")
        evidence.check_before_use(self.cfg, path, self.actor)
        return path

    async def _parsed(self, tool: str, path: Path, ev: dict, argv: list[str]) -> dict[str, Any]:
        """Run once per (tool, evidence digest, options); later calls reuse the result."""
        cache = Path(self.cfg.output_root) / ".toolcache" / "ez_parse.json"
        data = json.loads(cache.read_text(encoding="utf-8")) if cache.exists() else {}
        key = json.dumps([PARSE_FORMAT, tool, ev["sha256"], argv])
        rid = data.get(key)
        d = Path(self.cfg.output_root) / rid if rid else None
        if d is not None and d.is_dir() and results.read_meta(d).get("exit_code") == 0:
            m = results.read_meta(d)
            return {"result_id": rid, "dir": d, "plugin": tool, "argv": m["argv"], "exit_code": 0,
                    "timed_out": False, "output_exceeded": False, "row_count": m["row_count"],
                    "stderr_tail": "", "cached": True}
        r = await zimmerman.run(self.cfg, tool, path, argv, ev["sha256"])
        if r["exit_code"] == 0:
            data[key] = r["result_id"]
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(data, indent=1), encoding="utf-8")
        return {**r, "cached": False}

    def _ez_outcome(self, tool: str, params: dict, real: dict, ps: Any, ev: dict, r: dict,
                    q: dict, summary: str, notes: list[str] | None = None,
                    repeat: bool = False) -> Any:
        """repeat=True: server-side filters, so the next page re-runs this tool (cached parse)
        with the same parameters; otherwise query_results on the result."""
        from .ops import Outcome  # circular at import time

        extra: dict[str, Any] = {"exit_code": r["exit_code"]}
        if r["exit_code"] != 0:
            extra["stderr_tail"] = r["stderr_tail"]
        if r.get("error"):
            notes = [f"TOOL ERROR: {r['error']}. Zero rows here does NOT mean 'not present'.",
                     *(notes or [])]
        if notes:
            extra["notes"] = notes
        engine = f"{r['plugin']} (Eric Zimmerman)"
        payload = contract.build(
            tool=tool, engine=engine, plugin=r["plugin"], parameters=params, evidence=ev,
            summary=summary, rows=q["rows"], row_count=q["matched"], offset=q["offset"],
            limit=q["limit"], result_id=r["result_id"], truncated=q["truncated"], extra=extra,
            next_call={"tool": tool, "args": dict(params)} if repeat else None)
        return Outcome(payload, real, argv=r["argv"], engine=engine, evidence_sha256=ev["sha256"],
                       result_id=r["result_id"], exit_code=r["exit_code"],
                       timed_out=r["timed_out"], output_exceeded=r["output_exceeded"],
                       output_sha256=results.rows_sha256(r["dir"]), pseudo=ps,
                       error=r.get("error") or None)

    async def op_ez_list_tools(self, params: dict[str, Any], conf: Any = None) -> Any:
        missing = zimmerman.verify_registry()
        items = [{"tool": name, "inputs": " ".join(t.inputs), "artefacts": t.artefacts,
                  "options": "; ".join(f"{k}: {o.kind} ({o.flag}) {o.help}"
                                       for k, o in t.options.items()) or "-",
                  "runtime": t.runtime, "known_issue": t.known_issue or None,
                  "how_to_run": ("exécuter sous Windows (scripts/run_ez_windows.ps1) puis importer "
                                 "avec ez_import" if t.runtime == "windows_only"
                                 else "ez_run dans le conteneur")}
                 for name, t in zimmerman.REGISTRY.items()]
        recmd = next(i for i in items if i["tool"] == "RECmd")
        try:
            recmd["options"] += " | batch choices: " + ", ".join(zimmerman.batch_files(self.cfg))
        except Exception:  # RECmd not installed: listing still works
            pass
        summary = (f"{len(items)} Eric Zimmerman tools; every flag checked against "
                   f"docs/tool_help" + (f" — MISSING: {missing}" if missing else " (all present)"))
        return self._listing("ez_list_tools", params, items, summary)

    async def op_ez_run(self, params: dict[str, Any], conf: Any = None) -> Any:
        tool = str(params["tool"])
        zimmerman.ez_cmd(self.cfg, tool)  # unknown tool -> refused before touching evidence
        real, path, ps, ev = self._ez_input(params)
        argv = zimmerman.build_options(self.cfg, tool, real.get("options"), self._jail)
        r = await zimmerman.run(self.cfg, tool, path, argv, ev["sha256"])
        q = self._page(r["dir"], limit=params.get("limit") or 50, offset=params.get("offset") or 0)
        status = "" if r["exit_code"] == 0 else f" (exit code {r['exit_code']})"
        return self._ez_outcome("ez_run", params, real, ps, ev, r, q,
                                f"{r['row_count']} rows from {tool}{status}")

    async def op_evtx_query(self, params: dict[str, Any], conf: Any = None) -> Any:
        real, path, ps, ev = self._ez_input(params)
        preset = real.get("preset")
        if preset is not None and preset not in presets():
            raise ValueError(f"unknown preset {preset!r}; choices: {sorted(presets())}")
        events = presets()[preset]["events"] if preset else []
        ids = sorted(set(real.get("event_ids") or []) | {e["id"] for e in events})
        lo, hi = _window(real.get("start"), real.get("end"))
        chan = {e["id"]: e["channel"].lower() for e in events}
        full = await self._cached_full("EvtxECmd", ev)
        argv = [] if full or not ids else zimmerman.build_options(
            self.cfg, "EvtxECmd", {"event_ids": ids}, self._jail)
        r = full or await self._parsed("EvtxECmd", path, ev, argv)
        seen_channels: set[str] = set()

        def where(row: dict[str, Any]) -> bool:
            c = str(row.get("Channel") or "")
            seen_channels.add(c)
            eid = results.as_number(row.get("EventId"))
            if ids and eid not in ids:
                return False
            if eid in chan and c and c.lower() != chan[eid]:
                return False
            return _in_window(row.get("TimeCreated"), lo, hi)

        page = {"where": where, "contains": real.get("contains"), "columns": EVTX_COLUMNS,
                "limit": real.get("limit") or 50, "offset": real.get("offset") or 0}
        q = self._page(r["dir"], **page)
        if q["matched"] == 0 and events and argv:
            # an --inc parse cannot tell which logs the input holds: answer from a full parse
            r = await self._parsed("EvtxECmd", path, ev, [])
            q = self._page(r["dir"], **page)
        notes = []
        if q["matched"] == 0 and events:
            seen = {c.lower() for c in seen_channels if c}
            for e in events:
                present = "present" if e["channel"].lower() in seen else "ABSENT from the input"
                notes.append(f"{e['id']} ({e['channel']}, log {present}): requires {e['requires']}")
            notes.insert(0, f"No '{preset}' event found. 'No event' is not 'no activity': check "
                         "that each log below was collected and that its audit policy was on.")
        label = f"preset {preset}" if preset else (f"IDs {ids}" if ids else "all events")
        return self._ez_outcome("evtx_query", params, real, ps, ev, r, q,
                                f"{q['matched']} events ({label})"
                                + (" — parse reused" if r.get("cached") else ""), notes,
                                repeat=True)

    async def _cached_full(self, tool: str, ev: dict) -> dict[str, Any] | None:
        cache = Path(self.cfg.output_root) / ".toolcache" / "ez_parse.json"
        data = json.loads(cache.read_text(encoding="utf-8")) if cache.exists() else {}
        rid = data.get(json.dumps([PARSE_FORMAT, tool, ev["sha256"], []]))
        d = Path(self.cfg.output_root) / rid if rid else None
        if d is None or not d.is_dir():
            return None
        m = results.read_meta(d)
        return {"result_id": rid, "dir": d, "plugin": tool, "argv": m["argv"], "exit_code": 0,
                "timed_out": False, "output_exceeded": False, "row_count": m["row_count"],
                "stderr_tail": "", "cached": True}

    async def op_mft_search(self, params: dict[str, Any], conf: Any = None) -> Any:
        real, path, ps, ev = self._ez_input(params)
        if path.is_dir():
            raise ValueError("mft_search takes a $MFT file")
        field = real.get("time_field") or "Created0x10"
        if field not in MFT_TIME_FIELDS:
            raise ValueError(f"time_field must be one of {MFT_TIME_FIELDS}")
        lo, hi = _window(real.get("start"), real.get("end"))
        needle = (real.get("path_contains") or "").lower()
        ext = (real.get("extension") or "").lower()
        ext = ext if not ext or ext.startswith(".") else "." + ext
        r = await self._parsed("MFTECmd", path, ev, [])

        def where(row: dict[str, Any]) -> bool:
            if needle and needle not in f"{row.get('ParentPath', '')}\\{row.get('FileName', '')}".lower():
                return False
            if ext and str(row.get("Extension") or "").lower() != ext:
                return False
            return _in_window(row.get(field), lo, hi)

        q = self._page(r["dir"], where=where, columns=MFT_COLUMNS, sort_by=field if lo or hi else None,
                       limit=real.get("limit") or 50, offset=real.get("offset") or 0)
        return self._ez_outcome("mft_search", params, real, ps, ev, r, q,
                                f"{q['matched']} $MFT entries of {r['row_count']}"
                                + (" — parse reused" if r.get("cached") else ""), repeat=True)

    async def op_timeline(self, params: dict[str, Any], conf: Any = None) -> Any:
        from .ops import Outcome

        case = self._restore_path(str(params.get("case") or "."))
        case_dir = safety.jail_path(case, self.cfg.evidence_root)
        if not case_dir.is_dir():
            raise ValueError(f"case must be a folder under the evidence root: {params.get('case')}")
        ps = self._policy(case_dir / "_")
        events, sources, cut = timeline.build(self.cfg.output_root, case_dir,
                                              str(params["around"]),
                                              int(params.get("window_minutes") or 30))
        rid, d = results.new_result(self.cfg.output_root, "timeline")
        with open(d / "rows.jsonl", "w", encoding="utf-8") as fh:
            for e in events:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")
        results.write_meta(d, tool="timeline", plugin="timeline", argv=[], input_path=None,
                           sources=sources, params=params, row_count=len(events), exit_code=0)
        q = self._page(d, limit=params.get("limit") or 50, offset=params.get("offset") or 0)
        notes = [f"{len(sources)} source results merged"] + (
            [f"truncated at {timeline.MAX_EVENTS} events: narrow the window"] if cut else [])
        if not sources:
            notes.append("no source result for this case yet: run vol_pslist, evtx_query or "
                         "mft_search first")
        payload = contract.build(
            tool="timeline", engine="forensic-mcp", parameters=params,
            summary=f"{len(events)} events within ±{params.get('window_minutes') or 30} min of "
                    f"{timeline.iso(to_utc(params['around']))}", rows=q["rows"],
            row_count=q["matched"], offset=q["offset"], limit=q["limit"], result_id=rid,
            truncated=q["truncated"] or cut, extra={"notes": notes})
        return Outcome(payload, params, result_id=rid, output_sha256=results.rows_sha256(d),
                       pseudo=ps)
