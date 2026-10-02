"""Typed shortcuts for common disk artefacts (task 4.3b), modelled on evtx_query: parse once with
the EZ tool, filter on the server (text, UTC window, a few typed fields), keep the stable _row.

Column names come from the tools' READMEs and are NOT verified on real files yet (no sample, see
CLAUDE.md §11): when none of the listed columns exists in a row, text filters look at the whole
row and time filters at every column whose name looks like a timestamp."""
from __future__ import annotations

import json
import re
from typing import Any

from .ez_ops import _window
from .timeline import to_utc

TIMEY = re.compile(r"(time|date|run|created|modified|accessed|deleted|visit|lastwrite)", re.I)
SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SHORTCUTS: dict[str, dict[str, Any]] = {
    "prefetch_query": {"tool": "PECmd", "text_param": "executable_contains",
                       "text": ["ExecutableName", "SourceFilename"],
                       "time": ["LastRun", *[f"PreviousRun{i}" for i in range(7)]]},
    "browser_history": {"tool": "SQLECmd", "text_param": "url_contains",
                        "text": ["URL", "Url", "Title"],
                        "time": ["LastVisitTime", "VisitTime", "LastVisitDate", "VisitDate"]},
    "shimcache_query": {"tool": "AppCompatCacheParser", "text_param": "path_contains",
                        "text": ["Path"], "time": ["LastModifiedTimeUTC"]},
    "amcache_query": {"tool": "AmcacheParser", "text_param": "name_contains",
                      "text": ["FullPath", "Name", "ProgramName"],
                      "time": ["FileKeyLastWriteTimestamp", "KeyLastWriteTimestamp"]},
    "lnk_query": {"tool": "LECmd", "text_param": "target_contains",
                  "text": ["LocalPath", "CommonPath", "NetworkPath", "RelativePath", "Arguments",
                           "SourceFile"],
                  "time": ["TargetCreated", "TargetModified", "TargetAccessed", "SourceCreated",
                           "SourceModified"]},
    "jumplist_query": {"tool": "JLECmd", "text_param": "target_contains",
                       "text": ["Path", "LocalPath", "TargetIDAbsolutePath", "SourceFile"],
                       "time": ["LastModified", "CreationTime", "TargetCreated",
                                "TargetModified", "SourceModified"]},
    "recyclebin_query": {"tool": "RBCmd", "text_param": "name_contains",
                         "text": ["FileName", "SourceName"], "time": ["DeletedOn"]},
}


def _text_of(row: dict[str, Any], fields: list[str]) -> str:
    present = [str(row[f]) for f in fields if row.get(f) not in (None, "")]
    if present:
        return " ".join(present).lower()
    return json.dumps(row, ensure_ascii=False, default=str).lower()


def _times_of(row: dict[str, Any], fields: list[str]) -> list[Any]:
    vals = [row[f] for f in fields if row.get(f) not in (None, "")]
    if not vals and not any(f in row for f in fields):
        vals = [v for k, v in row.items() if TIMEY.search(k) and isinstance(v, str)]
    return [t for t in (to_utc(v) for v in vals) if t is not None]


class ArtefactOps:
    """Mixed into ops.Engine (uses EzOps._ez_input, _parsed, _ez_outcome and Engine._page)."""

    async def _shortcut(self, name: str, params: dict[str, Any]) -> Any:
        spec = SHORTCUTS[name]
        real, path, ps, ev = self._ez_input(params)
        lo, hi = _window(real.get("start"), real.get("end"))
        needle = (real.get(spec["text_param"]) or "").lower()
        sha1 = (real.get("sha1") or "").lower()
        if sha1 and not SHA1_RE.match(sha1):
            raise ValueError("sha1 must be 40 hex characters")
        executed = real.get("executed_only")
        r = await self._parsed(spec["tool"], path, ev, [])

        def where(row: dict[str, Any]) -> bool:
            if needle and needle not in _text_of(row, spec["text"]):
                return False
            if sha1 and not str(row.get("SHA1") or "").lower().endswith(sha1):
                return False
            if executed and str(row.get("Executed") or "").lower() not in ("yes", "true"):
                return False
            if lo is None and hi is None:
                return True
            return any((lo is None or t >= lo) and (hi is None or t <= hi)
                       for t in _times_of(row, spec["time"]))

        q = self._page(r["dir"], where=where, limit=real.get("limit") or 50,
                       offset=real.get("offset") or 0)
        cached = " — parse reused" if r.get("cached") else ""
        return self._ez_outcome(name, params, real, ps, ev, r, q,
                                f"{q['matched']} of {r['row_count']} {spec['tool']} rows{cached}")

    async def op_prefetch_query(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._shortcut("prefetch_query", params)

    async def op_browser_history(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._shortcut("browser_history", params)

    async def op_shimcache_query(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._shortcut("shimcache_query", params)

    async def op_amcache_query(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._shortcut("amcache_query", params)

    async def op_lnk_query(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._shortcut("lnk_query", params)

    async def op_jumplist_query(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._shortcut("jumplist_query", params)

    async def op_recyclebin_query(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._shortcut("recyclebin_query", params)
