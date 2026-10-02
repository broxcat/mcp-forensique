"""Timeline (CLAUDE.md §9 4.3): memory process times + EVTX + $MFT events, merged in UTC.

Sources are the results already produced for a case (vol3/vol2 process lists, EvtxECmd,
MFTECmd). Every event keeps (source_result_id, source_row) so it stays citable (EF-10). The
server converts timestamps; the LLM never does (§10).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from . import results

PROCESS_PLUGINS = {"pslist", "psscan", "pstree"}
MFT_FIELDS = {"Created0x10": "file_created", "LastModified0x10": "file_modified"}
MAX_EVENTS = 20_000
_FRACTION = re.compile(r"(\.\d{6})\d+")


def to_utc(value: Any) -> datetime | None:
    """Parse vol3 ISO, vol2 '... UTC+0000' and EZ 'yyyy-MM-dd HH:mm:ss.fffffff' (UTC) times."""
    if not isinstance(value, str) or not value.strip() or value.strip().upper() in ("N/A", "-"):
        return None
    s = value.strip().replace(" UTC+0000", "+00:00").replace("Z", "+00:00")
    s = _FRACTION.sub(r"\1", s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    """UTC ISO-8601 with a Z suffix (microseconds only when present)."""
    spec = "microseconds" if dt.microsecond else "seconds"
    return dt.astimezone(timezone.utc).isoformat(timespec=spec).replace("+00:00", "Z")


def _family(meta: dict[str, Any]) -> str:
    tool, plugin = str(meta.get("tool")), str(meta.get("plugin") or "").lower()
    if tool in ("vol3", "vol2"):
        parts = plugin.split(".")
        return "process" if (parts[-2] if len(parts) >= 2 else parts[0]) in PROCESS_PLUGINS else ""
    return {"EvtxECmd": "evtx", "MFTECmd": "mft"}.get(tool, "")


def _events(fam: str, rid: str, d: Path) -> Iterator[tuple[datetime, dict[str, Any]]]:
    for row in results.iter_rows(d):
        base = {"source_result_id": rid, "source_row": row["_row"]}
        if fam == "process":
            name = row.get("ImageFileName") or row.get("Name")
            detail = f"{name} PID {row.get('PID')} PPID {row.get('PPID')}"
            for col, ev in (("CreateTime", "process_start"), ("Start", "process_start"),
                            ("ExitTime", "process_exit"), ("Exit", "process_exit")):
                t = to_utc(row.get(col))
                if t:
                    yield t, {**base, "source": "memory", "event": ev, "detail": detail}
        elif fam == "evtx":
            t = to_utc(row.get("TimeCreated"))
            if t:
                detail = " ".join(str(row.get(k) or "") for k in (
                    "Channel", "MapDescription", "PayloadData1", "PayloadData2")).strip()
                yield t, {**base, "source": "evtx", "event": f"event {row.get('EventId')}",
                          "detail": detail}
        elif fam == "mft":
            path = f"{row.get('ParentPath', '')}\\{row.get('FileName', '')}"
            for col, ev in MFT_FIELDS.items():
                t = to_utc(row.get(col))
                if t:
                    yield t, {**base, "source": "mft", "event": ev, "detail": path}


def build(output_root: Path, case_dir: Path, around: str,
          window_minutes: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    """Events of results whose input lies under case_dir, within ±window of `around`.
    Returns (events sorted by time, source result_ids, truncated)."""
    center = to_utc(around)
    if center is None:
        raise ValueError(f"around must be an ISO-8601 time, got {around!r}")
    if not 1 <= window_minutes <= 1440:
        raise ValueError("window_minutes must be between 1 and 1440")
    lo, hi = center - timedelta(minutes=window_minutes), center + timedelta(minutes=window_minutes)
    case_dir = case_dir.resolve()
    seen: set[tuple[str, str, str]] = set()
    out: list[tuple[datetime, dict[str, Any]]] = []
    sources: list[str] = []
    truncated = False
    root = Path(output_root)
    for d in sorted(root.iterdir() if root.is_dir() else [], reverse=True):  # newest first
        meta = results.read_meta(d) if d.is_dir() else {}
        src = meta.get("input_path")
        fam = _family(meta)
        if not fam or not src or meta.get("exit_code") not in (0, None):
            continue
        src_path, out_root = Path(src).resolve(), root.resolve()
        if src_path.is_relative_to(out_root):  # a file extracted from a disk image
            m0 = results.read_meta(out_root / src_path.relative_to(out_root).parts[0])
            if m0.get("tool") == "disk_extract" and m0.get("input_path"):
                src_path = Path(m0["input_path"]).resolve()
        if not src_path.is_relative_to(case_dir):
            continue
        sources.append(d.name)
        for t, ev in _events(fam, d.name, d):
            key = (iso(t), ev["event"], ev["detail"])
            if lo <= t <= hi and key not in seen:
                seen.add(key)
                out.append((t, ev))
                if len(out) >= MAX_EVENTS:
                    truncated = True
                    break
        if truncated:
            break
    out.sort(key=lambda x: (x[0], x[1]["source"], x[1]["detail"]))
    return [{"time_utc": iso(t), **ev} for t, ev in out], sources, truncated
