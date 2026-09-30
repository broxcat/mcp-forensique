"""Append-only, hash-chained audit journal (CLAUDE.md §6, ET-04, objective 3).

Each line is {"prev_hash", "body", "hash"}; `body` is the canonical JSON text of the event and
hash = sha256(prev_hash + body). Appends take an exclusive flock so the HTTP and stdio server
processes can write concurrently (L2 §9.4).
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from . import schemas

GENESIS = "0" * 64


def utc_now() -> str:
    """Current time, ISO-8601 UTC with milliseconds and a Z suffix."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical(obj: Any) -> str:
    """Canonical JSON text: sorted keys, compact separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _digest(prev_hash: str, body: str) -> str:
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


def _last_line(fh: Any) -> bytes | None:
    """Last non-empty line of a binary file, read backwards from the end."""
    fh.seek(0, os.SEEK_END)
    end = fh.tell()
    buf = b""
    pos = end
    while pos > 0:
        step = min(65536, pos)
        pos -= step
        fh.seek(pos)
        buf = fh.read(step) + buf
        lines = [ln for ln in buf.split(b"\n") if ln.strip()]
        if len(lines) >= 2 or (pos == 0 and lines):
            return lines[-1]
    return None


def append(journal: str | Path, type_: str, actor: dict[str, Any], /,
           **fields: Any) -> dict[str, Any]:
    """Append one event; returns {"audit_id", "hash", "ts_utc"}."""
    path = Path(journal)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+b") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            last = _last_line(fh)
            if last is None:
                prev, audit_id = GENESIS, 1
            else:
                rec = json.loads(last)
                prev, audit_id = rec["hash"], json.loads(rec["body"])["audit_id"] + 1
            ts = utc_now()
            body = canonical({**fields, "audit_id": audit_id, "ts_utc": ts, "type": type_,
                              "actor": actor})
            h = _digest(prev, body)
            fh.seek(0, os.SEEK_END)
            line = json.dumps({"prev_hash": prev, "body": body, "hash": h}, ensure_ascii=False)
            fh.write(line.encode() + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)
    return {"audit_id": audit_id, "hash": h, "ts_utc": ts}


def iter_events(path: str | Path) -> Iterator[dict[str, Any]]:
    """Decoded event bodies, in order."""
    path = Path(path)
    if not path.exists():
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(json.loads(line)["body"])


def read_event(path: str | Path, audit_id: int) -> dict[str, Any]:
    """Event with this audit_id (KeyError if absent)."""
    for ev in iter_events(path):
        if ev.get("audit_id") == audit_id:
            return ev
    raise KeyError(f"unknown audit_id: {audit_id}")


def verify_report(path: str | Path, check_schema: bool = True) -> dict[str, Any]:
    """Recompute the chain, check contiguous audit_ids and (optionally) each event's schema."""
    path = Path(path)
    prev, n = GENESIS, 0
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                reason = ""
                try:
                    rec = json.loads(line)
                    body = json.loads(rec["body"])
                    if rec["prev_hash"] != prev:
                        reason = "prev_hash does not match the previous line"
                    elif rec["hash"] != _digest(prev, rec["body"]):
                        reason = "hash mismatch (line modified)"
                    elif body.get("audit_id") != n:
                        reason = f"audit_id {body.get('audit_id')} != line {n}"
                    elif check_schema:
                        errs = schemas.errors(schemas.event_validator(), body)
                        reason = f"schema: {errs[0]}" if errs else ""
                except (ValueError, KeyError, TypeError) as exc:
                    reason = f"unreadable line: {exc}"
                if reason:
                    return {"ok": False, "lines": n, "first_bad": n, "reason": reason,
                            "head_hash": prev}
                prev = rec["hash"]
    return {"ok": True, "lines": n, "first_bad": None, "reason": "", "head_hash": prev}


def verify_audit(path: str | Path) -> tuple[bool, int]:
    """(ok, number of lines) or (False, index of the first bad line)."""
    r = verify_report(path)
    return r["ok"], (r["lines"] if r["ok"] else r["first_bad"])


def head_hash(path: str | Path) -> str:
    """Hash of the last line (to anchor off-host, L2 §9.5)."""
    return verify_report(path, check_schema=False)["head_hash"]
