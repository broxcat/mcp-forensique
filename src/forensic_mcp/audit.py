"""Append-only, hash-chained audit log."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

GENESIS = "0" * 64


def _digest(prev_hash: str, body: str) -> str:
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


def _last_hash(path: Path) -> str:
    if not path.exists():
        return GENESIS
    last = GENESIS
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                last = json.loads(line)["hash"]
    return last


def append_audit(path: str | Path, event: str, **fields: object) -> str:
    """Append one event; each line stores prev_hash and hash = sha256(prev_hash + body)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    prev = _last_hash(path)
    body = json.dumps({"ts": time.time(), "event": event, **fields},
                      sort_keys=True, default=str)
    h = _digest(prev, body)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"prev_hash": prev, "body": body, "hash": h}) + "\n")
    return h


def verify_audit(path: str | Path) -> tuple[bool, int]:
    """Recompute the chain. Returns (ok, index of first bad line or number of lines)."""
    path = Path(path)
    if not path.exists():
        return True, 0
    prev = GENESIS
    n = 0
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            try:
                rec = json.loads(line)
                ok = rec["prev_hash"] == prev and rec["hash"] == _digest(prev, rec["body"])
            except (ValueError, KeyError):
                ok = False
            if not ok:
                return False, n
            prev = rec["hash"]
    return True, n
