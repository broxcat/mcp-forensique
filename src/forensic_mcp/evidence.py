"""Evidence registration and verification (EF-05, chain-of-evidence guardrail, L2 §9.3).

Registration = full SHA-256 before any analysis, journaled (`evidence_registered`) and kept in
output_root/evidence_registry.json. Before each call a quick size/mtime check compares the file
with its registration; a changed file is refused. `verify_full` re-hashes (stage "after").
"""
from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import audit
from .config import Config
from .results import sha256_file
from .safety import SafetyError

UNCHANGED, NOT_REGISTERED, CHANGED = "unchanged-since-registration", "not-registered", "CHANGED"


def _registry(cfg: Config) -> Path:
    return Path(cfg.output_root) / "evidence_registry.json"


@contextmanager
def _locked(cfg: Config) -> Iterator[dict[str, Any]]:
    """Load the registry under an exclusive lock; changes are saved atomically on exit."""
    reg = _registry(cfg)
    reg.parent.mkdir(parents=True, exist_ok=True)
    with open(reg.with_suffix(".lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = json.loads(reg.read_text(encoding="utf-8")) if reg.exists() else {}
        before = json.dumps(data, sort_keys=True)
        yield data
        if json.dumps(data, sort_keys=True) != before:
            tmp = reg.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
            os.replace(tmp, reg)


def load_registry(cfg: Config) -> dict[str, Any]:
    """Read-only snapshot of the registry."""
    reg = _registry(cfg)
    return json.loads(reg.read_text(encoding="utf-8")) if reg.exists() else {}


def relpath(cfg: Config, path: Path) -> str:
    """Path relative to the evidence root (the registry key)."""
    return str(Path(path).resolve().relative_to(Path(cfg.evidence_root).resolve()))


def register(cfg: Config, path: Path, actor: dict[str, Any]) -> dict[str, Any]:
    """Hash and journal the file if it is not registered yet; returns its registry record."""
    rel = relpath(cfg, path)
    existing = load_registry(cfg).get(rel)
    if existing:
        return existing
    st = path.stat()
    digest = sha256_file(path)  # long for big images: done outside the lock
    with _locked(cfg) as data:
        if rel in data:
            return data[rel]
        ev = audit.append(cfg.audit_file, "evidence_registered", actor, path=rel,
                          size=st.st_size, mtime_ns=st.st_mtime_ns, sha256=digest,
                          stage="registration")
        data[rel] = {"size": st.st_size, "mtime_ns": st.st_mtime_ns, "sha256": digest,
                     "registered_utc": ev["ts_utc"], "audit_id": ev["audit_id"]}
        return data[rel]


def status(cfg: Config, path: Path) -> tuple[str, dict[str, Any] | None]:
    """(UNCHANGED | NOT_REGISTERED | CHANGED, registry record) from a size/mtime quick check."""
    rec = load_registry(cfg).get(relpath(cfg, path))
    if rec is None:
        return NOT_REGISTERED, None
    st = path.stat()
    same = st.st_size == rec["size"] and st.st_mtime_ns == rec["mtime_ns"]
    return (UNCHANGED if same else CHANGED), rec


def check_before_use(cfg: Config, path: Path, actor: dict[str, Any]) -> dict[str, Any]:
    """Register on first use, refuse a changed file; returns the contract `evidence` block."""
    state, rec = status(cfg, path)
    rel = relpath(cfg, path)
    if state == NOT_REGISTERED:
        rec = register(cfg, path, actor)
        state = UNCHANGED
    elif state == CHANGED:
        st = path.stat()
        audit.append(cfg.audit_file, "evidence_verified", actor, path=rel, size=st.st_size,
                     mtime_ns=st.st_mtime_ns, sha256=rec["sha256"], stage="quick_check",
                     matches_registration=False)
        raise SafetyError(f"evidence changed since registration: {rel} (size/mtime differ). "
                          "Analysis refused: restore the original copy or register the new file "
                          "under a different name.")
    return {"path": rel, "sha256": rec["sha256"], "verified": state}


def verify_full(cfg: Config, path: Path, actor: dict[str, Any],
                stage: str = "after") -> dict[str, Any]:
    """Re-hash the whole file and compare with its registration (journaled)."""
    rel = relpath(cfg, path)
    rec = load_registry(cfg).get(rel)
    if rec is None:
        raise SafetyError(f"evidence not registered: {rel} (call register_evidence first)")
    st = path.stat()
    digest = sha256_file(path)
    match = digest == rec["sha256"]
    ev = audit.append(cfg.audit_file, "evidence_verified", actor, path=rel, size=st.st_size,
                      mtime_ns=st.st_mtime_ns, sha256=digest, stage=stage,
                      matches_registration=match)
    return {"path": rel, "sha256_registered": rec["sha256"], "sha256_now": digest,
            "matches_registration": match, "audit_id": ev["audit_id"]}
