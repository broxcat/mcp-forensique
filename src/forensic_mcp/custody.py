"""Chain of custody of a case folder (task 3.2 helper, EF-05; run by an analyst, not by the LLM).

before: every file under evidence/<case>/ is hashed and registered (`evidence_registered`,
        stage "registration", actor = the named analyst) — files already registered are only
        quick-checked (size/mtime), a changed one is reported, never re-registered.
after:  every registered file of the case is re-hashed (`evidence_verified`, stage "after");
        changed, missing and unregistered (new) files are reported.
Each run writes a manifest to /output/manifests/ (evidence is read-only) and prints its SHA-256
and the journal head hash, to be copied OFF the analysis PC (custody sheet).
This module is not imported by the MCP server (checked by a test): only a person runs it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import audit, evidence, safety
from .config import Config

FORMAT = "forensic-mcp/custody-manifest/1"


def _actor(analyst: str) -> dict[str, Any]:
    name = analyst.strip()
    if not 2 <= len(name) <= 80:
        raise ValueError("analyst name required (2-80 characters)")
    return {"kind": "analyst", "name": name, "client": "register_evidence.py"}


def _case_dir(cfg: Config, case: str) -> tuple[str, Path]:
    case = case.strip().strip("/")
    if not case:
        raise ValueError("case folder required (e.g. WS-042)")
    d = safety.jail_path(case, cfg.evidence_root)
    if not d.is_dir():
        raise ValueError(f"not a folder under the evidence root: {case}")
    return case, d


def _files(d: Path) -> list[Path]:
    out = sorted(p for p in d.rglob("*") if p.is_file())
    if len(out) > evidence.MAX_DIR_FILES:
        raise ValueError(f"{len(out)} files, more than {evidence.MAX_DIR_FILES}")
    return out


def _write_manifest(cfg: Config, case: str, stage: str, analyst: str,
                    files: list[dict[str, Any]]) -> dict[str, Any]:
    body = {"format": FORMAT, "case": case, "stage": stage, "analyst": analyst,
            "generated_utc": audit.utc_now(), "file_count": len(files), "files": files,
            "journal_head_hash": (audit.head_hash(cfg.audit_file)
                                  if Path(cfg.audit_file).is_file() else None)}
    text = json.dumps(body, ensure_ascii=False, indent=1, sort_keys=True) + "\n"
    out = Path(cfg.output_root) / "manifests"
    out.mkdir(parents=True, exist_ok=True)
    stamp = body["generated_utc"].replace(":", "").replace("-", "")
    path = out / f"{case.replace('/', '_')}_{stage}_{stamp}.json"
    path.write_text(text, encoding="utf-8")
    path.chmod(0o444)
    return {"manifest": str(path), "manifest_sha256": hashlib.sha256(text.encode()).hexdigest(),
            **{k: body[k] for k in ("case", "stage", "file_count", "journal_head_hash")}}


def register_case(cfg: Config, case: str, analyst: str) -> dict[str, Any]:
    """Stage "before": register (hash + journal) every file of the case folder."""
    actor = _actor(analyst)
    case, d = _case_dir(cfg, case)
    files, changed = [], []
    for p in _files(d):
        state, _ = evidence.status(cfg, p)
        rec = evidence.register(cfg, p, actor)
        if state == evidence.CHANGED:
            changed.append(evidence.relpath(cfg, p))
        files.append({"path": evidence.relpath(cfg, p), "size": rec["size"],
                      "sha256": rec["sha256"], "registration_audit_id": rec["audit_id"],
                      "state": "changed-since-registration" if state == evidence.CHANGED
                      else "registered" if state == evidence.NOT_REGISTERED
                      else "already-registered"})
    res = _write_manifest(cfg, case, "before", actor["name"], files)
    return {**res, "changed": changed, "ok": not changed}


def verify_case(cfg: Config, case: str, analyst: str) -> dict[str, Any]:
    """Stage "after": re-hash every registered file of the case and compare."""
    actor = _actor(analyst)
    case, d = _case_dir(cfg, case)
    reg = {k: v for k, v in evidence.load_registry(cfg).items()
           if k.startswith(case + "/") and not k.startswith("@")}
    on_disk = {evidence.relpath(cfg, p): p for p in _files(d)}
    files, changed = [], []
    for rel in sorted(reg):
        if rel not in on_disk:
            files.append({"path": rel, "sha256_registered": reg[rel]["sha256"], "state": "missing"})
            continue
        r = evidence.verify_full(cfg, on_disk[rel], actor, stage="after")
        if not r["matches_registration"]:
            changed.append(rel)
        files.append({"path": rel, "size": on_disk[rel].stat().st_size,
                      "sha256_registered": r["sha256_registered"], "sha256": r["sha256_now"],
                      "verification_audit_id": r["audit_id"],
                      "state": "unchanged" if r["matches_registration"] else "CHANGED"})
    missing = [f["path"] for f in files if f["state"] == "missing"]
    new = sorted(set(on_disk) - set(reg))
    files += [{"path": rel, "state": "not-registered"} for rel in new]
    res = _write_manifest(cfg, case, "after", actor["name"], files)
    return {**res, "changed": changed, "missing": missing, "not_registered": new,
            "ok": bool(reg) and not (changed or missing)}
