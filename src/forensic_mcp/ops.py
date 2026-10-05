"""Tool operations behind server.py, run through Engine.call():
every call (ok, failed or refused) is journaled as `tool_call` (ET-04, objective 3), every
response follows the output contract and is schema-validated (ET-03), the case policy decides
raw / pseudonymised / refused output (confidential-data guardrail)."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult

from . import audit, contract, evidence, results, safety, schemas
from .config import Config, load_tools
from .engines import volatility3
from .artefact_ops import ArtefactOps
from .checklist_ops import ChecklistOps
from .crisis_ops import CrisisOps
from .disk_ops import DiskOps
from .ez_ops import EzOps
from .findings_ops import FindingsOps
from .report import ReportOps
from .import_ops import ImportOps
from .memory_ops import TYPED_VOL3, MemoryOps
from .stakeholder_ops import StakeholderOps
from .redact import TOKEN, Pseudonymizer, case_for, pseudonymizer_for

REPLAYABLE = set(TYPED_VOL3) | {"vol3_run", "vol2_run", "vol2_imageinfo", "ez_run"}
MAX_LISTED = 500


@dataclass
class Outcome:
    """What an operation hands back to Engine.call()."""

    payload: dict[str, Any]
    params_real: dict[str, Any]
    argv: list[str] = field(default_factory=list)
    engine: str = "forensic-mcp"
    evidence_sha256: str | None = None
    result_id: str | None = None
    exit_code: int | None = None
    timed_out: bool = False
    output_exceeded: bool = False
    output_sha256: str | None = None
    pseudo: Pseudonymizer | None = None
    error: str | None = None  # tool ran but failed silently (e.g. exit 0, no output)
    audit_extra: dict[str, Any] = field(default_factory=dict)


def _rows_digest(rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(audit.canonical(rows).encode()).hexdigest()


class Engine(MemoryOps, EzOps, ArtefactOps, DiskOps, ImportOps, FindingsOps,
             ReportOps, ChecklistOps, CrisisOps, StakeholderOps):
    """Operations bound to one Config (memory operations in memory_ops.MemoryOps)."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.actor = {"kind": "llm", "client": f"mcp; llm_mode={cfg.llm_mode}"}

    def _journal(self, rec: dict[str, Any], t0: float, outcome: str, **extra: Any) -> int:
        ev = audit.append(self.cfg.audit_file, "tool_call", self.actor, **rec,
                          duration_s=round(time.monotonic() - t0, 3), outcome=outcome, **extra)
        return ev["audit_id"]

    async def call(self, tool: str, params: dict[str, Any], conf: Any = None) -> CallToolResult:
        """Run op_<tool>, journal it, pseudonymise if required, validate and render.
        `conf` = the analyst answer injected by the server resolver (sensitive calls)."""
        t0 = time.monotonic()
        rec: dict[str, Any] = {"tool": tool, "params": params, "argv": [],
                               "engine": "forensic-mcp", "evidence_sha256": None,
                               "result_id": None, "exit_code": None, "output_sha256": None}
        try:
            out: Outcome = await getattr(self, f"op_{tool}")(params, conf)
            payload = out.payload
            if out.pseudo:
                payload = out.pseudo.redact(payload)
                out.pseudo.save()
            payload = contract.fit(payload, self.cfg.max_response_kb)
            schemas.validate_output(payload)
        except (safety.SafetyError, ValueError, FileNotFoundError, KeyError) as exc:
            aid = self._journal(rec, t0, "refused", error=str(exc))
            raise ToolError(f"refused (audit_id {aid}): {exc}") from exc
        except Exception as exc:  # journal every failure, then report it
            aid = self._journal(rec, t0, "tool_error", error=f"{type(exc).__name__}: {exc}")
            raise ToolError(f"tool error (audit_id {aid}): {type(exc).__name__}: {exc}") from exc
        rec.update(params=out.params_real, argv=out.argv, engine=out.engine,
                   evidence_sha256=out.evidence_sha256, result_id=out.result_id,
                   exit_code=out.exit_code, output_sha256=out.output_sha256)
        extra = dict(out.audit_extra, timed_out=out.timed_out)
        if out.result_id:  # what this call returned: lets record_finding verify an absence (5.3)
            if isinstance(out.payload.get("row_count"), int):
                extra["row_count"] = out.payload["row_count"]
            if out.payload.get("notes"):
                extra["notes"] = [str(n) for n in out.payload["notes"]]
        if out.timed_out:
            outcome, extra["error"] = "timeout", f"timeout after {self.cfg.timeout_seconds} s"
        elif out.output_exceeded:
            outcome, extra["error"] = "tool_error", f"output over {self.cfg.max_output_mb} MB"
        elif out.error:
            outcome, extra["error"] = "tool_error", out.error
        elif out.exit_code not in (None, 0):
            outcome, extra["error"] = "tool_error", f"exit code {out.exit_code}"
        else:
            outcome = "ok"
        payload["audit_id"] = self._journal(rec, t0, outcome, **extra)
        return contract.render(payload)

    # ---- helpers -------------------------------------------------------------------------
    def _policy(self, path: Path | None) -> Pseudonymizer | None:
        return pseudonymizer_for(self.cfg, case_for(self.cfg, path))

    def _restore_path(self, p: str) -> str:
        """Tokens in a path (HOST_1/...) are looked up in every case mapping."""
        if not TOKEN.search(p):
            return p
        store = Path(self.cfg.output_root) / ".pseudo"
        rev: dict[str, str] = {}
        for f in sorted(store.glob("*.json")) if store.is_dir() else []:
            rev.update(json.loads(f.read_text(encoding="utf-8")).get("rev", {}))
        return TOKEN.sub(lambda m: rev.get(m.group(0), m.group(0)), p)

    def _rel(self, src: Path) -> str:
        """Evidence-relative path, or the raw path for results made under another root."""
        try:
            return evidence.relpath(self.cfg, src)
        except ValueError:
            return str(src)

    def _listing(self, tool: str, params: dict[str, Any], items: list[dict[str, Any]],
                 summary: str, **kw: Any) -> Outcome:
        limit = max(1, min(int(params.get("limit") or self.cfg.max_rows_returned),
                           self.cfg.max_rows_returned))
        offset = max(0, int(params.get("offset") or 0))
        rows = contract.numbered(items)[offset:offset + limit]  # _row stable over the full list
        payload = contract.build(tool=tool, engine="forensic-mcp", parameters=params,
                                 summary=summary, rows=rows, row_count=len(items),
                                 offset=offset, limit=limit,
                                 next_call={"tool": tool, "args": dict(params)})
        return Outcome(payload, params, output_sha256=_rows_digest(items), **kw)

    def _page(self, d: Path, **query: Any) -> dict[str, Any]:
        limit = max(1, min(int(query.pop("limit", 50)), self.cfg.max_rows_returned))
        offset = max(0, int(query.pop("offset", 0)))
        return results.query(d, limit=limit, offset=offset, max_cell_chars=self.cfg.max_cell_chars,
                             **query)

    # ---- operations ----------------------------------------------------------------------
    async def op_tool_status(self, params: dict[str, Any], conf: Any = None) -> Outcome:
        tools = load_tools(self.cfg.tools_file)
        try:
            vol3 = await volatility3.version(self.cfg)
        except Exception as exc:  # report, don't crash the listing
            vol3 = f"error: {exc}"
        items = [{"tool": t, "installed": True, "exposed": t != "dotnet",
                  "version": vol3 if t == "vol3" else ("2.6" if t == "vol2" else None)}
                 for t in sorted(tools)]
        return self._listing("tool_status", params, items,
                             f"{len(tools)} tools installed, exposed: vol3 {vol3}, vol2 2.6, 17 EZ tools, sleuthkit (disk_*)")

    async def op_list_evidence(self, params: dict[str, Any], conf: Any = None) -> Outcome:
        base = safety.jail_path(params.get("subdir") or ".", self.cfg.evidence_root)
        root = Path(self.cfg.evidence_root).resolve()
        reg = evidence.load_registry(self.cfg)
        items, withheld = [], 0
        for p in sorted(base.rglob("*")):
            rel = p.relative_to(root)
            if not p.is_file() or p.name == "case.toml" or any(
                    x.startswith(".") for x in rel.parts):
                continue
            case = case_for(self.cfg, p)
            try:
                ps = pseudonymizer_for(self.cfg, case)
            except safety.SafetyError:
                withheld += 1
                continue
            rec = reg.get(str(rel))
            row = {"path": str(rel), "size": p.stat().st_size,
                   "registered": rec is not None, "sha256": rec["sha256"] if rec else None,
                   "case": case.case_id, "classification": case.classification}
            if ps:
                row = ps.redact(row, "row")
                ps.save()
            items.append(row)
            if len(items) >= MAX_LISTED:
                break
        note = f", {withheld} withheld (client cases, cloud mode)" if withheld else ""
        return self._listing("list_evidence", params, items, f"{len(items)} files{note}")

    async def op_register_evidence(self, params: dict[str, Any], conf: Any = None) -> Outcome:
        path = volatility3.image_path(self.cfg, self._restore_path(params["path"]))
        ps = self._policy(path)
        already = evidence.status(self.cfg, path)[0] != evidence.NOT_REGISTERED
        rec = evidence.register(self.cfg, path, self.actor)
        rel = evidence.relpath(self.cfg, path)
        item = {"path": rel, **{k: rec[k] for k in ("size", "sha256", "registered_utc")},
                "registration_audit_id": rec["audit_id"], "already_registered": already}
        out = self._listing("register_evidence", params, [item],
                            f"{rel}: {'already registered' if already else 'registered'}",
                            evidence_sha256=rec["sha256"], pseudo=ps)
        out.payload["evidence"] = {"path": rel, "sha256": rec["sha256"],
                                   "verified": evidence.UNCHANGED}
        return out

    async def op_verify_evidence(self, params: dict[str, Any], conf: Any = None) -> Outcome:
        path = volatility3.image_path(self.cfg, self._restore_path(params["path"]))
        ps = self._policy(path)
        r = evidence.verify_full(self.cfg, path, self.actor)
        ok = r["matches_registration"]
        out = self._listing("verify_evidence", params, [r],
                            f"{r['path']}: {'unchanged' if ok else 'CHANGED'} since registration",
                            evidence_sha256=r["sha256_now"], pseudo=ps)
        out.payload["evidence"] = {"path": r["path"], "sha256": r["sha256_registered"],
                                   "verified": evidence.UNCHANGED if ok else evidence.CHANGED}
        return out

    async def op_query_results(self, params: dict[str, Any], conf: Any = None) -> Outcome:
        d = results.result_dir(self.cfg.output_root, params["result_id"])
        meta = results.read_meta(d)
        src = Path(meta["input_path"]) if meta.get("input_path") else None
        ps = self._policy(src)
        real = ps.restore(params) if ps else dict(params)
        filters = {k: real.get(k) for k in ("contains", "column", "equals", "regex", "columns",
                                              "sort_by", "sort_desc", "limit", "offset")
                   if real.get(k) is not None}
        q = self._page(d, **filters)
        ev = None
        if src is not None:
            try:
                state = evidence.status(self.cfg, src)[0]
            except OSError:
                state = evidence.CHANGED
            ev = {"path": self._rel(src), "sha256": meta["input_sha256"],
                  "verified": state}
        engine = f"{meta.get('tool', 'result')} {meta.get('tool_version', '')}".strip()
        payload = contract.build(
            tool="query_results", engine=engine, plugin=meta.get("plugin"), parameters=params,
            evidence=ev, summary=f"{q['matched']} matching rows", rows=q["rows"],
            row_count=q["matched"], offset=q["offset"], limit=q["limit"],
            result_id=d.name, truncated=q["truncated"],
            next_call={"tool": "query_results", "args": dict(params)})
        return Outcome(payload, real, engine=engine, result_id=d.name,
                       evidence_sha256=meta.get("input_sha256"),
                       output_sha256=_rows_digest(q["rows"]), pseudo=ps)

    async def op_list_results(self, params: dict[str, Any], conf: Any = None) -> Outcome:
        root = Path(self.cfg.output_root)
        items, withheld = [], 0
        for d in sorted(root.iterdir() if root.is_dir() else [], reverse=True):
            m = results.read_meta(d) if d.is_dir() else {}
            if not m:
                continue
            src = Path(m["input_path"]) if m.get("input_path") else None
            try:
                ps = self._policy(src)
            except safety.SafetyError:
                withheld += 1
                continue
            row = {"result_id": d.name, "tool": m.get("tool"), "plugin": m.get("plugin"),
                   "input": self._rel(src) if src else None,
                   "exit_code": m.get("exit_code"), "row_count": m.get("row_count")}
            items.append(ps.redact(row, "row") if ps else row)
            if len(items) >= MAX_LISTED:
                break
        note = f", {withheld} withheld (client cases, cloud mode)" if withheld else ""
        return self._listing("list_results", params, items, f"{len(items)} results{note}")

    async def op_replay(self, params: dict[str, Any], conf: Any = None) -> Outcome:
        orig = audit.read_event(self.cfg.audit_file, int(params["audit_id"]))
        if orig.get("type") != "tool_call" or orig.get("tool") not in REPLAYABLE:
            raise ValueError(f"audit_id {params['audit_id']} is not a replayable tool_call "
                             f"(replayable: {sorted(REPLAYABLE)})")
        if orig.get("outcome") != "ok":
            raise ValueError(f"audit_id {params['audit_id']} did not succeed; nothing to compare")
        new = await getattr(self, f"op_{orig['tool']}")(orig["params"], conf)
        match = new.output_sha256 == orig["output_sha256"]
        item = {"original_audit_id": orig["audit_id"], "original_result_id": orig["result_id"],
                "new_result_id": new.result_id, "original_output_sha256": orig["output_sha256"],
                "new_output_sha256": new.output_sha256, "match": match}
        out = self._listing("replay", params, [item],
                            f"replay of audit_id {orig['audit_id']}: output "
                            f"{'identical' if match else 'DIFFERENT'}", pseudo=new.pseudo)
        out.payload.update(result_id=new.result_id, evidence=new.payload["evidence"],
                           engine=new.engine, plugin=new.payload.get("plugin"),
                           raw_output=contract.raw_output(new.result_id))
        out.argv, out.engine, out.result_id = new.argv, new.engine, new.result_id
        out.evidence_sha256, out.exit_code = new.evidence_sha256, new.exit_code
        out.output_sha256 = new.output_sha256
        out.audit_extra = {"replay_of": orig["audit_id"], "replay_match": match}
        return out
