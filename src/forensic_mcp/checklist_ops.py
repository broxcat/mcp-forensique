"""checklist_status (EF-08, task 5.1): steps of rules/checklist.yaml, done / to do for a case,
derived from the audit journal only (no state of its own). Human steps (acquisition, analyst
validation) are seen through their result: registered evidence, recorded decisions."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from . import audit, results, safety
from .findings_ops import BLOCKING, STATUS_LABEL, load_findings

CHECKLIST = Path(__file__).resolve().parents[2] / "rules" / "checklist.yaml"


@lru_cache(maxsize=None)
def checklist() -> list[dict[str, Any]]:
    """The steps of rules/checklist.yaml."""
    return yaml.safe_load(CHECKLIST.read_text(encoding="utf-8"))["steps"]


class ChecklistOps:
    """Mixed into ops.Engine (uses cfg, _listing)."""

    def _rel_source(self, path: str, cache: dict[str, str | None]) -> str | None:
        """Evidence-relative path of a tool input ("@<extraction>/x" -> its source image)."""
        if not path.startswith("@"):
            return path.strip("/")
        rid = path[1:].split("/", 1)[0]
        if rid not in cache:
            src = results.read_meta(Path(self.cfg.output_root) / rid).get("input_path")
            root = Path(self.cfg.evidence_root).resolve()
            cache[rid] = (str(Path(src).resolve().relative_to(root))
                          if src and Path(src).resolve().is_relative_to(root) else None)
        return cache[rid]

    async def op_checklist_status(self, params: dict[str, Any], conf: Any = None) -> Any:
        case = str(params.get("case") or "").strip("/")
        case_dir = safety.jail_path(case or ".", self.cfg.evidence_root)
        if not case_dir.is_dir():
            raise ValueError(f"case must be a folder under the evidence root: {case!r}")

        def in_case(rel: str | None) -> bool:
            return rel is not None and (not case or rel == case or rel.startswith(case + "/"))

        hits: dict[str, list[int]] = {s["id"]: [] for s in checklist()}
        cache: dict[str, str | None] = {}
        where_of: dict[str, str | None] = {}  # result_id -> evidence-relative input
        for e in audit.iter_events(self.cfg.audit_file):
            if e["type"] == "tool_call" and e.get("outcome") == "ok":
                p = e.get("params") or {}
                where = p.get("case") if e["tool"] == "timeline" else p.get("path")
                rel = self._rel_source(str(where), cache) if where is not None else None
                if e.get("result_id") and e["result_id"] not in where_of:  # producer
                    where_of[e["result_id"]] = rel
            for s in checklist():
                det = s["detect"]
                if det["type"] == "registered" and e["type"] == "evidence_registered":
                    path = str(e.get("path", ""))
                    if in_case(path) and f"/{det['under']}/" in "/" + path:
                        hits[s["id"]].append(e["audit_id"])
                elif det["type"] == "tool_call" and e["type"] == "tool_call"                         and e.get("outcome") == "ok":
                    tool_ok = e["tool"] in det["tools"] or bool(
                        det.get("ez_tool") and e["tool"] in ("ez_run", "ez_import")
                        and p.get("tool") == det["ez_tool"])
                    if tool_ok and det.get("preset") in (None, p.get("preset")) and in_case(rel):
                        hits[s["id"]].append(e["audit_id"])
                elif det["type"] == "report_final" and e["type"] == "tool_call"                         and e["tool"] == "report_export" and e.get("outcome") == "ok"                         and (e.get("params") or {}).get("final"):
                    hits[s["id"]].append(e["audit_id"])
        mine = [f for f in load_findings(self.cfg.audit_file, with_citations=True)
                if f["status"] != STATUS_LABEL["rejected_by_server"]
                and any(in_case(where_of.get(c["result_id"])) for c in f["citation_list"])]
        items, todo = [], []
        host = case or "<racine>"
        for s in checklist():
            t = s["detect"]["type"]
            if t == "case_toml":
                done, proof = (case_dir / "case.toml").is_file(), "case.toml"
            elif t == "findings":
                done, proof = bool(mine), ", ".join(f["finding_id"] for f in mine[:5])
            elif t == "decided":
                pending = [f["finding_id"] for f in mine if f["status"] in BLOCKING]
                done = bool(mine) and not pending
                proof = ("en attente : " + ", ".join(pending[:5])) if pending else (
                    f"{len(mine)} décidés" if mine else "")
            else:
                done = bool(hits[s["id"]])
                proof = ", ".join(f"audit_id {a}" for a in hits[s["id"]][:3])
            items.append({"id": s["id"], "phase": s["phase"],
                          "etape": s["label"].replace("<HÔTE>", host),
                          "statut": "fait" if done else "à faire",
                          "qui": "analyste" if s.get("human") else "assistant",
                          "outil": s["tool"], "preuve": proof or None})
            if not done:
                todo.append(s)
        out = self._listing("checklist_status", params, items,
                            f"{len(items) - len(todo)}/{len(items)} étapes faites pour {host}"
                            + (f" ; prochaine : {todo[0]['id']}" if todo else ""))
        out.payload["next_steps"] = [
            {"tool": s["tool"],
             "args": ({"preset": s["detect"]["preset"]} if s["detect"].get("preset") else
                      {"case": case} if s["tool"] == "timeline" else {}),
             "why": s["label"].replace("<HÔTE>", host)}
            for s in todo if not s.get("human")][:3]
        return out
