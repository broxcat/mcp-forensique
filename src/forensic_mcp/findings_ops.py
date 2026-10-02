"""Findings (4.4; EF-10, EF-11; guardrails anti-hallucination, confidence limits, traceability).

record_finding: every AI statement is journaled as a `suggestion` with its kind (fact /
hypothesis / recommendation), confidence and citations (result_id, row, field, value). The
server CROSS-CHECKS each cited value against the raw row before accepting it; a finding with no
citation, an unknown result/row/field, a value that is not in the row or an ATT&CK ID that the
server's rule table does not provide is rejected with its reason (journaled too). Accepted
findings are "à valider" until an analyst validates them (never the LLM).
list_findings: rebuilt from the journal (single source of truth).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import analyzers, audit, decode, playbook, results
from .timeline import to_utc

KINDS = ("fact", "hypothesis", "recommendation")
CONFIDENCE = ("low", "medium", "high")
ATTACK_RE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
MAX_CITATIONS = 20
PARTIAL_MIN_CELL, PARTIAL_MIN_VALUE = 64, 4


def known_attack_ids() -> set[str]:
    """ATT&CK IDs the server itself provides (rule table + triage tree, task 5.1)."""
    ids: set[str] = set()
    for r in analyzers.rules()["rules"]:
        ids |= set(r.get("attack", [])) | set(r.get("attack_system_name", []))
    return ids | playbook.tree_attack_ids()


def _row(d: Path, n: int) -> dict[str, Any] | None:
    for row in results.iter_rows(d):
        if row["_row"] == n:
            return row
        if row["_row"] > n:
            break
    return None


def value_matches(cell: Any, value: Any) -> str | None:
    """'exact' | 'numeric' | 'time' | 'partial' when the cited value is supported by the cell."""
    a, b = str(cell if cell is not None else "").strip(), str(value).strip()
    if a.casefold() == b.casefold():
        return "exact"
    na, nb = results.as_number(cell), results.as_number(value)
    if na is not None and nb is not None and na == nb:
        return "numeric"
    ta, tb = to_utc(a), to_utc(b)
    if ta is not None and tb is not None and ta == tb:
        return "time"
    if len(a) >= PARTIAL_MIN_CELL and len(b) >= PARTIAL_MIN_VALUE and b.casefold() in a.casefold():
        return "partial"
    return None


# Journal codes -> labels shown to people (CDC: à valider / validé / rejeté).
STATUS_LABEL = {"à valider": "à valider", "rejected_by_server": "rejeté par le serveur",
                "validated": "validé", "rejected": "rejeté", "to_review": "à revoir"}
BLOCKING = ("à valider", "à revoir")  # a final report refuses these


def load_findings(audit_file: Path, with_citations: bool = False) -> list[dict[str, Any]]:
    """Every finding with its CURRENT status, rebuilt from the journal: the latest analyst
    `validation` event wins; nothing is ever deleted (rejected findings stay listed)."""
    out: dict[str, dict[str, Any]] = {}
    for e in audit.iter_events(audit_file):
        if e["type"] == "suggestion":
            f = {"finding_id": e["finding_id"], "kind": e["kind"],
                 "status": STATUS_LABEL[e["status"]], "confidence": e["confidence"],
                 "text": e["text"],
                 "citations": "; ".join(f"{c['result_id']}#{c['_row']}.{c['field']}"
                                        for c in e["citations"]),
                 "attack": ", ".join(e.get("attack") or []), "audit_id": e["audit_id"],
                 "decided_by": None, "decision_reason": None, "decided_utc": None,
                 "decision_audit_id": None}
            if with_citations:
                f["citation_list"] = e["citations"]
            out[e["finding_id"]] = f
        elif e["type"] == "validation" and e.get("finding_id") in out:
            out[e["finding_id"]].update(
                status=STATUS_LABEL[e["decision"]], decided_by=e["actor"].get("name"),
                decision_reason=e.get("comment"), decided_utc=e["ts_utc"],
                decision_audit_id=e["audit_id"])
    return list(out.values())


class FindingsOps:
    """Mixed into ops.Engine (uses cfg, actor, _policy, _listing)."""

    def _check(self, c: dict[str, Any]) -> tuple[dict[str, Any], str]:
        """Cross-check one citation; returns (journaled citation, problem or '')."""
        rid, n, field, value = c.get("result_id"), c.get("row"), c.get("field"), c.get("value")
        if not isinstance(value, (str, int, float, bool)) and value is not None:
            value = str(value)  # the journal keeps scalars only
        cit = {"result_id": str(rid),
               "_row": n if isinstance(n, int) and not isinstance(n, bool) and n > 0 else 0,
               "field": str(field), "value": value}
        try:
            d = results.result_dir(self.cfg.output_root, str(rid))
        except (ValueError, FileNotFoundError):
            return cit, f"unknown result_id {rid!r}"
        meta = results.read_meta(d)
        ps = self._policy(Path(meta["input_path"]) if meta.get("input_path") else None)
        if ps:  # tokens (HOST_1, IP_EXT_1…) cited in cloud mode -> real values
            value = ps.restore(value)
            cit["value"] = value
            self._finding_ps = ps
        if not isinstance(n, int) or isinstance(n, bool) or n < 1:
            return cit, "row must be a positive integer (_row)"
        row = _row(d, n)
        if row is None:
            return cit, f"row {n} does not exist in {rid}"
        if field == "decoded":
            args = next((row[k] for k in analyzers.ARGS if row.get(k)), None)
            dec = decode.decode_powershell(str(args)) if args else None
            if dec is None:
                return cit, f"row {n} of {rid} has no encoded command to decode"
            cell = dec["text"]
        elif field in row and field != "_row":
            cell = row[field]
        else:
            return cit, f"field {field!r} not in row {n} of {rid}"
        how = value_matches(cell, value) if field != "decoded" else (
            "partial" if str(value).casefold() in str(cell).casefold() and str(value).strip()
            else None)
        if how is None:
            return cit, f"value {value!r} not found in {rid} row {n} field {field!r} " \
                        f"(row has {str(cell)[:80]!r})"
        return cit, ""

    async def op_record_finding(self, params: dict[str, Any], conf: Any = None) -> Any:
        kind, confidence = params.get("kind"), params.get("confidence")
        text = str(params.get("text") or "").strip()
        citations = list(params.get("citations") or [])
        attack = list(params.get("attack") or [])
        if kind not in KINDS or confidence not in CONFIDENCE or not text:
            raise ValueError(f"kind must be one of {KINDS}, confidence one of {CONFIDENCE}, "
                             "text non-empty")
        if len(citations) > MAX_CITATIONS:
            raise ValueError(f"at most {MAX_CITATIONS} citations")
        problems: list[str] = []
        checked, rows = [], []
        self._finding_ps = None
        for i, c in enumerate(citations, 1):
            cit, problem = self._check(c if isinstance(c, dict) else {})
            checked.append(cit)
            rows.append({"citation": i, **{k: cit[k] for k in ("result_id", "_row", "field")},
                         "value": str(cit["value"])[:200], "check": problem or "ok"})
            if problem:
                problems.append(f"citation {i}: {problem}")
        if not citations:
            problems.append("no citation: every statement must cite result_id + row + field + "
                            "value (EF-10)")
        known = known_attack_ids()
        for t in attack:
            if not ATTACK_RE.match(str(t)) or t not in known:
                problems.append(f"ATT&CK ID {t!r} is not provided by the server's rule table")
        n = sum(1 for e in audit.iter_events(self.cfg.audit_file) if e["type"] == "suggestion")
        fid = f"F-{n + 1:04d}"
        status = "rejected_by_server" if problems else "à valider"
        if self._finding_ps is not None:  # the journal keeps real values (L2 §9.6)
            text = self._finding_ps.restore(text)
        ev = audit.append(self.cfg.audit_file, "suggestion", self.actor, finding_id=fid,
                          kind=kind, text=text, citations=checked, confidence=confidence,
                          attack=[str(t) for t in attack if ATTACK_RE.match(str(t))],
                          cross_check={"status": "failed" if problems else "passed",
                                       "mismatches": problems}, status=status)
        summary = (f"{fid} REJECTED by the cross-check: {'; '.join(problems)}" if problems else
                   f"{fid} recorded ({kind}, confidence {confidence}): à valider by an analyst")
        out = self._listing("record_finding", params, rows, summary)
        out.payload["notes"] = [f"suggestion journaled as audit_id {ev['audit_id']}"] + problems
        out.audit_extra = {"finding_id": fid, "finding_status": status}
        return out

    def findings(self) -> list[dict[str, Any]]:
        """All findings with their current status (see load_findings)."""
        return load_findings(self.cfg.audit_file)

    async def op_list_findings(self, params: dict[str, Any], conf: Any = None) -> Any:
        items = [f for f in self.findings()
                 if params.get("status") in (None, f["status"])
                 and params.get("kind") in (None, f["kind"])]
        pending = sum(1 for f in items if f["status"] == "à valider")
        return self._listing("list_findings", params, items,
                             f"{len(items)} findings, {pending} à valider")
