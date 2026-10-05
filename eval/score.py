"""Score one investigation session against the ground truth (P7, livrable L6; CDC §6).

Reads eval/ground_truth.yaml (schema eval/ground_truth.schema.json) and the audit journal of a
session (window of audit_ids or UTC times), then computes:
  - tools: expected server tools (from the expected facts) actually called with outcome "ok";
  - facts: expected facts found by an ACCEPTED finding whose citation matches the fact (tool
    that produced the cited result, evidence path, field, value; result_id/row when given);
    whether that finding was then validated by an analyst; precision of the fact findings;
  - IOCs and steps found;
  - citations: valid / invalid (re-checked by record_finding when the finding was recorded);
  - hallucinations: findings rejected by the server cross-check, with their reasons;
  - findings by current status (à valider / validé / rejeté / à revoir / rejeté par le serveur);
  - times: session start -> first finding, first validation, first sitrep (objective O4);
  - documentation completeness (6.3): checklist steps done (server's own checklist logic run
    on the journal up to the session end), accepted findings cited and validated, sitrep
    sections filled vs still "à compléter" (last sitrep of the session, read from its result).
Nothing is estimated: a metric that cannot be computed is null with the reason ("À MESURER").
Output: JSON (--json) and a French Markdown table (stdout or --markdown).

Run inside the container:
  docker compose exec forensic python eval/score.py --journal /output/audit.jsonl \
      --from-audit-id 120 --json /output/score_session1.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from forensic_mcp import audit
from forensic_mcp.checklist_ops import NOT_IN_JOURNAL, evaluate
from forensic_mcp.findings_ops import STATUS_LABEL, value_matches

HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "ground_truth.schema.json"
TODO = "À MESURER"
TO_COMPLETE = re.compile(r"à compléter", re.I)
NOTHING = "Rien à signaler à ce stade."
SECTION = re.compile(r"^## (\d+)\. (.+)$", re.M)


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _seconds(a: str | None, b: str | None) -> float | None:
    return round((_ts(b) - _ts(a)).total_seconds(), 1) if a and b else None


def load_ground_truth(path: Path) -> dict[str, Any]:
    gt = yaml.safe_load(path.read_text(encoding="utf-8"))
    errors = [e.message for e in jsonschema.Draft202012Validator(
        json.loads(SCHEMA.read_text(encoding="utf-8"))).iter_errors(gt)]
    if errors:
        raise ValueError(f"ground truth does not match its schema: {errors[:5]}")
    return gt


def window(events: list[dict[str, Any]], from_id: int | None = None, to_id: int | None = None,
           since: str | None = None, until: str | None = None) -> list[dict[str, Any]]:
    """The events of one session (inclusive bounds)."""
    return [e for e in events
            if (from_id is None or e["audit_id"] >= from_id)
            and (to_id is None or e["audit_id"] <= to_id)
            and (since is None or _ts(e["ts_utc"]) >= _ts(since))
            and (until is None or _ts(e["ts_utc"]) <= _ts(until))]


def _current_status(all_events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """finding_id -> {status, decided_by} from the WHOLE journal (validation may come later)."""
    out: dict[str, dict[str, Any]] = {}
    for e in all_events:
        if e["type"] == "suggestion":
            out[e["finding_id"]] = {"status": STATUS_LABEL[e["status"]], "decided_by": None}
        elif e["type"] == "validation" and e.get("finding_id") in out:
            out[e["finding_id"]].update(status=STATUS_LABEL[e["decision"]],
                                        decided_by=e["actor"].get("name"))
    return out


def _cites_fact(c: dict[str, Any], producer: dict[str, Any] | None, fact: dict[str, Any]) -> bool:
    if producer is None or producer.get("tool") != fact["tool"]:
        return False
    path = fact.get("evidence_path")
    if path:
        where = (producer.get("params") or {}).get(
            "case" if producer["tool"] == "timeline" else "path")
        if str(where or "").strip("/") != path.strip("/"):
            return False
    if fact.get("result_id") and c["result_id"] != fact["result_id"]:
        return False
    if fact.get("row") and c["_row"] != fact["row"]:
        return False
    if fact.get("field") and c["field"] != fact["field"]:
        return False
    if fact.get("value") is not None:
        if c["field"] == "decoded":
            return str(fact["value"]).casefold() in str(c["value"]).casefold()
        return value_matches(c["value"], fact["value"]) is not None
    return True


def _journal_rel_source(events: list[dict[str, Any]]) -> Any:
    """Evidence-relative path of a tool input, from the journal only: "@<result_id>/x" is
    mapped to the input of the call that produced that extraction."""
    producers: dict[str, dict[str, Any]] = {}
    for e in events:
        if e["type"] == "tool_call" and e.get("result_id") and e["result_id"] not in producers:
            producers[e["result_id"]] = e

    def rel(path: str, depth: int = 0) -> str | None:
        if not path.startswith("@"):
            return path.strip("/")
        prod = producers.get(path[1:].split("/", 1)[0])
        src = (prod.get("params") or {}).get("path") if prod else None
        return rel(str(src), depth + 1) if src and depth < 5 else None
    return rel


def _sitrep_sections(text: str) -> list[tuple[str, str]]:
    """(title, content) of each "## N. Title" section; the footer after "---" is dropped."""
    parts = SECTION.split(text)
    out = []
    for i in range(1, len(parts) - 2, 3):
        body = parts[i + 2].split("\n---", 1)[0].strip()
        out.append((f"{parts[i]}. {parts[i + 1].strip()}", body))
    return out


def completeness(session: list[dict[str, Any]], all_events: list[dict[str, Any]], case: str,
                 status: dict[str, dict[str, Any]], output_root: Path | None) -> dict[str, Any]:
    """Documentation completeness (6.3), computed from the journal (and the sitrep result the
    journal points to). Nothing is estimated: what cannot be read is reported as such."""
    end = session[-1]["audit_id"]
    upto = [e for e in all_events if e["audit_id"] <= end]
    rows, _ = evaluate(upto, case, None, _journal_rel_source(upto))
    measurable = [r for r in rows if r["statut"] != NOT_IN_JOURNAL]
    done = [r for r in measurable if r["statut"] == "fait"]
    out: dict[str, Any] = {"checklist": {
        "case": case, "steps": len(rows), "measurable": len(measurable), "done": len(done),
        "rate": round(len(done) / len(measurable), 3) if measurable else None,
        "to_do": [r["id"] for r in measurable if r["statut"] != "fait"],
        "not_measurable": [r["id"] for r in rows if r["statut"] == NOT_IN_JOURNAL]}}

    accepted = [e for e in session if e["type"] == "suggestion"
                and e["status"] != "rejected_by_server"]
    st = [status[e["finding_id"]]["status"] for e in accepted]
    out["findings"] = {
        "accepted": len(accepted),
        "cited": sum(1 for e in accepted if e["citations"]),
        "validated": st.count(STATUS_LABEL["validated"]),
        "pending": sum(1 for s in st if s in ("à valider", "à revoir")),
        "rejected_by_analyst": st.count(STATUS_LABEL["rejected"]),
        "validated_rate": round(st.count(STATUS_LABEL["validated"]) / len(accepted), 3)
        if accepted else None}

    call = next((e for e in reversed(session) if e["type"] == "tool_call"
                 and e["tool"] == "sitrep_draft" and e.get("outcome") == "ok"), None)
    f = (Path(output_root) / call["result_id"] / "sitrep.md") if call and output_root else None
    if call is None:
        out["sitrep"] = f"{TODO} : aucun sitrep_draft réussi dans la session"
    elif f is None or not f.is_file():
        out["sitrep"] = f"{TODO} : sitrep.md de {call['result_id']} introuvable (dossier de sortie)"
    else:
        text = f.read_text(encoding="utf-8")
        secs = _sitrep_sections(text)
        todo = [title for title, body in secs if not body or TO_COMPLETE.search(body)]
        out["sitrep"] = {
            "result_id": call["result_id"], "audit_id": call["audit_id"],
            "audience": (call.get("params") or {}).get("audience"),
            "sections": len(secs), "filled": len(secs) - len(todo),
            "rate": round((len(secs) - len(todo)) / len(secs), 3) if secs else None,
            "to_complete": todo,
            "nothing_to_report": [title for title, body in secs if body == NOTHING],
            "edited_after_generation": hashlib.sha256(f.read_bytes()).hexdigest()
            != call.get("sitrep_sha256")}
    return out


def score(gt: dict[str, Any], session: list[dict[str, Any]],
          all_events: list[dict[str, Any]] | None = None, output_root: Path | None = None,
          case: str | None = None) -> dict[str, Any]:
    all_events = all_events if all_events is not None else session
    calls = [e for e in session if e["type"] == "tool_call"]
    producers: dict[str, dict[str, Any]] = {}
    for e in all_events:  # the call that produced each result (may precede the window)
        if e["type"] == "tool_call" and e.get("result_id") and e["result_id"] not in producers:
            producers[e["result_id"]] = e
    status = _current_status(all_events)
    sugg = [e for e in session if e["type"] == "suggestion"]
    accepted = [e for e in sugg if e["status"] != "rejected_by_server"]
    rejected = [e for e in sugg if e["status"] == "rejected_by_server"]
    filled = gt.get("status") == "filled"

    # findings, citations, hallucinations (computable without a filled ground truth)
    n_cit = sum(len(e["citations"]) for e in sugg)
    bad_cit = sum(1 for e in sugg for m in e["cross_check"].get("mismatches", [])
                  if m.startswith("citation "))
    by_status: dict[str, int] = {}
    for e in sugg:
        s = status[e["finding_id"]]["status"]
        by_status[s] = by_status.get(s, 0) + 1
    out: dict[str, Any] = {
        "case": gt.get("case"), "ground_truth_status": gt.get("status"),
        "session": {"from_audit_id": session[0]["audit_id"] if session else None,
                    "to_audit_id": session[-1]["audit_id"] if session else None,
                    "start_utc": session[0]["ts_utc"] if session else None,
                    "end_utc": session[-1]["ts_utc"] if session else None,
                    "tool_calls": len(calls),
                    "tool_calls_not_ok": sum(1 for e in calls if e.get("outcome") != "ok")},
        "findings": {"total": len(sugg), "accepted_by_server": len(accepted),
                     "by_status": by_status},
        "citations": {"total": n_cit, "valid": n_cit - bad_cit, "invalid": bad_cit,
                      "valid_rate": round((n_cit - bad_cit) / n_cit, 3) if n_cit else None},
        "hallucinations": {"rejected_findings": len(rejected),
                           "rate": round(len(rejected) / len(sugg), 3) if sugg else None,
                           "reasons": [{"finding_id": e["finding_id"],
                                        "reasons": e["cross_check"].get("mismatches", [])}
                                       for e in rejected]},
    }
    if session:
        out["completeness"] = completeness(
            session, all_events, (case if case is not None else gt.get("case")) or "", status,
            output_root)

    # times (O4: start -> first sitrep)
    first = {t: next((e["ts_utc"] for e in session if pred(e)), None) for t, pred in {
        "finding": lambda e: e["type"] == "suggestion" and e["status"] != "rejected_by_server",
        "validation": lambda e: e["type"] == "validation",
        "sitrep": lambda e: e["type"] == "tool_call" and e["tool"] == "sitrep_draft"
        and e.get("outcome") == "ok"}.items()}
    start = out["session"]["start_utc"]
    out["times_s"] = {"to_first_finding": _seconds(start, first["finding"]),
                      "to_first_validation": _seconds(start, first["validation"]),
                      "to_first_sitrep": _seconds(start, first["sitrep"]),
                      "session_duration": _seconds(start, out["session"]["end_utc"])}

    if not filled:  # never score against an empty template
        reason = f"{TODO} : vérité terrain non remplie (status: {gt.get('status')})"
        out.update(tools=reason, facts=reason, iocs=reason, steps=reason)
        return out

    expected_tools = sorted({f["tool"] for s in gt["steps"] for f in s["expected_facts"]})
    called = {e["tool"] for e in calls if e.get("outcome") == "ok"}
    out["tools"] = {"expected": expected_tools, "called_ok": sorted(called),
                    "missing": [t for t in expected_tools if t not in called],
                    "recall": round(len(set(expected_tools) & called) / len(expected_tools), 3)}

    # a fact is established by a fact / observation finding, not by a hypothesis or a
    # recommendation that happens to cite the same row
    fact_findings = [e for e in accepted if e["kind"] in ("fact", "observation")]
    facts, matched_findings = [], set()
    for s in gt["steps"]:
        for i, f in enumerate(s["expected_facts"], 1):
            hits = sorted({e["finding_id"] for e in fact_findings for c in e["citations"]
                           if _cites_fact(c, producers.get(c["result_id"]), f)})
            matched_findings |= set(hits)
            facts.append({"step": s["step"], "fact": i, "description": f["description"],
                          "tool": f["tool"], "found": bool(hits), "findings": hits,
                          "validated": any(status[h]["status"] == STATUS_LABEL["validated"]
                                           for h in hits)})
    n_found = sum(f["found"] for f in facts)
    out["facts"] = {
        "expected": len(facts), "found": n_found,
        "recall": round(n_found / len(facts), 3) if facts else None,
        "found_and_validated": sum(f["validated"] for f in facts),
        "precision": round(sum(e["finding_id"] in matched_findings for e in fact_findings)
                           / len(fact_findings), 3) if fact_findings else None,
        "detail": facts}

    texts = [(e["text"] + " " + " ".join(str(c["value"]) for c in e["citations"])).casefold()
             for e in accepted]
    iocs = [{"step": s["step"], **i, "found": any(i["value"].casefold() in t for t in texts)}
            for s in gt["steps"] for i in s["iocs"]]
    out["iocs"] = {"expected": len(iocs), "found": sum(i["found"] for i in iocs),
                   "recall": round(sum(i["found"] for i in iocs) / len(iocs), 3) if iocs else None,
                   "detail": iocs}
    steps = [{"step": s["step"], "cdc_step": s["cdc_step"],
              "found": any(f["found"] for f in facts if f["step"] == s["step"])}
             for s in gt["steps"]]
    out["steps"] = {"expected": len(steps), "found": sum(s["found"] for s in steps),
                    "recall": round(sum(s["found"] for s in steps) / len(steps), 3),
                    "detail": steps}
    return out


def _pct(v: Any) -> str:
    return TODO if v is None else f"{v * 100:.0f} %"


def render_markdown(r: dict[str, Any]) -> str:
    """French summary table for L6."""
    def cell(section: str, key: str, fmt=str) -> str:
        v = r.get(section)
        return v if isinstance(v, str) else (TODO if v is None or v.get(key) is None
                                             else fmt(v[key]))

    t = r["times_s"]
    rows = [
        ("Appels d'outils (dont en échec)",
         f"{r['session']['tool_calls']} ({r['session']['tool_calls_not_ok']})"),
        ("Outils attendus appelés (rappel)", cell("tools", "recall", _pct)),
        ("Outils attendus non appelés", cell("tools", "missing", lambda m: ", ".join(m) or "aucun")),
        ("Faits attendus retrouvés", cell("facts", "found") + " / " + cell("facts", "expected")
         if isinstance(r.get("facts"), dict) else cell("facts", "found")),
        ("Rappel des faits (objectif O2 ≥ 80 %)", cell("facts", "recall", _pct)),
        ("Faits retrouvés puis validés par l'analyste", cell("facts", "found_and_validated")),
        ("Précision des constats de type fait", cell("facts", "precision", _pct)),
        ("Rappel des IOC", cell("iocs", "recall", _pct)),
        ("Étapes du scénario retrouvées", cell("steps", "recall", _pct)),
        ("Constats enregistrés / acceptés par le serveur",
         f"{r['findings']['total']} / {r['findings']['accepted_by_server']}"),
        ("Constats par statut", ", ".join(f"{k} : {v}" for k, v in
                                          sorted(r["findings"]["by_status"].items())) or "aucun"),
        ("Citations valides", f"{r['citations']['valid']} / {r['citations']['total']} "
                              f"({_pct(r['citations']['valid_rate'])})"),
        ("Hallucinations (constats rejetés par le serveur)",
         f"{r['hallucinations']['rejected_findings']} ({_pct(r['hallucinations']['rate'])})"),
        ("Délai jusqu'au premier constat (s)", t["to_first_finding"] or TODO),
        ("Délai jusqu'à la première validation (s)", t["to_first_validation"] or TODO),
        ("Délai jusqu'au premier sitrep (s, objectif O4 < 600)", t["to_first_sitrep"] or TODO),
        ("Durée de la session (s)", t["session_duration"] or TODO),
    ]
    c = r.get("completeness") or {}
    if c:
        ck, fd, sr = c["checklist"], c["findings"], c["sitrep"]
        rows += [
            ("Complétude — étapes de la checklist faites (mesurables depuis le journal)",
             f"{ck['done']} / {ck['measurable']} ({_pct(ck['rate'])})"
             + (f" ; non mesurable : {', '.join(ck['not_measurable'])}"
                if ck["not_measurable"] else "")),
            ("Complétude — constats acceptés : cités / validés par l'analyste",
             f"{fd['cited']} / {fd['validated']} sur {fd['accepted']} "
             f"({_pct(fd['validated_rate'])} validés)"),
            ("Complétude — sections du sitrep renseignées (sans « à compléter »)",
             sr if isinstance(sr, str) else
             f"{sr['filled']} / {sr['sections']} ({_pct(sr['rate'])})"
             + (f" ; à compléter : {', '.join(sr['to_complete'])}" if sr["to_complete"] else "")
             + (" ; modifié après génération" if sr["edited_after_generation"] else "")),
        ]
    head = (f"Session du cas {r['case']} — journal audit_id {r['session']['from_audit_id']} à "
            f"{r['session']['to_audit_id']} ({r['session']['start_utc']} → "
            f"{r['session']['end_utc']}) ; vérité terrain : {r['ground_truth_status']}.")
    return "\n".join([head, "", "| Mesure | Valeur |", "|---|---|",
                      *[f"| {a} | {b} |" for a, b in rows]])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score a session against the ground truth (P7).")
    ap.add_argument("--ground-truth", type=Path, default=HERE / "ground_truth.yaml")
    ap.add_argument("--journal", type=Path, default=Path("/output/audit.jsonl"))
    ap.add_argument("--from-audit-id", type=int)
    ap.add_argument("--to-audit-id", type=int)
    ap.add_argument("--since", help="UTC ISO-8601, e.g. 2026-10-15T09:00:00Z")
    ap.add_argument("--until")
    ap.add_argument("--output-root", type=Path,
                    help="results folder holding the sitrep (default: the journal's folder)")
    ap.add_argument("--case", help="checklist case folder (default: the ground truth's case)")
    ap.add_argument("--json", type=Path, help="write the JSON result here")
    ap.add_argument("--markdown", type=Path, help="write the French table here (else stdout)")
    a = ap.parse_args(argv)
    try:
        gt = load_ground_truth(a.ground_truth)
        rep = audit.verify_report(a.journal)
        if not rep["ok"]:
            raise ValueError(f"journal chain broken: {rep['reason']}")
        events = list(audit.iter_events(a.journal))
    except (ValueError, OSError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    session = window(events, a.from_audit_id, a.to_audit_id, a.since, a.until)
    if not session:
        print("refused: no journal event in this window", file=sys.stderr)
        return 2
    result = score(gt, session, events, a.output_root or a.journal.parent, a.case)
    result["journal"] = {"path": str(a.journal), "lines": rep["lines"],
                         "head_hash": rep["head_hash"]}
    if a.json:
        a.json.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    md = render_markdown(result)
    if a.markdown:
        a.markdown.write_text(md + "\n", encoding="utf-8")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
