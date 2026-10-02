"""Crisis assistant (P6, task 6.1): crisis timeline (EF-12), sitrep draft (EF-13), containment
suggestions (EF-14). The stakeholder board (EF-15, C) is not built (Gantt: dropped).

- crisis_add_event journals a `crisis_event` (C-NNNN): UTC time with an explicit offset, kind
  event / decision / action, owner, source. A source that names a finding, an audit_id or a
  result is checked to exist (source_ref); anything else is kept as free text.
- crisis_timeline lists the events in UTC order (journal = single source of truth).
- sitrep_draft fills templates/sitrep.md from VALIDATED findings and the crisis timeline only;
  the server writes it (deterministic), a person reviews it before it is sent.
- containment_suggestions returns rules/containment.yaml for one incident type: suggestions,
  always "à valider", never executed (no tool acts on the infrastructure).
"""
from __future__ import annotations

import json
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from . import audit, results, safety
from .findings_ops import BLOCKING, STATUS_LABEL, load_findings
from .redact import case_for, pseudonymizer_for
from .timeline import iso, to_utc

ROOT = Path(__file__).resolve().parents[2]
CONTAINMENT = ROOT / "rules" / "containment.yaml"
TEMPLATE = ROOT / "templates" / "sitrep.md"
KINDS = ("event", "decision", "action")
KIND_LABEL = {"event": "Événement", "decision": "Décision", "action": "Action"}
AUDIENCES = ("direction", "technique", "juridique", "communication")
SECTIONS = ("situation", "impact", "actions", "prochaines_etapes", "decisions_attendues")
EXPLICIT_TZ = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")
FINDING_RE = re.compile(r"\bF-\d{4,}\b")
AUDIT_RE = re.compile(r"\baudit(?:_id)?[ :#=]*(\d+)\b", re.I)
RESULT_RE = re.compile(r"\b\d{8}-\d{6}-[A-Za-z0-9._-]+-[0-9a-f]{6}\b")
NONE = "Rien à signaler à ce stade."


@lru_cache(maxsize=None)
def containment() -> dict[str, Any]:
    return yaml.safe_load(CONTAINMENT.read_text(encoding="utf-8"))


def _text(v: Any, name: str, lo: int, hi: int) -> str:
    s = str(v or "").strip()
    if not lo <= len(s) <= hi:
        raise ValueError(f"{name} must be {lo}-{hi} characters")
    return s


class CrisisOps:
    """Mixed into ops.Engine (uses cfg, actor, _listing)."""

    def _crisis_policy(self, case: str) -> tuple[str, Any]:
        case = str(case or "").strip().strip("/")
        d = safety.jail_path(case or ".", self.cfg.evidence_root)
        if case and not d.is_dir():
            raise ValueError(f"case must be a folder under the evidence root: {case!r}")
        return case, pseudonymizer_for(self.cfg, case_for(self.cfg, d / "case.toml"))

    def crisis_events(self, case: str | None = None) -> list[dict[str, Any]]:
        evs = [e for e in audit.iter_events(self.cfg.audit_file) if e["type"] == "crisis_event"
               and (not case or e.get("case") == case)]
        return sorted(evs, key=lambda e: (e["time_utc"], e["audit_id"]))

    def _source_ref(self, source: str) -> dict[str, Any]:
        """Check the references a source names; unknown ones are refused (no invented ID)."""
        refs: dict[str, Any] = {}
        fids = FINDING_RE.findall(source)
        if fids:
            known = {f["finding_id"] for f in load_findings(self.cfg.audit_file)}
            missing = [f for f in fids if f not in known]
            if missing:
                raise ValueError(f"source names unknown finding(s) {missing}")
            refs["findings"] = fids
        aids = [int(a) for a in AUDIT_RE.findall(source)]
        if aids:
            last = sum(1 for _ in audit.iter_events(self.cfg.audit_file))
            if any(not 1 <= a <= last for a in aids):
                raise ValueError(f"source names an audit_id outside 1..{last}")
            refs["audit_ids"] = aids
        rids = RESULT_RE.findall(source)
        for rid in rids:
            results.result_dir(self.cfg.output_root, rid)  # FileNotFoundError if unknown
        if rids:
            refs["results"] = rids
        return refs

    async def op_crisis_add_event(self, params: dict[str, Any], conf: Any = None) -> Any:
        case, ps = self._crisis_policy(params.get("case"))
        raw_time = str(params.get("time_utc") or "").strip()
        when = to_utc(raw_time)
        if when is None or not EXPLICIT_TZ.search(raw_time):
            raise ValueError("time_utc must be ISO-8601 with an explicit offset, e.g. "
                             "2026-10-06T14:32:07Z (no local time without offset)")
        if when.timestamp() > time.time() + 300:
            raise ValueError("time_utc is in the future")
        kind = params.get("kind")
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        fields = {"description": _text(params.get("description"), "description", 3, 1000),
                  "owner": _text(params.get("owner"), "owner", 2, 120),
                  "source": _text(params.get("source"), "source", 2, 300)}
        if ps is not None:  # tokens typed in cloud mode -> real values in the journal
            fields = {k: ps.restore(v) for k, v in fields.items()}
        refs = self._source_ref(fields["source"])
        n = sum(1 for e in audit.iter_events(self.cfg.audit_file) if e["type"] == "crisis_event")
        cid = f"C-{n + 1:04d}"
        ev = audit.append(self.cfg.audit_file, "crisis_event", self.actor, crisis_id=cid,
                          time_utc=iso(when), kind=kind, **fields, source_ref=refs,
                          **({"case": case} if case else {}))
        row = {"crisis_id": cid, "time_utc": iso(when), "kind": kind, **fields,
               "source_checked": ", ".join(f"{k}: {v}" for k, v in refs.items()) or "texte libre",
               "audit_id": ev["audit_id"]}
        out = self._listing("crisis_add_event", params, [row],
                            f"{cid} ajouté à la chronologie de crise ({KIND_LABEL[kind]}, "
                            f"{iso(when)})")
        out.pseudo = ps
        out.payload["notes"] = [f"crisis_event journaled as audit_id {ev['audit_id']}"]
        out.audit_extra = {"crisis_id": cid}
        return out

    async def op_crisis_timeline(self, params: dict[str, Any], conf: Any = None) -> Any:
        case, ps = self._crisis_policy(params.get("case"))
        kind = params.get("kind")
        if kind is not None and kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        items = [{"crisis_id": e.get("crisis_id"), "time_utc": e["time_utc"], "kind": e["kind"],
                  "description": e["description"], "owner": e["owner"], "source": e["source"],
                  "case": e.get("case"), "recorded_utc": e["ts_utc"], "audit_id": e["audit_id"]}
                 for e in self.crisis_events(case or None) if kind in (None, e["kind"])]
        span = f" du {items[0]['time_utc']} au {items[-1]['time_utc']}" if items else ""
        out = self._listing("crisis_timeline", params, items,
                            f"{len(items)} entrées de chronologie de crise{span}")
        out.pseudo = ps
        return out

    # ---- sitrep (EF-13) -------------------------------------------------------------------
    def _sitrep_sections(self, audience: str, events: list[dict[str, Any]],
                         findings: list[dict[str, Any]]) -> dict[str, str]:
        tech = audience == "technique"
        validated = [f for f in findings if f["status"] == STATUS_LABEL["validated"]]
        pending = [f for f in findings if f["status"] in BLOCKING]

        def cite(f: dict[str, Any]) -> str:
            base = f"{f['finding_id']}, validé par {f['decided_by']}"
            if tech:
                base += f" ; sources {f['citations']}" + (f" ; ATT&CK {f['attack']}"
                                                          if f["attack"] else "")
            return base

        def bullets(fs: list[dict[str, Any]], limit: int | None = None) -> str:
            shown = fs if limit is None else fs[-limit:]
            more = len(fs) - len(shown)
            lines = [f"- {f['text']} ({cite(f)})" for f in shown]
            if more:
                lines.append(f"- … et {more} autre(s) constat(s) validé(s) (voir le rapport).")
            return "\n".join(lines)

        facts = [f for f in validated if f["kind"] in ("fact", "observation")]
        hyps = [f for f in validated if f["kind"] == "hypothesis"]
        recos = [f for f in validated if f["kind"] == "recommendation"]
        evs = [e for e in events if e["kind"] == "event"]
        situation = []
        if events:
            situation.append(f"Chronologie de crise : {len(events)} entrées, du "
                             f"{events[0]['time_utc']} au {events[-1]['time_utc']} (UTC).")
            if evs:
                last = evs[-1]
                situation.append(f"Dernier événement : {last['time_utc']} — "
                                 f"{last['description']} ({last['owner']}).")
        if facts:
            situation += ["", "Faits établis (validés par un analyste) :",
                          bullets(facts, None if tech else 5)]
        if hyps:
            situation += ["", "Hypothèses retenues (validées comme hypothèses, non prouvées) :",
                          bullets(hyps, None if tech else 3)]
        cases = sorted({e["case"] for e in events if e.get("case")})
        impact = [f"Périmètre cité dans la chronologie : {', '.join(cases)}." if cases else
                  "Périmètre : aucun hôte nommé dans la chronologie de crise.",
                  "À compléter par le responsable de crise : services et métiers touchés, données "
                  "concernées, gravité. Le serveur ne qualifie pas l'impact."]
        acts = [f"- {e['time_utc']} — {KIND_LABEL[e['kind']]} : {e['description']} "
                f"(responsable : {e['owner']}" + (f" ; source : {e['source']}" if tech else "")
                + ")" for e in events if e["kind"] in ("action", "decision")]
        nxt = [f"- {f['text']} ({cite(f)})" for f in recos]
        dec = []
        if pending:
            dec.append(f"- Validation par un analyste de {len(pending)} constat(s) en attente "
                       f"({', '.join(f['finding_id'] for f in pending[:10])}) : non repris dans "
                       "ce point.")
        dec.append("- À compléter : décisions demandées à l'audience (confinement, "
                   "communication, notification, dépôt de plainte).")
        return {"situation": "\n".join(situation) or NONE, "impact": "\n".join(impact),
                "actions": "\n".join(acts) or NONE, "prochaines_etapes": "\n".join(nxt) or NONE,
                "decisions_attendues": "\n".join(dec)}

    async def op_sitrep_draft(self, params: dict[str, Any], conf: Any = None) -> Any:
        t0 = time.monotonic()
        audience = params.get("audience")
        if audience not in AUDIENCES:
            raise ValueError(f"audience must be one of {AUDIENCES}")
        case, ps = self._crisis_policy(params.get("case"))
        title = str(params.get("title") or "").strip()[:120] or (
            f"incident {case}" if case else "incident en cours")
        events = self.crisis_events(case or None)
        findings = load_findings(self.cfg.audit_file)
        sec = self._sitrep_sections(audience, events, findings)
        head = audit.verify_report(self.cfg.audit_file)
        n_val = sum(1 for f in findings if f["status"] == STATUS_LABEL["validated"])
        sources = (f"{len(events)} entrées de chronologie de crise, {n_val} constats validés ; "
                   f"journal d'audit {head['lines']} lignes")
        pied = ("Rédigé automatiquement à partir des seuls constats validés et de la chronologie "
                "de crise ; aucune mesure n'a été exécutée par l'assistant.")
        if audience == "juridique":
            pied += (f" Chaîne de preuve : hash de tête du journal `{head['head_hash']}`, "
                     f"chaîne vérifiée : {'oui' if head['ok'] else 'NON'}.")
        text = TEMPLATE.read_text(encoding="utf-8")
        for k, v in {"titre": title, "genere_utc": audit.utc_now(), "audience": audience,
                     "sources": sources, "pied": pied, **sec}.items():
            text = text.replace("{{" + k + "}}", v)
        missing = [s for s in SECTIONS if "{{" + s + "}}" in text]
        if missing or "{{" in text:
            raise ValueError(f"sitrep template not fully filled: {missing}")
        rid, d = results.new_result(self.cfg.output_root, "sitrep")
        (d / "sitrep.md").write_text(text, encoding="utf-8")
        items = [{"section": s, "contenu": sec[s]} for s in SECTIONS]
        (d / "rows.jsonl").write_text("".join(json.dumps(i, ensure_ascii=False) + "\n"
                                              for i in items), encoding="utf-8")
        elapsed = round(time.monotonic() - t0, 3)
        results.write_meta(d, tool="sitrep_draft", plugin="sitrep", argv=[], input_path=None,
                           audience=audience, head_hash=head["head_hash"], row_count=len(items),
                           sitrep_sha256=results.sha256_file(d / "sitrep.md"),
                           generation_s=elapsed, exit_code=0)
        out = self._listing("sitrep_draft", params, items,
                            f"Brouillon de sitrep ({audience}) : 5 sections, {len(events)} "
                            f"entrées de crise, {n_val} constats validés, généré en {elapsed} s")
        out.result_id = out.payload["result_id"] = rid
        out.payload["raw_output"] = {"container": f"/output/{rid}/",
                                     "host": f"<OUTPUT_DIR>/{rid}/"}
        out.payload["notes"] = [f"sitrep: /output/{rid}/sitrep.md",
                                "BROUILLON : à relire et compléter (impact, décisions) par le "
                                "responsable de crise avant diffusion."]
        out.pseudo = ps
        out.audit_extra = {"sitrep_sha256": results.sha256_file(d / "sitrep.md"),
                           "head_hash": head["head_hash"]}
        return out

    # ---- containment (EF-14) --------------------------------------------------------------
    async def op_containment_suggestions(self, params: dict[str, Any], conf: Any = None) -> Any:
        data = containment()
        itype = params.get("incident_type")
        if itype not in data["incident_types"]:
            raise ValueError(f"incident_type must be one of {sorted(data['incident_types'])}")
        spec = data["incident_types"][itype]
        items = [{"id": a["id"], "mesure": a["action"], "but": a["but"],
                  "precautions": a["precautions"], "responsable": a["responsable"],
                  "portee": "commune" if a in data["common"] else spec["label"],
                  "statut": "suggestion à valider — jamais exécutée par l'assistant"}
                 for a in [*data["common"], *spec["actions"]]]
        out = self._listing("containment_suggestions", params, items,
                            f"{len(items)} mesures proposées ({spec['label']}), toutes à valider "
                            "par la cellule de crise")
        out.payload["notes"] = [
            "Suggestions only: no tool of this server acts on the infrastructure. A measure "
            "decided by the crisis cell is recorded with crisis_add_event(kind='decision'), then "
            "kind='action' once an owner has done it."]
        return out
