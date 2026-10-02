"""report_export (CDC §5 traceability, chain of evidence, over-confidence; deliverable in French).

Draft (final=false): every finding accepted by the cross-check, pending ones marked
« NON VALIDÉ ». Final (final=true): refused while a finding is « à valider » or « à revoir »
(the blocking ones are listed), refused if the journal chain is broken or an evidence file
changed; contains only analyst-validated findings, re-hashes the evidence (« après », journaled)
and writes the journal head hash. Each citation carries its provenance: result, row, field,
value, tool, command line, version, evidence SHA-256, audit ids.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import audit, evidence, results, safety
from .findings_ops import BLOCKING, STATUS_LABEL, load_findings


def _md(s: Any) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


class ReportOps:
    """Mixed into ops.Engine (uses cfg, actor, _listing)."""

    def _provenance(self) -> dict[str, dict[str, Any]]:
        calls = {}
        for e in audit.iter_events(self.cfg.audit_file):
            if e["type"] == "tool_call" and e.get("result_id") and e.get("outcome") == "ok":
                calls.setdefault(e["result_id"], e)
        return calls

    def _evidence_after(self, paths: set[str], final: bool) -> tuple[list[dict], list[str]]:
        rows, changed = [], []
        reg = evidence.load_registry(self.cfg)
        for p in sorted(paths):
            entries = [(k, v) for k, v in reg.items() if k == p or k.startswith(p.rstrip("/") + "/")]
            for key, rec in entries:
                row = {"path": key, "sha256_registration": rec["sha256"], "sha256_export": None,
                       "matches": None}
                if final:
                    target = safety.jail_input(key, self.cfg.evidence_root, self.cfg.output_root)
                    r = evidence.verify_full(self.cfg, target, self.actor, stage="after")
                    row.update(sha256_export=r["sha256_now"], matches=r["matches_registration"])
                    if not r["matches_registration"]:
                        changed.append(key)
                rows.append(row)
        return rows, changed

    async def op_report_export(self, params: dict[str, Any], conf: Any = None) -> Any:
        final = bool(params.get("final"))
        title = str(params.get("title") or "Rapport d'investigation").strip()[:120]
        fs = [f for f in load_findings(self.cfg.audit_file, with_citations=True)
              if f["status"] != STATUS_LABEL["rejected_by_server"]]
        blocking = [f for f in fs if f["status"] in BLOCKING]
        if final and blocking:
            raise safety.SafetyError(
                "export final refusé : " + ", ".join(f"{f['finding_id']} ({f['status']})"
                                                     for f in blocking)
                + ". Un analyste doit les valider ou les rejeter hors bande : "
                "docker exec -it forensic-mcp python -m forensic_mcp validate")
        chain = audit.verify_report(self.cfg.audit_file)
        if final and not chain["ok"]:
            raise safety.SafetyError(f"export final refusé : journal altéré ({chain['reason']})")
        calls = self._provenance()
        shown = [f for f in fs if f["status"] == STATUS_LABEL["validated"]] if final else fs
        sources = set()
        for f in shown:
            for c in f["citation_list"]:
                call = calls.get(c["result_id"], {})
                meta = results.read_meta(Path(self.cfg.output_root) / c["result_id"])
                src = meta.get("input_path")
                if src:
                    try:
                        sources.add(evidence.relpath(self.cfg, Path(src)))
                    except ValueError:
                        pass
                c["provenance"] = {"tool": call.get("tool"), "engine": call.get("engine"),
                                   "argv": " ".join(str(a) for a in call.get("argv") or []),
                                   "evidence_sha256": call.get("evidence_sha256"),
                                   "tool_call_audit_id": call.get("audit_id")}
        ev_rows, changed = self._evidence_after(sources, final)
        if changed:
            raise safety.SafetyError(f"export final refusé : preuve modifiée depuis "
                                     f"l'enregistrement : {', '.join(changed)}")
        head = audit.verify_report(self.cfg.audit_file)  # after the "after" hashes
        rid, d = results.new_result(self.cfg.output_root, "report")
        text = self._markdown(title, final, head, shown, fs, ev_rows)
        (d / "report.md").write_text(text, encoding="utf-8")
        items = [{"finding_id": f["finding_id"], "status": f["status"], "kind": f["kind"],
                  "text": f["text"][:200]} for f in shown]
        (d / "rows.jsonl").write_text("".join(json.dumps(i, ensure_ascii=False) + "\n"
                                              for i in items), encoding="utf-8")
        results.write_meta(d, tool="report_export", plugin="report", argv=[], input_path=None,
                           final=final, head_hash=head["head_hash"], row_count=len(items),
                           report_sha256=results.sha256_file(d / "report.md"), exit_code=0)
        out = self._listing("report_export", params, items,
                            f"{'Rapport FINAL' if final else 'Brouillon'} : {len(items)} constats, "
                            f"{len(blocking)} non validés ; journal {head['lines']} lignes, "
                            f"hash de tête {head['head_hash'][:16]}…")
        out.result_id = out.payload["result_id"] = rid
        out.payload["raw_output"] = {"container": f"/output/{rid}/",
                                     "host": f"<OUTPUT_DIR>/{rid}/"}
        out.payload["notes"] = [f"report: /output/{rid}/report.md",
                                f"journal head hash: {head['head_hash']}"] + (
            [f"NON VALIDÉ : {f['finding_id']} ({f['status']})" for f in blocking] if not final
            else [])
        out.audit_extra = {"report_sha256": results.sha256_file(d / "report.md"),
                           "head_hash": head["head_hash"], "final": final}
        return out

    def _markdown(self, title: str, final: bool, head: dict, shown: list[dict], allf: list[dict],
                  ev_rows: list[dict]) -> str:
        from .audit import utc_now

        mode = "FINAL" if final else "BROUILLON — contient des constats NON VALIDÉS"
        lines = [f"# {_md(title)} ({mode})", "",
                 f"- Généré le : {utc_now()} (UTC), par forensic-mcp",
                 f"- Journal d'audit : {head['lines']} lignes, chaîne vérifiée : "
                 f"{'oui' if head['ok'] else 'NON — ' + head['reason']}",
                 f"- Hash de tête du journal : `{head['head_hash']}` (à conserver hors du poste ; "
                 "l'appel d'export est journalisé ensuite)", "",
                 "## Preuves", "",
                 "| Preuve | SHA-256 à l'enregistrement | SHA-256 à l'export | Conforme |",
                 "|---|---|---|---|"]
        for r in ev_rows:
            ok = "—" if r["matches"] is None else ("oui" if r["matches"] else "NON")
            lines.append(f"| {_md(r['path'])} | `{r['sha256_registration']}` | "
                         f"`{r['sha256_export'] or 'non recalculé (brouillon)'}` | {ok} |")
        lines += ["", "## Constats", ""]
        for f in shown:
            status = ("**NON VALIDÉ** (" + f["status"] + ")") if f["status"] in BLOCKING else (
                f"{f['status']} par {f['decided_by']} le {f['decided_utc']} — motif : "
                f"{f['decision_reason']}")
            lines += [f"### {f['finding_id']} — {f['kind']} — confiance {f['confidence']}", "",
                      f"{f['text']}", "", f"- Statut : {status}",
                      f"- ATT&CK : {f['attack'] or '—'}",
                      f"- Suggestion journalisée : audit_id {f['audit_id']}", "",
                      "| Résultat | Ligne | Champ | Valeur | Outil | Commande | Empreinte preuve | audit_id |",
                      "|---|---|---|---|---|---|---|---|"]
            for c in f["citation_list"]:
                p = c.get("provenance", {})
                lines.append(f"| {_md(c['result_id'])} | {c['_row']} | {_md(c['field'])} | "
                             f"{_md(c['value'])} | {_md(p.get('engine') or p.get('tool'))} | "
                             f"`{_md(p.get('argv', ''))[:160]}` | `{p.get('evidence_sha256')}` | "
                             f"{p.get('tool_call_audit_id')} |")
            lines.append("")
        rejected = [f for f in allf if f["status"] == STATUS_LABEL["rejected"]]
        if rejected:
            lines += ["## Constats rejetés par l'analyste (conservés au journal)", ""]
            lines += [f"- {f['finding_id']} : {f['text'][:120]} — {f['decided_by']} : "
                      f"{f['decision_reason']}" for f in rejected]
            lines.append("")
        lines += ["## Limites", "",
                  "Constats produits avec l'aide d'un assistant IA. Chaque valeur citée a été "
                  "recontrôlée par le serveur dans la donnée brute ; l'interprétation reste celle "
                  "de l'analyste qui a validé. Les résultats bruts sont dans /output/<result_id>/.",
                  ""]
        return "\n".join(lines)
