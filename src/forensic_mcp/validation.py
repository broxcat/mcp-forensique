"""Out-of-band validation of findings by a named analyst (CDC §5: human validation,
over-confidence). NEVER an MCP tool: the model can neither validate nor reject. Reached only by
`docker exec -it forensic-mcp python -m forensic_mcp validate`, which requires an interactive
terminal. Each decision is a chained `validation` event (finding_id, decision, analyst, reason,
ts_utc); a rejected or re-opened finding is never deleted.

This module is not imported by the MCP server (checked by a test).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Callable

from . import audit, decode, results
from .config import Config
from .findings_ops import BLOCKING, STATUS_LABEL, _row, load_findings
from .ops import Engine

DECISIONS = {"v": "validated", "r": "rejected", "a": "to_review"}
NAME_RE = re.compile(r"^[^\x00-\x1f]{2,80}$")


class ValidationError(ValueError):
    """A decision that cannot be recorded."""


def decide(cfg: Config, finding_id: str, decision: str, analyst: str, reason: str,
           channel: str = "cli") -> dict[str, Any]:
    """Journal one analyst decision; returns {"audit_id", "hash", "ts_utc"}."""
    analyst, reason = analyst.strip(), reason.strip()
    if decision not in DECISIONS.values():
        raise ValidationError(f"decision must be one of {sorted(DECISIONS.values())}")
    if not NAME_RE.match(analyst):
        raise ValidationError("analyst name required (2-80 characters)")
    if not 3 <= len(reason) <= 500 or "\x00" in reason:
        raise ValidationError("reason required (3-500 characters)")
    f = next((x for x in load_findings(cfg.audit_file) if x["finding_id"] == finding_id), None)
    if f is None:
        raise ValidationError(f"unknown finding {finding_id!r}")
    if f["status"] == STATUS_LABEL["rejected_by_server"] and decision != "rejected":
        raise ValidationError(f"{finding_id} was rejected by the server cross-check: it can only "
                              "be rejected (with a reason), never validated or re-opened")
    return audit.append(cfg.audit_file, "validation",
                        {"kind": "analyst", "name": analyst, "client": channel},
                        finding_id=finding_id, decision=decision, comment=reason)


def recheck(cfg: Config, finding: dict[str, Any]) -> list[dict[str, Any]]:
    """Each citation with the value cited, the value now in the row and a fresh cross-check."""
    eng = Engine(cfg)
    out = []
    for c in finding.get("citation_list", []):
        _, problem = eng._check({"result_id": c["result_id"], "row": c["_row"],
                                 "field": c["field"], "value": c["value"]})
        current: Any = None
        try:
            row = _row(results.result_dir(cfg.output_root, c["result_id"]), c["_row"])
            if row is not None and c["field"] == "decoded":
                args = next((row[k] for k in ("Args", "CommandLine") if row.get(k)), "")
                dec = decode.decode_powershell(str(args))
                current = dec["text"] if dec else None
            elif row is not None:
                current = row.get(c["field"])
        except (ValueError, FileNotFoundError):
            current = None
        out.append({**c, "current": current, "check": problem or "ok"})
    return out


def run_cli(cfg: Config, ask: Callable[[str], str] = input,
            say: Callable[[str], None] = print,
            interactive: Callable[[], bool] = lambda: sys.stdin.isatty()) -> int:
    """Interactive menu: list pending findings, show citations re-checked, record decisions."""
    if not interactive():
        say("Refusé : la validation exige un terminal interactif "
            "(docker exec -it forensic-mcp python -m forensic_mcp validate). "
            "Elle n'est jamais accessible au modèle.")
        return 2
    say(f"Validation des findings — journal {Path(cfg.audit_file)}")
    analyst = ask("Votre nom (analyste) : ").strip()
    if not NAME_RE.match(analyst):
        say("Nom invalide (2 à 80 caractères).")
        return 1
    while True:
        pending = [f for f in load_findings(cfg.audit_file, with_citations=True)
                   if f["status"] in BLOCKING]
        say("")
        if not pending:  # other findings (e.g. rejected by the server) stay reachable by id
            say("Aucun finding à valider ou à revoir.")
        for i, f in enumerate(pending, 1):
            say(f"[{i}] {f['finding_id']} ({f['kind']}, confiance {f['confidence']}, "
                f"{f['status']}) — {f['text'][:100]}")
        choice = ask("Numéro du finding, ou identifiant (ex. F-0002) pour un autre finding, "
                     "q pour quitter : ").strip()
        if choice.lower() in ("q", ""):
            return 0
        if re.fullmatch(r"F-[0-9]{4,}", choice.upper()):
            f = next((x for x in load_findings(cfg.audit_file, with_citations=True)
                      if x["finding_id"] == choice.upper()), None)
            if f is None:
                say("Finding inconnu.")
                continue
        elif choice.isdigit() and 1 <= int(choice) <= len(pending):
            f = pending[int(choice) - 1]
        else:
            say("Choix invalide.")
            continue
        say(f"\n{f['finding_id']} — {f['kind']} — confiance {f['confidence']} — {f['status']}")
        say(f"Énoncé : {f['text']}")
        if f["attack"]:
            say(f"ATT&CK : {f['attack']}")
        for c in recheck(cfg, f):
            say(f"  - {c['result_id']} ligne {c['_row']} champ {c['field']} : cité "
                f"{c['value']!r} | valeur actuelle {str(c['current'])[:120]!r} | "
                f"contrôle {c['check']}")
        code = ask("Décision : [v] valider, [r] rejeter, [a] à revoir, autre = annuler : ")
        decision = DECISIONS.get(code.strip().lower())
        if decision is None:
            say("Annulé.")
            continue
        reason = ask("Motif : ")
        label = STATUS_LABEL[decision]
        if ask(f"Confirmer « {label} » pour {f['finding_id']} par {analyst} ? (o/n) "
               ).strip().lower() != "o":
            say("Annulé.")
            continue
        try:
            ev = decide(cfg, f["finding_id"], decision, analyst, reason)
        except ValidationError as exc:
            say(f"Refusé : {exc}")
            continue
        say(f"Enregistré : {f['finding_id']} {label} (audit_id {ev['audit_id']}).")
