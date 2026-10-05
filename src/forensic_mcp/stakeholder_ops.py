"""Stakeholder coordination (EF-15, task 6.2): who must be told, by whom, by when, through which
channel, with which status. The server PROPOSES (stakeholder_suggest) and RECORDS what people
decided or did (stakeholder_upsert, comms_log); it never sends a message, an e-mail or a call.

- stakeholder_upsert journals a `stakeholder_update` (S-NNNN, creation or change). Nothing is
  rewritten: the current board is rebuilt from the journal, like list_findings.
- comms_log journals a `comms_logged`: a communication ALREADY made by a person. It never
  changes the status (a person decides it with stakeholder_upsert).
- stakeholder_list = the current board; stakeholder_suggest = rules/stakeholders.yaml for one
  incident type, "à valider", nothing written; legal delays are never stated as certain.
Names, notes and summaries are free text typed by the model: untrusted, bounded, and
pseudonymised in cloud mode (PERSON_n / CONTACT_n, redact.Pseudonymizer.people).
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from . import audit
from .redact import Pseudonymizer
from .timeline import iso, to_utc

RULES = Path(__file__).resolve().parents[2] / "rules" / "stakeholders.yaml"
STATUSES = ("a_prevenir", "prevenu", "accuse_reception", "sans_objet", "a_revoir")
STATUS_FR = {"a_prevenir": "à prévenir", "prevenu": "prévenu",
             "accuse_reception": "accusé de réception", "sans_objet": "sans objet",
             "a_revoir": "à revoir"}
NOTIFIED = ("prevenu", "accuse_reception")
OPEN = ("a_revoir", "a_prevenir")
SORT = {s: i for i, s in enumerate(("a_revoir", "a_prevenir", "prevenu", "accuse_reception",
                                     "sans_objet"))}
CHANNELS = ("telephone", "courriel", "reunion", "ticket", "autre")
DIRECTIONS = ("sortante", "entrante")
INCIDENT_TYPES = ("ransomware", "compte_compromis", "exfiltration", "autre")
LIMITS = {"name": 120, "organisation": 120, "owner": 120, "note": 500, "source": 300}
FIELDS = (*LIMITS, "channel", "notify_by_utc")
SID_RE = re.compile(r"^S-\d{4,}$")
EXPLICIT_TZ = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")
NO_SEND = ("Le serveur n'envoie rien : prévenir une personne reste une action humaine ; la "
           "consigner ensuite avec comms_log.")


@lru_cache(maxsize=None)
def rules() -> dict[str, Any]:
    return yaml.safe_load(RULES.read_text(encoding="utf-8"))


def roles() -> dict[str, str]:
    return rules()["roles"]


def _bounded(v: Any, name: str, hi: int, lo: int = 0) -> str:
    s = str(v).strip()
    if not lo <= len(s) <= hi:
        raise ValueError(f"{name} must be {lo}-{hi} characters")
    return s


def _explicit_utc(raw: Any, name: str) -> datetime:
    s = str(raw or "").strip()
    when = to_utc(s)
    if when is None or not EXPLICIT_TZ.search(s):
        raise ValueError(f"{name} must be ISO-8601 with an explicit offset, e.g. "
                         "2026-10-06T14:32:07Z (no local time without offset)")
    return when


def _late(st: dict[str, Any], now: datetime) -> bool:
    due = to_utc(st.get("notify_by_utc"))
    return bool(due and st["status"] in OPEN and due < now)


class StakeholderOps:
    """Mixed into ops.Engine (uses cfg, actor, _listing, _crisis_policy, _source_ref)."""

    def stakeholder_board(self, case: str | None = None) -> dict[str, dict[str, Any]]:
        """Current state of every entry, folded from the journal (case None or "" = all)."""
        board: dict[str, dict[str, Any]] = {}
        for e in audit.iter_events(self.cfg.audit_file):
            if e["type"] == "stakeholder_update":
                sid = e["stakeholder_id"]
                st = board.setdefault(sid, {
                    "stakeholder_id": sid, "case": e.get("case", ""), **dict.fromkeys(FIELDS),
                    "created_audit_id": e["audit_id"], "created_utc": e["ts_utc"],
                    "last_contact_utc": None, "last_direction": None, "communications": 0})
                st.update(role=e["role"], status=e["status"],
                          **{f: e[f] for f in FIELDS if f in e})
                st["last_audit_id"], st["updated_utc"] = e["audit_id"], e["ts_utc"]
            elif e["type"] == "comms_logged" and e.get("stakeholder_id") in board:
                st = board[e["stakeholder_id"]]
                st["communications"] += 1
                st["last_audit_id"] = e["audit_id"]
                last = to_utc(st["last_contact_utc"])
                if last is None or to_utc(e["at_utc"]) >= last:
                    st["last_contact_utc"], st["last_direction"] = e["at_utc"], e["direction"]
        return {k: v for k, v in board.items() if not case or v["case"] == case}

    def _learn_people(self, ps: Pseudonymizer | None, case: str) -> None:
        """Cloud mode: every name / contact of the case's board becomes a token before the
        response is redacted (names in any field, e-mails / phones in the free text)."""
        if ps is None:
            return
        entries = list(self.stakeholder_board(case).values())
        notes = [str(s.get(k) or "") for s in entries for k in ("note", "source", "owner")]
        comms = [e.get("summary", "") for e in audit.iter_events(self.cfg.audit_file)
                 if e["type"] == "comms_logged" and (not case or e.get("case", "") == case)]
        ps.people([s.get("name") or "" for s in entries], [*notes, *comms])

    @staticmethod
    def _board_row(st: dict[str, Any], now: datetime) -> dict[str, Any]:
        return {"stakeholder_id": st["stakeholder_id"], "role": st["role"],
                "role_label": roles().get(st["role"], st["role"]), "name": st["name"],
                "organisation": st["organisation"], "channel": st["channel"],
                "owner": st["owner"], "status": st["status"],
                "statut": STATUS_FR[st["status"]], "notify_by_utc": st["notify_by_utc"],
                "en_retard": _late(st, now), "last_contact_utc": st["last_contact_utc"],
                "last_direction": st["last_direction"], "communications": st["communications"],
                "note": st["note"], "source": st["source"], "case": st["case"] or None,
                "created_audit_id": st["created_audit_id"], "last_audit_id": st["last_audit_id"]}

    async def op_stakeholder_upsert(self, params: dict[str, Any], conf: Any = None) -> Any:
        case, ps = self._crisis_policy(params.get("case"))
        p = ps.restore(params) if ps else dict(params)
        role, status, channel = p.get("role"), p.get("status"), p.get("channel")
        if role not in roles():
            raise ValueError(f"role must be one of {sorted(roles())}")
        if status is not None and status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        fields: dict[str, Any] = {f: _bounded(p[f], f, hi) for f, hi in LIMITS.items()
                                  if p.get(f) is not None}
        if channel is not None:
            if channel not in CHANNELS:
                raise ValueError(f"channel must be one of {CHANNELS}")
            fields["channel"] = channel
        when = None
        if p.get("notify_by_utc") not in (None, ""):
            when = _explicit_utc(p["notify_by_utc"], "notify_by_utc")
            fields["notify_by_utc"] = iso(when)
        refs = self._source_ref(fields["source"]) if fields.get("source") else {}
        board = self.stakeholder_board()
        sid = str(p.get("stakeholder_id") or "").strip()
        if sid:
            if not SID_RE.match(sid) or sid not in board:
                raise ValueError(f"unknown stakeholder_id {sid!r}")
            prev = board[sid]
            if prev["case"] != case:
                raise ValueError(f"{sid} belongs to case {prev['case']!r}, not {case!r}")
        else:  # same case + role + name = the same person: update instead of a duplicate
            name = (fields.get("name") or "").casefold()
            prev = next((s for s in board.values() if name and s["case"] == case
                         and s["role"] == role and (s["name"] or "").casefold() == name), None)
            sid = prev["stakeholder_id"] if prev else ""
        new_status = status or (prev["status"] if prev else "a_prevenir")
        if new_status in NOTIFIED and when is not None and when.timestamp() > time.time() + 300:
            raise ValueError(f"status {new_status!r} with notify_by_utc in the future: a person "
                             "cannot have been notified at a future time")
        if not prev:
            n = sum(1 for e in audit.iter_events(self.cfg.audit_file)
                    if e["type"] == "stakeholder_update" and e.get("action") == "create")
            sid = f"S-{n + 1:04d}"
        ev = audit.append(self.cfg.audit_file, "stakeholder_update", self.actor,
                          stakeholder_id=sid, action="update" if prev else "create", role=role,
                          status=new_status, previous_status=prev["status"] if prev else None,
                          **fields, source_ref=refs, **({"case": case} if case else {}))
        st = self.stakeholder_board()[sid]
        self._learn_people(ps, case)
        row = {**self._board_row(st, datetime.now(timezone.utc)),
               "source_checked": ", ".join(f"{k}: {v}" for k, v in refs.items()) or None,
               "audit_id": ev["audit_id"]}
        verb = "mis à jour" if prev else "ajouté au tableau"
        out = self._listing("stakeholder_upsert", params, [row],
                            f"{sid} {verb} ({roles()[role]}, {STATUS_FR[new_status]})")
        out.pseudo = ps
        out.payload["notes"] = [f"stakeholder_update journaled as audit_id {ev['audit_id']}",
                                NO_SEND]
        out.audit_extra = {"stakeholder_id": sid}
        return out

    async def op_stakeholder_list(self, params: dict[str, Any], conf: Any = None) -> Any:
        case, ps = self._crisis_policy(params.get("case"))
        status, role = params.get("status"), params.get("role")
        if status is not None and status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        if role is not None and role not in roles():
            raise ValueError(f"role must be one of {sorted(roles())}")
        now = datetime.now(timezone.utc)
        entries = list(self.stakeholder_board(case).values())
        rows = sorted((self._board_row(s, now) for s in entries
                       if status in (None, s["status"]) and role in (None, s["role"])),
                      key=lambda r: (SORT[r["status"]], r["notify_by_utc"] or "~",
                                     r["stakeholder_id"]))
        n_open = sum(1 for r in rows if r["status"] in OPEN)
        late = [r for r in rows if r["en_retard"]]
        n_done = sum(1 for r in rows if r["status"] in NOTIFIED)
        self._learn_people(ps, case)
        out = self._listing("stakeholder_list", params, rows,
                            f"{len(rows)} parties prenantes : {n_open} à prévenir ou à revoir "
                            f"({len(late)} en retard), {n_done} prévenue(s)")
        out.pseudo = ps
        out.payload["next_steps"] = [
            {"tool": "comms_log", "args": {"case": case, "stakeholder_id": r["stakeholder_id"]},
             "why": f"{r['stakeholder_id']} ({r['role_label']}) : échéance {r['notify_by_utc']} "
                    "dépassée ; prévenir (action humaine) puis consigner la communication"}
            for r in late[:3]]
        out.payload["notes"] = [NO_SEND]
        return out

    async def op_stakeholder_suggest(self, params: dict[str, Any], conf: Any = None) -> Any:
        case, ps = self._crisis_policy(params.get("case"))
        data, itype = rules(), params.get("incident_type")
        if itype not in INCIDENT_TYPES or itype not in data["incident_types"]:
            raise ValueError(f"incident_type must be one of {INCIDENT_TYPES}")
        spec = data["incident_types"][itype]
        entries = list(self.stakeholder_board(case).values())
        items = []
        for c in sorted([*data["common"], *spec["contacts"]], key=lambda c: (c["ordre"], c["id"])):
            known = [s for s in entries if s["role"] == c["role"]]
            items.append({
                "regle": c["id"], "ordre": c["ordre"], "role": c["role"],
                "role_label": roles()[c["role"]],
                "delai_indicatif": data["legal_delay"] if c.get("legal") else c["delai"],
                "motif": c["motif"],
                "portee": "commune" if c in data["common"] else spec["label"],
                "deja_au_tableau": ", ".join(f"{s['stakeholder_id']} ({STATUS_FR[s['status']]})"
                                             for s in known) or None,
                "statut": "suggestion à valider — rien n'est écrit au tableau ni envoyé"})
        self._learn_people(ps, case)
        out = self._listing("stakeholder_suggest", params, items,
                            f"{len(items)} parties prenantes suggérées ({spec['label']}), toutes "
                            "à valider par la cellule de crise")
        out.pseudo = ps
        out.payload["notes"] = [
            "Suggestions from rules/stakeholders.yaml (rule id in `regle`): nothing is written "
            "to the board and nothing is sent. A stakeholder retained by the crisis cell is "
            "added with stakeholder_upsert.",
            f"Délais légaux, réglementaires ou contractuels : {data['legal_delay']} ; le "
            "serveur ne donne aucun avis juridique.",
            "Données personnelles : l'obligation de notifier l'autorité de protection des données "
            "est à évaluer par le DPO / le juridique."]
        return out

    async def op_comms_log(self, params: dict[str, Any], conf: Any = None) -> Any:
        case, ps = self._crisis_policy(params.get("case"))
        p = ps.restore(params) if ps else dict(params)
        sid = str(p.get("stakeholder_id") or "").strip()
        board = self.stakeholder_board()
        if not SID_RE.match(sid) or sid not in board:
            raise ValueError(f"unknown stakeholder_id {sid!r} (create it with stakeholder_upsert)")
        if board[sid]["case"] != case:
            raise ValueError(f"{sid} belongs to case {board[sid]['case']!r}, not {case!r}")
        direction = p.get("direction")
        if direction not in DIRECTIONS:
            raise ValueError(f"direction must be one of {DIRECTIONS}")
        summary = _bounded(p.get("summary") or "", "summary", 1000, 3)
        when = _explicit_utc(p.get("at_utc"), "at_utc")
        if when.timestamp() > time.time() + 300:
            raise ValueError("at_utc is in the future: comms_log records communications already "
                             "made")
        src = _bounded(p["source"], "source", LIMITS["source"]) if p.get("source") else None
        refs = self._source_ref(src) if src else {}
        ev = audit.append(self.cfg.audit_file, "comms_logged", self.actor, stakeholder_id=sid,
                          direction=direction, summary=summary, at_utc=iso(when),
                          **({"source": src} if src else {}), source_ref=refs,
                          **({"case": case} if case else {}))
        st = self.stakeholder_board()[sid]
        self._learn_people(ps, case)
        row = {"stakeholder_id": sid, "direction": direction, "at_utc": iso(when),
               "summary": summary, "role_label": roles()[st["role"]], "name": st["name"],
               "status": st["status"], "statut": STATUS_FR[st["status"]],
               "communications": st["communications"], "source": src,
               "audit_id": ev["audit_id"]}
        out = self._listing("comms_log", params, [row],
                            f"Communication {direction} avec {sid} consignée ({iso(when)}) ; "
                            f"statut inchangé : {STATUS_FR[st['status']]}")
        out.pseudo = ps
        if direction == "sortante" and st["status"] in OPEN:
            out.payload["next_steps"] = [{
                "tool": "stakeholder_upsert",
                "args": {"case": case, "stakeholder_id": sid, "role": st["role"],
                         "status": "prevenu"},
                "why": "communication sortante consignée : passer le statut à « prévenu » "
                       "seulement si la personne a bien été jointe (décision humaine)"}]
        out.payload["notes"] = [f"comms_logged journaled as audit_id {ev['audit_id']}", NO_SEND]
        out.audit_extra = {"stakeholder_id": sid}
        return out

    def stakeholder_timeline(self, case: str | None = None) -> list[dict[str, Any]]:
        """Crisis-timeline entries (kind "communication"): every status change of the board and
        every logged communication, in UTC."""
        out: list[dict[str, Any]] = []
        seen: dict[str, dict[str, Any]] = {}
        for e in audit.iter_events(self.cfg.audit_file):
            if e["type"] not in ("stakeholder_update", "comms_logged"):
                continue
            sid = e.get("stakeholder_id")
            if e["type"] == "stakeholder_update":
                st = seen.setdefault(sid, {})
                st.update(role=e["role"], **{f: e[f] for f in ("name", "owner") if f in e})
            elif sid not in seen:
                continue
            st = seen[sid]
            who = f"{sid} {roles().get(st['role'], st['role'])}" + (
                f" — {st['name']}" if st.get("name") else "")
            if e["type"] == "comms_logged":
                when, text = e["at_utc"], f"{who} : communication {e['direction']} — {e['summary']}"
            elif e.get("action") == "create" or e["status"] != e.get("previous_status"):
                use_notified = e["status"] in NOTIFIED and e.get("notify_by_utc")
                when = e["notify_by_utc"] if use_notified else iso(to_utc(e["ts_utc"]))
                text = (f"{who} : ajouté au tableau de coordination ({STATUS_FR[e['status']]})"
                        if e.get("action") == "create" else
                        f"{who} : statut {STATUS_FR.get(e.get('previous_status'), '?')} → "
                        f"{STATUS_FR[e['status']]}")
            else:
                continue
            if case and e.get("case", "") != case:
                continue
            out.append({"crisis_id": sid, "time_utc": when, "kind": "communication",
                        "description": text, "owner": st.get("owner") or "—",
                        "source": e.get("source") or e["type"], "case": e.get("case"),
                        "recorded_utc": e["ts_utc"], "audit_id": e["audit_id"]})
        return out

    def communications_section(self, audience: str, case: str | None) -> str:
        """Sitrep section 6: stakeholders whose status is confirmed, then those still open. An
        open status is never written as done (EF-15)."""
        detail = audience in ("technique", "juridique")
        now = datetime.now(timezone.utc)
        entries = sorted(self.stakeholder_board(case).values(),
                         key=lambda s: (SORT[s["status"]], s["stakeholder_id"]))
        if not entries:
            return ("Aucune partie prenante au tableau de coordination (stakeholder_upsert). "
                    "Le serveur n'envoie aucun message.")

        def who(s: dict[str, Any]) -> str:
            return roles().get(s["role"], s["role"]) + (f" — {s['name']}" if s["name"] else "") \
                + (f" ({s['organisation']})" if s["organisation"] else "")

        def ref(s: dict[str, Any]) -> str:
            return f" [{s['stakeholder_id']}, audit_id {s['last_audit_id']}]" if detail else ""

        done = [s for s in entries if s["status"] in NOTIFIED]
        wait = [s for s in entries if s["status"] in OPEN]
        lines: list[str] = []
        if done:
            lines.append("Prévenues (statut confirmé au tableau de coordination) :")
            for s in done:
                when = s["last_contact_utc"] or s["notify_by_utc"]
                lines.append(f"- {who(s)} : {STATUS_FR[s['status']]}"
                             + (f", le {when}" if when else ", heure non renseignée")
                             + (f", par {s['channel']}" if detail and s["channel"] else "")
                             + (f" ; responsable : {s['owner']}" if s["owner"] else "") + ref(s))
        if wait:
            lines += ["", "À prévenir / en attente (non confirmé, ne pas présenter comme fait) :"]
            for s in wait:
                extra = []
                if s["notify_by_utc"]:
                    extra.append(f"échéance {s['notify_by_utc']}"
                                 + (" (DÉPASSÉE)" if _late(s, now) else ""))
                if s["last_contact_utc"]:
                    extra.append(f"communication {s['last_direction']} consignée le "
                                 f"{s['last_contact_utc']}, statut non confirmé")
                if s["owner"]:
                    extra.append(f"responsable : {s['owner']}")
                lines.append(f"- {who(s)} : {STATUS_FR[s['status']]}"
                             + (f" ({' ; '.join(extra)})" if extra else "") + ref(s))
        n_na = sum(1 for s in entries if s["status"] == "sans_objet")
        if n_na:
            lines += ["", f"Sans objet : {n_na} partie(s) prenante(s)."]
        lines += ["", "Tableau tenu par la cellule de crise ; le serveur n'envoie aucun message."]
        return "\n".join(lines).strip()
