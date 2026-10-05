"""Task 6.2: stakeholder coordination (EF-15) — board rebuilt from the journal, suggestions
that write nothing and state no legal deadline, communications recorded (never sent),
pseudonymisation of names and contacts in cloud mode, sitrep section 6, crisis timeline."""
import json
import re
from pathlib import Path

import pytest
import yaml
from mcp import Client
from mcp.server.mcpserver.exceptions import ToolError

from forensic_mcp import audit, schemas, server, stakeholder_ops
from forensic_mcp.ops import Engine

pytestmark = pytest.mark.anyio
ROOT = Path(__file__).resolve().parents[1]
REFS = ROOT / "skills" / "playbook-poste-compromis" / "references"
PAST = "2026-10-01T10:00:00+02:00"  # -> 08:00:00Z
FUTURE = "2999-01-01T00:00:00Z"


async def _call(c, tool, args):
    r = await c.call_tool(tool, args)
    if r.is_error:
        return r.content[0].text
    assert schemas.errors(schemas.output_validator(), r.structured_content) == []
    return r.structured_content


def _events(cfg, type_):
    return [e for e in audit.iter_events(cfg.audit_file) if e["type"] == type_]


async def test_upsert_refusals_and_board_rebuilt_from_journal(cfg) -> None:
    async with Client(server.build_server(cfg)) as c:
        a = await _call(c, "stakeholder_upsert", {
            "case": "", "role": "direction", "name": "Camille Exemple", "channel": "telephone",
            "owner": "Responsable de crise", "notify_by_utc": PAST})
        b = await _call(c, "stakeholder_upsert", {"case": "", "role": "dpo",
                                                  "name": "Dominique Fictif"})
        # same case + role + name = same entry (update, not a duplicate)
        a2 = await _call(c, "stakeholder_upsert", {
            "case": "", "role": "direction", "name": "camille exemple", "status": "prevenu",
            "notify_by_utc": "2026-10-01T08:05:00Z", "source": f"audit_id {a['audit_id']}"})
        b2 = await _call(c, "stakeholder_upsert", {"case": "", "role": "dpo",
                                                   "stakeholder_id": "S-0002",
                                                   "note": "rappeler après la réunion"})
        refused = {
            "naive time": {"case": "", "role": "rssi", "notify_by_utc": "2026-10-01T10:00:00"},
            "future notified": {"case": "", "role": "rssi", "status": "prevenu",
                                "notify_by_utc": FUTURE},
            "unknown source": {"case": "", "role": "rssi", "source": "constat F-9999"},
            "unknown result": {"case": "", "role": "rssi",
                               "source": "20990101-000000-vol3_x-abcdef"},
            "unknown id": {"case": "", "role": "rssi", "stakeholder_id": "S-0042"},
            "name too long": {"case": "", "role": "rssi", "name": "x" * 121},
            "bad case": {"case": "../etc", "role": "rssi"},
        }
        out = {k: await _call(c, "stakeholder_upsert", v) for k, v in refused.items()}
        sdk = await c.call_tool("stakeholder_upsert", {"case": "", "role": "pdg"})
        board = await _call(c, "stakeholder_list", {"case": ""})
        open_ = await _call(c, "stakeholder_list", {"case": "", "status": "a_prevenir"})
    # a role / channel outside the list is refused by the server itself, not only by the SDK
    eng = Engine(cfg)
    for bad in ({"case": "", "role": "pdg"}, {"case": "", "role": "rssi", "channel": "pigeon"},
                {"case": "", "role": "rssi", "status": "fait"}):
        with pytest.raises(ToolError, match="refused"):
            await eng.call("stakeholder_upsert", bad)
    assert sdk.is_error
    assert a["rows"][0]["stakeholder_id"] == "S-0001" and a["rows"][0]["notify_by_utc"] == \
        "2026-10-01T08:00:00Z" and a["rows"][0]["statut"] == "à prévenir"
    assert a["rows"][0]["en_retard"] is True  # deadline passed, computed by the server
    assert b["rows"][0]["stakeholder_id"] == "S-0002"
    assert a2["rows"][0]["stakeholder_id"] == "S-0001" and a2["rows"][0]["status"] == "prevenu"
    assert a2["rows"][0]["channel"] == "telephone" and not a2["rows"][0]["en_retard"]
    assert "audit_ids" in a2["rows"][0]["source_checked"]
    assert b2["rows"][0]["status"] == "a_prevenir" and b2["rows"][0]["note"]  # status kept
    for k, v in out.items():
        assert isinstance(v, str) and "refused" in v, k
    assert [r["stakeholder_id"] for r in board["rows"]] == ["S-0002", "S-0001"]  # open first
    assert [r["stakeholder_id"] for r in open_["rows"]] == ["S-0002"]
    rows = {r["stakeholder_id"]: r for r in board["rows"]}
    assert rows["S-0001"]["created_audit_id"] == a["audit_id"] - 1  # cites its journal events
    assert rows["S-0001"]["last_audit_id"] == a2["audit_id"] - 1
    evs = _events(cfg, "stakeholder_update")
    assert [e["action"] for e in evs] == ["create", "create", "update", "update"]
    assert evs[0]["status"] == "a_prevenir" and evs[2]["previous_status"] == "a_prevenir"
    assert "name" not in evs[3] and evs[3]["note"]  # only the given fields: nothing rewritten
    calls = [e for e in _events(cfg, "tool_call") if e["tool"] == "stakeholder_upsert"]
    assert sum(e["outcome"] == "refused" for e in calls) == len(refused) + 3  # all journaled
    assert audit.verify_report(cfg.audit_file)["ok"]


async def test_comms_log_records_never_changes_status_and_feeds_the_timeline(cfg) -> None:
    (Path(cfg.evidence_root) / "WS-042").mkdir()
    async with Client(server.build_server(cfg)) as c:
        await _call(c, "crisis_add_event", {"time_utc": "2026-10-01T07:30:00Z", "kind": "event",
                                            "description": "Alerte EDR", "owner": "SOC",
                                            "source": "SOC", "case": "WS-042"})
        s = await _call(c, "stakeholder_upsert", {"case": "WS-042", "role": "rssi",
                                                  "name": "Alex Fictif"})
        log = await _call(c, "comms_log", {"case": "WS-042", "stakeholder_id": "S-0001",
                                           "direction": "sortante", "at_utc": PAST,
                                           "summary": "Appel : incident qualifié, cellule réunie"})
        refused = {
            "future": {"case": "WS-042", "stakeholder_id": "S-0001", "direction": "entrante",
                       "summary": "réponse", "at_utc": FUTURE},
            "unknown id": {"case": "WS-042", "stakeholder_id": "S-0009", "direction": "entrante",
                           "summary": "réponse", "at_utc": PAST},
            "other case": {"case": "", "stakeholder_id": "S-0001", "direction": "entrante",
                           "summary": "réponse", "at_utc": PAST},
            "naive": {"case": "WS-042", "stakeholder_id": "S-0001", "direction": "entrante",
                      "summary": "réponse", "at_utc": "2026-10-01T10:00:00"},
        }
        out = {k: await _call(c, "comms_log", v) for k, v in refused.items()}
        await _call(c, "stakeholder_upsert", {"case": "WS-042", "role": "rssi",
                                              "stakeholder_id": s["rows"][0]["stakeholder_id"],
                                              "status": "accuse_reception"})
        tl = await _call(c, "crisis_timeline", {"case": "WS-042"})
        comm = await _call(c, "crisis_timeline", {"case": "WS-042", "kind": "communication"})
    row = log["rows"][0]
    assert row["at_utc"] == "2026-10-01T08:00:00Z" and row["status"] == "a_prevenir"
    assert log["next_steps"][0]["tool"] == "stakeholder_upsert"  # proposed, not done
    assert log["next_steps"][0]["args"]["status"] == "prevenu"
    for k, v in out.items():
        assert isinstance(v, str) and "refused" in v, k
    kinds = [(r["kind"], r["crisis_id"]) for r in tl["rows"]]
    assert ("event", "C-0001") in kinds and kinds.count(("communication", "S-0001")) == 3
    times = [r["time_utc"] for r in tl["rows"]]
    assert times[:2] == ["2026-10-01T07:30:00Z", "2026-10-01T08:00:00Z"]  # UTC order
    assert "communication sortante" in tl["rows"][1]["description"]
    assert "à prévenir → accusé de réception" in tl["rows"][-1]["description"]
    assert {r["kind"] for r in comm["rows"]} == {"communication"}
    ev = _events(cfg, "comms_logged")
    assert len(ev) == 1 and ev[0]["case"] == "WS-042" and ev[0]["at_utc"] == row["at_utc"]
    assert audit.verify_report(cfg.audit_file)["ok"]


async def test_suggest_writes_nothing_and_states_no_legal_deadline(cfg) -> None:
    data = stakeholder_ops.rules()
    async with Client(server.build_server(cfg)) as c:
        await _call(c, "stakeholder_upsert", {"case": "", "role": "dpo"})
        before = sum(1 for _ in audit.iter_events(cfg.audit_file))
        got = {t: await _call(c, "stakeholder_suggest", {"case": "", "incident_type": t})
               for t in stakeholder_ops.INCIDENT_TYPES}
        bad = await c.call_tool("stakeholder_suggest", {"case": "", "incident_type": "panne"})
    assert bad.is_error
    evs = list(audit.iter_events(cfg.audit_file))
    assert {e["type"] for e in evs[before:]} == {"tool_call"}  # nothing written to the board
    legal_roles = {c["role"] for t in data["incident_types"].values() for c in t["contacts"]
                   if c.get("legal")}
    for itype, r in got.items():
        spec = data["incident_types"][itype]
        assert r["row_count"] == len(data["common"]) + len(spec["contacts"])
        assert [x["ordre"] for x in r["rows"]] == sorted(x["ordre"] for x in r["rows"])
        for x in r["rows"]:
            assert "à valider" in x["statut"] and x["regle"]
            if x["role"] in legal_roles - {"dpo"} and x["portee"] != "commune":
                assert x["delai_indicatif"] == "à confirmer par le juridique", x
            if x["role"] == "autorite_protection_donnees":
                assert "à évaluer par le DPO / le juridique" in x["motif"]
        assert any(x["role"] == "dpo" and x["deja_au_tableau"] == "S-0001 (à prévenir)"
                   for x in r["rows"])
        assert any("à confirmer par le juridique" in n for n in r["notes"])
    # no legal delay stated as certain anywhere in the rules or the reference
    text = (ROOT / "rules" / "stakeholders.yaml").read_text(encoding="utf-8") + \
        (REFS / "coordination.md").read_text(encoding="utf-8")
    assert not re.search(r"\b\d+\s*(h|heures?|jours?)\b|72|obligatoire|doit notifier", text, re.I)
    for t in data["incident_types"].values():
        for x in t["contacts"]:
            assert ("delai" in x) != bool(x.get("legal")), x["id"]  # legal => no delay of ours


def test_rules_roles_tools_and_reference_in_sync() -> None:
    data = stakeholder_ops.rules()
    ids = [c["id"] for c in data["common"]] + [c["id"] for t in data["incident_types"].values()
                                                for c in t["contacts"]]
    md = (REFS / "coordination.md").read_text(encoding="utf-8")
    assert len(ids) == len(set(ids)) and set(re.findall(r"\| `([a-z_]+)` \|", md)) == set(ids)
    roles = set(data["roles"])
    assert len(roles) == 13 and all(c["role"] in roles for c in data["common"])
    assert set(data["incident_types"]) == set(stakeholder_ops.INCIDENT_TYPES)
    schema = json.loads((ROOT / "docs" / "audit_schema.json").read_text(encoding="utf-8"))
    blocks = [b["then"] for b in schema["$defs"]["event"]["allOf"]
              if b["if"]["properties"]["type"].get("const") == "stakeholder_update"]
    assert set(blocks[0]["properties"]["role"]["enum"]) == roles
    assert set(schema["$defs"]["stakeholder_status"]["enum"]) == set(stakeholder_ops.STATUSES)
    # nothing real in the repository files: no phone number, no e-mail address
    for f in (ROOT / "rules" / "stakeholders.yaml", REFS / "coordination.md"):
        t = f.read_text(encoding="utf-8")
        assert not re.search(r"@|\b0\d([ .]?\d{2}){4}\b|\+\d{2}[ .]?\d([ .]?\d{2}){4}", t), f


async def test_no_coordination_tool_acts_outside(cfg) -> None:
    names = ("stakeholder_upsert", "stakeholder_list", "stakeholder_suggest", "comms_log")
    async with Client(server.build_server(cfg)) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        await _call(c, "stakeholder_upsert", {"case": "", "role": "communication"})
        await _call(c, "comms_log", {"case": "", "stakeholder_id": "S-0001",
                                     "direction": "sortante", "summary": "message validé lu",
                                     "at_utc": PAST})
        await _call(c, "stakeholder_list", {"case": ""})
        await _call(c, "stakeholder_suggest", {"case": "", "incident_type": "ransomware"})
    for n in names:
        assert tools[n].annotations.open_world_hint is False, n
        assert tools[n].annotations.destructive_hint is False, n
    assert tools["stakeholder_list"].annotations.read_only_hint is True
    assert tools["stakeholder_suggest"].annotations.read_only_hint is True
    # no process, no network, no mail: the module imports none of them
    src = (ROOT / "src" / "forensic_mcp" / "stakeholder_ops.py").read_text(encoding="utf-8")
    imports = set(re.findall(r"^(?:from|import) ([\w.]+)", src, re.M))
    assert not imports & {"subprocess", "socket", "smtplib", "urllib", "http", "httpx",
                          "requests", "asyncio", ".runner", "os"}, imports
    calls = [e for e in _events(cfg, "tool_call") if e["tool"] in names]
    assert len(calls) == 4 and all(e["argv"] == [] and e["outcome"] == "ok" for e in calls)
    assert not [t for t in server.TOOL_NAMES
                if re.search(r"send|envoy|mail|notif|sms|call_|appel", t)]


async def test_names_and_contacts_pseudonymised_in_cloud_mode(cfg) -> None:
    case = Path(cfg.evidence_root) / "WS-042"
    case.mkdir()
    (case / "case.toml").write_text('case = "WS-042"\nclassification = "internal"\n')
    cfg.llm_mode = "cloud"
    real = ("Camille Exemple", "06 00 00 00 01", "camille.exemple@example.invalid")
    async with Client(server.build_server(cfg)) as c:
        up = await _call(c, "stakeholder_upsert", {
            "case": "WS-042", "role": "dpo", "name": real[0], "organisation": "Société Fictive",
            "note": f"joindre au {real[1]} ou {real[2]}", "owner": "RSSI"})
        tok = up["rows"][0]["name"]
        # the model answers with the token: restored server-side, same entry updated
        up2 = await _call(c, "stakeholder_upsert", {"case": "WS-042", "role": "dpo",
                                                    "name": tok, "status": "prevenu",
                                                    "notify_by_utc": PAST})
        log = await _call(c, "comms_log", {"case": "WS-042", "stakeholder_id": "S-0001",
                                           "direction": "sortante", "at_utc": PAST,
                                           "summary": f"{real[0]} jointe au {real[1]}"})
        lst = await _call(c, "stakeholder_list", {"case": "WS-042"})
        tl = await _call(c, "crisis_timeline", {"case": "WS-042"})
        sit = await _call(c, "sitrep_draft", {"case": "WS-042", "audience": "technique"})
        sug = await _call(c, "stakeholder_suggest", {"case": "WS-042",
                                                     "incident_type": "exfiltration"})
    assert re.fullmatch(r"PERSON_\d+", tok)
    assert up2["rows"][0]["stakeholder_id"] == "S-0001" and up2["rows"][0]["name"] == tok
    for r in (up, up2, log, lst, tl, sit, sug):
        blob = json.dumps(r, ensure_ascii=False)
        assert not any(v.lower() in blob.lower() for v in real), r["tool"]
    assert "CONTACT_" in up["rows"][0]["note"] and "PERSON_" in log["rows"][0]["summary"]
    ev = _events(cfg, "stakeholder_update")
    assert ev[0]["name"] == real[0] and ev[1]["name"] == real[0]  # real values in the journal
    assert real[1] in ev[0]["note"]
    assert len({e["stakeholder_id"] for e in ev}) == 1


async def test_sitrep_communications_never_state_an_open_status_as_done(cfg) -> None:
    async with Client(server.build_server(cfg)) as c:
        await _call(c, "stakeholder_upsert", {"case": "", "role": "direction",
                                              "name": "Camille Exemple", "status": "prevenu",
                                              "notify_by_utc": PAST, "channel": "reunion"})
        await _call(c, "stakeholder_upsert", {"case": "", "role": "dpo",
                                              "name": "Dominique Fictif",
                                              "notify_by_utc": "2026-10-01T09:00:00Z"})
        await _call(c, "comms_log", {"case": "", "stakeholder_id": "S-0002",
                                     "direction": "sortante", "at_utc": PAST,
                                     "summary": "message laissé, pas de réponse"})
        await _call(c, "stakeholder_upsert", {"case": "", "role": "client", "status": "sans_objet"})
        st1 = await _call(c, "checklist_status", {"case": ""})
        reps = {a: await _call(c, "sitrep_draft", {"audience": a})
                for a in ("direction", "technique")}
        await _call(c, "stakeholder_upsert", {"case": "", "role": "dpo", "stakeholder_id": "S-0002",
                                              "status": "accuse_reception"})
        st2 = await _call(c, "checklist_status", {"case": ""})
    for a, r in reps.items():
        assert r["rows"][-1]["section"] == "communications"
        t = (Path(cfg.output_root) / r["result_id"] / "sitrep.md").read_text(encoding="utf-8")
        assert "## 6. Communications avec les parties prenantes" in t and "{{" not in t
        sec = t.split("## 6. Communications")[1]
        done, _, wait = sec.partition("À prévenir / en attente")
        assert "Camille Exemple" in done and "Dominique Fictif" not in done, a
        assert "Dominique Fictif" in wait and "statut non confirmé" in wait
        assert "DÉPASSÉE" in wait and "Sans objet : 1" in sec
        assert ("S-0001" in sec) == (a == "technique")  # detail depends on the audience
    s1 = {x["id"]: x for x in st1["rows"]}["stakeholders"]
    s2 = {x["id"]: x for x in st2["rows"]}["stakeholders"]
    assert s1["statut"] == "à faire" and "S-0002" in s1["preuve"]
    assert s2["statut"] == "fait" and "audit_id" in s2["preuve"]


def test_template_has_the_communications_section() -> None:
    t = (ROOT / "templates" / "sitrep.md").read_text(encoding="utf-8")
    assert "{{communications}}" in t and yaml.safe_load(
        (ROOT / "rules" / "stakeholders.yaml").read_text(encoding="utf-8"))["legal_delay"]
