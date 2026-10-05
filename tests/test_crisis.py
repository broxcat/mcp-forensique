"""Task 6.1: crisis assistant — crisis timeline (EF-12), sitrep draft (EF-13), containment
suggestions (EF-14). EF-15 (stakeholder board) is tested in test_stakeholders.py (6.2)."""
import re
from pathlib import Path

import pytest
import yaml
from mcp import Client

from forensic_mcp import audit, schemas, server, validation
from forensic_mcp.crisis_ops import SECTIONS, containment

pytestmark = pytest.mark.anyio
ROOT = Path(__file__).resolve().parents[1]


async def _call(c, tool, args):
    r = await c.call_tool(tool, args)
    if r.is_error:
        return r.content[0].text
    assert schemas.errors(schemas.output_validator(), r.structured_content) == []
    return r.structured_content


def _ev(time_utc, kind, description, owner="RSSI", source="appel du SOC", **kw):
    return {"time_utc": time_utc, "kind": kind, "description": description, "owner": owner,
            "source": source, **kw}


async def test_crisis_timeline_is_journaled_and_checked(cfg) -> None:
    async with Client(server.build_server(cfg)) as c:
        ps = await _call(c, "vol_pslist", {"path": "mem.raw"})
        f = await _call(c, "record_finding", {
            "kind": "fact", "text": "System is PID 4", "confidence": "high",
            "citations": [{"result_id": ps["result_id"], "row": 1, "field": "PID", "value": 4}]})
        fid = f["summary"].split()[0]
        later = await _call(c, "crisis_add_event", _ev(
            "2026-09-29T16:40:00+02:00", "decision", "Isoler le poste", owner="Directeur SI",
            source=f"constat {fid}"))
        first = await _call(c, "crisis_add_event", _ev(
            "2026-09-29T14:00:00Z", "event", "Alerte EDR sur le poste", source=f"résultat "
            f"{ps['result_id']} audit_id {ps['audit_id']}"))
        refused = {
            "naive time": _ev("2026-09-29T14:00:00", "event", "heure locale"),
            "future": _ev("2999-01-01T00:00:00Z", "event", "futur"),
            "unknown finding": _ev("2026-09-29T14:00:00Z", "event", "x y z", source="F-9999"),
            "unknown audit_id": _ev("2026-09-29T14:00:00Z", "event", "x y z", source="audit_id 99999"),
            "unknown result": _ev("2026-09-29T14:00:00Z", "event", "x y z",
                                  source="20990101-000000-vol3_x-abcdef"),
            "short text": _ev("2026-09-29T14:00:00Z", "event", "x"),
            "bad case": _ev("2026-09-29T14:00:00Z", "event", "x y z", case="../etc"),
        }
        out = {k: await _call(c, "crisis_add_event", v) for k, v in refused.items()}
        tl = await _call(c, "crisis_timeline", {})
        dec = await _call(c, "crisis_timeline", {"kind": "decision"})
    assert later["rows"][0]["time_utc"] == "2026-09-29T14:40:00Z"  # offset converted to UTC
    assert later["rows"][0]["crisis_id"] == "C-0001" and "findings" in later["rows"][0]["source_checked"]
    assert "results" in first["rows"][0]["source_checked"]
    for k, v in out.items():
        assert isinstance(v, str) and "refused" in v, k
    assert [r["crisis_id"] for r in tl["rows"]] == ["C-0002", "C-0001"]  # UTC order
    assert [r["kind"] for r in dec["rows"]] == ["decision"]
    evs = [e for e in audit.iter_events(cfg.audit_file) if e["type"] == "crisis_event"]
    assert len(evs) == 2 and evs[0]["source_ref"] == {"findings": [fid]}
    assert evs[0]["actor"]["kind"] == "llm"
    assert audit.verify_report(cfg.audit_file)["ok"]


async def test_sitrep_uses_validated_findings_only(cfg) -> None:
    async with Client(server.build_server(cfg)) as c:
        ps = await _call(c, "vol_pslist", {"path": "mem.raw"})
        rid = ps["result_id"]
        cite = [{"result_id": rid, "row": 1, "field": "PID", "value": 4}]
        for kind, text in [("fact", "Processus System présent (PID 4)"),
                           ("recommendation", "Collecter le disque du poste"),
                           ("fact", "Constat encore en attente")]:
            await _call(c, "record_finding", {"kind": kind, "text": text, "confidence": "high",
                                              "citations": cite})
        validation.decide(cfg, "F-0001", "validated", "Analyste A", "vérifié dans pslist")
        validation.decide(cfg, "F-0002", "validated", "Analyste A", "à faire demain")
        await _call(c, "crisis_add_event", _ev("2026-09-29T14:00:00Z", "event", "Alerte EDR"))
        await _call(c, "crisis_add_event", _ev("2026-09-29T14:20:00Z", "action",
                                               "Dump mémoire réalisé", owner="Analyste A"))
        tech = await _call(c, "sitrep_draft", {"audience": "technique", "title": "WS-042"})
        boss = await _call(c, "sitrep_draft", {"audience": "direction"})
        legal = await _call(c, "sitrep_draft", {"audience": "juridique"})
    texts = {}
    for name, r in (("tech", tech), ("boss", boss), ("legal", legal)):
        assert [x["section"] for x in r["rows"]] == list(SECTIONS)
        texts[name] = (Path(cfg.output_root) / r["result_id"] / "sitrep.md").read_text(encoding="utf-8")
        t = texts[name]
        assert "{{" not in t and "BROUILLON" in t
        for h in ("## 1. Situation", "## 2. Impact", "## 3. Actions", "## 4. Prochaines étapes",
                  "## 5. Décisions attendues"):
            assert h in t, (name, h)
        assert "Processus System présent" in t and "Collecter le disque" in t
        assert "Constat encore en attente" not in t      # not validated -> not stated
        assert "F-0003" in t                              # ... but listed as awaiting validation
        assert "Dump mémoire réalisé" in t
    assert rid in texts["tech"] and rid not in texts["boss"]  # detail depends on the audience
    assert "hash de tête du journal" in texts["legal"]
    calls = [e for e in audit.iter_events(cfg.audit_file) if e["type"] == "tool_call"
             and e["tool"] == "sitrep_draft"]
    assert len(calls) == 3 and all(e["outcome"] == "ok" and e.get("sitrep_sha256") for e in calls)


async def test_containment_suggestions_are_never_actions(cfg) -> None:
    data = containment()
    md = (ROOT / "skills" / "playbook-poste-compromis" / "references" / "confinement.md").read_text(
        encoding="utf-8")
    ids = [a["id"] for a in data["common"]] + [a["id"] for t in data["incident_types"].values()
                                                for a in t["actions"]]
    in_md = set(re.findall(r"\| `([a-z_]+)` \|", md)) - set(server.TOOL_NAMES)
    assert len(ids) == len(set(ids)) and in_md == set(ids)
    async with Client(server.build_server(cfg)) as c:
        for itype, spec in data["incident_types"].items():
            r = await _call(c, "containment_suggestions", {"incident_type": itype})
            assert r["row_count"] == len(data["common"]) + len(spec["actions"])
            assert all("à valider" in x["statut"] and "jamais exécutée" in x["statut"]
                       for x in r["rows"])
        tools = {t.name: t for t in (await c.list_tools()).tools}
    assert tools["containment_suggestions"].annotations.read_only_hint is True
    # no tool of the server acts on the infrastructure (CDC: out of scope)
    assert not [t for t in server.TOOL_NAMES
                if re.search(r"isolat|isoler|block|bloquer|disable|reset|quarant|kill", t)]


async def test_crisis_text_is_pseudonymised_in_cloud_mode(cfg) -> None:
    case = Path(cfg.evidence_root) / "WS-042"
    case.mkdir()
    (case / "case.toml").write_text('case = "WS-042"\nclassification = "internal"\n'
                                    'hosts = ["WS-042"]\n')
    cfg.llm_mode = "cloud"
    async with Client(server.build_server(cfg)) as c:
        r = await _call(c, "crisis_add_event", _ev("2026-09-29T14:00:00Z", "event",
                                                   "Poste WS-042 isolé du réseau", case="WS-042"))
        tl = await _call(c, "crisis_timeline", {"case": "WS-042"})
    assert "WS-042" not in r["rows"][0]["description"] and "HOST_" in r["rows"][0]["description"]
    assert "WS-042" not in tl["rows"][0]["description"]
    ev = [e for e in audit.iter_events(cfg.audit_file) if e["type"] == "crisis_event"][0]
    assert ev["description"] == "Poste WS-042 isolé du réseau" and ev["case"] == "WS-042"


def test_template_has_the_five_sections() -> None:
    t = (ROOT / "templates" / "sitrep.md").read_text(encoding="utf-8")
    assert all("{{" + s + "}}" in t for s in SECTIONS)
    assert yaml.safe_load((ROOT / "rules" / "containment.yaml").read_text(encoding="utf-8"))
