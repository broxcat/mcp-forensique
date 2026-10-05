"""P7: eval/score.py on the synthetic WS-042 reference case (tests/scenario_ws042). The session
is the golden conversation (5 true findings accepted, 7 false ones rejected), then two analyst
decisions and a sitrep; the score is checked against the fixture ground truth."""
import importlib.util
import json
import re
from pathlib import Path

import pytest
import yaml
from mcp import Client

from forensic_mcp import audit, server, validation
from scenario_ws042.test_reference_conversation import FAKEBIN, HERE
from scenario_ws042.test_reference_conversation import test_reference_conversation as golden

pytestmark = pytest.mark.anyio
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("score", ROOT / "eval" / "score.py")
score = importlib.util.module_from_spec(spec)
spec.loader.exec_module(score)
GT = HERE / "ground_truth.yaml"


async def _session(cfg) -> list:
    root = Path(cfg.evidence_root) / "WS-042"
    for rel in ("memory/ws042.raw", "kape/Security.evtx"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(b"fixture " + rel.encode())
    (root / "case.toml").write_text('case = "WS-042"\nclassification = "lab"\n')
    tools = Path(cfg.tools_file)
    tools.write_text(tools.read_text().replace(str(FAKEBIN / "vol"), str(HERE / "vol")))
    await golden(cfg)
    validation.decide(cfg, "F-0001", "validated", "Analyste A", "vérifié dans pslist")
    validation.decide(cfg, "F-0003", "validated", "Analyste A", "vérifié dans netscan")
    async with Client(server.build_server(cfg)) as c:
        r = await c.call_tool("sitrep_draft", {"audience": "direction"})
        assert not r.is_error
    return list(audit.iter_events(cfg.audit_file))


async def test_score_on_the_reference_case(cfg) -> None:
    events = await _session(cfg)
    gt = score.load_ground_truth(GT)
    r = score.score(gt, events, output_root=cfg.output_root)
    assert r["tools"]["recall"] == 0.8 and r["tools"]["missing"] == ["mft_search"]
    assert (r["facts"]["expected"], r["facts"]["found"]) == (6, 4)
    assert r["facts"]["recall"] == 0.667 and r["facts"]["precision"] == 1.0
    assert r["facts"]["found_and_validated"] == 2
    found = {(f["step"], f["fact"]): f["findings"] for f in r["facts"]["detail"]}
    assert found[(1, 1)] == ["F-0001"] and found[(5, 1)] == ["F-0003"] and found[(3, 1)] == []
    assert (r["iocs"]["expected"], r["iocs"]["found"]) == (4, 3)
    assert [s["found"] for s in r["steps"]["detail"]] == [True, True, False, False, True]
    assert r["findings"]["total"] == 12 and r["findings"]["accepted_by_server"] == 5
    assert r["findings"]["by_status"] == {"validé": 2, "à valider": 3, "rejeté par le serveur": 7}
    assert r["citations"] == {"total": 15, "valid": 10, "invalid": 5, "valid_rate": 0.667}
    assert r["hallucinations"]["rejected_findings"] == 7 and r["hallucinations"]["rate"] == 0.583
    assert all(h["reasons"] for h in r["hallucinations"]["reasons"])
    t = r["times_s"]
    assert t["to_first_sitrep"] is not None and t["to_first_sitrep"] >= t["to_first_finding"] >= 0
    md = score.render_markdown(r)
    assert "| Rappel des faits (objectif O2 ≥ 80 %) | 67 % |" in md and "À MESURER" not in md


async def test_documentation_completeness_from_the_journal(cfg) -> None:
    """6.3: checklist / findings / sitrep completeness, computed, never estimated."""
    events = await _session(cfg)
    r = score.score(score.load_ground_truth(GT), events, output_root=cfg.output_root)
    c = r["completeness"]
    # checklist: the server's own logic on the journal; case.toml is on disk, not in the journal
    async with Client(server.build_server(cfg)) as cl:
        srv = (await cl.call_tool("checklist_status", {"case": "WS-042"})).structured_content
    want = {x["id"] for x in srv["rows"] if x["statut"] == "fait"} - {"case_folder"}
    ck = c["checklist"]
    assert ck["not_measurable"] == ["case_folder"] and ck["measurable"] == ck["steps"] - 1
    assert ck["done"] == len(want) and not want & set(ck["to_do"])
    assert {"validation", "report", "stakeholders"} <= set(ck["to_do"])
    assert ck["rate"] == round(ck["done"] / ck["measurable"], 3)
    # findings: 5 accepted, all cited, F-0001 and F-0003 validated, 3 pending
    assert c["findings"] == {"accepted": 5, "cited": 5, "validated": 2, "pending": 3,
                             "rejected_by_analyst": 0, "validated_rate": 0.4}
    # sitrep: the server leaves Impact and Décisions attendues "à compléter"
    s = c["sitrep"]
    assert (s["sections"], s["filled"], s["rate"]) == (6, 4, 0.667)
    assert s["to_complete"] == ["2. Impact", "5. Décisions attendues"]
    assert s["edited_after_generation"] is False and s["audience"] == "direction"
    md = score.render_markdown(r)
    assert "| Complétude — sections du sitrep renseignées (sans « à compléter ») | 4 / 6 (67 %)" in md
    # a person completes the sitrep: measured as such, and flagged as edited
    f = Path(cfg.output_root) / s["result_id"] / "sitrep.md"
    f.write_text(f.read_text(encoding="utf-8").replace(
        "À compléter par le responsable de crise : services et métiers touchés, données "
        "concernées, gravité. Le serveur ne qualifie pas l'impact.",
        "Poste WS-042 seul ; pas de donnée sensible identifiée."), encoding="utf-8")
    s2 = score.score(score.load_ground_truth(GT), events,
                     output_root=cfg.output_root)["completeness"]["sitrep"]
    assert s2["filled"] == 5 and s2["edited_after_generation"] is True
    # what cannot be read is reported, not guessed
    no_dir = score.score(score.load_ground_truth(GT), events)["completeness"]["sitrep"]
    assert isinstance(no_dir, str) and no_dir.startswith("À MESURER")
    no_sitrep = [e for e in events if not (e["type"] == "tool_call"
                                           and e["tool"] == "sitrep_draft")]
    assert score.score(score.load_ground_truth(GT), no_sitrep, events,
                       cfg.output_root)["completeness"]["sitrep"].startswith("À MESURER")


async def test_session_window_and_template_never_scored(cfg) -> None:
    events = await _session(cfg)
    first_sugg = next(e["audit_id"] for e in events if e["type"] == "suggestion")
    later = score.window(events, from_id=first_sugg)
    assert later[0]["audit_id"] == first_sugg
    r = score.score(score.load_ground_truth(GT), later, events)
    assert "sitrep_draft" in r["tools"]["called_ok"]
    assert "vol_pslist" not in r["tools"]["called_ok"]  # memory tools ran before the window
    assert r["facts"]["found"] == 4  # results produced before the window still resolve
    template = score.load_ground_truth(ROOT / "eval" / "ground_truth.yaml")
    t = score.score(template, events)
    assert all(isinstance(t[k], str) and t[k].startswith("À MESURER") for k in
               ("tools", "facts", "iocs", "steps"))
    assert "À MESURER" in score.render_markdown(t)


def test_l6_draft_invents_no_result() -> None:
    """Until the timed sessions are played, the L6 results section holds no number."""
    l6 = (ROOT / "docs" / "L6_evaluation.md").read_text(encoding="utf-8")
    results = l6.split("## 6. Résultats")[1].split("## 7.")[0]
    lines = [ln for ln in results.splitlines() if ln.startswith("|")]
    body = [ln for i, ln in enumerate(lines) if not ln.startswith("|---")
            and not (i + 1 < len(lines) and lines[i + 1].startswith("|---"))]  # no header rows
    cells = [c.strip() for ln in body for c in ln.strip("|").split("|")[1:]]
    assert len(cells) > 30 and not [c for c in cells if c != "—" and "À MESURER" not in c]
    assert "À MESURER" in (ROOT / "docs" / "L7_note_risques.md").read_text(encoding="utf-8") or \
        "À COMPLÉTER APRÈS L6" in (ROOT / "docs" / "L7_note_risques.md").read_text(encoding="utf-8")


def test_l7_junior_overconfidence_is_its_own_risk() -> None:
    """6.3: the junior analyst's over-confidence is a risk of its own, observed facts kept
    apart from hypotheses, with mitigation and residual, and listed in the synthesis."""
    l7 = (ROOT / "docs" / "L7_note_risques.md").read_text(encoding="utf-8")
    sec = re.search(r"^## (\d+)\. Sur-confiance de l'analyste junior\n(.*?)^## ", l7, re.M | re.S)
    assert sec, "L7: no section on the junior analyst's over-confidence"
    body = sec.group(2)
    heads = ["**Risque.**", "**Observé.**", "**Hypothèses (non observées", "**Parade (en place).**",
             "**Résiduel.**"]
    pos = [body.find(h) for h in heads]
    assert -1 not in pos and pos == sorted(pos), dict(zip(heads, pos))
    observed = body[pos[1]:pos[2]]
    assert "Aucune session avec un analyste junior" in observed  # no invented observation
    synth = l7.split("Synthèse")[-1]
    assert f"(§{sec.group(1)})" in synth and "junior" in synth


async def test_cli(cfg, tmp_path) -> None:
    await _session(cfg)
    out = tmp_path / "score.json"
    assert score.main(["--ground-truth", str(GT), "--journal", str(cfg.audit_file),
                       "--json", str(out), "--markdown", str(tmp_path / "score.md")]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["facts"]["found"] == 4 and data["journal"]["head_hash"]
    assert "Hallucinations" in (tmp_path / "score.md").read_text(encoding="utf-8")
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"format": "x"}))
    assert score.main(["--ground-truth", str(bad), "--journal", str(cfg.audit_file)]) == 2
    assert score.main(["--ground-truth", str(GT), "--journal", str(cfg.audit_file),
                       "--from-audit-id", "99999"]) == 2
