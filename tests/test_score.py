"""P7: eval/score.py on the synthetic WS-042 reference case (tests/scenario_ws042). The session
is the golden conversation (5 true findings accepted, 7 false ones rejected), then two analyst
decisions and a sitrep; the score is checked against the fixture ground truth."""
import importlib.util
import json
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
    r = score.score(gt, events)
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
