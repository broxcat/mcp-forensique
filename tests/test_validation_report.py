"""Analyst validation (out of band) and report export (CDC §5: human validation, over-confidence,
traceability, chain of evidence)."""
import re
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import Client

from forensic_mcp import audit, schemas, server, validation

pytestmark = pytest.mark.anyio
SRC = Path(__file__).resolve().parents[1] / "src" / "forensic_mcp"


async def _call(cfg, tool, args, ok=True):
    async with Client(server.build_server(cfg)) as c:
        r = await c.call_tool(tool, args)
    if r.is_error:
        assert not ok, r.content[0].text
        return r.content[0].text
    assert schemas.errors(schemas.output_validator(), r.structured_content) == []
    return r.structured_content


async def _three_findings(cfg) -> dict:
    """F-0001 and F-0002 accepted (à valider), F-0003 rejected by the server."""
    ps = await _call(cfg, "vol_pslist", {"path": "mem.raw"})
    row = next(r for r in ps["rows"] if r["PID"] == 4312)
    cite = {"result_id": ps["result_id"], "row": row["_row"], "field": "PPID"}
    for text, value in (("powershell started by PID 2980", 2980),
                        ("powershell has parent 2980 (second statement)", 2980),
                        ("invented parent", 1)):
        await _call(cfg, "record_finding", {"kind": "fact", "text": text, "confidence": "high",
                                            "citations": [{**cite, "value": value}]})
    return ps


def _events(cfg, t):
    return [e for e in audit.iter_events(cfg.audit_file) if e["type"] == t]


# ---- the model cannot reach validation ------------------------------------------------------
def test_no_mcp_path_writes_a_validation() -> None:
    assert not [t for t in server.TOOL_NAMES if "valid" in t]
    for p in SRC.rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        if p.name not in ("validation.py", "__main__.py"):
            assert not re.search(r"from \.validation import|import validation|forensic_mcp\.validation",
                                 text), p.name
            assert not re.search(r"append\([^)]*\"validation\"", text), p.name
    code = ("import sys; import forensic_mcp.server as s; s.build_server(); "
            "print('forensic_mcp.validation' in sys.modules)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"  # building the MCP server never loads validation


async def test_mcp_calls_never_produce_a_validation(cfg) -> None:
    await _three_findings(cfg)
    await _call(cfg, "list_findings", {"status": "validé"})
    await _call(cfg, "report_export", {"final": False})
    await _call(cfg, "report_export", {"final": True}, ok=False)
    assert _events(cfg, "validation") == []


# ---- CLI ------------------------------------------------------------------------------------
async def test_cli_refuses_without_a_terminal(cfg) -> None:
    await _three_findings(cfg)
    said: list[str] = []
    rc = validation.run_cli(cfg, ask=lambda q: "x", say=said.append, interactive=lambda: False)
    assert rc == 2 and "terminal interactif" in said[0] and _events(cfg, "validation") == []


async def test_cli_decisions_are_chained_and_nothing_is_deleted(cfg) -> None:
    await _three_findings(cfg)
    answers = iter(["L. Plancke", "1", "v", "valeurs recontrôlées", "o",
                    "1", "r", "doublon de F-0001", "o", "F-0003", "v",
                    "F-0003", "r", "finding de test", "o", "q"])
    said: list[str] = []
    rc = validation.run_cli(cfg, ask=lambda q: next(answers), say=said.append,
                            interactive=lambda: True)
    assert rc == 0
    out = "\n".join(said)
    assert "valeur actuelle '2980'" in out and "contrôle ok" in out
    assert re.search(r"\[1\] F-0001", out)  # the pending list format this assertion relies on
    assert not re.search(r"\[\d+\] F-0003", out)  # server-rejected: never offered as pending
    ev = _events(cfg, "validation")
    assert [(e["finding_id"], e["decision"], e["actor"]["name"], e["comment"]) for e in ev] == [
        ("F-0001", "validated", "L. Plancke", "valeurs recontrôlées"),
        ("F-0002", "rejected", "L. Plancke", "doublon de F-0001"),
        ("F-0003", "rejected", "L. Plancke", "finding de test")]  # validating F-0003 was refused
    assert "seul [r] rejeter est possible" in out
    assert audit.verify_report(cfg.audit_file)["ok"]  # chained and schema-valid
    listing = await _call(cfg, "list_findings", {})
    assert {r["finding_id"]: r["status"] for r in listing["rows"]} == {
        "F-0001": "validé", "F-0002": "rejeté", "F-0003": "rejeté"}


async def test_cli_server_rejected_offers_only_reject(cfg) -> None:
    """A server-rejected finding: only [r] / [q]; no reason or confirmation is asked for an
    impossible action. An invalid first answer recalls the expected formats."""
    await _three_findings(cfg)
    prompts: list[str] = []
    answers = iter(["L. Plancke", "win-10lab", "r", "F-0003", "v", "F-0003", "q",
                    "F-0003", "r", "finding de test", "o", "q"])

    def ask(q: str) -> str:
        prompts.append(q)
        return next(answers)

    said: list[str] = []
    assert validation.run_cli(cfg, ask=ask, say=said.append, interactive=lambda: True) == 0
    out = "\n".join(said)
    expected = "Formats attendus : un numéro de la liste (1 à 2), un identifiant F-NNNN"
    assert out.count(expected) == 2  # "win-10lab" and "r" at the first prompt
    menus = [p for p in prompts if p.startswith("Rejeté par le serveur")]
    assert len(menus) == 3 and all("[r] rejeter, [q] retour" in p and "[v]" not in p for p in menus)
    assert not any(p.startswith("Décision") for p in prompts)  # no [v]/[a] menu for F-0003
    assert sum(p.startswith("Motif") for p in prompts) == 1      # only for the real rejection
    assert sum(p.startswith("Confirmer") for p in prompts) == 1
    assert "seul [r] rejeter est possible" in out and "Refusé" not in out
    ev = _events(cfg, "validation")
    assert [(e["finding_id"], e["decision"], e["comment"]) for e in ev] == [
        ("F-0003", "rejected", "finding de test")]


async def test_decide_refusals_and_to_review(cfg) -> None:
    await _three_findings(cfg)
    bad = [("F-0003", "validated", "L. Plancke", "ok ok"), ("F-9999", "validated", "L. P", "motif"),
           ("F-0001", "validated", "", "motif"), ("F-0001", "validated", "L. P", ""),
           ("F-0001", "approved", "L. P", "motif")]
    for args in bad:
        with pytest.raises(validation.ValidationError):
            validation.decide(cfg, *args)
    validation.decide(cfg, "F-0003", "rejected", "L. Plancke", "finding de test")  # annotation
    validation.decide(cfg, "F-0001", "to_review", "W. Triffault", "citation à vérifier")
    listing = await _call(cfg, "list_findings", {"status": "à revoir"})
    assert [r["finding_id"] for r in listing["rows"]] == ["F-0001"]


# ---- report ---------------------------------------------------------------------------------
async def test_report_draft_final_refusal_then_final(cfg) -> None:
    await _three_findings(cfg)
    draft = await _call(cfg, "report_export", {"final": False, "title": "WS-042"})
    md = (Path(cfg.output_root) / draft["result_id"] / "report.md").read_text(encoding="utf-8")
    assert "BROUILLON" in md and md.count("**NON VALIDÉ**") == 2 and "F-0003" not in md
    head = re.search(r"Hash de tête du journal : `([0-9a-f]{64})`", md).group(1)
    assert len(head) == 64
    refused = await _call(cfg, "report_export", {"final": True}, ok=False)
    assert "export final refusé" in refused and "F-0001 (à valider)" in refused
    assert "F-0002 (à valider)" in refused and "python -m forensic_mcp validate" in refused
    validation.decide(cfg, "F-0001", "validated", "L. Plancke", "conforme")
    validation.decide(cfg, "F-0002", "to_review", "L. Plancke", "à revoir")
    still = await _call(cfg, "report_export", {"final": True}, ok=False)
    assert "F-0002 (à revoir)" in still and "F-0001" not in still
    validation.decide(cfg, "F-0002", "rejected", "L. Plancke", "doublon")
    final = await _call(cfg, "report_export", {"final": True})
    md = (Path(cfg.output_root) / final["result_id"] / "report.md").read_text(encoding="utf-8")
    assert "(FINAL)" in md and "NON VALIDÉ" not in md
    assert "### F-0001" in md and "### F-0002" not in md and "doublon" in md
    assert "validé par L. Plancke" in md and "mem.raw" in md
    after = _events(cfg, "evidence_verified")
    assert after and after[-1]["stage"] == "after" and after[-1]["matches_registration"]
    head = re.search(r"Hash de tête du journal : `([0-9a-f]{64})`", md).group(1)
    lines = [ln for ln in (Path(cfg.audit_file)).read_text().splitlines() if head in ln]
    assert lines, "the head hash written in the report is a real journal hash"
    call = [e for e in _events(cfg, "tool_call") if e["tool"] == "report_export"][-1]
    assert call["outcome"] == "ok" and call["head_hash"] == head and call["final"] is True


async def test_final_refused_when_evidence_changed(cfg) -> None:
    await _three_findings(cfg)
    validation.decide(cfg, "F-0001", "validated", "L. Plancke", "ok ok")
    validation.decide(cfg, "F-0002", "rejected", "L. Plancke", "ok ok")
    with open(Path(cfg.evidence_root) / "mem.raw", "ab") as fh:
        fh.write(b"tampered")
    refused = await _call(cfg, "report_export", {"final": True}, ok=False)
    assert "preuve modifiée" in refused and "mem.raw" in refused
