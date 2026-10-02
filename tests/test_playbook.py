"""Task 5.1: skill "playbook poste compromis" — checklist (EF-08) derived from the journal,
triage tree (EF-09) tied to real tools and accepted ATT&CK IDs, MCP prompt (ET-06/ET-07)."""
import re
from pathlib import Path

import pytest
import yaml
from mcp import Client

from forensic_mcp import playbook, schemas, server
from forensic_mcp.checklist_ops import checklist
from forensic_mcp.findings_ops import ATTACK_RE, known_attack_ids

pytestmark = pytest.mark.anyio
ROOT = Path(__file__).resolve().parents[1]
REFS = ROOT / "skills" / "playbook-poste-compromis" / "references"


async def _call(c, tool, args):
    r = await c.call_tool(tool, args)
    assert not r.is_error, r.content[0].text
    assert schemas.errors(schemas.output_validator(), r.structured_content) == []
    return r.structured_content


def test_checklist_yaml_matches_reference_and_tools() -> None:
    md = (REFS / "checklist_collecte.md").read_text(encoding="utf-8")
    ids = [s["id"] for s in checklist()]
    assert len(ids) == len(set(ids)) == 21
    assert set(re.findall(r"\| `([a-z_]+)` \|", md)) == set(ids)
    for s in checklist():
        assert s["phase"] and s["label"] and s["detect"]["type"] in (
            "case_toml", "registered", "tool_call", "findings", "decided", "report_final")
        for t in s["detect"].get("tools", []):
            assert t in server.TOOL_NAMES, (s["id"], t)


def test_triage_tree_tools_and_attack_ids() -> None:
    md = (REFS / "arbre_triage.md").read_text(encoding="utf-8")
    ids = playbook.tree_attack_ids()
    assert {b["id"] for b in playbook.tree()} == {
        "execution", "persistence", "lateral_movement", "exfiltration", "defense_evasion"}
    assert all(ATTACK_RE.match(a) for a in ids)
    assert ids == set(re.findall(r"T\d{4}(?:\.\d{3})?", md))  # YAML and French doc in sync
    assert ids <= known_attack_ids()  # record_finding accepts the tree's IDs
    for b in playbook.tree():
        for q in b["questions"]:
            assert q["tools"] and all(t in server.TOOL_NAMES for t in q["tools"]), q["q"]
            for t in q["tools"]:
                assert f"`{t}`" in md, t


async def test_checklist_status_from_journal(cfg) -> None:
    ev = Path(cfg.evidence_root)
    (ev / "WS-042" / "memory").mkdir(parents=True)
    (ev / "WS-042" / "memory" / "mem.raw").write_bytes(b"\1" * 64)
    (ev / "WS-042" / "case.toml").write_text('case = "WS-042"\nclassification = "lab"\n')
    (ev / "WS-099").mkdir()
    async with Client(server.build_server(cfg)) as c:
        empty = await _call(c, "checklist_status", {"case": "WS-042"})
        assert empty["summary"].startswith("1/21")  # only case.toml
        r = await _call(c, "vol_pslist", {"path": "WS-042/memory/mem.raw"})
        await _call(c, "vol_cmdline", {"path": "WS-042/memory/mem.raw"})
        await _call(c, "query_results", {"result_id": r["result_id"], "limit": 1})  # same rid
        await _call(c, "record_finding", {
            "kind": "fact", "text": "System is PID 4", "confidence": "high",
            "citations": [{"result_id": r["result_id"], "row": 1, "field": "PID", "value": 4}]})
        st = await _call(c, "checklist_status", {"case": "WS-042"})
        other = await _call(c, "checklist_status", {"case": "WS-099"})
        bad = await c.call_tool("checklist_status", {"case": "../etc"})
    rows = {x["id"]: x for x in st["rows"]}
    assert {k for k, x in rows.items() if x["statut"] == "fait"} == {
        "case_folder", "memory_acquired", "mem_processes", "mem_cmdline", "findings"}
    assert "audit_id" in rows["mem_processes"]["preuve"]
    assert rows["validation"]["statut"] == "à faire" and "F-0001" in rows["validation"]["preuve"]
    assert rows["memory_acquired"]["qui"] == "analyste"
    assert st["next_steps"][0]["tool"] == "vol_netscan"
    assert all(x["statut"] == "à faire" for x in other["rows"])  # per case, not global
    assert bad.is_error


async def test_playbook_prompt() -> None:
    async with Client(server.build_server()) as c:
        prompts = {p.name for p in (await c.list_prompts()).prompts}
        assert "playbook_poste_compromis" in prompts
        got = await c.get_prompt("playbook_poste_compromis", {"case": "WS-042"})
    text = got.messages[0].content.text
    assert text.startswith("Cas : `WS-042`") and "<HÔTE>" not in text
    assert "checklist_status" in text and "T1053.005" in text and "name:" not in text.split("\n")[2]
    with pytest.raises(ValueError):
        playbook.render("../x")


def test_references_5_2_use_real_tools_and_allowed_attack_ids() -> None:
    interp = (REFS / "interpretation_artefacts.md").read_text(encoding="utf-8")
    rules = (REFS / "regles_citation.md").read_text(encoding="utf-8")
    tools = {t for line in interp.splitlines() if line.startswith("**Outils :**")
             for t in re.findall(r"`([a-z0-9_]+)`", line)}
    tools |= set(re.findall(r"\*\*Outils :\*\* `([a-z_]+)`", interp))
    assert len(tools) >= 15 and tools <= set(server.TOOL_NAMES), tools - set(server.TOOL_NAMES)
    for text in (interp, rules):  # the skill never teaches an ID record_finding would reject
        ids = set(re.findall(r"T\d{4}(?:\.\d{3})?", text))
        assert ids and ids <= known_attack_ids(), ids - known_attack_ids()
    # the documented matching rules are the server's
    from forensic_mcp.findings_ops import PARTIAL_MIN_CELL, PARTIAL_MIN_VALUE
    assert f"≥ {PARTIAL_MIN_CELL} caractères" in rules and f"≥ {PARTIAL_MIN_VALUE}" in rules
    for kind in ("`fact`", "`hypothesis`", "`recommendation`", "`high`", "`medium`", "`low`"):
        assert kind in rules
    skill = (ROOT / "skills" / "playbook-poste-compromis" / "SKILL.md").read_text(encoding="utf-8")
    for ref in REFS.glob("*.md"):
        assert f"references/{ref.name}" in skill, ref.name


def test_skill_frontmatter() -> None:
    skill = (ROOT / "skills" / "playbook-poste-compromis" / "SKILL.md").read_text(encoding="utf-8")
    front = yaml.safe_load(skill.split("---")[1])
    assert front["name"] == "playbook-poste-compromis" and len(front["description"]) > 50
