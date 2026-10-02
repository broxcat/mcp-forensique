"""Skill "playbook poste compromis" (P5, ET-06): the triage tree data (EF-09) and the MCP prompt
and resources that hand SKILL.md and its references to clients without skill support (local
model, ET-07). The prompt returns SKILL.md only by default (bounded size, 5.3); each reference
is a section asked explicitly, also readable as the resource playbook://references/<section>."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
TREE = ROOT / "rules" / "triage_tree.yaml"
SKILL_DIR = ROOT / "skills" / "playbook-poste-compromis"
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SECTIONS = {"artefacts": "interpretation_artefacts.md", "citations": "regles_citation.md",
            "checklist": "checklist_collecte.md", "arbre": "arbre_triage.md",
            "confinement": "confinement.md"}
MAX_DEFAULT_CHARS = 6000


@lru_cache(maxsize=None)
def tree() -> list[dict[str, Any]]:
    """Branches of rules/triage_tree.yaml."""
    return yaml.safe_load(TREE.read_text(encoding="utf-8"))["branches"]


def tree_attack_ids() -> set[str]:
    return {a for b in tree() for q in b["questions"] for a in q["attack"]}


def section_text(section: str) -> str:
    """One reference of the skill, by section name."""
    if section not in SECTIONS:
        raise ValueError(f"section must be one of {sorted(SECTIONS)}")
    return (SKILL_DIR / "references" / SECTIONS[section]).read_text(encoding="utf-8").strip()


def render(case: str, section: str | None = None) -> str:
    """SKILL.md (frontmatter dropped) by default, or one reference; <HÔTE> set to the case."""
    case = case.strip().strip("/")
    if case and not HOST_RE.match(case):
        raise ValueError("case must be a host folder name (letters, digits, . _ -)")
    if section:
        text = section_text(section)
    else:
        skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        body = skill.split("---", 2)[2].strip() if skill.startswith("---") else skill
        text = body + "\n\n---\nSections (à demander au besoin) : " + ", ".join(
            f"`{s}`" for s in SECTIONS) + " — prompt `playbook_poste_compromis(case, section)` " \
            "ou ressource `playbook://references/<section>`."
    head = f"Cas : `{case}`.\n\n" if case else ""
    return head + text.replace("<HÔTE>", case or "<HÔTE>")
