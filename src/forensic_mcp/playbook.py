"""Skill "playbook poste compromis" (P5, ET-06): the triage tree data (EF-09) and the MCP prompt
that hands SKILL.md + its references to clients without skill support (local model, ET-07)."""
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


@lru_cache(maxsize=None)
def tree() -> list[dict[str, Any]]:
    """Branches of rules/triage_tree.yaml."""
    return yaml.safe_load(TREE.read_text(encoding="utf-8"))["branches"]


def tree_attack_ids() -> set[str]:
    return {a for b in tree() for q in b["questions"] for a in q["attack"]}


def render(case: str) -> str:
    """SKILL.md (frontmatter dropped) + every reference, with <HÔTE> set to the case folder."""
    case = case.strip().strip("/")
    if case and not HOST_RE.match(case):
        raise ValueError("case must be a host folder name (letters, digits, . _ -)")
    skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    parts = [skill.split("---", 2)[2].strip() if skill.startswith("---") else skill]
    for ref in sorted((SKILL_DIR / "references").glob("*.md")):
        parts.append(f"<!-- references/{ref.name} -->\n" + ref.read_text(encoding="utf-8").strip())
    text = "\n\n---\n\n".join(parts)
    head = f"Cas : `{case}`.\n\n" if case else ""
    return head + text.replace("<HÔTE>", case or "<HÔTE>")
