"""Task 6.4: the README lists what the server really exposes. The tables are generated from
tools/list (scripts/tool_inventory.py) and docs/tool_catalog.yaml; these tests fail when the
README, the catalog or tool_status no longer match the server."""
import importlib.util
import json
import re
from pathlib import Path

import pytest
from mcp import Client

from forensic_mcp import schemas, server

pytestmark = pytest.mark.anyio
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tool_inventory", ROOT / "scripts" / "tool_inventory.py")
inv_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inv_mod)
README = (ROOT / "README.md").read_text(encoding="utf-8")
CATEGORY_WORDS = ["Socle", "Volatility 3", "Volatility 2", "Zimmerman", "disque", "Constats",
                  "crise", "parties prenantes"]


async def test_readme_tool_tables_are_the_servers(cfg) -> None:
    inv = await inv_mod.inventory(cfg)
    cat = inv_mod.catalog()
    names = [t["name"] for t in inv["tools"]]
    assert inv["tool_count"] == len(names) == len(server.TOOL_NAMES) == 51
    # the README block is exactly what the server + catalog generate (fails when out of date)
    block = inv_mod.readme_block(README)
    assert block == inv_mod.render(inv, cat), \
        "README out of date: run `python scripts/tool_inventory.py --write` in the container"
    # one row per server tool, no other tool name in the tables
    rows = re.findall(r"^\| `([a-z0-9_]+)` \|", block, re.M)
    assert sorted(rows) == sorted(names) and len(rows) == len(set(rows))
    # every count stated in the README is the server's
    assert f"**{len(names)} outils**, {len(inv['prompts'])} prompt, " \
           f"{len(inv['resources'])} ressources" in block
    stated = re.findall(r"\((\d+)\s+pour cette version\)", README)
    assert stated == [str(len(names))]
    assert all(f"`{r['uri']}`" in block for r in inv["resources"])
    assert "`playbook_poste_compromis(case, section)`" in block


async def test_catalog_matches_the_server(cfg) -> None:
    inv = await inv_mod.inventory(cfg)
    cat = inv_mod.catalog()
    by = {t["name"]: t for t in inv["tools"]}
    listed = [n for c in cat["categories"] for n in c["tools"]]
    assert sorted(listed) == sorted(by) == sorted(cat["tools"])  # each tool once, none invented
    # the eight categories, each with its description, as headings of the README block
    block = inv_mod.readme_block(README)
    assert len(cat["categories"]) == len(CATEGORY_WORDS)
    for c, word in zip(cat["categories"], CATEGORY_WORDS):
        assert word.lower() in c["title"].lower(), (c["title"], word)
        assert len(c["description"]) > 30 and c["tools"]
        assert f"### {c['title']}\n\n{c['description']}\n" in block
    # catalog facts that can be checked against the server
    events = set(json.loads((ROOT / "docs" / "audit_schema.json").read_text(encoding="utf-8"))
                 ["$defs"]["event"]["properties"]["type"]["enum"])
    for name, meta in cat["tools"].items():
        assert len(meta["role"]) > 15, name
        cited = set(re.findall(r"`([a-z_]+)`", meta.get("journal") or "")) & events
        assert bool(meta.get("journal")) == bool(cited), name  # journal text names real events
        sensitive = "action_request" in (meta.get("journal") or "")
        assert sensitive == (by[name]["class"] == "action_on_demand"), name
        assert by[name]["read_only"] == (by[name]["class"] == "read"), name
        if by[name]["class"] == "journal":
            assert meta.get("journal") or name in ("report_export", "sitrep_draft"), name
    assert {n for n, m in cat["tools"].items() if m.get("windows_only")} == {
        "ez_import", "prefetch_query", "browser_history", "srum_query"}
    assert "verify_audit" not in by  # asked for in 6.4: not a tool of this server


async def test_tool_status_says_what_is_running(cfg) -> None:
    async with Client(server.build_server(cfg)) as c:
        r = (await c.call_tool("tool_status", {})).structured_content
    assert schemas.errors(schemas.output_validator(), r) == []
    m = re.search(r"server: (\d+) MCP tools, code (\S+)(?: \(\S+\))?, started (\S+), llm_mode (\w+)",
                  r["summary"])
    assert m, r["summary"]
    assert int(m.group(1)) == len(server.TOOL_NAMES)
    assert re.fullmatch(r"[0-9a-f]{12}|unknown", m.group(2))
    assert m.group(4) == cfg.llm_mode and r["notes"][0] in r["summary"]
    head = ROOT / ".git" / "HEAD"
    if head.is_file():  # in a clone the commit is read, not "unknown"
        assert m.group(2) != "unknown"


def test_readme_sections_and_no_secret() -> None:
    for heading in ("## 2. Installation", "## 3. Un seul dossier de déploiement",
                    "## 4. Clients et modes LLM", "## 5. Outils disponibles",
                    "## 6. Hors serveur MCP", "## 7. Outils Eric Zimmerman Windows-only",
                    "## 8. Limites connues", "## 9. Modèle de sécurité", "## 10. Tests",
                    "## 11. Versions épinglées"):
        assert heading in README, heading
    for needle in ("COMPOSE_PROJECT_NAME", "EVIDENCE_DIR", "templates/analysis-workspace",
                   "docker inspect forensic-mcp", "tool_status", "validate",
                   "run_ez_windows.ps1", "register_evidence.py", "eval/score.py", "ez_import",
                   "ne prouve pas quel binaire", "Hasher", 'kind="observation"',
                   "n'envoie jamais de message", "hors MCP", "rules/ez_zips.sha256",
                   "échoue\nvolontairement"):
        assert needle in README, needle
    # what the README says about files of the repository is true
    for path in re.findall(r"\]\(([^)#:]+)\)", README):
        assert (ROOT / path).exists(), path
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "COMPOSE_PROJECT_NAME=forensic-mcp" in example
    for var in re.findall(r"^\| `([A-Z_]+)` \|", README, re.M):
        assert var in example, var
    n_zips = len((ROOT / "rules" / "ez_zips.sha256").read_text(encoding="utf-8").split()) // 2
    assert n_zips == 17 and "17 outils EZ" in README
    # no secret: nothing that looks like a token or a key value
    assert not re.search(r"Bearer [A-Za-z0-9_-]{16,}|WEBUI_SECRET_KEY\s*=|[0-9a-f]{40,}", README)
