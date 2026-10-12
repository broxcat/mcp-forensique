"""Inventory of what the MCP server really exposes (task 6.4): tools/list, prompts/list and
resources/list asked to the server through an in-memory MCP client, never written from memory.

Per tool, from the SERVER: name, description, typed parameters, read-only hint, class
(read / journal / action_on_demand). From docs/tool_catalog.yaml (reviewed by hand, checked
against the server by tests/test_inventory.py): category, French one-line purpose, the journal
events it writes besides its own `tool_call`, Windows-only import.

  python scripts/tool_inventory.py            # French Markdown tables (README section)
  python scripts/tool_inventory.py --json     # full inventory (descriptions, schemas)
  python scripts/tool_inventory.py --write    # rewrite the block between the README markers
  python scripts/tool_inventory.py --check    # exit 1 if the README block is out of date
Run inside the container (docker compose exec forensic python scripts/tool_inventory.py).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from mcp import Client

from forensic_mcp import server

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs" / "tool_catalog.yaml"
README = ROOT / "README.md"
BEGIN = "<!-- tools:begin (généré par scripts/tool_inventory.py --write, ne pas éditer) -->"
END = "<!-- tools:end -->"
CLASS_FR = {"read": "lecture seule", "journal": "écrit au journal",
            "action_on_demand": "sensible : confirmation d'un analyste nommé"}


def catalog() -> dict[str, Any]:
    return yaml.safe_load(CATALOG.read_text(encoding="utf-8"))


def _type(spec: dict[str, Any]) -> str:
    """Short type of one JSON Schema property (enum values kept, null = optional)."""
    if "enum" in spec:
        vals = [str(v) for v in spec["enum"]]
        return " \\| ".join(vals) if len(vals) <= 6 else f"liste fermée de {len(vals)} valeurs"
    if "anyOf" in spec:
        return " \\| ".join(dict.fromkeys(_type(s) for s in spec["anyOf"]
                                         if s.get("type") != "null"))
    if spec.get("type") == "array":
        return f"liste de {_type(spec.get('items', {}))}"
    if "$ref" in spec:
        return spec["$ref"].rsplit("/", 1)[-1]
    return {"string": "texte", "integer": "entier", "boolean": "booléen", "number": "nombre",
            "object": "objet"}.get(spec.get("type", ""), spec.get("type", "?"))


async def inventory(cfg: Any = None) -> dict[str, Any]:
    """Ask the server (in-memory client) what it exposes."""
    async with Client(server.build_server(cfg)) as c:
        tools = (await c.list_tools()).tools
        prompts = (await c.list_prompts()).prompts
        resources = (await c.list_resources()).resources
    out_tools = []
    for t in tools:
        schema = t.input_schema or {}
        required = set(schema.get("required", []))
        out_tools.append({
            "name": t.name, "description": " ".join((t.description or "").split()),
            "class": server.TOOL_CLASSES[t.name],
            "read_only": bool(t.annotations and t.annotations.read_only_hint),
            "parameters": [{"name": k, "type": _type(v), "required": k in required,
                            **({"default": v["default"]} if "default" in v else {})}
                           for k, v in schema.get("properties", {}).items()]})
    return {"tool_count": len(out_tools), "tools": out_tools,
            "prompts": [{"name": p.name, "description": p.description,
                         "arguments": [a.name for a in (p.arguments or [])]} for p in prompts],
            "resources": [{"uri": str(r.uri), "name": r.name} for r in resources]}


def render(inv: dict[str, Any], cat: dict[str, Any]) -> str:
    """French Markdown: one table per category, one row per tool."""
    by_name = {t["name"]: t for t in inv["tools"]}
    lines = [f"**{inv['tool_count']} outils**, {len(inv['prompts'])} prompt, "
             f"{len(inv['resources'])} ressources (liste demandée au serveur). `*` = paramètre "
             "obligatoire. Chaque appel qui atteint le serveur, réussi, refusé ou en échec, "
             "écrit un `tool_call` au journal ; la colonne « Journal » donne ce qui s'y ajoute.",
             ""]
    for c in cat["categories"]:
        lines += [f"### {c['title']}", "", c["description"], "",
                  "| Outil | Rôle | Paramètres | Classe | Journal (en plus de `tool_call`) |",
                  "|---|---|---|---|---|"]
        for name in c["tools"]:
            t, meta = by_name[name], cat["tools"][name]
            # limit + offset = paging only when the tool has both (vol3_run's `offset` is a
            # memory address, not a page)
            is_paged = {"limit", "offset"} <= {p["name"] for p in t["parameters"]}
            params = ", ".join(f"`{p['name']}{'*' if p['required'] else ''}` ({p['type']})"
                               for p in t["parameters"]
                               if not (is_paged and p["name"] in ("limit", "offset"))) or "—"
            paged = " ; pagination `limit`, `offset`" if is_paged else ""
            cls = CLASS_FR[t["class"]] + (" ; import Windows" if meta.get("windows_only")
                                          else "")
            lines.append(f"| `{name}` | {meta['role']} | {params}{paged} | {cls} | "
                         f"{meta.get('journal') or '—'} |")
        lines.append("")
    lines += ["Prompt : " + ", ".join(f"`{p['name']}({', '.join(p['arguments'])})`"
                                      for p in inv["prompts"]) + ". Ressources : "
              + ", ".join(f"`{r['uri']}`" for r in inv["resources"]) + "."]
    return "\n".join(lines)


def readme_block(text: str) -> str:
    return text.split(BEGIN, 1)[1].split(END, 1)[0].strip("\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Inventory of the MCP server (6.4).")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--json", action="store_true")
    g.add_argument("--write", action="store_true")
    g.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    inv = asyncio.run(inventory())
    if a.json:
        print(json.dumps(inv, ensure_ascii=False, indent=1))
        return 0
    block = render(inv, catalog())
    if a.write or a.check:
        text = README.read_text(encoding="utf-8")
        if a.check:
            ok = readme_block(text) == block
            print("README tool tables: " + ("up to date" if ok else "OUT OF DATE"))
            return 0 if ok else 1
        head, rest = text.split(BEGIN, 1)
        README.write_text(head + BEGIN + "\n" + block + "\n" + END + rest.split(END, 1)[1],
                          encoding="utf-8", newline="\n")
        print(f"README updated: {inv['tool_count']} tools")
        return 0
    print(block)
    return 0


if __name__ == "__main__":
    sys.exit(main())
