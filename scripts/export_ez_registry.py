#!/usr/bin/env python3
"""Write rules/ez_registry.json from the server's EZ registry (used by scripts/run_ez_windows.ps1).
Run in the container: docker compose exec forensic python scripts/export_ez_registry.py"""
from pathlib import Path

from forensic_mcp.engines.ez_registry import registry_json_text

out = Path(__file__).resolve().parents[1] / "rules" / "ez_registry.json"
out.write_text(registry_json_text(), encoding="utf-8")
print(f"wrote {out}")
