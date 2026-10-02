"""Fake Windows exports, built like scripts/run_ez_windows.ps1 writes them (manifest format 1)."""
import hashlib
import json
from pathlib import Path

from forensic_mcp.engines.ez_registry import registry_json_text
from forensic_mcp.import_ops import FORMAT, content_digest


def jsonl(rows: list[dict]) -> bytes:
    """JSON lines with a UTF-8 BOM, like the real EvtxECmd / EZ --json output."""
    return ("\ufeff" + "".join(json.dumps(r) + "\n" for r in rows)).encode("utf-8")


def make_export(evidence_root: Path, host: str, tool: str, input_rel: str,
                files: dict[str, bytes], stamp: str = "20261006T150000Z",
                **overrides: object) -> str:
    """Write <root>/<host>/ez_out/<tool>_<stamp>/{out/..., manifest.json}; return its rel path."""
    root = Path(evidence_root)
    export = root / host / "ez_out" / f"{tool}_{stamp}"
    (export / "out").mkdir(parents=True)
    listed = []
    for name, data in files.items():
        f = export / "out" / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(data)
        listed.append({"file": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    manifest = {
        "format": FORMAT, "tool": tool, "tool_version": "1.5.1.0", "tool_exe_sha256": "e" * 64,
        "tool_signature": "Valid", "host": host,
        "input": {"path": input_rel, "kind": "folder" if (root / input_rel).is_dir() else "file",
                  "sha256": content_digest(root / input_rel)},
        "argv": [tool, "-d", f"C:\\cases\\{input_rel}", "--json", "C:\\cases\\out", "-q"],
        "output_format": "--json", "outputs": listed,
        "started_utc": "2026-10-06T15:00:00.000Z", "finished_utc": "2026-10-06T15:00:03.000Z",
        "exit_code": 0, "stdout_tail": "Processed 2 files", "stderr_tail": "",
        "script": "run_ez_windows.ps1", "script_version": "1",
        "registry_sha256": hashlib.sha256(registry_json_text().encode()).hexdigest(),
        "analyst": "lplancke", "workstation": "ANALYST-PC"}
    manifest.update(overrides)
    (export / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return f"{host}/ez_out/{tool}_{stamp}"
