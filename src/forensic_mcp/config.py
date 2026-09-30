"""Configuration: dataclass, TOML loader and tools.toml launch commands."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    """Server settings (keys match forensic-mcp.toml)."""

    evidence_root: Path = Path("evidence")
    output_root: Path = Path("output")
    tools_file: Path = Path("tools.toml")
    vol3_symbols_dir: Path | None = None
    http_host: str = "127.0.0.1"
    http_port: int = 8000
    api_token_file: Path = Path("output/api_token")
    allowed_hosts: list[str] = field(
        default_factory=lambda: ["localhost:8000", "127.0.0.1:8000"])
    allowed_origins: list[str] = field(
        default_factory=lambda: ["http://localhost:8000", "http://127.0.0.1:8000"])
    max_upload_gb: int = 64
    timeout_seconds: int = 1800
    max_rows_returned: int = 100
    max_cell_chars: int = 400
    llm_mode: str = "local"


_PATH_KEYS = {"evidence_root", "output_root", "tools_file", "vol3_symbols_dir", "api_token_file"}


def load_config(path: str | Path | None = None) -> Config:
    """Load config from `path`, env FORENSIC_MCP_CONFIG, or defaults if neither exists."""
    path = path or os.environ.get("FORENSIC_MCP_CONFIG")
    if not path:
        return Config()
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)
    unknown = set(raw) - set(Config.__dataclass_fields__)
    if unknown:
        raise ValueError(f"unknown config keys: {sorted(unknown)}")
    for key in _PATH_KEYS & set(raw):
        raw[key] = Path(raw[key])
    cfg = Config(**raw)
    if cfg.llm_mode not in ("local", "cloud"):
        raise ValueError("llm_mode must be 'local' or 'cloud'")
    return cfg


def load_tools(tools_file: str | Path) -> dict[str, list[str]]:
    """Return {tool_name: launch argv prefix} for every tool marked ok in tools.toml."""
    with open(tools_file, "rb") as fh:
        data = tomllib.load(fh)
    return {name: list(t["cmd"]) for name, t in data.get("tools", {}).items() if t.get("ok")}
