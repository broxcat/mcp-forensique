"""Configuration: dataclass, TOML loader and tools.toml launch commands."""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CLASSIFICATIONS = ("lab", "internal", "client")
# Human operator of a server process (ET-04, objective 3: who drove each journaled call).
# MANDATORY: the CLI refuses to start a server without one and Engine.call refuses (and
# journals) any call without one. Declared, not authenticated; distinct from the nominative
# confirmation of sensitive actions. Only per process, never from the shared TOML: stdio
# sessions ONLY by --operator (a container-wide variable would be a shared name), the HTTP
# main process by --operator or FORENSIC_OPERATOR. UNDECLARED_OPERATOR only appears in journaled refusals and in events
# written outside a server process; a declared name can never take that value.
OPERATOR_ENV = "FORENSIC_OPERATOR"
UNDECLARED_OPERATOR = "<undeclared>"
NO_OPERATOR = (f"no human operator declared for this server process: start it with "
               f"--operator \"First Last\" (stdio: only this way) or {OPERATOR_ENV} (HTTP)")
OPERATOR_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{2,80}$")


def check_operator(name: str | None) -> str | None:
    """Normalised operator name, None when absent; ValueError when unusable."""
    if name is None or not name.strip():
        return None
    name = name.strip()
    if not OPERATOR_RE.fullmatch(name):
        raise ValueError("operator must be 2-80 printable characters, without '<' or '>'")
    return name


def operator_of(cfg: "Config") -> str:
    """Operator name written in every journal actor of this process."""
    return cfg.operator or UNDECLARED_OPERATOR


@dataclass
class Config:
    """Server settings (keys match forensic-mcp.docker.toml)."""

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
    timeout_seconds: int = 1800
    max_rows_returned: int = 100
    max_cell_chars: int = 400
    max_response_kb: int = 64          # response size bound (ET-02, §5)
    max_output_mb: int = 1024          # stdout+stderr bound of one tool run (ET-02)
    max_session_output_mb: int = 10240  # persistent output-root budget, shared by processes
    # Data policy (ET-07, confidential-data guardrail): restrictive "cloud" unless a process
    # is explicitly started for a local model (`--llm-mode local`). Never default to "local".
    llm_mode: str = "cloud"            # "cloud" (default) or "local" (explicit only)
    operator: str | None = None        # set by the CLI only (--operator / FORENSIC_OPERATOR)
    default_classification: str = "internal"  # when no case.toml applies
    sleuthkit_dir: Path = Path("/usr/bin")    # mmls, fls, icat (task 4.3c)
    sleuthkit_prefix: list[str] = field(default_factory=list)  # e.g. [python] for test stubs
    max_extract_file_mb: int = 8192           # bound of one file copied by disk_extract
    tshark_dir: Path = Path("/usr/bin")       # tshark, capinfos (task 6.7)
    tshark_prefix: list[str] = field(default_factory=list)     # e.g. [python] for test stubs

    @property
    def audit_file(self) -> Path:
        """The hash-chained journal (§6)."""
        return Path(self.output_root) / "audit.jsonl"


_PATH_KEYS = {"evidence_root", "output_root", "tools_file", "vol3_symbols_dir", "api_token_file",
              "sleuthkit_dir", "tshark_dir"}


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
    if "operator" in raw:
        raise ValueError(f"operator is per process: use --operator or {OPERATOR_ENV}, "
                         "not the configuration file")
    if cfg.default_classification not in CLASSIFICATIONS:
        raise ValueError(f"default_classification must be one of {CLASSIFICATIONS}")
    return cfg


def load_tools(tools_file: str | Path) -> dict[str, list[str]]:
    """Return {tool_name: launch argv prefix} for every tool marked ok in tools.toml."""
    with open(tools_file, "rb") as fh:
        data = tomllib.load(fh)
    return {name: list(t["cmd"]) for name, t in data.get("tools", {}).items() if t.get("ok")}
