"""ET-07 / confidential-data guardrail: the data policy is restrictive (cloud) unless a process
is explicitly started for a local model. These tests build every Config WITHOUT naming
llm_mode, so they fail if the default ever becomes permissive again (audit 27/11/2026, P0 n°2)."""
import json
from dataclasses import fields
from pathlib import Path

import pytest
from mcp import Client

from forensic_mcp import audit, server
from forensic_mcp.config import Config, load_config

DOCKER_TOML = Path(__file__).parents[1] / "forensic-mcp.docker.toml"
pytestmark = pytest.mark.anyio


def _default_mode(cfg: Config) -> Config:
    """Same settings as the test fixture, llm_mode left to the dataclass default."""
    return Config(**{f.name: getattr(cfg, f.name) for f in fields(Config) if f.name != "llm_mode"})


def _case(cfg: Config, classification: str, name: str = "WS-042") -> str:
    d = Path(cfg.evidence_root) / name
    d.mkdir()
    (d / "mem.raw").write_bytes(b"\1" * 4096)
    (d / "case.toml").write_text(f'case = "{name}"\nclassification = "{classification}"\n'
                                 f'hosts = ["{name}"]\n')
    return f"{name}/mem.raw"


def test_dataclass_default_is_cloud() -> None:
    assert Config().llm_mode == "cloud"


def test_load_config_without_file_is_cloud(monkeypatch) -> None:
    monkeypatch.delenv("FORENSIC_MCP_CONFIG", raising=False)
    assert load_config().llm_mode == "cloud"


def test_toml_without_llm_mode_is_cloud(tmp_path: Path) -> None:
    f = tmp_path / "c.toml"
    f.write_text('evidence_root = "/e"\n')
    assert load_config(f).llm_mode == "cloud"


def test_docker_toml_is_cloud() -> None:
    assert load_config(DOCKER_TOML).llm_mode == "cloud"


def test_explicit_local_is_still_possible(tmp_path: Path) -> None:
    f = tmp_path / "c.toml"
    f.write_text('llm_mode = "local"\n')
    assert load_config(f).llm_mode == "local"


async def test_default_config_pseudonymises_internal_case(cfg) -> None:
    cfg = _default_mode(cfg)
    path = _case(cfg, "internal")
    async with Client(server.build_server(cfg)) as c:
        r = await c.call_tool("vol3_run", {"path": path, "plugin": "windows.cmdline"})
    assert not r.is_error
    out = json.dumps(r.structured_content) + r.content[0].text
    for real in ("alice", "WS-042", "203.0.113.10", "10.0.0.5"):
        assert real.lower() not in out.lower(), real
    for tok in ("USER_1", "HOST_1", "IP_EXT_1", "IP_INT_1"):
        assert tok in out


async def test_default_config_refuses_client_case(cfg) -> None:
    cfg = _default_mode(cfg)
    path = _case(cfg, "client")
    async with Client(server.build_server(cfg)) as c:
        r = await c.call_tool("vol3_run", {"path": path, "plugin": "windows.cmdline"})
    assert r.is_error and path not in r.content[0].text
    calls = [e for e in audit.iter_events(cfg.audit_file) if e["type"] == "tool_call"]
    assert calls[-1]["outcome"] == "refused" and "classified 'client'" in calls[-1]["error"]
    assert not [e for e in audit.iter_events(cfg.audit_file) if e["type"] == "evidence_registered"]
