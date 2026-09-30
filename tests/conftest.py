"""Shared fixtures: a Config pointing at a tmp evidence folder and the fake vol stub."""
import sys
from pathlib import Path

import pytest

from forensic_mcp.config import Config
from forensic_mcp.engines import volatility2, volatility3

FAKEBIN = Path(__file__).parent / "fakebin"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    ev = tmp_path / "evidence"
    ev.mkdir()
    (ev / "mem.raw").write_bytes(b"\0" * 4096)
    tools = tmp_path / "tools.toml"
    tools.write_text(f'[tools.vol3]\ncmd = ["{sys.executable}", "{FAKEBIN / "vol"}"]\nok = true\n'
                     f'[tools.vol2]\ncmd = ["{sys.executable}", "{FAKEBIN / "vol2"}"]\nok = true\n')
    volatility3._cache.clear()
    volatility3._opt_cache.clear()
    volatility2._cache.clear()
    return Config(evidence_root=ev, output_root=tmp_path / "output", tools_file=tools,
                  api_token_file=tmp_path / "secrets" / "api_token", timeout_seconds=30,
                  allowed_hosts=["localhost:8000", "127.0.0.1:8000"])
