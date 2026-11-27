"""Shared fixtures: a Config pointing at a tmp evidence folder and the fake vol stub."""
import sys
from pathlib import Path

import pytest

from forensic_mcp.config import Config
from forensic_mcp.engines import tshark, volatility2, volatility3, zimmerman

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
                     f'[tools.vol2]\ncmd = ["{sys.executable}", "{FAKEBIN / "vol2"}"]\nok = true\n'
                     + "".join(f'[tools.{t}]\ncmd = ["{sys.executable}", "{FAKEBIN / "ez"}", '
                               f'"{FAKEBIN / "ez_tools" / (t + ".dll")}"]\nok = true\n'
                               for t in zimmerman.REGISTRY))
    volatility3._cache.clear()
    volatility3._opt_cache.clear()
    volatility2._cache.clear()
    tshark._version.clear()
    # llm_mode="local" is EXPLICIT on purpose: these fixtures test raw tool behaviour (values,
    # error details). The default is now the restrictive cloud policy (audit 27/11/2026, P0 n°2);
    # that policy is tested on its own (test_config_llm_default.py, test_socle.py *_cloud_mode,
    # tests setting cfg.llm_mode = "cloud"). Open P1: replay the reference scenario WS-042 in
    # both modes (cloud = production default) so cross-checks also run on pseudonymised data.
    return Config(evidence_root=ev, output_root=tmp_path / "output", tools_file=tools,
                  api_token_file=tmp_path / "secrets" / "api_token", timeout_seconds=30,
                  sleuthkit_dir=FAKEBIN / "disk", sleuthkit_prefix=[sys.executable],
                  tshark_dir=FAKEBIN / "net", tshark_prefix=[sys.executable],
                  allowed_hosts=["localhost:8000", "127.0.0.1:8000"], llm_mode="local")
