"""The container config must load and carry the network allowlists (not hardcoded)."""
from pathlib import Path

from forensic_mcp.config import load_config

DOCKER_TOML = Path(__file__).parents[1] / "forensic-mcp.docker.toml"


def test_docker_config_hosts_and_origins() -> None:
    cfg = load_config(DOCKER_TOML)
    assert "forensic:8000" in cfg.allowed_hosts and "localhost:8000" in cfg.allowed_hosts
    assert "http://localhost:3000" in cfg.allowed_origins
    assert str(cfg.evidence_root) == "/evidence" and cfg.http_host == "0.0.0.0"
