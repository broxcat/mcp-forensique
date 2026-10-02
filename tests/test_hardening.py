"""P7 hardening (L2 §12 point 4, decision 3): pinned versions and download hashes, analysis
workspace template without shell. Static checks of the build files (the build itself is run by
`docker compose build`)."""
import json
import re
from pathlib import Path

from forensic_mcp.engines.ez_registry import REGISTRY

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"^[0-9a-f]{64}$")


def test_dockerfile_pins_base_python_dotnet_and_downloads() -> None:
    df = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^FROM python:3\.12-slim-bookworm@sha256:[0-9a-f]{64}$", df, re.M)
    assert "-r /tmp/requirements.lock" in df and '"pip==' in df
    assert re.search(r"DOTNET_RUNTIME_VERSION=9\.0\.\d+", df) and "--channel" not in df
    for arg in ("DOTNET_INSTALL_SHA256", "VOL2_SHA256"):
        m = re.search(rf"ARG {arg}=(\S+)", df)
        assert m and SHA.match(m.group(1)), arg
    assert df.count("sha256sum -c -") == 3  # dotnet script, each EZ zip, vol2
    assert "sleuthkit=4.11.1+dfsg-1+b1" in df and "ewf-tools=20140813-1+b1" in df


def test_requirements_lock_is_exact() -> None:
    lines = [ln for ln in (ROOT / "requirements.lock").read_text(encoding="utf-8").splitlines()
             if ln.strip()]
    assert lines and all(re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+", ln) for ln in lines)
    names = {ln.split("==")[0].lower() for ln in lines}
    assert {"mcp", "volatility3", "uvicorn", "pyyaml", "pytest", "jsonschema"} <= names
    assert "forensic-mcp" not in names  # the project itself is bind-mounted, not on PyPI


def test_every_ez_tool_zip_has_a_hash() -> None:
    rows = [ln.split() for ln in (ROOT / "rules" / "ez_zips.sha256").read_text(
        encoding="utf-8").splitlines() if ln.strip()]
    assert all(len(r) == 2 and SHA.match(r[0]) for r in rows)
    assert {r[1] for r in rows} == set(REGISTRY) and len(rows) == 17


def test_compose_pins_open_webui_and_build_context_excludes_secrets() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert re.search(r"image: ghcr\.io/open-webui/open-webui:\S*@sha256:[0-9a-f]{64}", compose)
    ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
    assert {".env", ".secrets/", "evidence/", "output/"} <= set(ignore)


def test_analysis_workspace_template_has_no_shell() -> None:
    base = ROOT / "templates" / "analysis-workspace"
    settings = json.loads((base / ".claude" / "settings.json").read_text(encoding="utf-8"))
    deny, allow = settings["permissions"]["deny"], settings["permissions"]["allow"]
    assert {"Bash", "PowerShell", "Edit", "Write", "WebFetch"} <= set(deny)
    assert any(d.startswith("Read(") and ".secrets" in d for d in deny)
    assert allow == ["mcp__forensic__*"]
    mcp = json.loads((base / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]["forensic"]
    assert mcp["command"] == "docker" and mcp["args"][-1] == "--stdio"
