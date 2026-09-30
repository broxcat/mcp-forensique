#!/usr/bin/env python3
"""Phase 1 check: verify every forensic tool starts, save its help text, write tools.toml.

Stdlib only. Run from the project root:
    .venv/bin/python scripts/check_tools.py             # check only
    python3 scripts/check_tools.py --install            # download what is missing, then check

--install only acts on tools whose file is absent; it never re-downloads a tool that exists.
Sources: pip (volatility3), official .NET install script, volatilityfoundation.org (vol2),
download.ericzimmermanstools.com/net9 (EZ tools).

Default locations (override with the options below):
    Volatility 3 : <project>/.venv/bin/vol
    Volatility 2 : ~/forensic-tools/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone
    .NET         : ~/.dotnet/dotnet
    EZ tools     : ~/forensic-tools/ez/<Tool>/**/<Tool>.dll  (run as: dotnet <Tool>.dll)
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

EZ_URL = "https://download.ericzimmermanstools.com/net9/{tool}.zip"
VOL2_URL = "https://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip"
DOTNET_INSTALL_URL = "https://dot.net/v1/dotnet-install.sh"

EZ_TOOLS = [
    "EvtxECmd", "MFTECmd", "PECmd", "RECmd", "AmcacheParser", "AppCompatCacheParser",
    "LECmd", "JLECmd", "SBECmd", "SrumECmd", "SQLECmd", "WxTCmd", "RBCmd",
    "RecentFileCacheParser", "SumECmd", "bstrings", "rla",
]
# Words that show a real help screen was printed (tools differ in exit codes).
HELP_MARKERS = ("usage", "description", "options", "author")

PROJECT = Path(__file__).resolve().parent.parent
HOME = Path.home()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--vol3", type=Path, default=PROJECT / ".venv" / "bin" / "vol")
    p.add_argument("--vol2", type=Path, default=HOME / "forensic-tools" / "volatility_2.6_lin64_standalone"
                   / "volatility_2.6_lin64_standalone")
    p.add_argument("--dotnet", type=Path, default=HOME / ".dotnet" / "dotnet")
    p.add_argument("--ez-dir", type=Path, default=HOME / "forensic-tools" / "ez")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--help-dir", type=Path, default=PROJECT / "docs" / "tool_help")
    p.add_argument("--toml", type=Path, default=PROJECT / "tools.toml")
    p.add_argument("--install", action="store_true", help="download missing tools before checking")
    p.add_argument("--ez-url", default=EZ_URL, help=argparse.SUPPRESS)      # overridable for tests
    p.add_argument("--vol2-url", default=VOL2_URL, help=argparse.SUPPRESS)
    return p.parse_args()


# ---------------------------------------------------------------- installation

def download(url: str, dest: Path) -> None:
    """Download url to dest (atomic: temp file then rename)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(url, timeout=120) as resp, tmp.open("wb") as fh:
        while chunk := resp.read(1 << 20):
            fh.write(chunk)
    tmp.replace(dest)


def download_and_unzip(url: str, target_dir: Path) -> None:
    """Download a zip, check it, extract it into target_dir (zipfile strips '..' and absolute paths)."""
    with tempfile.TemporaryDirectory() as tmp:
        zpath = Path(tmp) / "pkg.zip"
        download(url, zpath)
        with zipfile.ZipFile(zpath) as zf:
            bad = zf.testzip()
            if bad:
                raise RuntimeError(f"corrupt zip member: {bad}")
            target_dir.mkdir(parents=True, exist_ok=True)
            zf.extractall(target_dir)


def run_step(cmd: list[str], env: dict[str, str]) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", env=env)
    if proc.returncode != 0:
        tail = (proc.stdout + proc.stderr).strip().splitlines()[-3:]
        raise RuntimeError(" | ".join(tail) or f"exit code {proc.returncode}")


def install_missing(args: argparse.Namespace, env: dict[str, str]) -> None:
    """Install only what is absent. Each step reports INSTALL OK / INSTALL FAIL and never aborts the run."""
    steps: list[tuple[str, callable]] = []

    if not args.vol3.exists():
        venv_dir = args.vol3.parent.parent
        venv_py = args.vol3.parent / "python"

        def vol3() -> None:
            if not venv_py.exists():
                run_step([sys.executable, "-m", "venv", str(venv_dir)], env)
            run_step([str(venv_py), "-m", "pip", "install", "-q", "volatility3"], env)
        steps.append(("vol3 (pip install volatility3)", vol3))

    if not args.vol2.exists():
        def vol2() -> None:
            # the zip contains volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone
            download_and_unzip(args.vol2_url, args.vol2.parent.parent)
            if not args.vol2.exists():
                raise RuntimeError(f"archive did not contain {args.vol2.name}")
            args.vol2.chmod(args.vol2.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        steps.append(("vol2 (standalone 2.6)", vol2))

    if not args.dotnet.exists():
        def dotnet() -> None:
            with tempfile.TemporaryDirectory() as tmp:
                script = Path(tmp) / "dotnet-install.sh"
                download(DOTNET_INSTALL_URL, script)
                run_step(["bash", str(script), "--channel", "9.0", "--runtime", "dotnet",
                          "--install-dir", str(args.dotnet.parent)], env)
        steps.append((".NET 9 runtime", dotnet))

    for tool in EZ_TOOLS:
        if find_ez_dll(args.ez_dir, tool) is None:
            def ez(tool: str = tool) -> None:
                download_and_unzip(args.ez_url.format(tool=tool), args.ez_dir / tool)
                if find_ez_dll(args.ez_dir, tool) is None:
                    raise RuntimeError(f"{tool}.dll not in the downloaded archive")
            steps.append((tool, ez))

    if not steps:
        print("Nothing to install: every tool is already present.\n")
        return
    print(f"Installing {len(steps)} missing tool(s)...")
    for label, fn in steps:
        try:
            fn()
            print(f"  INSTALL OK   {label}")
        except Exception as exc:  # report and continue with the others
            print(f"  INSTALL FAIL {label}: {exc}")
    print()


def find_ez_dll(ez_dir: Path, tool: str) -> Path | None:
    """Return <Tool>.dll under ez_dir/<Tool>/ (shallowest match), or None."""
    base = ez_dir / tool
    if not base.is_dir():
        return None
    matches = sorted(base.rglob(f"{tool}.dll"), key=lambda p: (len(p.parts), str(p)))
    return matches[0] if matches else None


def run_help(cmd: list[str], env: dict[str, str], timeout: int) -> tuple[bool, str]:
    """Run a help command, capture everything, decide if the tool really started."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=timeout, env=env, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return False, f"not found: {cmd[0]}"
    except PermissionError:
        return False, f"not executable: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, f"timeout after {timeout}s"
    out = (proc.stdout or "") + (proc.stderr or "")
    looks_like_help = any(m in out.lower() for m in HELP_MARKERS)
    ok = looks_like_help and "unhandled exception" not in out.lower()
    return ok, out


def toml_str(value: str) -> str:
    return json.dumps(value)  # a JSON string is a valid TOML basic string


def main() -> int:
    args = parse_args()
    env = dict(os.environ)
    dotnet_root = str(args.dotnet.parent)
    env.setdefault("DOTNET_ROOT", dotnet_root)
    env["PATH"] = dotnet_root + os.pathsep + env.get("PATH", "")
    env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"

    if args.install:
        install_missing(args, env)

    # name -> (launch command without help flag, help flag, path shown)
    checks: list[tuple[str, list[str], str, Path | None]] = [
        ("vol3", [str(args.vol3)], "-h", args.vol3),
        ("vol2", [str(args.vol2)], "-h", args.vol2),
        ("dotnet", [str(args.dotnet)], "--list-runtimes", args.dotnet),
    ]
    for tool in EZ_TOOLS:
        dll = find_ez_dll(args.ez_dir, tool)
        cmd = [str(args.dotnet), str(dll)] if dll else []
        checks.append((tool, cmd, "--help", dll))

    args.help_dir.mkdir(parents=True, exist_ok=True)
    results: list[tuple[str, list[str], Path | None, bool, str]] = []
    width = max(len(c[0]) for c in checks)

    for name, cmd, flag, path in checks:
        if not cmd:
            ok, out = False, f"{name}.dll not found under {args.ez_dir / name}"
        else:
            ok, out = run_help(cmd + [flag], env, args.timeout)
            if name == "dotnet":
                ok = "Microsoft.NETCore.App 9." in out
        (args.help_dir / f"{name}.txt").write_text(out, encoding="utf-8")
        status = "OK" if ok else "FAIL"
        print(f"{name:<{width}} | {path if path else '-'} | {status}")
        if not ok:
            reason = out.strip().splitlines()[-1] if out.strip() else "no output"
            print(f"{'':<{width}}   -> {reason[:200]}")
        results.append((name, cmd, path, ok, out))

    lines = ["# Generated by scripts/check_tools.py. Do not edit by hand, re-run the script.", ""]
    for name, cmd, path, ok, _ in results:
        lines.append(f"[tools.{name}]")
        lines.append(f"cmd = [{', '.join(toml_str(c) for c in cmd)}]")
        lines.append(f"path = {toml_str(str(path) if path else '')}")
        lines.append(f"ok = {'true' if ok else 'false'}")
        lines.append("")
    args.toml.write_text("\n".join(lines), encoding="utf-8")

    failed = [r[0] for r in results if not r[3]]
    print()
    print(f"{len(results) - len(failed)}/{len(results)} tools OK. "
          f"Help texts in {args.help_dir}, launch commands in {args.toml}.")
    if failed:
        print("FAILED: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
