"""Path jail and argument validation."""
from __future__ import annotations

import re
from pathlib import Path

ARG_RE = re.compile(r"^[A-Za-z0-9_.:=,/-]+$")

FORBIDDEN_FLAGS: dict[str, set[str]] = {
    "vol3": {"-f", "-o", "-r", "-c", "-p", "-s", "--output-dir", "--renderer",
             "--plugin-dirs", "--symbol-dirs", "--write-config"},
    "ez": {"-f", "-d", "--csv", "--json", "--csvf", "--jsonf"},
    "vol2": {"-f", "--output", "--output-file", "--dump-dir"},
}


class SafetyError(ValueError):
    """Raised when a path or argument is refused."""


def jail_path(path: str | Path, evidence_root: str | Path) -> Path:
    """Resolve `path` (relative paths are under the root) and require it inside evidence_root."""
    root = Path(evidence_root).resolve()
    p = Path(path)
    if not p.is_absolute():
        p = root / p
    resolved = p.resolve()
    if resolved != root and not resolved.is_relative_to(root):
        raise SafetyError(f"path outside evidence root: {path}")
    return resolved


def validate_args(extra_args: list[str], family: str) -> list[str]:
    """Check extra_args against the character whitelist and the family's forbidden flags."""
    forbidden = FORBIDDEN_FLAGS[family]
    for arg in extra_args:
        if not ARG_RE.match(arg):
            raise SafetyError(f"invalid characters in argument: {arg!r}")
        flag = arg.split("=", 1)[0]
        if flag in forbidden:
            raise SafetyError(f"flag not allowed: {flag}")
    return list(extra_args)
