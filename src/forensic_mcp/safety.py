"""Path jail (ET-05). Tool parameters are typed; no free-form argument reaches a tool (rule 8)."""
from __future__ import annotations

from pathlib import Path

OUTSIDE_ROOT_HELP = (
    "Place the evidence under EVIDENCE_DIR (mounted read-only at {root}), then call "
    "list_evidence. Do not analyse it outside this server: such work is not journaled, not "
    "hashed and not citable.")


class SafetyError(ValueError):
    """Raised when a request is refused (journaled with outcome 'refused')."""


def jail_path(path: str | Path, evidence_root: str | Path) -> Path:
    """Resolve `path` (relative paths are under the root) and require it inside evidence_root."""
    root = Path(evidence_root).resolve()
    p = Path(path)
    if not p.is_absolute():
        p = root / p
    resolved = p.resolve()
    if resolved != root and not resolved.is_relative_to(root):
        raise SafetyError(f"path outside evidence root: {path}. "
                          + OUTSIDE_ROOT_HELP.format(root=root))
    return resolved
