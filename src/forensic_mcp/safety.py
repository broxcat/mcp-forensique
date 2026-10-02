"""Path jail (ET-05). Tool parameters are typed; no free-form argument reaches a tool (rule 8)."""
from __future__ import annotations

import re
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


EXTRACT_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-disk_extract-[0-9a-f]{6}$")


def jail_input(path: str | Path, evidence_root: str | Path,
               output_root: str | Path | None = None) -> Path:
    """Evidence root, or the second read-only root (task 4.3c): "@<result_id>/<path>" = a file
    copied by disk_extract into output_root/<result_id>/extracted/. Same resolve + is_relative_to
    rule; any other place under output_root is refused."""
    s = str(path)
    if not s.startswith("@"):
        return jail_path(path, evidence_root)
    rid, _, rest = s[1:].partition("/")
    if output_root is None or not EXTRACT_RE.fullmatch(rid):
        raise SafetyError(f"not an extraction reference: {s!r} (expected @<disk_extract result_id>/...)")
    base = (Path(output_root) / rid / "extracted").resolve()
    if not base.is_dir():
        raise SafetyError(f"unknown extraction: {rid}")
    resolved = (base / rest).resolve()
    if resolved != base and not resolved.is_relative_to(base):
        raise SafetyError(f"path outside the extraction {rid}: {s}")
    return resolved
