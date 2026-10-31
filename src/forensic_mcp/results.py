"""Result folders: meta.json, stable `_row` numbers and streaming queries over CSV/JSONL rows."""
from __future__ import annotations

def manifest(d):
    """Digest every result file, including raw outputs and metadata."""
    return {p.relative_to(d).as_posix(): sha256_file(p) for p in sorted(d.rglob('*')) if p.is_file()}


def _integrity_failure(cfg, rid):
    from . import audit
    from .safety import SafetyError
    audit.append(cfg.audit_file, 'tool_call', {'kind':'server'}, tool='verify_result',
                 params={'result_id':rid}, argv=[], engine='forensic-mcp', evidence_sha256=None,
                 result_id=None, exit_code=None, duration_s=0, output_sha256=None,
                 outcome='refused', error='result integrity or provenance mismatch')
    raise SafetyError('result integrity or provenance mismatch; rerun the analysis')


def _sealed_meta(cfg, rid, producer):
    raw = (result_dir(cfg.output_root, rid)/'meta.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != producer['result_manifest'].get('meta.json'):
        _integrity_failure(cfg, rid)
    return json.loads(raw)


def verify_result(cfg, rid, seen=None):
    """Refuse missing, unsuccessful or altered result producers."""
    from . import audit
    from .safety import SafetyError
    seen = set() if seen is None else seen
    if rid in seen or len(seen) >= 32:
        _integrity_failure(cfg, rid)
    seen.add(rid)
    d = result_dir(cfg.output_root, rid)
    producer = next((e for e in audit.iter_events(cfg.audit_file)
                    if e['type'] == 'tool_call' and e.get('result_id') == rid), None)
    valid = (audit.verify_report(cfg.audit_file)['ok'] and producer
             and producer.get('outcome') == 'ok' and producer.get('result_manifest')
             and producer['result_manifest'] == manifest(d))
    if not valid:
        _integrity_failure(cfg, rid)
    meta = _sealed_meta(cfg, rid, producer)
    parents = list(meta.get('policy_sources', []))
    if meta.get('input_path'):
        src, root = Path(meta['input_path']).resolve(), Path(cfg.output_root).resolve()
        if src.is_relative_to(root) and src != root:
            parents.append(src.relative_to(root).parts[0])
    for parent in set(parents):
        verify_result(cfg, parent, set(seen))
    return producer


def verified_meta(cfg, rid):
    """Integrity is independent of policy; parse only bytes matching the sealed digest."""
    producer = verify_result(cfg, rid)
    return _sealed_meta(cfg, rid, producer)

import csv
import hashlib
import heapq
import json
import re
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterator

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


def new_result(output_root: Path, tool: str) -> tuple[str, Path]:
    """Create output_root/<yyyymmdd-HHMMSS>-<tool>-<6hex>/ and return (result_id, dir)."""
    rid = f"{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-{tool}-{secrets.token_hex(3)}"
    d = Path(output_root) / rid
    d.mkdir(parents=True)
    return rid, d


def result_dir(output_root: Path, result_id: str) -> Path:
    """Return the folder of a result_id, rejecting anything that is not a plain id."""
    if not re.fullmatch(r"[A-Za-z0-9._-]+", result_id) or ".." in result_id:
        raise ValueError(f"invalid result_id: {result_id!r}")
    d = Path(output_root) / result_id
    if not d.is_dir():
        raise FileNotFoundError(f"unknown result_id: {result_id}")
    return d


def sha256_file(path: Path) -> str:
    """SHA-256 of a file, read in 1 MiB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _row_files(d: Path) -> list[Path]:
    jl = d / "rows.jsonl"
    return [jl] if jl.exists() else sorted(d.rglob("*.csv"))


def rows_sha256(d: Path) -> str | None:
    """SHA-256 over the row files of a result (compared by replay); None if there are none."""
    files = _row_files(d)
    if not files:
        return None
    h = hashlib.sha256()
    for p in files:
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    return h.hexdigest()


def write_meta(d: Path, **meta: Any) -> None:
    """Write meta.json (tool, argv, version, input, sha256, start/end, exit_code, row_count)."""
    (d / "meta.json").write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")


def read_meta(d: Path) -> dict[str, Any]:
    """Read meta.json (empty dict if missing)."""
    p = d / "meta.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def iter_rows(d: Path) -> Iterator[dict[str, Any]]:
    """Stream rows (rows.jsonl, else every *.csv), each with a stable 1-based `_row` first."""
    n = 0
    for p in _row_files(d):
        if p.suffix == ".jsonl":
            fh = open(p, encoding="utf-8", errors="replace")
            source: Iterator[dict[str, Any]] = (json.loads(ln) for ln in fh if ln.strip())
        else:
            fh = open(p, newline="", encoding="utf-8-sig", errors="replace")
            source = csv.DictReader(fh)
        with fh:
            for row in source:
                n += 1
                row.pop("_row", None)
                yield {"_row": n, **row}


def truncate_cells(row: dict[str, Any], limit: int) -> tuple[dict[str, Any], bool]:
    """Cells longer than `limit` are cut (marked with …); nested values become JSON text."""
    out, cut = {}, False
    for k, v in row.items():
        s = json.dumps(v, default=str) if isinstance(v, (dict, list)) else v
        if isinstance(s, str) and len(s) > limit:
            s, cut = s[:limit] + "…", True
        out[k] = s
    return out, cut


def count_rows(d: Path) -> int:
    """Count rows by streaming."""
    return sum(1 for _ in iter_rows(d))


def _is_empty(v: Any) -> bool:
    return v is None or (isinstance(v, str) and not v.strip())


def as_number(v: Any) -> int | float | None:
    """Exact number for ints, decimal strings and "0x" hex strings (64-bit addresses); else None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return v
    if not isinstance(v, str):
        return None
    s = v.strip()
    try:
        if s.lower().startswith(("0x", "-0x")):
            return int(s, 16)
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        return None


def _values_equal(cell: Any, wanted: str) -> bool:
    """Exact text match, or numeric match so "0xff" equals "255" (no float rounding)."""
    if str(cell) == wanted:
        return True
    a, b = as_number(cell), as_number(wanted)
    return a is not None and b is not None and a == b


def _sort_key(v: Any) -> tuple[int, int | float, str]:
    """Numbers (incl. hex strings) sort numerically and exactly, before text."""
    n = as_number(v)
    return (0, n, "") if n is not None else (1, 0, str(v))


def query(d: Path, contains: str | None = None, column: str | None = None,
          equals: str | None = None, regex: str | None = None,
          columns: list[str] | None = None, sort_by: str | None = None,
          sort_desc: bool = False, limit: int = 100, offset: int = 0,
          max_cell_chars: int = 400,
          where: Callable[[dict[str, Any]], bool] | None = None) -> dict[str, Any]:
    """Filter rows lazily; returns {rows, matched, offset, limit, truncated}. `matched` counts
    every matching row (full stream, bounded memory); sorting covers all matches (heap)."""
    needle = contains.lower() if contains else None
    rx = re.compile(regex, re.IGNORECASE) if regex else None

    def keep(row: dict[str, Any]) -> bool:
        if where is not None and not where(row):
            return False
        if column is not None and equals is not None and not _values_equal(row.get(column), equals):
            return False
        if needle or rx:
            text = " ".join(str(v) for k, v in row.items() if k != "_row")
            if needle and needle not in text.lower():
                return False
            if rx and not rx.search(text):
                return False
        return True

    k = offset + limit
    matched = 0
    page: list[dict[str, Any]] = []
    empties: list[dict[str, Any]] = []

    def counted() -> Iterator[dict[str, Any]]:
        nonlocal matched
        for row in filter(keep, iter_rows(d)):
            matched += 1
            if sort_by and _is_empty(row.get(sort_by)):
                if len(empties) < k:
                    empties.append(row)
                continue
            yield row

    if sort_by:
        pick = heapq.nlargest if sort_desc else heapq.nsmallest
        page = (pick(k, counted(), key=lambda r: _sort_key(r[sort_by])) + empties)[offset:k]
    else:
        for i, row in enumerate(counted()):
            if offset <= i < k:
                page.append(row)
    if columns:  # project on the columns that exist; a row with none of them stays whole
        page = [{"_row": r["_row"], **{c: r[c] for c in columns if c != "_row" and c in r}}
                if any(c in r for c in columns if c != "_row") else r for r in page]
    rows, cut = [], False
    for r in page:
        t, c = truncate_cells(r, max_cell_chars)
        rows.append(t)
        cut = cut or c
    return {"rows": rows, "matched": matched, "offset": offset, "limit": limit, "truncated": cut}
