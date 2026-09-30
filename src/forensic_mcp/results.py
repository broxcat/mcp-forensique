"""Result folders: meta.json, summaries and streaming queries over CSV/JSONL rows."""
from __future__ import annotations

import csv
import hashlib
import heapq
import itertools
import json
import re
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Iterator

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


def new_result(output_root: Path, tool: str) -> tuple[str, Path]:
    """Create output_root/<yyyymmdd-HHMMSS>-<tool>-<6hex>/ and return (result_id, dir)."""
    rid = f"{time.strftime('%Y%m%d-%H%M%S')}-{tool}-{secrets.token_hex(3)}"
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


def _hash_cache_key(path: Path) -> str:
    st = path.stat()
    return f"{path.resolve()}|{st.st_size}|{st.st_mtime_ns}"


def cached_sha256(path: Path, output_root: Path) -> str | None:
    """SHA-256 from output_root/.cache/sha256.json if the file is unchanged, else None."""
    cache = Path(output_root) / ".cache" / "sha256.json"
    if not cache.exists():
        return None
    return json.loads(cache.read_text(encoding="utf-8")).get(_hash_cache_key(path))


def sha256_cached(path: Path, output_root: Path) -> str:
    """SHA-256 of an evidence file, cached by (path, size, mtime) under output_root/.cache."""
    hit = cached_sha256(path, output_root)
    if hit:
        return hit
    digest = sha256_file(path)
    cache = Path(output_root) / ".cache" / "sha256.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    data = json.loads(cache.read_text(encoding="utf-8")) if cache.exists() else {}
    data[_hash_cache_key(path)] = digest
    cache.write_text(json.dumps(data, indent=1), encoding="utf-8")
    return digest


def write_meta(d: Path, **meta: Any) -> None:
    """Write meta.json (tool, argv, version, input, sha256, start/end, exit_code, row_count)."""
    (d / "meta.json").write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")


def read_meta(d: Path) -> dict[str, Any]:
    """Read meta.json (empty dict if missing)."""
    p = d / "meta.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def _iter_jsonl(p: Path) -> Iterator[dict[str, Any]]:
    with open(p, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def _iter_csv(p: Path) -> Iterator[dict[str, Any]]:
    with open(p, newline="", encoding="utf-8-sig", errors="replace") as fh:
        yield from csv.DictReader(fh)


def iter_rows(d: Path) -> Iterator[dict[str, Any]]:
    """Stream rows: rows.jsonl if present, else every *.csv in the folder (one row at a time)."""
    jl = d / "rows.jsonl"
    if jl.exists():
        yield from _iter_jsonl(jl)
        return
    for p in sorted(d.rglob("*.csv")):
        yield from _iter_csv(p)


def _trunc(row: dict[str, Any], limit: int) -> dict[str, Any]:
    out = {}
    for k, v in row.items():
        s = v if isinstance(v, str) else json.dumps(v, default=str) if isinstance(v, (dict, list)) else v
        out[k] = s[:limit] + "…" if isinstance(s, str) and len(s) > limit else s
    return out


def count_rows(d: Path) -> int:
    """Count rows by streaming."""
    return sum(1 for _ in iter_rows(d))


def summarize(d: Path, n: int = 100, max_cell_chars: int = 400) -> dict[str, Any]:
    """result_id, row_count, columns, first n rows (cells truncated), stderr tail if exit != 0."""
    meta = read_meta(d)
    first: list[dict[str, Any]] = []
    count = 0
    columns: list[str] = []
    for row in iter_rows(d):
        if count < n:
            first.append(_trunc(row, max_cell_chars))
            columns = columns or list(row)
        count += 1
    out: dict[str, Any] = {"result_id": d.name, "row_count": count, "columns": columns, "rows": first}
    if meta.get("exit_code", 0) != 0:
        err = d / "stderr.txt"
        out["exit_code"] = meta["exit_code"]
        out["stderr_tail"] = err.read_text(errors="replace")[-2000:] if err.exists() else ""
    return out


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


def _sorted_page(matches: Iterator[dict[str, Any]], sort_by: str, sort_desc: bool,
                 offset: int, limit: int) -> list[dict[str, Any]]:
    """Top offset+limit rows over ALL matches, streaming (heap of k rows), empties last."""
    k = offset + limit
    empties: list[dict[str, Any]] = []

    def non_empty() -> Iterator[dict[str, Any]]:
        for row in matches:
            if _is_empty(row.get(sort_by)):
                if len(empties) < k:
                    empties.append(row)
            else:
                yield row

    pick = heapq.nlargest if sort_desc else heapq.nsmallest
    top = pick(k, non_empty(), key=lambda r: _sort_key(r[sort_by]))
    return (top + empties)[offset:k]


def query(d: Path, contains: str | None = None, column: str | None = None,
          equals: str | None = None, regex: str | None = None,
          columns: list[str] | None = None, sort_by: str | None = None,
          sort_desc: bool = False, limit: int = 100, offset: int = 0,
          max_cell_chars: int = 400) -> dict[str, Any]:
    """Filter rows lazily. contains/regex look at all cells; column+equals is an exact match."""
    needle = contains.lower() if contains else None
    rx = re.compile(regex, re.IGNORECASE) if regex else None

    def keep(row: dict[str, Any]) -> bool:
        if column is not None and equals is not None and not _values_equal(row.get(column), equals):
            return False
        if needle or rx:
            text = " ".join(str(v) for v in row.values())
            if needle and needle not in text.lower():
                return False
            if rx and not rx.search(text):
                return False
        return True

    matches = filter(keep, iter_rows(d))
    if sort_by:
        page = _sorted_page(matches, sort_by, sort_desc, offset, limit)
    else:
        page = list(itertools.islice(matches, offset, offset + limit))
    if columns:
        page = [{c: r.get(c) for c in columns} for r in page]
    return {"result_id": d.name, "returned": len(page), "offset": offset,
            "rows": [_trunc(r, max_cell_chars) for r in page]}
