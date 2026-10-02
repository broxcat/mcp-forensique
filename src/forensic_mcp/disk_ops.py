"""Disk-image operations (task 4.3c, Décision J3): disk_info (mmls), disk_list (fls) and
disk_extract (fixed targets copied with icat),
disk_extract_file (files chosen by inode in the disk_list listing, deleted files included). Images are read as files, never mounted.
Each extracted file is hashed, made read-only (0444) and journaled with its provenance; it is
then reachable by the other tools as "@<result_id>/<path>" (second read-only jail root)."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from . import contract, evidence, results
from .engines import sleuthkit, volatility3

MAX_EXTRACT_FILES = 5000
MAX_INODES = 20


class DiskOps:
    """Mixed into ops.Engine (uses cfg, actor, _policy, _restore_path, _page, _confirm)."""

    def _image(self, params: dict[str, Any]) -> tuple[dict[str, Any], Path, Any, dict]:
        real = {**params, "path": self._restore_path(str(params["path"]))}
        path = volatility3.image_path(self.cfg, real["path"])
        ps = self._policy(path)
        ev = evidence.check_before_use(self.cfg, path, self.actor)
        return real, path, ps, ev

    @staticmethod
    def _sector(v: Any) -> int:
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise ValueError("partition_offset must be a non-negative integer (sectors, see disk_info)")
        return v

    def _outcome(self, tool: str, params: dict, real: dict, ps: Any, ev: dict, rid: str, d: Path,
                 argv: list[str], exit_code: int, q: dict, summary: str, notes: list[str],
                 error: str | None = None, repeat: bool = False) -> Any:
        from .ops import Outcome  # circular at import time

        extra: dict[str, Any] = {"exit_code": exit_code}
        if notes:
            extra["notes"] = notes
        payload = contract.build(
            tool=tool, engine="The Sleuth Kit 4.11.1", plugin=tool, parameters=params,
            evidence=ev, summary=summary, rows=q["rows"], row_count=q["matched"],
            offset=q["offset"], limit=q["limit"], result_id=rid, truncated=q["truncated"],
            extra=extra, next_call={"tool": tool, "args": dict(params)} if repeat else None)
        return Outcome(payload, real, argv=argv, engine="The Sleuth Kit 4.11.1",
                       evidence_sha256=ev["sha256"], result_id=rid, exit_code=exit_code,
                       output_sha256=results.rows_sha256(d), pseudo=ps, error=error)

    async def op_disk_info(self, params: dict[str, Any], conf: Any = None) -> Any:
        real, path, ps, ev = self._image(params)
        rid, d = results.new_result(self.cfg.output_root, "disk_info")
        argv = [*sleuthkit.cmd(self.cfg, "mmls"), str(path)]
        rr = await sleuthkit.run_to_file(self.cfg, argv, d / "stdout.txt", d / "stderr.txt", 16)
        text = (d / "stdout.txt").read_text(errors="replace")
        rows = sleuthkit.parse_mmls(text)
        (d / "rows.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
        results.write_meta(d, tool="disk_info", plugin="mmls", argv=argv, input_path=str(path),
                           input_sha256=ev["sha256"], exit_code=rr.exit_code, row_count=len(rows))
        notes = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("Units are")]
        if not rows:
            err = (d / "stderr.txt").read_text(errors="replace").strip().splitlines()
            notes.append("No partition table found (mmls: " + (err[-1] if err else "no output")
                         + "). The image may hold a single volume: use partition_offset=0.")
        else:
            notes.append("Use start_sector of a file-system partition as partition_offset.")
        q = self._page(d)
        return self._outcome("disk_info", params, real, ps, ev, rid, d, argv, rr.exit_code, q,
                             f"{len(rows)} partition table entries", notes)

    async def _fls(self, path: Path, ev: dict, sector: int) -> tuple[str, Path, list[str], int]:
        """Recursive file listing of one file system, parsed once per (image, offset)."""
        cache = Path(self.cfg.output_root) / ".toolcache" / "fls.json"
        data = json.loads(cache.read_text(encoding="utf-8")) if cache.exists() else {}
        key = f"{ev['sha256']}|{sector}"
        rid = data.get(key)
        if rid and (Path(self.cfg.output_root) / rid / "rows.jsonl").exists():
            d = Path(self.cfg.output_root) / rid
            return rid, d, results.read_meta(d).get("argv", []), 0
        rid, d = results.new_result(self.cfg.output_root, "disk_list")
        argv = [*sleuthkit.cmd(self.cfg, "fls"), "-r", "-p", "-o", str(sector), str(path)]
        rr = await sleuthkit.run_to_file(self.cfg, argv, d / "fls.txt", d / "stderr.txt",
                                         self.cfg.max_output_mb)
        n = 0
        with open(d / "rows.jsonl", "w", encoding="utf-8") as out, \
                open(d / "fls.txt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                row = sleuthkit.parse_fls_line(line)
                if row:
                    out.write(json.dumps(row, ensure_ascii=False) + "\n")
                    n += 1
        results.write_meta(d, tool="disk_list", plugin="fls", argv=argv, input_path=str(path),
                           input_sha256=ev["sha256"], partition_offset=sector,
                           exit_code=rr.exit_code, row_count=n)
        if rr.exit_code == 0 and n:
            data[key] = rid
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(data, indent=1), encoding="utf-8")
        return rid, d, argv, rr.exit_code

    async def op_disk_list(self, params: dict[str, Any], conf: Any = None) -> Any:
        real, path, ps, ev = self._image(params)
        sector = self._sector(real.get("partition_offset") or 0)
        rid, d, argv, code = await self._fls(path, ev, sector)
        needle = (real.get("path_contains") or "").lower()
        deleted = real.get("deleted")

        def where(row: dict[str, Any]) -> bool:
            return (not needle or needle in str(row.get("path", "")).lower()) and (
                deleted is None or row.get("deleted") is deleted)

        q = self._page(d, where=where, limit=real.get("limit") or 50,
                       offset=real.get("offset") or 0)
        notes = [] if code == 0 else [(d / "stderr.txt").read_text(errors="replace")[-300:]]
        return self._outcome("disk_list", params, real, ps, ev, rid, d, argv, code, q,
                             f"{q['matched']} entries (partition_offset {sector})", notes,
                             repeat=True)

    async def op_disk_extract(self, params: dict[str, Any], conf: Any = None) -> Any:
        real, path, ps, ev = self._image(params)
        sector = self._sector(real.get("partition_offset") or 0)
        targets = list(real.get("targets") or [])
        unknown = [t for t in targets if t not in sleuthkit.TARGETS]
        if not targets or unknown:
            raise ValueError(f"targets must be a non-empty list of {sorted(sleuthkit.TARGETS)}")
        if set(targets) & sleuthkit.SENSITIVE_TARGETS:
            await self._confirm("disk_extract", real, "credential hives (SAM/SECURITY)", conf)
        lrid, ld, _, code = await self._fls(path, ev, sector)
        if code != 0:
            raise ValueError(f"fls failed on this image/offset (see result {lrid}); check disk_info")
        selected = [r for _, r in zip(range(MAX_EXTRACT_FILES + 1), (
            {**row, "target": t} for row in results.iter_rows(ld)
            if row.get("meta_type") == "r" and (real.get("include_deleted") or not row["deleted"])
            for t in [sleuthkit.match_targets(row["path"], targets)] if t))]
        notes = [f"listing: result {lrid}"]
        if len(selected) > MAX_EXTRACT_FILES:
            selected = selected[:MAX_EXTRACT_FILES]
            notes.append(f"truncated at {MAX_EXTRACT_FILES} files: extract fewer targets")
        return await self._extract("disk_extract", params, real, path, ps, ev, sector, selected,
                                   lrid, notes, {"targets": targets}, ", ".join(targets))

    async def _extract(self, tool: str, params: dict, real: dict, path: Path, ps: Any, ev: dict,
                       sector: int, selected: list[dict[str, Any]], lrid: str, notes: list[str],
                       meta: dict[str, Any], label: str) -> Any:
        """Copy the selected listing rows with icat: hashed, 0444, registered with provenance."""
        rid, d = results.new_result(self.cfg.output_root, tool)
        base = d / "extracted"
        base.mkdir()
        results.write_meta(d, tool=tool, plugin="icat", argv=[], input_path=str(path),
                           input_sha256=ev["sha256"], partition_offset=sector, **meta,
                           exit_code=None, row_count=0)
        rows, failed = [], 0
        for row in selected:
            dest = base / sleuthkit.safe_relpath(row["path"])
            if dest.exists():
                dest = dest.with_name(f"{dest.name}~{row['inode']}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not sleuthkit.INODE_RE.match(row["inode"]):
                continue
            argv = [*sleuthkit.cmd(self.cfg, "icat"), "-o", str(sector), str(path), row["inode"]]
            rr = await sleuthkit.run_to_file(self.cfg, argv, dest, d / "icat_stderr.txt",
                                             self.cfg.max_extract_file_mb)
            item = {"source_path": row["path"], "target": row.get("target"),
                    "inode": row["inode"], "deleted": row["deleted"]}
            if rr.exit_code != 0 or rr.timed_out or rr.output_exceeded:
                failed += 1
                dest.unlink(missing_ok=True)
                rows.append({**item, "path": None, "status": "failed: " + (
                    (d / "icat_stderr.txt").read_text(errors="replace").strip()[-200:]
                    or f"exit {rr.exit_code}")})
                continue
            digest = results.sha256_file(dest)
            os.chmod(dest, 0o444)
            reg = evidence.register_derived(
                self.cfg, dest, digest, self.actor, source_image=ev["path"],
                source_sha256=ev["sha256"], inode=row["inode"], partition_offset=sector)
            rows.append({**item, "path": evidence.relpath(self.cfg, dest), "size": reg["size"],
                         "sha256": digest, "status": "ok", "registration_audit_id": reg["audit_id"]})
        (d / "rows.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n"
                                              for r in rows), encoding="utf-8")
        results.write_meta(d, tool=tool, plugin="icat", argv=["icat", "-o", str(sector)],
                           input_path=str(path), input_sha256=ev["sha256"],
                           partition_offset=sector, **meta, exit_code=0 if not failed
                           else 1, row_count=len(rows), listing_result_id=lrid)
        if failed:
            notes.append(f"{failed} file(s) could not be copied (see status)")
        notes.append('Use the "path" column (@<result_id>/...) as input of ez_run, evtx_query, '
                     "mft_search and the *_query tools.")
        q = self._page(d, limit=real.get("limit") or 50, offset=real.get("offset") or 0)
        return self._outcome(tool, params, real, ps, ev, rid, d,
                             ["icat", "-o", str(sector), "<image>", "<inode>"], 0 if not failed
                             else 1, q, f"{len(rows) - failed} files extracted "
                             f"({label}), {failed} failed", notes)

    # ---- chosen files by inode (request L. Plancke 02/10: recover a deleted file) ----------
    def _cached_listing(self, real: dict[str, Any], path: Path) -> tuple[str, Path] | None:
        """The disk_list result of (image, offset) if it exists (no fls run here)."""
        rec = evidence.load_registry(self.cfg).get(evidence.relpath(self.cfg, path))
        cache = Path(self.cfg.output_root) / ".toolcache" / "fls.json"
        if not rec or not cache.exists():
            return None
        key = f"{rec['sha256']}|{self._sector(real.get('partition_offset') or 0)}"
        rid = json.loads(cache.read_text(encoding="utf-8")).get(key)
        d = Path(self.cfg.output_root) / rid if rid else None
        return (rid, d) if d and (d / "rows.jsonl").exists() else None

    @staticmethod
    def _inodes(v: Any) -> list[int]:
        if not isinstance(v, list) or not 1 <= len(v) <= MAX_INODES or any(
                isinstance(i, bool) or not isinstance(i, int) or i < 0 for i in v):
            raise ValueError(f"inodes must be 1-{MAX_INODES} non-negative integers from disk_list")
        return sorted(set(v))

    @staticmethod
    def _select_inodes(ld: Path, inodes: list[int]) -> list[dict[str, Any]]:
        wanted = {str(i) for i in inodes}
        rows = [r for r in results.iter_rows(ld) if r.get("meta_type") == "r"
                and str(r.get("inode", "")).split("-")[0] in wanted]
        missing = wanted - {str(r["inode"]).split("-")[0] for r in rows}
        if missing:
            raise ValueError(f"inode(s) {sorted(missing, key=int)} are not regular files of this "
                             "file system listing (see disk_list)")
        return rows

    async def extract_file_sensitive(self, params: dict[str, Any]) -> str | None:
        """Confirmation needed if a requested inode is a credential hive (same rule as the
        sam_security target of disk_extract)."""
        real = {**params, "path": self._restore_path(str(params["path"]))}
        path = volatility3.image_path(self.cfg, real["path"])
        hit = self._cached_listing(real, path)
        if hit is None:
            return None  # the operation refuses without a listing
        rows = self._select_inodes(hit[1], self._inodes(real.get("inodes")))
        if any(sleuthkit.match_targets(r["path"], sorted(sleuthkit.SENSITIVE_TARGETS))
               for r in rows):
            return "credential hives (SAM/SECURITY)"
        return None

    async def op_disk_extract_file(self, params: dict[str, Any], conf: Any = None) -> Any:
        real, path, ps, ev = self._image(params)
        sector = self._sector(real.get("partition_offset") or 0)
        inodes = self._inodes(real.get("inodes"))
        hit = self._cached_listing(real, path)
        if hit is None:
            raise ValueError("no listing of this file system yet: call disk_list with the same "
                             "path and partition_offset, then pick inodes from it")
        lrid, ld = hit
        selected = self._select_inodes(ld, inodes)
        reason = await self.sensitive_reason("disk_extract_file", params)
        if reason:
            await self._confirm("disk_extract_file", real, reason, conf)
        notes = [f"listing: result {lrid}"]
        if any(r["deleted"] for r in selected):
            notes.append("Deleted file(s): content read from the clusters the entry still points "
                         "to; it may be partly overwritten if they were reused (check size, type "
                         "and hash).")
        return await self._extract("disk_extract_file", params, real, path, ps, ev, sector,
                                   selected, lrid, notes, {"inodes": inodes},
                                   "inode " + ", ".join(map(str, inodes)))
