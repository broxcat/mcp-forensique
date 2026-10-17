"""Network-capture operations (task 6.7, extension EXT-03 approved 17/10/2026): pcap_info
(capinfos), pcap_conversations, pcap_dns_query, pcap_http_objects, pcap_tls_info (tshark, one
typed view each) and net_extract_pcap (a filtered copy written as derived evidence).

Captures are read as files, never from an interface. The display filter is built by
engines.tshark.build_filter from typed parameters (ip, port, proto, ISO-8601 window); text
searches (host, name, URI) are applied here, on the parsed rows, so no caller string is ever
part of an argv (rule 8). A parse is done once per (capture, view, filter) and reused.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from . import contract, evidence, results, safety
from .engines import tshark

MAX_EXTRACT_NOTE = ('Use the "path" column (@<result_id>/...) as input of the pcap_* tools: the '
                    "filtered copy is registered evidence of its own.")


class NetOps:
    """Mixed into ops.Engine (uses cfg, actor, _policy, _restore_path, _page, _confirm)."""

    def _capture(self, params: dict[str, Any]) -> tuple[dict[str, Any], Path, Any, dict]:
        """Jail the capture path (evidence root or @<result_id>/...), check it before use."""
        real = {**params, "path": self._restore_path(str(params["path"]))}
        path = safety.jail_input(real["path"], self.cfg.evidence_root, self.cfg.output_root)
        if not path.is_file():
            raise FileNotFoundError(f"not a file under the evidence root: {real['path']}")
        ps = self._policy(path)
        ev = evidence.check_before_use(self.cfg, path, self.actor)
        return real, path, ps, ev

    @staticmethod
    def _filter(view: str, real: dict[str, Any]) -> str:
        """The display filter of this call: typed values only."""
        return tshark.build_filter(view, ip=real.get("ip"), port=real.get("port"),
                                   proto=real.get("proto"), start=real.get("start"),
                                   end=real.get("end"))

    @staticmethod
    def _contains(real: dict[str, Any], *columns: str) -> Any:
        """Server-side text filter on the parsed rows (never in the tshark argv)."""
        needles = [(c, str(real[f"{c}_contains"]).lower()) for c in columns
                   if real.get(f"{c}_contains")]
        if not needles:
            return None

        def where(row: dict[str, Any]) -> bool:
            return all(needle in str(row.get(col, "")).lower() for col, needle in needles)
        return where

    def _net_outcome(self, tool: str, params: dict, real: dict, ps: Any, ev: dict, rid: str, d: Path,
                 argv: list[str], exit_code: int, q: dict, summary: str, notes: list[str],
                 engine: str, error: str | None = None, repeat: bool = True) -> Any:
        from .ops import Outcome  # circular at import time

        extra: dict[str, Any] = {"exit_code": exit_code}
        if notes:
            extra["notes"] = notes
        payload = contract.build(
            tool=tool, engine=engine, plugin=tool, parameters=params, evidence=ev,
            summary=summary, rows=q["rows"], row_count=q["matched"], offset=q["offset"],
            limit=q["limit"], result_id=rid, truncated=q["truncated"], extra=extra,
            next_call={"tool": tool, "args": dict(params)} if repeat else None)
        return Outcome(payload, real, argv=argv, engine=engine, evidence_sha256=ev["sha256"],
                       result_id=rid, exit_code=exit_code,
                       output_sha256=results.rows_sha256(d), pseudo=ps, error=error)

    async def _net_parsed(self, path: Path, ev: dict, view: str,
                      filt: str) -> tuple[str, Path, list[str], int, list[str]]:
        """Parse one view of a capture with tshark, once per (capture, view, filter)."""
        cache = Path(self.cfg.output_root) / ".toolcache" / "tshark.json"
        data = json.loads(cache.read_text(encoding="utf-8")) if cache.exists() else {}
        key = f"{ev['sha256']}|{view}|{filt}"
        rid = data.get(key)
        if rid and (Path(self.cfg.output_root) / rid / "rows.jsonl").exists():
            d = Path(self.cfg.output_root) / rid
            return rid, d, results.read_meta(d).get("argv", []), 0, []
        rid, d = results.new_result(self.cfg.output_root, f"pcap_{view}")
        argv = tshark.read_argv(self.cfg, path, view, filt)
        rr = await tshark.run_to_file(self.cfg, argv, d / "fields.txt", d / "stderr.txt",
                                      self.cfg.max_output_mb)
        n, notes = 0, []
        with open(d / "rows.jsonl", "w", encoding="utf-8") as out:
            for row in tshark.iter_rows(d / "fields.txt", view):
                if n >= tshark.MAX_ROWS:
                    notes.append(f"parse truncated at {tshark.MAX_ROWS} packets: narrow the "
                                 "filter (ip, port, proto, start/end)")
                    break
                out.write(json.dumps(row, ensure_ascii=False) + "\n")
                n += 1
        results.write_meta(d, tool=f"pcap_{view}", plugin="tshark", argv=argv,
                           input_path=str(path), input_sha256=ev["sha256"],
                           display_filter=filt, exit_code=rr.exit_code, row_count=n)
        if rr.exit_code != 0 or rr.timed_out or rr.output_exceeded:
            tail = (d / "stderr.txt").read_text(errors="replace").strip()[-300:]
            notes.append(f"tshark failed (exit {rr.exit_code}): {tail}" if tail
                         else f"tshark exit {rr.exit_code}")
        else:
            data[key] = rid
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(data, indent=1), encoding="utf-8")
        return rid, d, argv, rr.exit_code, notes

    @staticmethod
    def _empty_note(view: str) -> str:
        """What "0 rows" does and does not mean (same lesson as the EVTX presets, 4.3)."""
        return (f"0 packet matched. This means: nothing in THIS capture matches this filter "
                f"({view} view). It does not prove the activity did not happen: the capture may "
                "start after it, miss the interface, or the traffic may be encrypted/tunnelled.")

    async def _view_result(self, tool: str, view: str, params: dict[str, Any],
                           columns: tuple[str, ...]) -> Any:
        """Shared body of the four read views: parse once, then page with the text filters."""
        real, path, ps, ev = self._capture(params)
        filt = self._filter(view, real)
        engine = await tshark.version(self.cfg)
        rid, d, argv, code, notes = await self._net_parsed(path, ev, view, filt)
        q = self._page(d, where=self._contains(real, *columns),
                       limit=real.get("limit") or 50, offset=real.get("offset") or 0)
        notes = [f"display filter: {filt or '(none)'}", *notes]
        if not q["matched"]:
            notes.append(self._empty_note(view))
        return self._net_outcome(tool, params, real, ps, ev, rid, d, argv, code, q,
                             f"{q['matched']} {view} rows", notes, engine)

    # ---- the five read tools ---------------------------------------------------------------
    async def op_pcap_info(self, params: dict[str, Any], conf: Any = None) -> Any:
        real, path, ps, ev = self._capture(params)
        engine = await tshark.version(self.cfg)
        rid, d = results.new_result(self.cfg.output_root, "pcap_info")
        argv = tshark.capinfos_argv(self.cfg, path)
        rr = await tshark.run_to_file(self.cfg, argv, d / "stdout.txt", d / "stderr.txt", 16)
        text = (d / "stdout.txt").read_text(errors="replace")
        row = tshark.parse_capinfos(text)
        (d / "rows.jsonl").write_text((json.dumps(row, ensure_ascii=False) + "\n") if row else "",
                                      encoding="utf-8")
        results.write_meta(d, tool="pcap_info", plugin="capinfos", argv=argv,
                           input_path=str(path), input_sha256=ev["sha256"],
                           exit_code=rr.exit_code, row_count=1 if row else 0)
        notes = []
        if not row:
            tail = (d / "stderr.txt").read_text(errors="replace").strip()[-300:]
            notes.append(f"capinfos read nothing from this file: {tail or 'no output'}. "
                         "Is it really a pcap/pcapng capture?")
        elif row.get("snapshot_length"):
            notes.append(f"Snapshot length {row['snapshot_length']} bytes: packets longer than "
                         "this were cut at capture time, so payloads may be incomplete.")
        q = self._page(d, limit=real.get("limit") or 50, offset=real.get("offset") or 0)
        summary = (f"{row.get('packets', 0)} packets, {row.get('file_type', 'unknown type')}, "
                   f"{row.get('first_packet_utc', '?')} -> {row.get('last_packet_utc', '?')}"
                   if row else "capture not readable")
        return self._net_outcome("pcap_info", params, real, ps, ev, rid, d, argv, rr.exit_code, q,
                             summary, notes, engine,
                             error=None if row else "capinfos produced no information",
                             repeat=False)

    async def op_pcap_conversations(self, params: dict[str, Any], conf: Any = None) -> Any:
        """Conversations aggregated by the server from the parsed packets (tshark's own
        `-z conv,...` is never used: -z is forbidden)."""
        real, path, ps, ev = self._capture(params)
        filt = self._filter("packets", real)
        engine = await tshark.version(self.cfg)
        prid, pd, argv, code, notes = await self._net_parsed(path, ev, "packets", filt)
        rid, d = results.new_result(self.cfg.output_root, "pcap_conversations")
        rows = tshark.conversations(results.iter_rows(pd))
        (d / "rows.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n"
                                              for r in rows), encoding="utf-8")
        results.write_meta(d, tool="pcap_conversations", plugin="tshark", argv=argv,
                           input_path=str(path), input_sha256=ev["sha256"], display_filter=filt,
                           exit_code=code, row_count=len(rows), packets_result_id=prid)
        q = self._page(d, limit=real.get("limit") or 50, offset=real.get("offset") or 0)
        notes = [f"display filter: {filt or '(none)'}", f"packets: result {prid}",
                 "Counts are per conversation, both directions (a_to_b = from the src column).",
                 *notes]
        if not rows:
            notes.append(self._empty_note("packets"))
        return self._net_outcome("pcap_conversations", params, real, ps, ev, rid, d, argv, code, q,
                             f"{len(rows)} conversations", notes, engine)

    async def op_pcap_dns_query(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._view_result("pcap_dns_query", "dns", params,
                                       ("query_name", "answer_a"))

    async def op_pcap_http_objects(self, params: dict[str, Any], conf: Any = None) -> Any:
        out = await self._view_result("pcap_http_objects", "http", params,
                                      ("host", "uri", "content_type"))
        out.payload.setdefault("notes", []).append(
            "Inventory of the HTTP objects seen (request and response metadata), not their "
            "content: no file is carved out of the capture (--export-objects is never passed). "
            "To keep the traffic of one object, use net_extract_pcap with its ip/port.")
        return out

    async def op_pcap_tls_info(self, params: dict[str, Any], conf: Any = None) -> Any:
        out = await self._view_result("pcap_tls_info", "tls", params, ("server_name", "ja3"))
        out.payload.setdefault("notes", []).append(
            "Handshakes only (ClientHello / ServerHello): server_name (SNI) and ja3 identify "
            "the contacted name and the client stack; the session content stays encrypted.")
        return out

    # ---- the extraction tool (confirmed, hashed, registered) -------------------------------
    async def op_net_extract_pcap(self, params: dict[str, Any], conf: Any = None) -> Any:
        real, path, ps, ev = self._capture(params)
        filt = self._filter("packets", real)
        if not filt:
            raise ValueError("give at least one filter (ip, port, proto, start, end): "
                             "net_extract_pcap never copies a whole capture")
        engine = await tshark.version(self.cfg)
        await self._confirm("net_extract_pcap", real,
                            "network extraction (filtered copy of a capture)", conf)
        rid, d = results.new_result(self.cfg.output_root, "net_extract_pcap")
        base = d / "extracted"
        base.mkdir()
        dest = base / f"{Path(path).stem}_filtered.pcapng"
        argv = tshark.extract_argv(self.cfg, path, filt, dest)
        rr = await tshark.run_to_file(self.cfg, argv, d / "stdout.txt", d / "stderr.txt", 16)
        notes = [f"display filter: {filt}"]
        rows: list[dict[str, Any]] = []
        failed = rr.exit_code != 0 or rr.timed_out or rr.output_exceeded or not dest.exists()
        info: dict[str, Any] = {}
        if not failed:
            ir = await tshark.run_to_file(self.cfg, tshark.capinfos_argv(self.cfg, dest),
                                          d / "capinfos.txt", d / "capinfos_err.txt", 16)
            info = tshark.parse_capinfos((d / "capinfos.txt").read_text(errors="replace")) \
                if ir.exit_code == 0 else {}
        if failed or not info.get("packets"):
            dest.unlink(missing_ok=True)
            tail = (d / "stderr.txt").read_text(errors="replace").strip()[-300:]
            error = (f"tshark failed (exit {rr.exit_code}): {tail}" if failed
                     else "no packet matched the filter: nothing extracted")
            notes.append(error if failed else self._empty_note("packets"))
            summary = "nothing extracted"
        else:
            digest = results.sha256_file(dest)
            os.chmod(dest, 0o444)
            reg = evidence.register_derived(
                self.cfg, dest, digest, self.actor, source_capture=ev["path"],
                source_sha256=ev["sha256"], display_filter=filt)
            rows.append({"path": evidence.relpath(self.cfg, dest), "size": reg["size"],
                         "sha256": digest, "packets": info.get("packets"),
                         "first_utc": info.get("first_packet_utc"),
                         "last_utc": info.get("last_packet_utc"),
                         "file_type": info.get("file_type"),
                         "registration_audit_id": reg["audit_id"]})
            error, summary = None, (f"{info['packets']} packets extracted, hashed and registered "
                                    f"({reg['size']} bytes, pcapng)")
            notes += ["The copy is rewritten by tshark as pcapng: its SHA-256 is the hash of the "
                      "new file, NOT a subset hash of the source capture (the source keeps its "
                      "own registered hash).", MAX_EXTRACT_NOTE]
        (d / "rows.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n"
                                              for r in rows), encoding="utf-8")
        results.write_meta(d, tool="net_extract_pcap", plugin="tshark", argv=argv,
                           input_path=str(path), input_sha256=ev["sha256"], display_filter=filt,
                           exit_code=rr.exit_code, row_count=len(rows))
        q = self._page(d, limit=real.get("limit") or 50, offset=real.get("offset") or 0)
        return self._net_outcome("net_extract_pcap", params, real, ps, ev, rid, d, argv,
                             rr.exit_code, q, summary, notes, engine, error=error, repeat=False)
