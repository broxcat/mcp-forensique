"""Memory operations (EF-01, Décision J3): typed vol3 tools, vol3_run / vol2_run on any plugin,
sensitive plugins confirmed by a human, analyzers on every result.

Typed parameters only (rule 8): pid, offset, key, dump, profile. Each is translated to an option
that the plugin's own help declares; anything else is refused."""
from __future__ import annotations

import json
import os
import re
import secrets
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from . import analyzers, audit, contract, evidence, results, safety
from .engines import volatility2, volatility3

TYPED_VOL3 = {"vol_pslist": "windows.pslist", "vol_pstree": "windows.pstree",
              "vol_cmdline": "windows.cmdline", "vol_netscan": "windows.netscan",
              "vol_malfind": "windows.malfind", "vol_dlllist": "windows.dlllist",
              "vol_printkey": "windows.registry.printkey"}
SENSITIVE_VOL3 = re.compile(r"hashdump|lsadump|cachedump|dumpfiles|pedump|layerwriter|truecrypt|"
                            r"recoverfs", re.I)
SENSITIVE_VOL2 = {"hashdump", "lsadump", "cachedump", "truecryptmaster", "truecryptpassphrase"}
KEY_RE = re.compile(r"^[^-\x00-\x1f][^\x00-\x1f]{0,511}$")
PROFILE_RE = re.compile(r"^[A-Za-z0-9_]+$")
# vol2 plugin to use when a typed vol3 tool cannot read the image (Windows XP / 2003).
VOL2_EQUIVALENT = {"vol_pslist": "pslist", "vol_pstree": "pstree", "vol_cmdline": "cmdline",
                   "vol_netscan": "connscan", "vol_malfind": "malfind", "vol_dlllist": "dlllist",
                   "vol_printkey": "printkey"}
# vol3 2.28 on an XP/2003 image: a symbol table is found but it has no _ETHREAD.
XP_SIGNATURE = re.compile(r"Symbol type not in \S+ SymbolTable: _ETHREAD")
NO_SYMBOLS = re.compile(r"Unable to validate the plugin requirements: .*symbol_table_name")
LEGACY_PROFILE = re.compile(r"^Win(XP|2003)")
YARA_TEXT = re.compile(r"^[\x20-\x7e]{3,128}$")
YARA_HEX = re.compile(r"^[0-9A-Fa-f]{2}(?: ?[0-9A-Fa-f]{2}){1,63}$")
DUMP_NAME = re.compile(r"(0x[0-9a-fA-F]+)-(0x[0-9a-fA-F]+)")


class Approval(BaseModel):
    """Form shown to the analyst for a sensitive action."""

    approve: bool
    analyst: str = ""


def _offset(v: Any) -> int:
    if isinstance(v, bool):
        raise ValueError("offset must be an integer")
    if isinstance(v, int):
        n = v
    elif isinstance(v, str) and re.fullmatch(r"(0[xX][0-9a-fA-F]+|\d+)", v.strip()):
        n = int(v.strip(), 0)
    else:
        raise ValueError(f"offset must be an integer or 0x-hex string, got {v!r}")
    if n < 0:
        raise ValueError("offset must be >= 0")
    return n


def _pid(v: Any) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise ValueError("pid must be a non-negative integer")
    return v


def _key(v: Any) -> str:
    if not isinstance(v, str) or not KEY_RE.match(v):
        raise ValueError("key must be a registry path (no control character, no leading '-')")
    return v


def yara_string(text: Any, hex_bytes: Any) -> str:
    """The ONE string vol2 yarascan searches (-Y): an escaped text or a hex byte sequence.
    vol2 wraps it into `rule r1 {strings: $a = "<text>" condition: $a}`; a leading "{" or "/"
    would make it a hex or regex string, and an unescaped quote would end the string and let
    the caller write rule syntax."""
    if (text is None) == (hex_bytes is None):
        raise ValueError("give exactly one of text or hex_bytes")
    if hex_bytes is not None:
        if not isinstance(hex_bytes, str) or not YARA_HEX.match(hex_bytes.strip()):
            raise ValueError("hex_bytes must be 2-64 bytes written as hex pairs, e.g. '4d 5a 90'")
        h = hex_bytes.replace(" ", "").lower()
        return "{ " + " ".join(h[i:i + 2] for i in range(0, len(h), 2)) + " }"
    if not isinstance(text, str) or not YARA_TEXT.match(text):
        raise ValueError("text must be 3-128 printable ASCII characters")
    if text[0] in "{/":
        raise ValueError("text cannot start with '{' or '/' (vol2 would read it as a hex or "
                         "regex pattern): start one character later")
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _printable(hexdata: str, wide: bool) -> str:
    try:
        raw = bytes.fromhex(hexdata)
    except ValueError:
        return ""
    if wide:
        raw = raw[::2]
    return "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in raw)


class MemoryOps:
    """Mixed into ops.Engine (uses its cfg, actor, _policy, _restore_path, _page)."""

    async def sensitive_reason(self, tool: str, params: dict[str, Any]) -> str | None:
        """Why a call needs human confirmation (None = it does not). Used both by the
        server-side resolver that asks the analyst and by the operation that enforces it."""
        try:
            if tool == "replay":
                orig = audit.read_event(self.cfg.audit_file, int(params["audit_id"]))
                return await self.sensitive_reason(orig.get("tool", ""), orig.get("params", {}))
            if tool == "disk_extract_file":
                return await self.extract_file_sensitive(params)
            if tool == "mem_extract_vad":
                return "memory extraction (one VAD of one process)"
            if tool == "net_extract_pcap":
                return "network extraction (filtered copy of a capture)"
            if tool == "disk_extract":
                from .engines.sleuthkit import SENSITIVE_TARGETS
                return ("credential hives (SAM/SECURITY)"
                        if set(params.get("targets") or []) & SENSITIVE_TARGETS else None)
            if params.get("dump"):
                return "extraction (--dump)"
            if tool == "vol3_run":
                full = volatility3.resolve_plugin(str(params["plugin"]),
                                                  await volatility3.list_plugins(self.cfg))
                return "credential/extraction plugin" if SENSITIVE_VOL3.search(full) else None
            if tool == "vol2_run" and str(params.get("plugin")) in SENSITIVE_VOL2:
                return "credential plugin"
        except (KeyError, ValueError, TypeError):
            return None  # invalid request: the operation itself refuses it
        return None

    async def _confirm(self, tool: str, params: dict[str, Any], reason: str, conf: Any) -> None:
        """Enforce the analyst's answer (never the LLM's); journaled either way.
        `conf` is the ElicitationResult injected by the server's resolver: Accepted with an
        Approval, Declined/Cancelled, or Accepted with a marker string ("unsupported",
        "not-needed") when nothing could be asked."""
        aid = secrets.token_hex(4)
        audit.append(self.cfg.audit_file, "action_request", self.actor, action_id=aid, tool=tool,
                     params=params, reason=reason)
        decision, analyst, error = "denied", "", ""
        data = getattr(conf, "data", None)
        action = getattr(conf, "action", None)
        if isinstance(data, Approval):
            analyst = data.analyst.strip()
            if action == "accept" and data.approve and analyst:
                decision = "approved"
            else:
                error = "approval without an analyst name" if data.approve else "refused"
        elif action in ("decline", "cancel"):
            error = f"analyst answered {action}"
        elif data == "unsupported":
            error = "this MCP client cannot ask the analyst (no form elicitation)"
        else:
            error = "no confirmation was requested for this call"
        actor = {"kind": "analyst", "name": analyst} if analyst else {"kind": "server"}
        audit.append(self.cfg.audit_file, "action_confirmed", actor, action_id=aid, tool=tool,
                     params=params, decision=decision, channel="elicitation",
                     **({"error": error} if error else {}))
        if decision != "approved":
            raise safety.SafetyError(f"sensitive action not confirmed by a named analyst "
                                     f"({reason}; action_id {aid}){': ' + error if error else ''}")

    async def _memory_result(self, tool: str, params: dict[str, Any], real: dict[str, Any],
                             path: Path, ps: Any, ev: dict[str, Any], r: dict[str, Any],
                             engine: str, pid_filter: int | None = None,
                             page: dict[str, Any] | None = None) -> Any:
        from .ops import Outcome  # circular at import time

        analysis = analyzers.analyze(self.cfg.output_root, ev["sha256"], r["plugin"],
                                     results.iter_rows(r["dir"]))
        filters = {"column": "PID", "equals": str(pid_filter)} if pid_filter is not None else {}
        q = self._page(r["dir"], **filters, **(page or {}))
        status = "" if r["exit_code"] == 0 else f" (exit code {r['exit_code']})"
        n_anom = len(analysis["anomalies"])
        extra: dict[str, Any] = {"exit_code": r["exit_code"],
                                 "anomalies": analysis["anomalies"],
                                 "next_steps": analysis["next_steps"]}
        if analysis["iocs"]:
            extra["iocs"] = analysis["iocs"]
        if analysis["decoded"]:
            extra["decoded"] = analysis["decoded"]
        if r["exit_code"] != 0:
            extra["stderr_tail"] = r["stderr_tail"]
        total = q["matched"] if pid_filter is not None else r["row_count"]
        payload = contract.build(
            tool=tool, engine=engine, plugin=r["plugin"], parameters=params, evidence=ev,
            summary=f"{total} rows from {r['plugin']}{status}. {n_anom} anomalies"
                    + (f" ({', '.join(sorted({a['severity'] for a in analysis['anomalies']}))})"
                       if n_anom else "") + ".",
            rows=q["rows"], row_count=total, offset=q["offset"], limit=q["limit"],
            result_id=r["result_id"], truncated=q["truncated"], extra=extra,
            next_call=None if pid_filter is None else {"tool": "query_results", "args": {
                "result_id": r["result_id"], "column": "PID", "equals": str(pid_filter)}})
        return Outcome(payload, real, argv=r["argv"], engine=engine, evidence_sha256=ev["sha256"],
                       result_id=r["result_id"], exit_code=r["exit_code"],
                       timed_out=r["timed_out"], output_exceeded=r["output_exceeded"],
                       output_sha256=results.rows_sha256(r["dir"]), pseudo=ps)

    def _prepare(self, params: dict[str, Any]) -> tuple[dict[str, Any], Path, Any]:
        real = {**params, "path": self._restore_path(params["path"])}
        path = volatility3.image_path(self.cfg, real["path"])
        ps = self._policy(path)
        if ps:
            real = {**ps.restore(real), "path": real["path"]}
        return real, path, ps

    async def _vol3(self, tool: str, params: dict[str, Any], plugin: str, conf: Any) -> Any:
        real, path, ps = self._prepare(params)
        full = volatility3.resolve_plugin(plugin, await volatility3.list_plugins(self.cfg))
        known = await volatility3.plugin_options(self.cfg, full)
        opts: list[str] = []
        pid_filter = None
        if real.get("pid") is not None:
            if "--pid" in known:
                opts += ["--pid", str(_pid(real["pid"]))]
            elif tool == "vol_netscan":
                pid_filter = _pid(real["pid"])  # netscan has no --pid: filtered by the server
            else:
                raise ValueError(f"{full} has no --pid option")
        if real.get("offset") is not None:
            if "--offset" not in known:
                raise ValueError(f"{full} has no --offset option")
            opts += ["--offset", str(_offset(real["offset"]))]
        if real.get("key") is not None:
            if "--key" not in known or not KEY_RE.match(str(real["key"])):
                raise ValueError(f"{full} has no --key option or the key is invalid")
            opts += ["--key", str(real["key"])]
        if real.get("dump"):
            if "--dump" not in known:
                raise ValueError(f"{full} has no --dump option")
            opts.append("--dump")
        if SENSITIVE_VOL3.search(full) or real.get("dump"):
            reason = "extraction (--dump)" if real.get("dump") else "credential/extraction plugin"
            await self._confirm(tool, real, reason, conf)
        ev = evidence.check_before_use(self.cfg, path, self.actor)
        r = await volatility3.run(self.cfg, path, full, opts, ev["sha256"])
        out = await self._memory_result(tool, params, real, path, ps, ev, r,
                                        f"volatility3 {r['version']}", pid_filter)
        self._legacy_hint(tool, params, ev, r, out)
        return out

    def _legacy_profiles(self, sha256: str) -> list[str]:
        cache = Path(self.cfg.output_root) / ".toolcache" / "vol2_imageinfo.json"
        return [p for p in _read_json(cache).get(sha256, {}).get("profiles", [])
                if LEGACY_PROFILE.match(p)]

    def _legacy_hint(self, tool: str, params: dict[str, Any], ev: dict[str, Any],
                     r: dict[str, Any], out: Any) -> None:
        """A vol3 run that failed on symbols says what to do instead of a raw symbol error:
        Windows XP / 2003 images are not supported by Volatility 3 (known limit, not a bug)."""
        if r["exit_code"] == 0 or not NO_SYMBOLS.search(r["stderr_tail"]):
            return
        profiles = self._legacy_profiles(ev["sha256"])
        xp = bool(profiles) or bool(XP_SIGNATURE.search(r["stderr_tail"]))
        plugin = VOL2_EQUIVALENT.get(tool)
        if xp:
            msg = ("Windows XP / 2003 image detected"
                   + (f" (vol2 profile {profiles[0]})" if profiles else " (vol3 symbol table "
                      "without _ETHREAD)")
                   + ": Volatility 3 does not support it, so the vol_* tools and vol3_run "
                     "cannot read this image. Use vol2_run"
                   + (f" (plugin {plugin})" if plugin else "")
                   + (f" with profile {profiles[0]}." if profiles
                      else " with a profile from vol2_imageinfo."))
        else:
            msg = ("Volatility 3 found no usable symbol table for this image (no symbols for "
                   "this Windows build, or offline symbol cache). If vol2_imageinfo suggests a "
                   "profile, use vol2_run instead.")
        steps = [{"tool": "vol2_imageinfo", "args": {"path": params["path"]},
                  "why": "vol2 profile of this image"}]
        if profiles and plugin:
            steps = [{"tool": "vol2_run", "args": {"path": params["path"], "plugin": plugin,
                                                    "profile": profiles[0]},
                      "why": "same question with Volatility 2, which supports this image"}]
        out.payload["summary"] = msg
        out.payload["notes"] = [msg, *out.payload.get("notes", [])]
        out.payload["next_steps"] = steps
        out.error = msg

    async def _typed(self, tool: str, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._vol3(tool, params, TYPED_VOL3[tool], conf)

    async def op_vol_pslist(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._typed("vol_pslist", params, conf)

    async def op_vol_pstree(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._typed("vol_pstree", params, conf)

    async def op_vol_cmdline(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._typed("vol_cmdline", params, conf)

    async def op_vol_netscan(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._typed("vol_netscan", params, conf)

    async def op_vol_malfind(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._typed("vol_malfind", params, conf)

    async def op_vol_dlllist(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._typed("vol_dlllist", params, conf)

    async def op_vol_printkey(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._typed("vol_printkey", params, conf)

    async def op_vol3_run(self, params: dict[str, Any], conf: Any = None) -> Any:
        return await self._vol3("vol3_run", params, params["plugin"], conf)

    async def op_vol_list_plugins(self, params: dict[str, Any], conf: Any = None) -> Any:
        plugins = await volatility3.list_plugins(self.cfg)
        needle = (params.get("contains") or "").lower()
        items = [{"name": k, **v, "sensitive": bool(SENSITIVE_VOL3.search(k))}
                 for k, v in plugins.items() if needle in k.lower()]
        out = self._listing("vol_list_plugins", params, items, f"{len(items)} vol3 plugins")
        out.engine = out.payload["engine"] = f"volatility3 {await volatility3.version(self.cfg)}"
        return out

    async def op_vol2_list_plugins(self, params: dict[str, Any], conf: Any = None) -> Any:
        inf = await volatility2.info(self.cfg)
        needle = (params.get("contains") or "").lower()
        items = [{"name": k, "description": v, "sensitive": k in SENSITIVE_VOL2,
                  "refused_needs_dump_dir": ("dump" in k and k not in volatility2.PRINTING_DUMPS)
                  or k in volatility2.NEEDS_DUMP_DIR}
                 for k, v in inf.get("Plugins", {}).items() if needle in k.lower()]
        profiles = sorted(inf.get("Profiles", {}))
        out = self._listing("vol2_list_plugins", params, items,
                            f"{len(items)} vol2 plugins; {len(profiles)} profiles: "
                            + ", ".join(profiles))
        out.engine = out.payload["engine"] = "volatility2 2.6"
        return out

    async def op_vol2_imageinfo(self, params: dict[str, Any], conf: Any = None) -> Any:
        real, path, ps = self._prepare(params)
        ev = evidence.check_before_use(self.cfg, path, self.actor)
        cache = Path(self.cfg.output_root) / ".toolcache" / "vol2_imageinfo.json"
        known = _read_json(cache).get(ev["sha256"])
        if known and (Path(self.cfg.output_root) / known["result_id"]).is_dir():
            d = results.result_dir(self.cfg.output_root, known["result_id"])
            meta = results.read_meta(d)
            r = {"result_id": d.name, "dir": d, "plugin": "imageinfo", "argv": meta["argv"],
                 "version": "2.6", "exit_code": meta["exit_code"], "timed_out": False,
                 "output_exceeded": False, "row_count": meta["row_count"], "stderr_tail": ""}
        else:
            r = await volatility2.run(self.cfg, path, "imageinfo", None, [], ev["sha256"])
            profiles = volatility2.parse_imageinfo(list(results.iter_rows(r["dir"])))
            data = _read_json(cache)
            data[ev["sha256"]] = {"result_id": r["result_id"], "profiles": profiles}
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(data, indent=1), encoding="utf-8")
        out = await self._memory_result("vol2_imageinfo", params, real, path, ps, ev, r,
                                        "volatility2 2.6")
        profiles = volatility2.parse_imageinfo(list(results.iter_rows(r["dir"])))
        out.payload["summary"] = ("Suggested profiles: " + ", ".join(profiles) if profiles
                                  else "no profile suggested") + (" (cached)" if known else "")
        return out

    async def op_vol2_run(self, params: dict[str, Any], conf: Any = None) -> Any:
        real, path, ps = self._prepare(params)
        inf = await volatility2.info(self.cfg)
        plugin = volatility2.check_plugin(str(real["plugin"]), inf.get("Plugins", {}))
        profile = str(real["profile"])
        if not PROFILE_RE.match(profile) or profile not in inf.get("Profiles", {}):
            raise ValueError(f"unknown vol2 profile {profile!r} (see vol2_list_plugins / "
                             "vol2_imageinfo)")
        known = await volatility2.plugin_options(self.cfg, plugin)
        opts: list[str] = []
        for name, flag, conv in (("pid", "--pid", _pid), ("offset", "--offset", _offset),
                                 ("key", "--key", _key)):
            if real.get(name) is not None:
                if flag not in known:
                    raise ValueError(f"vol2 {plugin} has no {flag} option")
                opts.append(f"{flag}={conv(real[name])}")
        if plugin in SENSITIVE_VOL2:
            await self._confirm("vol2_run", real, "credential plugin", conf)
        ev = evidence.check_before_use(self.cfg, path, self.actor)
        r = await volatility2.run(self.cfg, path, plugin, profile, opts, ev["sha256"])
        return await self._memory_result("vol2_run", params, real, path, ps, ev, r,
                                         "volatility2 2.6")

    async def _vol2_profile(self, real: dict[str, Any], plugin: str) -> tuple[str, set[str]]:
        inf = await volatility2.info(self.cfg)
        if plugin not in inf.get("Plugins", {}):
            raise ValueError(f"the installed vol2 has no {plugin} plugin")
        profile = str(real["profile"])
        if not PROFILE_RE.match(profile) or profile not in inf.get("Profiles", {}):
            raise ValueError(f"unknown vol2 profile {profile!r} (see vol2_list_plugins / "
                             "vol2_imageinfo)")
        return profile, await volatility2.plugin_options(self.cfg, plugin)

    async def op_vol2_yarascan(self, params: dict[str, Any], conf: Any = None) -> Any:
        """One string searched in the address space of ONE process (vol2 yarascan -p -Y)."""
        real, path, ps = self._prepare(params)
        profile, known = await self._vol2_profile(real, "yarascan")
        if real.get("pid") is None:
            raise ValueError("pid is required: this tool searches the memory of one process")
        extra = (["--wide"] if real.get("wide") else []) + (
            ["--case"] if real.get("case_insensitive") else [])
        missing = [f for f in ["--pid", "--yara-rules", *extra] if f not in known]
        if missing:
            raise ValueError(f"vol2 yarascan has no {', '.join(missing)} option")
        opts = [f"--pid={_pid(real['pid'])}",
                f"--yara-rules={yara_string(real.get('text'), real.get('hex_bytes'))}", *extra]
        ev = evidence.check_before_use(self.cfg, path, self.actor)
        r = await volatility2.run(self.cfg, path, "yarascan", profile, opts, ev["sha256"])
        rows = []
        for row in results.iter_rows(r["dir"]):
            if "Data" not in row:  # text fallback: keep the lines as they are
                rows.append({k: v for k, v in row.items() if k != "_row"})
                continue
            owner = str(row.get("Owner", ""))
            m = re.search(r"Pid (\d+)", owner)
            addr = row.get("Address")
            rows.append({"Owner": owner, "PID": int(m.group(1)) if m else None,
                         "Address": hex(addr) if isinstance(addr, int) else addr,
                         "Text": _printable(str(row["Data"]), bool(real.get("wide"))),
                         "Data": row["Data"]})
        _write_rows(r["dir"], rows)
        r["row_count"] = len(rows)
        out = await self._memory_result(
            "vol2_yarascan", params, real, path, ps, ev, r, "volatility2 2.6",
            page={"limit": real.get("limit") or 50, "offset": real.get("offset") or 0})
        out.payload["summary"] = (f"{len(rows)} matches in the memory of PID {real['pid']}"
                                  + (f" (exit code {r['exit_code']})" if r["exit_code"] else "")
                                  + ". Text = printable bytes from the match on.")
        out.payload["notes"] = [
            "Text is the server's ASCII rendering of the bytes in Data ('.' = non printable"
            + ("; wide: every second byte" if real.get("wide") else "") + ").",
            "0 match means the string is not in the pages of this process that are present in "
            "the image (paged-out memory is not searched), not that it never existed."]
        return out

    async def op_mem_extract_vad(self, params: dict[str, Any], conf: Any = None) -> Any:
        """Memory counterpart of disk_extract_file: ONE memory region (VAD) of ONE process is
        written under the result folder, hashed and registered as derived evidence. Never a
        whole process, never the whole image; always confirmed by a named analyst."""
        real, path, ps = self._prepare(params)
        pid = _pid(real.get("pid"))
        try:
            addr = _offset(real.get("address"))
        except ValueError as exc:
            raise ValueError(str(exc).replace("offset", "address")) from exc
        cap = self.cfg.max_output_mb * 1024 * 1024
        if real.get("profile"):
            profile, known = await self._vol2_profile(real, "vaddump")
            flags = ["--pid", "--base", "--max-size", "--dump-dir"]
        else:
            profile = None
            full = volatility3.resolve_plugin("windows.vadinfo",
                                              await volatility3.list_plugins(self.cfg))
            known = set(await volatility3.plugin_options(self.cfg, full))
            flags = ["--pid", "--address", "--maxsize", "--dump"]
        missing = [f for f in flags if f not in known]
        if missing:
            raise ValueError(f"the installed engine has no {', '.join(missing)} option")
        await self._confirm("mem_extract_vad", real,
                            "memory extraction (one VAD of one process)", conf)
        ev = evidence.check_before_use(self.cfg, path, self.actor)
        if profile:
            engine = "volatility2 2.6"
            r = await volatility2.run(
                self.cfg, path, "vaddump", profile,
                [f"--pid={pid}", f"--base={addr:#x}", f"--max-size={cap}"], ev["sha256"],
                dump=True)
            produced = sorted((r["dir"] / "extracted").iterdir())
        else:
            r = await volatility3.run(self.cfg, path, full, [
                "--pid", str(pid), "--address", str(addr), "--maxsize", str(cap), "--dump"],
                ev["sha256"])
            engine = f"volatility3 {r['version']}"
            (r["dir"] / "extracted").mkdir()
            produced = sorted(p for p in (r["dir"] / "files").iterdir() if p.is_file())
        rows = []
        for n, src in enumerate(produced, 1):
            m = DUMP_NAME.search(src.name)
            start, end = (m.group(1).lower(), m.group(2).lower()) if m else (None, None)
            dest = r["dir"] / "extracted" / (f"pid{pid}_vad_{start}-{end}.dmp" if m
                                             else f"pid{pid}_region_{n}.dmp")
            os.replace(src, dest)
            digest = results.sha256_file(dest)
            os.chmod(dest, 0o444)
            reg = evidence.register_derived(
                self.cfg, dest, digest, self.actor, source_image=ev["path"],
                source_sha256=ev["sha256"], pid=pid, vad_start=start, vad_end=end)
            rows.append({"pid": pid, "vad_start": start, "vad_end": end,
                         "path": evidence.relpath(self.cfg, dest), "size": reg["size"],
                         "sha256": digest, "engine_file_name": src.name,
                         "registration_audit_id": reg["audit_id"]})
        _write_rows(r["dir"], rows)
        r["row_count"] = len(rows)
        out = await self._memory_result("mem_extract_vad", params, real, path, ps, ev, r, engine)
        notes = ["The SHA-256 is the hash of a memory region as it was in the image (pages "
                 "absent from the image are zero-filled). It is NOT the hash of the file on "
                 "disk: do not compare it with a file hash from another source.",
                 'Use the "path" column (@<result_id>/...) as input of ez_run (e.g. bstrings).']
        if rows:
            out.payload["summary"] = (f"{len(rows)} memory region of PID {pid} extracted, "
                                      f"hashed and registered ({rows[0]['size']} bytes).")
        else:
            msg = (f"nothing extracted: PID {pid} has no VAD "
                   + ("starting at" if profile else "containing") + f" {addr:#x} within "
                   f"{self.cfg.max_output_mb} MB (see the vadinfo plugin for the regions of "
                   "this process)")
            out.payload["summary"], out.error = msg, msg
            notes.insert(0, msg)
        out.payload["notes"] = notes
        return out


def _write_rows(d: Path, rows: list[dict[str, Any]]) -> None:
    (d / "rows.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False, default=str) + "\n"
                                          for r in rows), encoding="utf-8")


def _read_json(p: Path) -> dict[str, Any]:
    """JSON file content, {} if absent."""
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
