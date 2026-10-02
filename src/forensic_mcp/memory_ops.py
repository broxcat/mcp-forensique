"""Memory operations (EF-01, Décision J3): typed vol3 tools, vol3_run / vol2_run on any plugin,
sensitive plugins confirmed by a human, analyzers on every result.

Typed parameters only (rule 8): pid, offset, key, dump, profile. Each is translated to an option
that the plugin's own help declares; anything else is refused."""
from __future__ import annotations

import json
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
                             engine: str, pid_filter: int | None = None) -> Any:
        from .ops import Outcome  # circular at import time

        analysis = analyzers.analyze(self.cfg.output_root, ev["sha256"], r["plugin"],
                                     results.iter_rows(r["dir"]))
        filters = {"column": "PID", "equals": str(pid_filter)} if pid_filter is not None else {}
        q = self._page(r["dir"], **filters)
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
            rows=q["rows"], row_count=total, limit=q["limit"], result_id=r["result_id"],
            truncated=q["truncated"], extra=extra,
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
        return await self._memory_result(tool, params, real, path, ps, ev, r,
                                         f"volatility3 {r['version']}", pid_filter)

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
        for name, flag, conv in (("pid", "--pid", _pid), ("offset", "--offset", _offset)):
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


def _read_json(p: Path) -> dict[str, Any]:
    """JSON file content, {} if absent."""
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
