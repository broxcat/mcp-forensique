"""Case classification and pseudonymisation (confidential-data guardrail, L2 §10).

case.toml (nearest one above the evidence file, inside the evidence root):
    case = "WS-042"
    classification = "lab" | "internal" | "client"
    hosts = ["WS-042"]       # optional seeds, always pseudonymised
    users = ["alice"]
Policy: llm_mode "local" -> raw output. "cloud": lab -> raw, internal -> pseudonymised,
client -> refused. Tokens (HOST_1, USER_1, IP_EXT_1, IP_INT_1) are stable per case, the mapping
stays server-side (output_root/.pseudo/<case>.json) and tokens are accepted as tool inputs.
"""
from __future__ import annotations

import ipaddress
import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import CLASSIFICATIONS, Config
from .safety import SafetyError

IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
TOKEN = re.compile(r"\b(?:HOST|USER|IP_EXT|IP_INT)_\d+\b")
HOST_COLS = {"computer", "computername", "hostname", "host", "machinename", "workstationname",
             "domain", "targetdomainname", "subjectdomainname"}
USER_COLS = {"user", "username", "account", "accountname", "targetusername", "subjectusername"}
GENERIC = {"", "-", "n/a", "system", "local service", "network service", "localsystem",
           "nt authority", "anonymous logon", "workgroup"}
BUILTIN = re.compile(r"^(dwm|umfd)-\d+$", re.I)
# Explicit list: Python's is_private also covers documentation ranges (TEST-NET), which the lab
# uses to stand for public addresses.
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10")]
# Response fields that never carry artefact data (identifiers, hashes, fixed text).
SKIP_KEYS = {"result_id", "tool", "engine", "plugin", "sha256", "untrusted_notice", "audit_id",
             "rule_id", "attack", "severity", "_row"}


@dataclass
class Case:
    """Case settings resolved for one evidence path."""

    case_id: str
    classification: str
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    source: str | None = None


def case_for(cfg: Config, path: Path | None) -> Case:
    """Nearest case.toml between the evidence file and the evidence root; default otherwise."""
    root = Path(cfg.evidence_root).resolve()
    d = Path(path).resolve().parent if path else root
    while d.is_relative_to(root):
        f = d / "case.toml"
        if f.is_file():
            raw = tomllib.loads(f.read_text(encoding="utf-8"))
            cls = raw.get("classification")
            if cls not in CLASSIFICATIONS:
                raise SafetyError(f"{f.relative_to(root)}: classification must be one of "
                                  f"{CLASSIFICATIONS}, got {cls!r}")
            case_id = str(raw.get("case") or d.name)
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", case_id):
                raise SafetyError(f"invalid case id {case_id!r}")
            return Case(case_id, cls, list(raw.get("hosts", [])), list(raw.get("users", [])),
                        str(f.relative_to(root)))
        if d == root:
            break
        d = d.parent
    return Case("default", cfg.default_classification)


def pseudonymizer_for(cfg: Config, case: Case) -> "Pseudonymizer | None":
    """Apply the policy: None = raw output; refuse client data in cloud mode."""
    if cfg.llm_mode == "local" or case.classification == "lab":
        return None
    if case.classification == "client":
        raise SafetyError(f"case {case.case_id} is classified 'client': analysis refused while "
                          "llm_mode = 'cloud' (use the local model)")
    return Pseudonymizer(Path(cfg.output_root) / ".pseudo" / f"{case.case_id}.json", case)


def _norm(col: str) -> str:
    return re.sub(r"[^a-z]", "", col.lower())


class Pseudonymizer:
    """Stable tokens for hosts, users and IPs of one case."""

    def __init__(self, store: Path, case: Case) -> None:
        self.store = store
        data = json.loads(store.read_text(encoding="utf-8")) if store.exists() else {}
        self.fwd: dict[str, str] = data.get("fwd", {})       # lower(real) -> token
        self.rev: dict[str, str] = data.get("rev", {})       # token -> real
        self.count: dict[str, int] = data.get("count", {})
        for h in case.hosts:
            self.token("HOST", h)
        for u in case.users:
            self.token("USER", u)

    def save(self) -> None:
        """Persist the mapping server-side (never returned to the LLM)."""
        self.store.parent.mkdir(parents=True, exist_ok=True)
        self.store.write_text(json.dumps({"fwd": self.fwd, "rev": self.rev, "count": self.count},
                                         indent=1), encoding="utf-8")

    def token(self, kind: str, value: str) -> str:
        """Token for a real value (created on first sight)."""
        key = value.lower()
        if key not in self.fwd:
            self.count[kind] = self.count.get(kind, 0) + 1
            tok = f"{kind}_{self.count[kind]}"
            self.fwd[key], self.rev[tok] = tok, value
        return self.fwd[key]

    def _ip(self, m: re.Match[str]) -> str:
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            return m.group(0)
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast or str(ip) == "255.255.255.255":
            return m.group(0)
        internal = any(ip in net for net in INTERNAL_NETS)
        return self.token("IP_INT" if internal else "IP_EXT", str(ip))

    def text(self, s: str) -> str:
        """Pseudonymise one string: IPv4 addresses, then every known host/user name."""
        s = IPV4.sub(self._ip, s)
        names = sorted((k for k, t in self.fwd.items() if not t.startswith("IP_")), key=len,
                       reverse=True)
        if names:
            rx = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(map(re.escape, names))
                            + r")(?![A-Za-z0-9_])", re.I)
            s = rx.sub(lambda m: self.fwd[m.group(1).lower()], s)
        return s

    def learn(self, rows: list[dict[str, Any]]) -> None:
        """Register values of host/user columns so they are replaced everywhere."""
        for row in rows:
            for col, v in row.items():
                if not isinstance(v, str) or v.strip().lower() in GENERIC or BUILTIN.match(v):
                    continue
                n = _norm(col)
                if n in HOST_COLS:
                    self.token("HOST", v.strip())
                elif n in USER_COLS:
                    self.token("USER", v.strip())

    def redact(self, obj: Any, key: str = "") -> Any:
        """Pseudonymise every string of a response (except SKIP_KEYS)."""
        if key in SKIP_KEYS:
            return obj
        if isinstance(obj, dict):
            if key == "" and isinstance(obj.get("rows"), list):
                self.learn(obj["rows"])
            return {k: self.redact(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.redact(v, key) for v in obj]
        return self.text(obj) if isinstance(obj, str) else obj

    def restore(self, obj: Any) -> Any:
        """Replace tokens by real values in tool inputs."""
        if isinstance(obj, str):
            return TOKEN.sub(lambda m: self.rev.get(m.group(0), m.group(0)), obj)
        if isinstance(obj, list):
            return [self.restore(v) for v in obj]
        if isinstance(obj, dict):
            return {k: self.restore(v) for k, v in obj.items()}
        return obj
