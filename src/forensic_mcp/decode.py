"""Server-side decoding of encoded PowerShell and IOC extraction (CLAUDE.md §10).

The LLM never decodes base64: the server does it (≤ 2 layers, base64 → UTF-16LE) and returns
the decoded text and the IOCs it contains.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from typing import Any

MAX_LAYERS = 2
FULL = "encodedcommand"
ALIASES = {"ec"}
B64 = re.compile(r"^[A-Za-z0-9+/=]{8,}$")
FROM_B64 = re.compile(r"FromBase64String\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)", re.I)
URL = re.compile(r"https?://[^\s'\"<>()]+", re.I)
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def _is_enc_flag(tok: str) -> bool:
    """True for -e, -en, …, -EncodedCommand, -ec (also with '/'), case-insensitive."""
    if len(tok) < 2 or tok[0] not in "-/":
        return False
    name = tok[1:].lower()
    return name in ALIASES or FULL.startswith(name)


def _b64_utf16(blob: str) -> str | None:
    blob = blob.strip().strip("'\"")
    if not B64.match(blob):
        return None
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        text = raw.decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    return text if text and printable / len(text) > 0.9 else None


def encoded_blob(args: str) -> str | None:
    """The base64 argument of an -EncodedCommand flag (any prefix), if present."""
    toks = args.split()
    for i, tok in enumerate(toks[:-1]):
        if _is_enc_flag(tok):
            return toks[i + 1].strip("'\"")
    return None


def decode_powershell(args: str) -> dict[str, Any] | None:
    """{"layers": n, "text": decoded} for an encoded PowerShell command line, else None."""
    blob = encoded_blob(args)
    text = _b64_utf16(blob) if blob else None
    if text is None:
        return None
    layers = 1
    while layers < MAX_LAYERS:
        inner = encoded_blob(text)
        m = FROM_B64.search(text) if inner is None else None
        nxt = _b64_utf16(inner) if inner else (_b64_utf16(m.group(1)) if m else None)
        if nxt is None:
            break
        text, layers = nxt, layers + 1
    return {"layers": layers, "text": text}


def extract_iocs(text: str) -> list[dict[str, str]]:
    """URLs, their host (IP or domain) and standalone IPv4 addresses (loopback excluded)."""
    found: dict[tuple[str, str], None] = {}
    for url in URL.findall(text):
        url = url.rstrip(".,;'\"")
        found[("url", url)] = None
        host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split(":")[0]
        found[("ip" if IPV4.fullmatch(host) else "domain", host.lower())] = None
    for ip in IPV4.findall(text):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not (addr.is_loopback or addr.is_unspecified):
            found[("ip", ip)] = None
    return [{"type": t, "value": v} for t, v in found]
