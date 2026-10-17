"""Network captures (task 6.7, extension EXT-03 approved 17/10/2026): .pcap / .pcapng files read
with tshark and capinfos (wireshark-common 4.0.17), never a live interface.

Flags come from docs/tool_help/{tshark,capinfos}.txt (rule 6) and every field name used here is
in `tshark -G fields` (docs/tool_help/tshark_fields_used.txt, written by
scripts/capture_net_help.sh). No caller string ever reaches the command line (rule 8): the
display filter is BUILT here from typed values (ipaddress.ip_address, ports 1-65535, a closed
protocol set, ISO-8601 instants); text searches are applied server-side on the parsed rows.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .. import runner
from ..config import Config

# Never passed TO TSHARK: -X loads extension options, -z is the statistics machinery (it can
# follow and print whole streams), -o overrides any preference (including output paths), -i / -k
# capture from a live interface, --export-objects writes carved files out of a capture. These
# letters mean other, harmless things in capinfos (-o = chronological status), whose argv is
# fixed by capinfos_argv and holds no caller value at all: the list applies to tshark only.
FORBIDDEN = frozenset({"-X", "-z", "-o", "-i", "-k", "--interface", "--export-objects"})
# -w is passed by net_extract_pcap only, with a path chosen by the server inside the result
# folder; -G only by the field-name check (it takes no capture file and no caller value).
SERVER_ONLY = frozenset({"-w", "-G"})
USED_TSHARK = frozenset({"-n", "-r", "-Y", "-T", "-E", "-e", "-w", "-G", "--version"})
USED_CAPINFOS = frozenset({"-M", "-S", "-t", "-E", "-c", "-s", "-d", "-l", "-u", "-a", "-e",
                           "-o", "--version"})
# Protocols accepted as a typed parameter; each is a bare protocol name of the display-filter
# language ("the packet holds this protocol").
PROTOCOLS = ("tcp", "udp", "icmp", "dns", "http", "tls")
MAX_ROWS = 200_000          # rows written for one parse (bound, ET-02)
_version: dict[str, str] = {}


@dataclass(frozen=True)
class View:
    """One typed reading of a capture: its own display filter and its own field list."""

    base: str                                    # fixed filter of the view (never from a caller)
    fields: tuple[tuple[str, str], ...]          # (column name, tshark field name)

    @property
    def columns(self) -> tuple[str, ...]:
        return tuple(c for c, _ in self.fields)


_FRAME = (("frame", "frame.number"), ("time_epoch", "frame.time_epoch"),
          ("protocols", "frame.protocols"))
_IP = (("src", "ip.src"), ("dst", "ip.dst"), ("src6", "ipv6.src"), ("dst6", "ipv6.dst"))
VIEWS: dict[str, View] = {
    "packets": View("", (*_FRAME, ("length", "frame.len"), *_IP,
                         ("tcp_src", "tcp.srcport"), ("tcp_dst", "tcp.dstport"),
                         ("udp_src", "udp.srcport"), ("udp_dst", "udp.dstport"))),
    "dns": View("dns", (*_FRAME, *_IP, ("response", "dns.flags.response"),
                        ("query_name", "dns.qry.name"), ("query_type", "dns.qry.type"),
                        ("answer_a", "dns.a"), ("answer_aaaa", "dns.aaaa"),
                        ("answer_cname", "dns.cname"), ("rcode", "dns.flags.rcode"))),
    "http": View("http.request || http.response",
                 (*_FRAME, *_IP, ("dst_port", "tcp.dstport"),
                  ("method", "http.request.method"), ("host", "http.host"),
                  ("uri", "http.request.uri"), ("full_uri", "http.request.full_uri"),
                  ("user_agent", "http.user_agent"), ("response_code", "http.response.code"),
                  ("content_type", "http.content_type"),
                  ("content_length", "http.content_length"))),
    "tls": View("tls.handshake.type == 1 || tls.handshake.type == 2",
                (*_FRAME, *_IP, ("dst_port", "tcp.dstport"),
                 ("handshake_type", "tls.handshake.type"),
                 ("version", "tls.handshake.version"),
                 ("ciphersuite", "tls.handshake.ciphersuite"),
                 ("server_name", "tls.handshake.extensions_server_name"),
                 ("ja3", "tls.handshake.ja3"), ("ja3s", "tls.handshake.ja3s"))),
}
_INT_COLUMNS = frozenset({"frame", "length", "response_code", "content_length", "rcode",
                          "query_type", "handshake_type", "tcp_src", "tcp_dst", "udp_src",
                          "udp_dst", "dst_port"})


def all_fields() -> list[str]:
    """Every tshark field name the server can ask for (checked by scripts/capture_net_help.sh)."""
    return sorted({f for v in VIEWS.values() for _, f in v.fields})


def cmd(cfg: Config, tool: str) -> list[str]:
    """Launch argv of a network tool."""
    if tool not in ("tshark", "capinfos"):
        raise ValueError(f"unknown network tool {tool!r}")
    return [*cfg.tshark_prefix, str(Path(cfg.tshark_dir) / tool)]


def verify_flags() -> list[str]:
    """Flags the server can pass that are NOT in the saved help, or that are forbidden
    (rule 6 + §11). An empty list means the engine matches the installed tools."""
    out: list[str] = []
    here = Path(__file__).resolve().parents[3] / "docs" / "tool_help"
    for tool, used in (("tshark", USED_TSHARK), ("capinfos", USED_CAPINFOS)):
        try:
            help_text = (here / f"{tool}.txt").read_text(encoding="utf-8", errors="replace")
        except OSError:
            out.append(f"{tool}: no docs/tool_help/{tool}.txt")
            continue
        for flag in sorted(used):
            if tool == "tshark" and flag in FORBIDDEN:
                out.append(f"{tool} {flag} is forbidden")
            # the help lists a flag alone or after its short form: "  -v, --version  ..."
            elif not re.search(rf"(?m)^\s*(?:-[^\s,]+,\s*)*{re.escape(flag)}(?:[\s,=<]|$)",
                               help_text):
                out.append(f"{tool} {flag}")
    return out


def check_argv(argv: list[str], writes: Path | None = None) -> None:
    """Last guard before a run (rule 8): no forbidden flag, and -w only to the file the server
    chose inside the result folder."""
    for n, a in enumerate(argv):
        if a in FORBIDDEN or (a.startswith("-X") and len(a) > 2):
            raise ValueError(f"forbidden tshark option: {a}")
        if a == "-w" and (writes is None or argv[n + 1:n + 2] != [str(writes)]):
            raise ValueError("-w is only used by net_extract_pcap, towards the result folder")
        if a == "--export-objects" or a.startswith("--export-objects="):
            raise ValueError("forbidden tshark option: --export-objects")


def epoch(value: str, label: str) -> float:
    """ISO-8601 instant -> epoch seconds (naive = UTC). Raises ValueError, never guesses."""
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be an ISO-8601 UTC instant "
                         f"(e.g. 2026-10-16T14:30:00Z), got {value!r}") from exc
    return (dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt).timestamp()


def iso(epoch_seconds: float) -> str:
    """Epoch seconds -> UTC ISO-8601 with a Z suffix (what every result exposes, §5)."""
    dt = datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc)
    return dt.isoformat(timespec="microseconds" if dt.microsecond else "seconds").replace(
        "+00:00", "Z")


def build_filter(view: str, ip: str | None = None, port: int | None = None,
                 proto: str | None = None, start: str | None = None,
                 end: str | None = None) -> str:
    """The display filter of a call, built here from typed values only (rule 8): every piece is
    a number, an ipaddress-normalised address or a name of PROTOCOLS — never caller text."""
    parts = []
    if VIEWS[view].base:
        parts.append(f"({VIEWS[view].base})")
    if ip not in (None, ""):
        addr = ipaddress.ip_address(str(ip).strip())   # ValueError -> refused and journaled
        parts.append(f"{'ipv6' if addr.version == 6 else 'ip'}.addr == {addr}")
    if port is not None:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("port must be an integer between 1 and 65535")
        parts.append(f"(tcp.port == {port} || udp.port == {port})")
    if proto not in (None, ""):
        if proto not in PROTOCOLS:
            raise ValueError(f"proto must be one of {PROTOCOLS}")
        parts.append(str(proto))
    if start not in (None, ""):
        parts.append(f"frame.time_epoch >= {epoch(str(start), 'start'):.6f}")
    if end not in (None, ""):
        parts.append(f"frame.time_epoch <= {epoch(str(end), 'end'):.6f}")
    return " && ".join(parts)


def read_argv(cfg: Config, path: Path, view: str, display_filter: str) -> list[str]:
    """argv of one typed reading: -n disables every name resolution (no DNS query, no OUI
    lookup, no update check), fixed output format, one -e per field of the view."""
    argv = [*cmd(cfg, "tshark"), "-n", "-r", str(path)]
    if display_filter:
        argv += ["-Y", display_filter]
    argv += ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,",
             "-E", "quote=n", "-E", "header=n"]
    for _, field in VIEWS[view].fields:
        argv += ["-e", field]
    check_argv(argv)
    return argv


def extract_argv(cfg: Config, path: Path, display_filter: str, out_file: Path) -> list[str]:
    """argv of net_extract_pcap: -w towards the file the server chose (pcapng output)."""
    argv = [*cmd(cfg, "tshark"), "-n", "-r", str(path)]
    if display_filter:
        argv += ["-Y", display_filter]
    argv += ["-w", str(out_file)]
    check_argv(argv, writes=out_file)
    return argv


def capinfos_argv(cfg: Config, path: Path) -> list[str]:
    """argv of pcap_info: machine-readable long report, times as epoch seconds. Fully fixed —
    the only caller-dependent item is the jailed capture path (so no flag guard is needed, and
    the tshark FORBIDDEN letters mean something else here: capinfos cannot capture or write)."""
    return [*cmd(cfg, "capinfos"), "-M", "-S", "-t", "-E", "-c", "-s", "-d", "-l", "-u", "-a",
            "-e", "-o", str(path)]


async def version(cfg: Config) -> str:
    """"tshark 4.0.17" (first line of --version), read once per process."""
    if "tshark" not in _version:
        out = Path(cfg.output_root) / ".toolcache"
        out.mkdir(parents=True, exist_ok=True)
        rr = await runner.run_process([*cmd(cfg, "tshark"), "--version"], out / "tshark_v.txt",
                                      out / "tshark_v.err", 60, max_output_bytes=1 << 20)
        first = (out / "tshark_v.txt").read_text(errors="replace").splitlines()
        m = re.search(r"(\d+\.\d+\.\d+)", first[0] if first else "")
        _version["tshark"] = f"tshark {m.group(1)}" if m and rr.exit_code == 0 else "tshark"
    return _version["tshark"]


async def run_to_file(cfg: Config, argv: list[str], stdout: Path, stderr: Path,
                      max_mb: int) -> runner.RunResult:
    """Run a network tool with timeout and an output bound (ET-02)."""
    return await runner.run_process(argv, stdout, stderr, cfg.timeout_seconds,
                                    max_output_bytes=max_mb * 1024 * 1024)


def _value(column: str, raw: str) -> Any:
    """One cell: "" -> None, several occurrences stay a comma-joined string, counters -> int."""
    if raw == "":
        return None
    if column in _INT_COLUMNS and raw.isdigit():
        return int(raw)
    return raw


def iter_rows(text_file: Path, view: str) -> Iterator[dict[str, Any]]:
    """Parse the `-T fields` output of one view: one dict per packet, UTC time added, empty
    fields dropped. Lines with the wrong column count are skipped (never guessed)."""
    columns = VIEWS[view].columns
    with open(text_file, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            cells = line.rstrip("\n").split("\t")
            if len(cells) != len(columns) or not any(cells):
                continue
            row = {c: _value(c, v) for c, v in zip(columns, cells)}
            if row.get("time_epoch"):
                try:
                    row["time_utc"] = iso(float(row["time_epoch"]))
                except (TypeError, ValueError):
                    row["time_utc"] = None
            row["protocol"] = str(row.get("protocols") or "").split(":")[-1] or None
            yield {k: v for k, v in row.items() if v is not None}


def endpoints(row: dict[str, Any]) -> tuple[str | None, str | None, int | None, int | None]:
    """(src, dst, src_port, dst_port) of a parsed packet row, IPv4 or IPv6."""
    src = row.get("src") or row.get("src6")
    dst = row.get("dst") or row.get("dst6")
    sport = row.get("tcp_src") if row.get("tcp_src") is not None else row.get("udp_src")
    dport = row.get("tcp_dst") if row.get("tcp_dst") is not None else row.get("udp_dst")
    return src, dst, sport, dport


def conversations(rows: Iterator[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate parsed packets into conversations, server-side (tshark's own `-z conv,...` is
    never used: -z is forbidden). One row per (src, dst, ports, transport), both directions
    folded together, with packet/byte counts per direction and the UTC first/last times."""
    conv: dict[tuple, dict[str, Any]] = {}
    for row in rows:
        src, dst, sport, dport = endpoints(row)
        if src is None or dst is None:
            continue
        transport = "tcp" if row.get("tcp_src") is not None or row.get("tcp_dst") is not None \
            else ("udp" if row.get("udp_src") is not None or row.get("udp_dst") is not None
                  else (row.get("protocol") or "ip"))
        forward = (str(src), sport or 0) <= (str(dst), dport or 0)
        key = ((src, sport, dst, dport) if forward else (dst, dport, src, sport)) + (transport,)
        c = conv.setdefault(key, {
            "src": key[0], "src_port": key[1], "dst": key[2], "dst_port": key[3],
            "transport": transport, "packets": 0, "bytes": 0, "packets_a_to_b": 0,
            "packets_b_to_a": 0, "bytes_a_to_b": 0, "bytes_b_to_a": 0, "first_utc": None,
            "last_utc": None, "first_frame": row.get("frame"), "protocols": set(),
            "_first": None, "_last": None})
        size = int(row.get("length") or 0)
        c["packets"] += 1
        c["bytes"] += size
        c["packets_a_to_b" if forward else "packets_b_to_a"] += 1
        c["bytes_a_to_b" if forward else "bytes_b_to_a"] += size
        if row.get("protocol"):
            c["protocols"].add(row["protocol"])
        # bounds kept on the epoch, never on the ISO text: "…01Z" and "…01.200000Z" do not
        # compare in time order as strings
        try:
            when = float(row["time_epoch"])
        except (KeyError, TypeError, ValueError):
            when = None
        if when is not None:
            c["_first"] = when if c["_first"] is None else min(c["_first"], when)
            c["_last"] = when if c["_last"] is None else max(c["_last"], when)
    out = []
    for c in conv.values():
        c["protocols"] = ",".join(sorted(c["protocols"])) or None
        c["src_port"] = c["src_port"] or None
        c["dst_port"] = c["dst_port"] or None
        c["first_utc"] = iso(c.pop("_first")) if c["_first"] is not None else None
        c["last_utc"] = iso(c.pop("_last")) if c["_last"] is not None else None
        c.pop("_first", None)
        c.pop("_last", None)
        out.append(c)
    out.sort(key=lambda c: (-c["bytes"], str(c["src"]), str(c["dst"])))
    return out


# capinfos long report: "Number of packets:   12" (-M keeps the values machine-readable).
_INFO_KEYS = {
    "file type": "file_type", "file encapsulation": "encapsulation",
    "number of packets": "packets", "file size": "file_size_bytes",
    "data size": "data_size_bytes", "packet size limit": "snapshot_length",
    "capture duration": "duration_seconds", "first packet time": "first_packet_epoch",
    "last packet time": "last_packet_epoch", "strict time order": "strict_time_order"}
_NUMERIC = {"packets", "file_size_bytes", "data_size_bytes", "duration_seconds",
            "first_packet_epoch", "last_packet_epoch"}


def parse_capinfos(text: str) -> dict[str, Any]:
    """The capinfos report as one typed row; unknown lines are ignored, times become UTC."""
    row: dict[str, Any] = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        name = _INFO_KEYS.get(key.strip().lower())
        if not name or not value.strip():
            continue
        raw = value.strip()
        if name in _NUMERIC:
            number = re.match(r"-?\d+(\.\d+)?", raw)
            row[name] = (float(number.group(0)) if "." in number.group(0)
                         else int(number.group(0))) if number else None
        else:
            row[name] = raw
    for name, out in (("first_packet_epoch", "first_packet_utc"),
                      ("last_packet_epoch", "last_packet_utc")):
        if isinstance(row.get(name), (int, float)):
            row[out] = iso(row[name])
    return row
