"""A real libpcap capture built byte by byte (task 6.7), so the end-to-end test runs the real
tshark on a real file without ever capturing traffic: a DNS query and its answer, an HTTP
download and a TLS ClientHello with an SNI, between a lab host and a TEST-NET-3 address.
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

START = "2026-10-16T14:30:00Z"
CLIENT, SERVER, RESOLVER = "192.168.56.101", "203.0.113.10", "192.168.56.1"
DOMAIN = "c2.example.test"
URI = "/a.ps1"
CLIENT_MAC, SERVER_MAC = bytes.fromhex("005056c00008"), bytes.fromhex("0050563fab01")


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).replace(
        tzinfo=timezone.utc).timestamp()


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x1234, 0, 64, proto, 0,
                       bytes(int(x) for x in src.split(".")),
                       bytes(int(x) for x in dst.split(".")))
    return head[:10] + struct.pack("!H", _checksum(head)) + head[12:] + payload


def _eth(src_mac: bytes, dst_mac: bytes, payload: bytes) -> bytes:
    return dst_mac + src_mac + b"\x08\x00" + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _tcp(sport: int, dport: int, seq: int, payload: bytes) -> bytes:
    # data offset 5 words, flags PSH+ACK; checksums are not verified by tshark by default
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 0x50, 0x18, 8192, 0, 0) + payload


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def _dns_query(txid: int, name: str) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + _dns_name(name) \
        + struct.pack("!HH", 1, 1)


def _dns_answer(txid: int, name: str, ip: str) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + _dns_name(name) \
        + struct.pack("!HH", 1, 1) + _dns_name(name) + struct.pack("!HHIH", 1, 1, 60, 4) \
        + bytes(int(x) for x in ip.split("."))


def _client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0x0000, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = (struct.pack("!H", 0x0303) + bytes(range(32)) + b"\x00"
            + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(sni_ext)) + sni_ext)
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def packets() -> list[tuple[float, bytes]]:
    """(epoch, Ethernet frame) of the five packets of the capture."""
    t0 = _epoch(START)
    get = (f"GET {URI} HTTP/1.1\r\nHost: {DOMAIN}\r\nUser-Agent: Mozilla/5.0 (lab)\r\n"
           "Accept: */*\r\n\r\n").encode()
    body = b"hello"
    resp = (b"HTTP/1.1 200 OK\r\nServer: lab\r\nContent-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    return [
        (t0, _eth(CLIENT_MAC, SERVER_MAC, _ipv4(CLIENT, RESOLVER, 17,
                                                _udp(50000, 53, _dns_query(0x1a2b, DOMAIN))))),
        (t0 + 0.05, _eth(SERVER_MAC, CLIENT_MAC,
                         _ipv4(RESOLVER, CLIENT, 17,
                               _udp(53, 50000, _dns_answer(0x1a2b, DOMAIN, SERVER))))),
        (t0 + 1.0, _eth(CLIENT_MAC, SERVER_MAC,
                        _ipv4(CLIENT, SERVER, 6, _tcp(49800, 80, 1, get)))),
        (t0 + 1.2, _eth(SERVER_MAC, CLIENT_MAC,
                        _ipv4(SERVER, CLIENT, 6, _tcp(80, 49800, 1, resp)))),
        (t0 + 2.0, _eth(CLIENT_MAC, SERVER_MAC,
                        _ipv4(CLIENT, SERVER, 6, _tcp(49802, 443, 1,
                                                      _client_hello(DOMAIN))))),
    ]


def write_test_pcap(path: Path) -> dict[str, Any]:
    """Write the capture (libpcap, Ethernet, microsecond timestamps) and return its facts."""
    path.parent.mkdir(parents=True, exist_ok=True)
    frames = packets()
    with open(path, "wb") as fh:
        fh.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for when, frame in frames:
            fh.write(struct.pack("!IIII", int(when), int(round((when % 1) * 1_000_000)),
                                 len(frame), len(frame)))
            fh.write(frame)
    return {"packets": len(frames), "first_utc": START, "domain": DOMAIN, "uri": URI,
            "client": CLIENT, "server": SERVER, "resolver": RESOLVER,
            "last_epoch": frames[-1][0]}
