"""MCP tool definitions for network captures (task 6.7): pcap_info, pcap_conversations,
pcap_dns_query, pcap_http_objects, pcap_tls_info and net_extract_pcap. Registered by
server.build_server(). Every filter is typed here (ip as text validated by ipaddress, port as
int, proto from a closed set, ISO-8601 window): the tshark display filter is built server-side.
"""
# No `from __future__ import annotations` (see server.py: Resolve annotations are evaluated).
from typing import Annotated, Any, Callable, Literal

from mcp.server.elicitation import ElicitationResult
from mcp.server.mcpserver import Context, Resolve
from mcp.types import CallToolResult

from .memory_ops import Approval

Result = Annotated[CallToolResult, dict[str, Any]]
Confirm = ElicitationResult[Approval]
Proto = Literal["tcp", "udp", "icmp", "dns", "http", "tls"]
NET_TOOLS = {"pcap_info": "read", "pcap_conversations": "read", "pcap_dns_query": "read",
             "pcap_http_objects": "read", "pcap_tls_info": "read",
             "net_extract_pcap": "action_on_demand"}


def register_net_tools(tool: Callable[[str], Any], run: Callable[..., Any],
                       ask: Callable[..., Any]) -> None:
    """Define the network tools on the server (`tool`, `run`, `ask` come from build_server)."""

    async def ask_extract_pcap(path: str, ctx: Context) -> Any:
        return await ask("net_extract_pcap", {"path": path}, ctx)

    def window(**kw: Any) -> dict[str, Any]:
        return {k: v for k, v in kw.items()}

    @tool("pcap_info")
    async def pcap_info(path: str, ctx: Context) -> Result:
        """Summary of a capture file (.pcap / .pcapng, capinfos): format, encapsulation, number
        of packets, size, snapshot length, first and last packet in UTC. Call this first: it
        says which period the capture covers."""
        return await run("pcap_info", {"path": path}, ctx)

    @tool("pcap_conversations")
    async def pcap_conversations(path: str, ctx: Context, ip: str | None = None,
                                 port: int | None = None, proto: Proto | None = None,
                                 start: str | None = None, end: str | None = None,
                                 limit: int = 50, offset: int = 0) -> Result:
        """Who talked to whom in a capture: one row per conversation (addresses, ports,
        transport, packets and bytes per direction, first/last UTC), computed by the server from
        the packets. Filter by one address, one port, a protocol and a UTC window.
        Example: "quelles connexions vers l'extérieur ?"."""
        return await run("pcap_conversations", window(path=path, ip=ip, port=port, proto=proto,
                                                      start=start, end=end, limit=limit,
                                                      offset=offset), ctx)

    @tool("pcap_dns_query")
    async def pcap_dns_query(path: str, ctx: Context, query_name_contains: str | None = None,
                             answer_a_contains: str | None = None, ip: str | None = None,
                             start: str | None = None, end: str | None = None,
                             limit: int = 50, offset: int = 0) -> Result:
        """DNS queries and answers of a capture: queried name, type, answers (A, AAAA, CNAME),
        response code, UTC time. `query_name_contains` filters on the name,
        `answer_a_contains` on the returned IPv4. Example: "quels domaines ont été résolus ?"."""
        return await run("pcap_dns_query", window(path=path,
                                                  query_name_contains=query_name_contains,
                                                  answer_a_contains=answer_a_contains, ip=ip,
                                                  start=start, end=end, limit=limit,
                                                  offset=offset), ctx)

    @tool("pcap_http_objects")
    async def pcap_http_objects(path: str, ctx: Context, host_contains: str | None = None,
                                uri_contains: str | None = None,
                                content_type_contains: str | None = None, ip: str | None = None,
                                port: int | None = None, start: str | None = None,
                                end: str | None = None, limit: int = 50,
                                offset: int = 0) -> Result:
        """HTTP objects transferred in clear in a capture (inventory, not the file contents):
        method, host, URI, user agent, response code, content type and length, UTC time.
        Example: "quel fichier a été téléchargé en HTTP ?"."""
        return await run("pcap_http_objects", window(path=path, host_contains=host_contains,
                                                     uri_contains=uri_contains,
                                                     content_type_contains=content_type_contains,
                                                     ip=ip, port=port, start=start, end=end,
                                                     limit=limit, offset=offset), ctx)

    @tool("pcap_tls_info")
    async def pcap_tls_info(path: str, ctx: Context, server_name_contains: str | None = None,
                            ja3_contains: str | None = None, ip: str | None = None,
                            port: int | None = None, start: str | None = None,
                            end: str | None = None, limit: int = 50, offset: int = 0) -> Result:
        """TLS handshakes of a capture: SNI (contacted name), version, cipher suite, JA3/JA3S
        fingerprints, UTC time. The session content stays encrypted.
        Example: "vers quels domaines HTTPS la machine a-t-elle parlé ?"."""
        return await run("pcap_tls_info", window(path=path,
                                                 server_name_contains=server_name_contains,
                                                 ja3_contains=ja3_contains, ip=ip, port=port,
                                                 start=start, end=end, limit=limit,
                                                 offset=offset), ctx)

    @tool("net_extract_pcap")
    async def net_extract_pcap(path: str, ctx: Context,
                               confirmation: Annotated[Confirm, Resolve(ask_extract_pcap)],
                               ip: str | None = None, port: int | None = None,
                               proto: Proto | None = None, start: str | None = None,
                               end: str | None = None) -> Result:
        """Copy the packets matching one filter (at least one of ip, port, proto, start, end)
        into a new pcapng file, hashed, read-only and registered as derived evidence, then
        usable as "@<result_id>/..." by the pcap_* tools. Needs the analyst's confirmation; a
        whole capture is never copied."""
        return await run("net_extract_pcap", window(path=path, ip=ip, port=port, proto=proto,
                                                    start=start, end=end), ctx, confirmation)
