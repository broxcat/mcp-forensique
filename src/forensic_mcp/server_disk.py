"""MCP tool definitions for disk artefacts (tasks 4.3a/b/c): Eric Zimmerman tools, typed
artefact shortcuts, timeline, disk images. Registered by server.build_server()."""
# No `from __future__ import annotations` (see server.py: Resolve annotations are evaluated).
from typing import Annotated, Any, Callable, Literal

from mcp.server.elicitation import ElicitationResult
from mcp.server.mcpserver import Context, Resolve
from mcp.types import CallToolResult

from .memory_ops import Approval

Result = Annotated[CallToolResult, dict[str, Any]]
Confirm = ElicitationResult[Approval]
EzTool = Literal["EvtxECmd", "MFTECmd", "PECmd", "RECmd", "AmcacheParser",
                 "AppCompatCacheParser", "LECmd", "JLECmd", "SBECmd", "SrumECmd", "SQLECmd",
                 "WxTCmd", "RBCmd", "RecentFileCacheParser", "SumECmd", "bstrings", "rla"]
EvtxPreset = Literal["logons", "rdp", "execution", "persistence", "log_clearing"]
MftTimeField = Literal["Created0x10", "LastModified0x10", "LastRecordChange0x10",
                       "LastAccess0x10", "Created0x30", "LastModified0x30",
                       "LastRecordChange0x30", "LastAccess0x30"]
DiskTarget = Literal["mft", "usnjrnl", "logfile", "registry_system", "sam_security", "ntuser",
                     "usrclass", "amcache", "recentfilecache", "evtx", "prefetch", "srum",
                     "jumplists", "lnk", "recyclebin", "browser", "activities", "sum",
                     "scheduled_tasks"]
EzOptions = dict[str, bool | int | str | list[int]]
DISK_TOOLS = {"ez_list_tools": "read", "ez_run": "read", "evtx_query": "read",
              "mft_search": "read", "timeline": "read", "prefetch_query": "read",
              "browser_history": "read", "shimcache_query": "read", "amcache_query": "read",
              "lnk_query": "read", "jumplist_query": "read", "recyclebin_query": "read",
              "disk_info": "read", "disk_list": "read", "disk_extract": "action_on_demand",
              "disk_extract_file": "action_on_demand",
              "ez_import": "journal", "srum_query": "read"}
SrumTable = Literal["network_usage", "app_resource", "network_connections", "energy",
                    "push_notifications", "app_timeline", "vfu"]


def register_disk_tools(tool: Callable[[str], Any], run: Callable[..., Any],
                        ask: Callable[..., Any]) -> None:
    """Define the disk tools on the server (`tool`, `run`, `ask` come from build_server)."""

    async def ask_extract(path: str, targets: list[str], ctx: Context) -> Any:
        return await ask("disk_extract", {"path": path, "targets": targets}, ctx)

    async def ask_extract_file(path: str, inodes: list[int], ctx: Context,
                               partition_offset: int = 0) -> Any:
        return await ask("disk_extract_file", {"path": path, "inodes": inodes,
                                               "partition_offset": partition_offset}, ctx)

    def window(**kw: Any) -> dict[str, Any]:
        return {k: v for k, v in kw.items()}

    @tool("ez_list_tools")
    async def ez_list_tools(limit: int = 50, offset: int = 0) -> Result:
        """The Eric Zimmerman CLI tools: accepted artefacts, input (-f file / -d folder), output
        (JSON or CSV) and the typed options of each (for ez_run)."""
        return await run("ez_list_tools", {"limit": limit, "offset": offset})

    @tool("ez_run")
    async def ez_run(tool: EzTool, path: str, ctx: Context, options: EzOptions | None = None,
                     limit: int = 50, offset: int = 0) -> Result:
        """Run one Eric Zimmerman tool on a file or folder of the evidence root (or an extracted
        file "@<result_id>/..."), e.g. tool="RECmd", options={"batch": "Kroll_Batch.reb"}.
        Only the typed options listed by ez_list_tools."""
        return await run("ez_run", {"tool": tool, "path": path, "options": options,
                                    "limit": limit, "offset": offset}, ctx)

    @tool("evtx_query")
    async def evtx_query(path: str, ctx: Context, preset: EvtxPreset | None = None,
                         event_ids: list[int] | None = None, start: str | None = None,
                         end: str | None = None, contains: str | None = None,
                         limit: int = 50, offset: int = 0) -> Result:
        """Windows event logs (.evtx file or folder) with EvtxECmd, filtered by preset
        (logons, rdp, execution, persistence, log_clearing), event IDs, UTC time range
        (ISO-8601) and text. Example: "qui s'est connecté en RDP ?" -> preset="rdp".
        An empty preset says which log or audit policy was required."""
        return await run("evtx_query", window(path=path, preset=preset, event_ids=event_ids,
                                              start=start, end=end, contains=contains,
                                              limit=limit, offset=offset), ctx)

    @tool("mft_search")
    async def mft_search(path: str, ctx: Context, path_contains: str | None = None,
                         extension: str | None = None, start: str | None = None,
                         end: str | None = None, time_field: MftTimeField = "Created0x10",
                         limit: int = 50, offset: int = 0) -> Result:
        """Search a $MFT (MFTECmd, parsed once): path substring, extension (".exe"), UTC time
        range on one timestamp (Created0x10 = $STANDARD_INFORMATION creation…)."""
        return await run("mft_search", window(path=path, path_contains=path_contains,
                                              extension=extension, start=start, end=end,
                                              time_field=time_field, limit=limit,
                                              offset=offset), ctx)

    @tool("timeline")
    async def timeline(around: str, ctx: Context, case: str = "", window_minutes: int = 30,
                       limit: int = 50, offset: int = 0) -> Result:
        """Merged UTC timeline of a case folder (process start/exit from memory, EVTX events,
        $MFT created/modified) within ±window_minutes of `around` (ISO-8601), from results
        already produced; each event cites its source result_id and row."""
        return await run("timeline", window(case=case, around=around,
                                            window_minutes=window_minutes, limit=limit,
                                            offset=offset), ctx)

    @tool("prefetch_query")
    async def prefetch_query(path: str, ctx: Context, executable_contains: str | None = None,
                             start: str | None = None, end: str | None = None,
                             limit: int = 50, offset: int = 0) -> Result:
        """Prefetch (PECmd runs on Windows only: pass the export folder made by
        scripts/run_ez_windows.ps1): executions filtered by executable name and a UTC window on
        LastRun / PreviousRun0-6. Example: "was psexec run?"."""
        return await run("prefetch_query", window(path=path, executable_contains=executable_contains,
                                                  start=start, end=end, limit=limit,
                                                  offset=offset), ctx)

    @tool("browser_history")
    async def browser_history(path: str, ctx: Context, url_contains: str | None = None,
                              start: str | None = None, end: str | None = None,
                              limit: int = 50, offset: int = 0) -> Result:
        """Browser history (SQLECmd runs on Windows only: pass the export folder made by
        scripts/run_ez_windows.ps1), filtered by URL/title text and a UTC visit window."""
        return await run("browser_history", window(path=path, url_contains=url_contains,
                                                   start=start, end=end, limit=limit,
                                                   offset=offset), ctx)

    @tool("shimcache_query")
    async def shimcache_query(path: str, ctx: Context, path_contains: str | None = None,
                              executed_only: bool = False, start: str | None = None,
                              end: str | None = None, limit: int = 50, offset: int = 0) -> Result:
        """ShimCache / AppCompatCache of a SYSTEM hive (AppCompatCacheParser, always on the given
        file, never the live registry): path text, Executed flag, UTC window."""
        return await run("shimcache_query", window(path=path, path_contains=path_contains,
                                                   executed_only=executed_only, start=start,
                                                   end=end, limit=limit, offset=offset), ctx)

    @tool("amcache_query")
    async def amcache_query(path: str, ctx: Context, name_contains: str | None = None,
                            sha1: str | None = None, start: str | None = None,
                            end: str | None = None, limit: int = 50, offset: int = 0) -> Result:
        """Amcache.hve (AmcacheParser): program/file entries by name or path text, SHA-1 (40 hex)
        and a UTC window on the key last-write time."""
        return await run("amcache_query", window(path=path, name_contains=name_contains, sha1=sha1,
                                                 start=start, end=end, limit=limit,
                                                 offset=offset), ctx)

    @tool("lnk_query")
    async def lnk_query(path: str, ctx: Context, target_contains: str | None = None,
                        start: str | None = None, end: str | None = None,
                        limit: int = 50, offset: int = 0) -> Result:
        """LNK shortcut files (file or folder, LECmd): target path / arguments text and a UTC
        window on target and source times."""
        return await run("lnk_query", window(path=path, target_contains=target_contains,
                                             start=start, end=end, limit=limit,
                                             offset=offset), ctx)

    @tool("jumplist_query")
    async def jumplist_query(path: str, ctx: Context, target_contains: str | None = None,
                             start: str | None = None, end: str | None = None,
                             limit: int = 50, offset: int = 0) -> Result:
        """Jump lists (*.automaticDestinations-ms / *.customDestinations-ms, JLECmd): target
        text and a UTC window."""
        return await run("jumplist_query", window(path=path, target_contains=target_contains,
                                                  start=start, end=end, limit=limit,
                                                  offset=offset), ctx)

    @tool("recyclebin_query")
    async def recyclebin_query(path: str, ctx: Context, name_contains: str | None = None,
                               start: str | None = None, end: str | None = None,
                               limit: int = 50, offset: int = 0) -> Result:
        """Recycle Bin $I files / INFO2 (RBCmd): deleted file name text and a UTC window on
        DeletedOn."""
        return await run("recyclebin_query", window(path=path, name_contains=name_contains,
                                                    start=start, end=end, limit=limit,
                                                    offset=offset), ctx)

    @tool("ez_import")
    async def ez_import(tool: EzTool, path: str, ctx: Context, limit: int = 50,
                        offset: int = 0) -> Result:
        """Import an export made on Windows by scripts/run_ez_windows.ps1 (folder
        evidence/<HOST>/ez_out/<Tool>_<time>/ with manifest.json), for the tools that do not run
        on Linux (PECmd, SQLECmd, WxTCmd, SrumECmd, SumECmd). Verifies the manifest, the output
        hashes and the input hash, then normalises the rows (_row) and journals the import."""
        return await run("ez_import", {"tool": tool, "path": path, "limit": limit,
                                       "offset": offset}, ctx)

    @tool("srum_query")
    async def srum_query(path: str, ctx: Context, app_contains: str | None = None,
                         table: SrumTable | None = None, start: str | None = None,
                         end: str | None = None, limit: int = 50, offset: int = 0) -> Result:
        """SRUM (SrumECmd, run on Windows then imported: pass the export folder): per-app
        network and resource usage, filtered by application text, table and UTC window."""
        return await run("srum_query", window(path=path, app_contains=app_contains, table=table,
                                              start=start, end=end, limit=limit,
                                              offset=offset), ctx)

    @tool("disk_info")
    async def disk_info(path: str, ctx: Context) -> Result:
        """Partition table of a disk image (raw/dd, E01, VMDK, VHD; mmls). Gives the
        start_sector to use as partition_offset."""
        return await run("disk_info", {"path": path}, ctx)

    @tool("disk_list")
    async def disk_list(path: str, ctx: Context, partition_offset: int = 0,
                        path_contains: str | None = None, deleted: bool | None = None,
                        limit: int = 50, offset: int = 0) -> Result:
        """Recursive file listing of one file system of a disk image (fls -r -p, parsed once),
        filtered by path text and deleted state."""
        return await run("disk_list", window(path=path, partition_offset=partition_offset,
                                             path_contains=path_contains, deleted=deleted,
                                             limit=limit, offset=offset), ctx)

    @tool("disk_extract")
    async def disk_extract(path: str, targets: list[DiskTarget], ctx: Context,
                           confirmation: Annotated[Confirm, Resolve(ask_extract)],
                           partition_offset: int = 0, include_deleted: bool = False,
                           limit: int = 50, offset: int = 0) -> Result:
        """Copy fixed artefact targets out of a disk image (icat): each file hashed, journaled,
        read-only, then usable as "@<result_id>/..." by the other tools. "sam_security"
        (credential hives) needs the analyst's confirmation."""
        return await run("disk_extract", window(path=path, targets=targets,
                                                partition_offset=partition_offset,
                                                include_deleted=include_deleted, limit=limit,
                                                offset=offset), ctx, confirmation)

    @tool("disk_extract_file")
    async def disk_extract_file(path: str, inodes: list[int], ctx: Context,
                                confirmation: Annotated[Confirm, Resolve(ask_extract_file)],
                                partition_offset: int = 0, limit: int = 50,
                                offset: int = 0) -> Result:
        """Copy chosen files out of a disk image by inode (icat), DELETED files included. The
        inodes must be regular files of the disk_list listing of the same path and
        partition_offset (call disk_list first; 1-20 inodes). Each file is hashed, journaled with
        image + inode, read-only, then usable as "@<result_id>/..." by the other tools.
        Credential hives need the analyst's confirmation."""
        return await run("disk_extract_file", window(path=path, inodes=inodes,
                                                     partition_offset=partition_offset,
                                                     limit=limit, offset=offset),
                         ctx, confirmation)
