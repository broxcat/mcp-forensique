"""Async subprocess runner: no shell, timeout, bounded output, process-group kill (ET-02)."""
from __future__ import annotations

import asyncio
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path

POLL_SECONDS = 0.25


@dataclass
class RunResult:
    """Outcome of one external run."""

    exit_code: int
    stdout_path: Path
    stderr_path: Path
    duration: float
    timed_out: bool = False
    output_exceeded: bool = False


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _truncate(stdout_path: Path, stderr_path: Path, limit: int) -> None:
    """Cut the files so that together they never exceed `limit` bytes on disk."""
    err_keep = min(os.path.getsize(stderr_path), limit // 4)
    os.truncate(stderr_path, err_keep)
    os.truncate(stdout_path, min(os.path.getsize(stdout_path), limit - err_keep))


async def run_process(argv: list[str], stdout_path: Path, stderr_path: Path, timeout: float,
                      env: dict[str, str] | None = None,
                      max_output_bytes: int | None = None) -> RunResult:
    """Run argv, stream stdout/stderr to files; kill the process group on timeout or when
    stdout+stderr grow beyond max_output_bytes (checked every POLL_SECONDS)."""
    start = time.monotonic()
    deadline = start + timeout
    timed_out = exceeded = False
    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=out, stderr=err, stdin=asyncio.subprocess.DEVNULL,
            start_new_session=True, env={**os.environ, **(env or {})})
        while proc.returncode is None:
            try:
                await asyncio.wait_for(proc.wait(), POLL_SECONDS)
                break
            except asyncio.TimeoutError:
                pass
            if max_output_bytes is not None and (
                    os.path.getsize(stdout_path) + os.path.getsize(stderr_path) > max_output_bytes):
                exceeded = True
            elif time.monotonic() >= deadline:
                timed_out = True
            if exceeded or timed_out:
                _kill_group(proc.pid)
                await proc.wait()
    if exceeded and max_output_bytes is not None:
        _truncate(stdout_path, stderr_path, max_output_bytes)
    code = proc.returncode if proc.returncode is not None else -1
    return RunResult(code, stdout_path, stderr_path, time.monotonic() - start, timed_out, exceeded)
