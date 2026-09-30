"""Async subprocess runner with timeout and process-group kill."""
from __future__ import annotations

import asyncio
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RunResult:
    """Outcome of one external run."""

    exit_code: int
    stdout_path: Path
    stderr_path: Path
    duration: float
    timed_out: bool = False


async def run_process(argv: list[str], stdout_path: Path, stderr_path: Path,
                      timeout: float, env: dict[str, str] | None = None) -> RunResult:
    """Run argv (no shell), stream stdout/stderr to files, kill the process group on timeout."""
    start = time.monotonic()
    timed_out = False
    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=out, stderr=err, stdin=asyncio.subprocess.DEVNULL,
            start_new_session=True, env={**os.environ, **(env or {})})
        try:
            await asyncio.wait_for(proc.wait(), timeout)
        except asyncio.TimeoutError:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await proc.wait()
    code = proc.returncode if proc.returncode is not None else -1
    return RunResult(code, stdout_path, stderr_path, time.monotonic() - start, timed_out)
