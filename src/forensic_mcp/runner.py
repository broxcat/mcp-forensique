"""Async subprocess runner: no shell, timeout, bounded output, process-group kill (ET-02)."""
from __future__ import annotations

import asyncio
import os
import signal
import time
import tempfile
import fcntl
from dataclasses import dataclass
from pathlib import Path
from typing import Any

POLL_SECONDS = 0.25


async def capture(argv: list[str], timeout: float = 120) -> str:
    """Bound discovery/help commands with the same process cleanup as analyses."""
    with tempfile.TemporaryDirectory(prefix='forensic-help-') as folder:
        d = Path(folder)
        rr = await run_process(argv, d/'stdout', d/'stderr', timeout,
                               max_output_bytes=16 * 1024 * 1024)
        if rr.timed_out or rr.output_exceeded or rr.exit_code != 0:
            raise ValueError('tool discovery failed, timed out or exceeded output budget')
        return (d/'stdout').read_text(errors='replace') + (d/'stderr').read_text(errors='replace')


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
                      max_output_bytes: int | None = None,
                      tty_stdin: bool = False, session_root: Path | None = None,
                      session_max_bytes: int | None = None) -> RunResult:
    """Run argv, stream stdout/stderr to files; kill the process group on timeout or when
    stdout+stderr grow beyond max_output_bytes (checked every POLL_SECONDS).
    tty_stdin: give the tool a pseudo-terminal as stdin (nothing is ever written to it), for
    tools that read stdin when it is redirected (bstrings checks Console.IsInputRedirected)."""
    if session_root is not None and session_max_bytes is not None:
        session_root.mkdir(parents=True, exist_ok=True)
        with (session_root / '.output-budget.lock').open('a+b') as lock:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        stdout_path.write_bytes(b'')
                        stderr_path.write_bytes(b'')
                        return RunResult(-1, stdout_path, stderr_path, timeout, timed_out=True)
                    await asyncio.sleep(0.05)
            remaining = max(0, session_max_bytes - output_volume(session_root))
            limit = min(max_output_bytes, remaining) if max_output_bytes is not None else remaining
            try:
                if limit <= 0:
                    stdout_path.write_bytes(b'')
                    stderr_path.write_bytes(b'')
                    return RunResult(-1, stdout_path, stderr_path, 0, output_exceeded=True)
                return await run_process(argv, stdout_path, stderr_path, max(0.01, deadline-time.monotonic()),
                                         env, limit, tty_stdin)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
    start = time.monotonic()
    deadline = start + timeout
    master, slave = os.openpty() if tty_stdin else (None, None)
    try:
        return await _run(argv, stdout_path, stderr_path, deadline, start, env,
                          max_output_bytes, asyncio.subprocess.DEVNULL if slave is None else slave)
    finally:
        for fd in (slave, master):
            if fd is not None:
                os.close(fd)


async def _run(argv: list[str], stdout_path: Path, stderr_path: Path, deadline: float,
               start: float, env: dict[str, str] | None, max_output_bytes: int | None,
               stdin: Any) -> RunResult:
    timed_out = exceeded = False
    root = stdout_path.parent
    existing = {p for p in root.rglob('*') if p.is_file()} - {stdout_path, stderr_path}

    def outputs():
        return [p for p in root.rglob('*') if p.is_file() and not p.is_symlink()
                and p not in existing]

    def over_budget():
        return max_output_bytes is not None and sum(p.stat().st_size for p in outputs()) > max_output_bytes

    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=out, stderr=err, stdin=stdin,
            start_new_session=True, env={**os.environ, **(env or {})})
        while proc.returncode is None:
            try:
                await asyncio.wait_for(proc.wait(), POLL_SECONDS)
                break
            except asyncio.TimeoutError:
                pass
            if over_budget():
                exceeded = True
            elif time.monotonic() >= deadline:
                timed_out = True
            if exceeded or timed_out:
                _kill_group(proc.pid)
                await proc.wait()
    exceeded = exceeded or over_budget()
    if exceeded and max_output_bytes is not None:
        _kill_group(proc.pid)
        remaining = max_output_bytes
        for p in sorted(outputs()):
            keep = min(p.stat().st_size, remaining)
            os.chmod(p, 0o600)
            os.truncate(p, keep)
            remaining -= keep
    code = proc.returncode if proc.returncode is not None else -1
    if exceeded and code == 0:
        code = -1
    return RunResult(code, stdout_path, stderr_path, time.monotonic() - start, timed_out, exceeded)


def output_volume(root: Path) -> int:
    return sum(p.stat().st_size for p in root.rglob('*') if p.is_file() and not p.is_symlink())


def bound_result(root: Path, result: Path, limit: int) -> bool:
    """Account for normalized/native files created after subprocess termination."""
    if output_volume(root) <= limit:
        return False
    available = max(0, limit - (output_volume(root) - output_volume(result)))
    for p in sorted(result.rglob('*')):
        if p.is_file() and not p.is_symlink():
            keep = min(p.stat().st_size, available)
            os.chmod(p, 0o600)
            os.truncate(p, keep)
            available -= keep
    return True
