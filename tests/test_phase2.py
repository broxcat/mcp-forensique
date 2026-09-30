"""Phase 2 acceptance tests: jail, runner, results streaming, audit chain."""
import asyncio
import json
import tracemalloc
from pathlib import Path

import pytest

from forensic_mcp import audit, config, results, runner, safety


def test_jail_blocks_traversal_and_symlink(tmp_path: Path) -> None:
    root = tmp_path / "ev"
    root.mkdir()
    (root / "ok.raw").write_text("x")
    outside = tmp_path / "secret"
    outside.write_text("s")
    (root / "link").symlink_to(outside)
    assert safety.jail_path("ok.raw", root) == (root / "ok.raw").resolve()
    for bad in ("../etc/passwd", "../secret", "link", "/etc/passwd"):
        with pytest.raises(safety.SafetyError):
            safety.jail_path(bad, root)


def test_runner_kills_on_timeout(tmp_path: Path) -> None:
    res = asyncio.run(runner.run_process(["sleep", "10"], tmp_path / "o", tmp_path / "e", 1))
    assert res.timed_out and res.duration < 5
    ok = asyncio.run(runner.run_process(["echo", "hi"], tmp_path / "o", tmp_path / "e", 5))
    assert ok.exit_code == 0 and (tmp_path / "o").read_text() == "hi\n"


def test_query_streams_big_csv(tmp_path: Path) -> None:
    rid, d = results.new_result(tmp_path, "fake")
    with open(d / "big.csv", "w") as fh:
        fh.write("id,name,note\n")
        for i in range(100_000):
            fh.write(f"{i},proc{i},{'needle' if i % 1000 == 7 else 'hay'}\n")
    tracemalloc.start()
    out = results.query(d, contains="needle", limit=5)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert len(out["rows"]) == 5 and out["rows"][0]["id"] == "7"
    assert peak < 5_000_000  # a full load of 100k rows would be far larger
    assert results.query(d, column="name", equals="proc42")["matched"] == 1
    assert results.query(d, regex=r"proc99\d{3}\b", limit=1000)["matched"] == 1000
    srt = results.query(d, sort_by="id", sort_desc=True, limit=1, columns=["id"])
    assert srt["rows"] == [{"_row": 100000, "id": "99999"}]
    small = results.query(d, contains="needle", sort_by="id", sort_desc=True, limit=1)
    assert small["rows"][0]["id"] == "99007"
    assert results.count_rows(d) == 100_000


def test_page_truncates_cells_and_numbers_rows(tmp_path: Path) -> None:
    rid, d = results.new_result(tmp_path, "vol3")
    (d / "rows.jsonl").write_text(json.dumps({"a": "x" * 1000}) + "\n")
    q = results.query(d, max_cell_chars=10)
    assert q["matched"] == 1 and len(q["rows"][0]["a"]) == 11 and q["truncated"]
    assert q["rows"][0]["_row"] == 1
    with pytest.raises(ValueError):
        results.result_dir(tmp_path, "../x")


def test_audit_chain_detects_tampering(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    for i in range(3):
        audit.append(log, "crisis_event", {"kind": "server"}, time_utc="2026-10-06T10:15:00Z",
                     kind="event", description=f"n{i}", owner="x", source="test")
    assert audit.verify_audit(log) == (True, 3)
    lines = log.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["body"] = rec["body"].replace('"n1"', '"n9"')
    lines[1] = json.dumps(rec)
    log.write_text("\n".join(lines) + "\n")
    assert audit.verify_audit(log) == (False, 2)


def test_config_and_tools(tmp_path: Path) -> None:
    cfg_file = tmp_path / "c.toml"
    cfg_file.write_text('evidence_root = "/e"\nhttp_port = 9\n')
    cfg = config.load_config(cfg_file)
    assert cfg.evidence_root == Path("/e") and cfg.http_port == 9 and cfg.llm_mode == "local"
    tools = config.load_tools(Path(__file__).parents[1] / "tools.toml")
    assert len(tools) == 20 and tools["EvtxECmd"][0].endswith("dotnet")


def test_sort_covers_all_rows_with_bounded_memory(tmp_path: Path) -> None:
    _, d = results.new_result(tmp_path, "fake")
    with open(d / "big.csv", "w") as fh:
        fh.write("id,score\n")
        for i in range(99_999):
            fh.write(f"{i},{i % 1000}\n")
        fh.write("99999,5000000\n")  # the largest value is on the LAST row
    tracemalloc.start()
    out = results.query(d, sort_by="score", sort_desc=True, limit=5)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert out["rows"][0]["id"] == "99999" and len(out["rows"]) == 5
    assert peak < 5_000_000
    asc = results.query(d, sort_by="score", limit=2, offset=1)
    assert [r["score"] for r in asc["rows"]] == ["0", "0"]
    assert "sort_truncated" not in out


def test_sort_empty_values_last(tmp_path: Path) -> None:
    _, d = results.new_result(tmp_path, "fake")
    (d / "rows.jsonl").write_text("\n".join(json.dumps(r) for r in (
        {"v": ""}, {"v": "10"}, {"v": None}, {"v": "9"}, {"v": "abc"})) + "\n")
    for desc, expected in ((False, ["9", "10", "abc", "", None]), (True, ["abc", "10", "9", "", None])):
        got = [r["v"] for r in results.query(d, sort_by="v", sort_desc=desc)["rows"]]
        assert got == expected


def test_jail_sibling_prefix_symlink_dir_and_relative(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    evil = tmp_path / "evidence_evil"
    outdir = tmp_path / "outside_dir"
    for p in (root, evil, outdir):
        p.mkdir()
    (evil / "x.raw").write_text("x")
    (outdir / "loot.txt").write_text("l")
    (root / "sub").mkdir()
    (root / "sub" / "good.raw").write_text("g")
    (root / "dirlink").symlink_to(outdir, target_is_directory=True)
    # (a) sibling directory sharing the string prefix must be refused
    with pytest.raises(safety.SafetyError):
        safety.jail_path(evil / "x.raw", root)
    # (b) file reached through a symlinked directory that escapes the root
    with pytest.raises(safety.SafetyError):
        safety.jail_path(root / "dirlink" / "loot.txt", root)
    with pytest.raises(safety.SafetyError):
        safety.jail_path("dirlink/loot.txt", root)
    # (c) relative path accepted
    assert safety.jail_path("sub/good.raw", root) == (root / "sub" / "good.raw").resolve()
