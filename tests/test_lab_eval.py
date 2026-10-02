"""Task 3.1 / 3.2, defensive part: lab logging scripts, ground truth template + schema, chain of
custody script (EF-05). No attack content is generated or tested here."""
import copy
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
import yaml

from forensic_mcp import audit, custody, server

ROOT = Path(__file__).resolve().parents[1]
GT = ROOT / "eval" / "ground_truth.yaml"
SCHEMA = json.loads((ROOT / "eval" / "ground_truth.schema.json").read_text(encoding="utf-8"))
GUID = r"\{0CCE92[0-9A-F]{2}-69AE-11D9-BED3-505054503030\}"


def _errors(doc):
    v = jsonschema.Draft202012Validator(SCHEMA)
    return [e.message for e in v.iter_errors(doc)]


# ---- lab scripts ------------------------------------------------------------------------------
def test_lab_scripts_check_what_they_set() -> None:
    prep = (ROOT / "lab" / "prepare_victim.ps1").read_text(encoding="utf-8")
    check = (ROOT / "lab" / "check_logging.ps1").read_text(encoding="utf-8")
    guids = set(re.findall(GUID, prep))
    assert len(guids) == 10 and guids == set(re.findall(GUID, check))
    for needle in ("ProcessCreationIncludeCmdLine_Enabled", "EnableScriptBlockLogging",
                   "EnableModuleLogging", "SCENoApplyLegacyAuditPolicy",
                   "Microsoft-Windows-TaskScheduler/Operational", "SecurityLogMB"):
        assert needle in prep and needle in check, needle
    assert "SupportsShouldProcess" in prep  # -WhatIf
    for text in (prep, check):  # plain ASCII: Windows PowerShell 5.1 reads BOM-less files as ANSI
        assert text.isascii()
        assert not re.search(r"Invoke-WebRequest|DownloadString|DownloadFile|Start-BitsTransfer|iex\b",
                             text, re.I)
    assert "/set" not in check and "Set-RegDword" not in check and "SaveChanges" not in check


# ---- ground truth -----------------------------------------------------------------------------
def test_schema_is_valid() -> None:
    jsonschema.Draft202012Validator.check_schema(SCHEMA)


def test_template_is_valid_and_empty() -> None:
    doc = yaml.safe_load(GT.read_text(encoding="utf-8"))
    assert _errors(doc) == []
    assert doc["status"] == "template" and [s["step"] for s in doc["steps"]] == [1, 2, 3, 4, 5]
    for s in doc["steps"]:  # the agent fills nothing: every team field is empty
        assert s["procedure_ref"] == "" and s["attack"] == [] and s["timestamp_utc"] is None
        assert s["iocs"] == [] and s["expected_facts"] == []
    md = (ROOT / "docs" / "L3_scenario.md").read_text(encoding="utf-8")
    for s in doc["steps"]:
        assert s["cdc_step"] in md, s["cdc_step"]


def _filled():
    doc = yaml.safe_load(GT.read_text(encoding="utf-8"))
    doc.update(status="filled", filled_by=["Analyste A"],
               scenario_played_utc={"start": "2026-10-05T14:00:00Z", "end": "2026-10-05T15:00:00Z"})
    doc["hosts"][0]["timezone"] = "Romance Standard Time"
    doc["hosts"][1].update(name="WS-043", timezone="Romance Standard Time")
    for s in doc["steps"]:
        s.update(attack=["T1059.001"], timestamp_utc="2026-10-05T14:30:07Z",
                 procedure_ref="REF-TEAM", iocs=[{"type": "ip", "value": "203.0.113.10"}],
                 expected_facts=[{"description": "fait attendu", "artefact": "memory",
                                  "evidence_path": "WS-042/memory/WS-042.raw", "tool": "vol_pslist",
                                  "field": "PID", "value": 4312, "result_id": None, "row": None}])
    return doc


def test_filled_document_rules() -> None:
    doc = _filled()
    assert _errors(doc) == []
    for s in doc["steps"]:
        for f in s["expected_facts"]:
            assert f["tool"] in server.TOOL_NAMES
    bad = []
    for path, value in [(("steps", 0, "timestamp_utc"), None),          # filled needs a time
                        (("steps", 0, "timestamp_utc"), "2026-10-05 14:30:07"),  # not UTC Z
                        (("steps", 0, "procedure_ref"), ""),
                        (("steps", 0, "attack"), ["T12"]),
                        (("steps", 0, "expected_facts"), []),
                        (("steps", 0, "expected_facts", 0, "evidence_path"), "../etc/passwd"),
                        (("steps", 0, "expected_facts", 0, "row"), 0),
                        (("hosts", 1, "name"), ""),
                        (("filled_by",), [])]:
        d = copy.deepcopy(doc)
        tgt = d
        for k in path[:-1]:
            tgt = tgt[k]
        tgt[path[-1]] = value
        bad.append((path, _errors(d)))
    assert all(errs for _, errs in bad), [p for p, errs in bad if not errs]
    d = copy.deepcopy(doc)
    d["steps"][0]["extra"] = 1
    assert _errors(d)


# ---- chain of custody -------------------------------------------------------------------------
def _case(cfg):
    d = Path(cfg.evidence_root) / "WS-042"
    (d / "memory").mkdir(parents=True)
    (d / "memory" / "WS-042.raw").write_bytes(b"\1" * 4096)
    (d / "kape" / "C").mkdir(parents=True)
    (d / "kape" / "C" / "Security.evtx").write_bytes(b"\2" * 512)
    (d / "case.toml").write_text('case = "WS-042"\nclassification = "lab"\n')
    return d


def test_register_then_verify(cfg) -> None:
    d = _case(cfg)
    r = custody.register_case(cfg, "WS-042", "Analyste A")
    assert r["ok"] and r["file_count"] == 3 and r["journal_head_hash"]
    man = json.loads(Path(r["manifest"]).read_text(encoding="utf-8"))
    assert man["stage"] == "before" and {f["state"] for f in man["files"]} == {"registered"}
    assert os.stat(r["manifest"]).st_mode & 0o777 == 0o444
    regs = [e for e in audit.iter_events(cfg.audit_file) if e["type"] == "evidence_registered"]
    assert len(regs) == 3 and all(e["actor"] == {"kind": "analyst", "name": "Analyste A",
                                                  "client": "register_evidence.py"} for e in regs)
    again = custody.register_case(cfg, "WS-042", "Analyste A")  # idempotent, nothing re-hashed
    assert {f["state"] for f in json.loads(Path(again["manifest"]).read_text())["files"]} == {
        "already-registered"}
    ok = custody.verify_case(cfg, "WS-042", "Analyste B")
    assert ok["ok"] and ok["stage"] == "after"
    ver = [e for e in audit.iter_events(cfg.audit_file) if e["type"] == "evidence_verified"]
    assert len(ver) == 3 and all(e["stage"] == "after" and e["matches_registration"] for e in ver)
    # tampering, deletion and an extra file are all reported
    (d / "kape" / "C" / "Security.evtx").write_bytes(b"\3" * 512)
    (d / "memory" / "WS-042.raw").unlink()
    (d / "kape" / "C" / "new.txt").write_text("x")
    bad = custody.verify_case(cfg, "WS-042", "Analyste B")
    assert not bad["ok"]
    assert bad["changed"] == ["WS-042/kape/C/Security.evtx"]
    assert bad["missing"] == ["WS-042/memory/WS-042.raw"]
    assert bad["not_registered"] == ["WS-042/kape/C/new.txt"]
    assert audit.verify_audit(cfg.audit_file)[0]


def test_custody_refusals(cfg) -> None:
    _case(cfg)
    for case, name in [("../x", "Analyste A"), ("", "Analyste A"), ("nope", "Analyste A"),
                       ("WS-042", " ")]:
        with pytest.raises(ValueError):
            custody.register_case(cfg, case, name)
    assert not custody.verify_case(cfg, "WS-042", "Analyste A")["ok"]  # nothing registered yet


def test_script_exit_codes(cfg, tmp_path) -> None:
    _case(cfg)
    conf = tmp_path / "conf.toml"
    conf.write_text(f'evidence_root = "{cfg.evidence_root}"\noutput_root = "{cfg.output_root}"\n')
    env = {**os.environ, "FORENSIC_MCP_CONFIG": str(conf)}
    script = [sys.executable, str(ROOT / "scripts" / "register_evidence.py")]

    def run(*args):
        return subprocess.run(script + list(args), capture_output=True, text=True, env=env)

    assert run("WS-042").returncode == 2  # --analyst required
    r = run("WS-042", "--analyst", "Analyste A")
    assert r.returncode == 0 and "RESULT: OK" in r.stdout and "manifest sha256" in r.stdout
    assert run("WS-042", "--analyst", "Analyste A", "--after").returncode == 0
    (Path(cfg.evidence_root) / "WS-042" / "case.toml").write_text("changed\n")
    r = run("WS-042", "--analyst", "Analyste A", "--after")
    assert r.returncode == 1 and "CHANGED: WS-042/case.toml" in r.stdout
    assert run("../etc", "--analyst", "Analyste A").returncode == 2


def test_server_never_loads_custody() -> None:
    assert "custody" not in " ".join(server.TOOL_NAMES)
    code = ("import sys; import forensic_mcp.server as s; s.build_server(); "
            "print('forensic_mcp.custody' in sys.modules)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"
