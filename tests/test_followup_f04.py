import sys
import shutil
import pytest
from forensic_mcp import runner, audit
from forensic_mcp.ops import Engine
from test_artefacts_disk import case, IMG

@pytest.mark.anyio
@pytest.mark.parametrize('continuous',[False,True])
async def test_separated_stderr_is_bounded(tmp_path,continuous):
    d = tmp_path/'task'
    (d/'extracted').mkdir(parents=True)
    script = "import sys;sys.stderr.write('x'*2000000)"
    if continuous:
        script = "import sys,time\nwhile True:\n sys.stderr.write('x'*4096);sys.stderr.flush();time.sleep(.01)"
    rr = await runner.run_process([sys.executable,'-c',script],d/'extracted'/'file.bin',d/'stderr',10,max_output_bytes=1024)
    assert rr.output_exceeded and rr.exit_code != 0 and not rr.timed_out
    assert sum(p.stat().st_size for p in d.rglob('*') if p.is_file()) <= 1024

@pytest.mark.anyio
async def test_native_scope_deduplicates_and_preserves_other_files(tmp_path):
    d = tmp_path/'task'
    (d/'extracted').mkdir(parents=True)
    sentinel = d/'preexisting'
    sentinel.write_bytes(b'preserve'*1000)
    other = tmp_path/'other-result'
    other.mkdir()
    (other/'data').write_bytes(b'other'*1000)
    script = "from pathlib import Path;import sys;Path(sys.argv[1]).write_bytes(b'x'*300);sys.stdout.write('y'*300);sys.stderr.write('z'*300)"
    rr = await runner.run_process([sys.executable,'-c',script,str(d/'native')],
        d/'extracted'/'file.bin',d/'stderr',10,max_output_bytes=1024,output_dir=d)
    assert rr.exit_code == 0 and not rr.output_exceeded  # 900 bytes, not counted twice
    assert sentinel.read_bytes() == b'preserve'*1000
    assert (other/'data').read_bytes() == b'other'*1000
    script = "from pathlib import Path;import sys;Path(sys.argv[1]).write_bytes(b'x'*2000000)"
    rr = await runner.run_process([sys.executable,'-c',script,str(d/'native2')],
        d/'extracted'/'file2.bin',d/'stderr2',10,max_output_bytes=1024,output_dir=d)
    assert rr.output_exceeded and (d/'native2').stat().st_size <= 1024
    assert sentinel.read_bytes() == b'preserve'*1000
    assert (d/'native').read_bytes() == b'x'*300

@pytest.mark.anyio
async def test_disk_extraction_accounts_for_parent_stderr(case,tmp_path):
    tools = tmp_path/'disk-tools'
    shutil.copytree(case.sleuthkit_dir,tools)
    (tools/'icat').write_text("import sys;sys.stdout.write('synthetic');sys.stderr.write('x'*2000000)")
    case.sleuthkit_dir = tools
    case.max_extract_file_mb = 1
    result = (await Engine(case).call('disk_extract',dict(path=IMG,partition_offset=206848,targets=['mft']))).structured_content
    events = list(audit.iter_events(case.audit_file))
    assert events[-1]['outcome'] == 'tool_error'
    assert result['rows'][0]['status'] != 'ok'
    d = case.output_root/result['result_id']
    assert sum(p.stat().st_size for p in d.rglob('*') if p.is_file() and p.name not in ('meta.json','rows.jsonl')) <= 1024*1024
