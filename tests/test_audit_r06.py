import sys
import pytest
from forensic_mcp.runner import run_process

@pytest.mark.anyio
@pytest.mark.parametrize('native', [False, True])
async def test_completed_outputs_are_bounded(tmp_path, native):
    script = ("from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(b'x'*2000000)"
              if native else "import sys; sys.stdout.write('x'*1000000); sys.stderr.write('x'*1000000)")
    rr = await run_process([sys.executable,'-c',script,str(tmp_path/'native')],
                           tmp_path/'stdout',tmp_path/'stderr',10,max_output_bytes=1024)
    assert rr.output_exceeded and rr.exit_code != 0
    assert sum(p.stat().st_size for p in tmp_path.iterdir()) <= 1024
