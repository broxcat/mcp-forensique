"""Container integration checks with installed forensic binaries and synthetic data."""
import shutil
import struct
import pytest
from forensic_mcp.runner import run_process

@pytest.mark.anyio
async def test_real_tshark_native_output_limit(tmp_path):
    binary = shutil.which('tshark')
    assert binary, 'Run in the project Docker image, which provides tshark'
    source = tmp_path/'synthetic.pcap'
    source.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    out = tmp_path/'result'
    out.mkdir()
    rr = await run_process([binary,'-r',str(source),'-w',str(out/'native.pcap')],
                           out/'stdout',out/'stderr',30,max_output_bytes=16)
    assert rr.output_exceeded and rr.exit_code != 0
    assert sum(p.stat().st_size for p in out.iterdir()) <= 16
