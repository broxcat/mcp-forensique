import pytest
from export_helpers import make_export, jsonl
from forensic_mcp import evidence
from forensic_mcp.ops import Engine
from forensic_mcp.safety import SafetyError

@pytest.mark.anyio
@pytest.mark.parametrize('change',['modify','delete'])
async def test_cached_import_reverifies_registered_original(cfg,change):
    exp = make_export(cfg.evidence_root,'A','PECmd','mem.raw',{'x.json':jsonl([{'x':1}])})
    eng = Engine(cfg)
    await eng.op_ez_import({'tool':'PECmd','path':exp})
    assert 'mem.raw' in evidence.load_registry(cfg)
    source = cfg.evidence_root/'mem.raw'
    if change == 'delete':
        source.unlink()
    else:
        source.write_bytes(b'changed')
    with pytest.raises((SafetyError,FileNotFoundError)):
        await eng.op_ez_import({'tool':'PECmd','path':exp})
