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

@pytest.mark.anyio
async def test_option_sources_are_registered_and_checked_before_cache(cfg):
    from forensic_mcp.results import sha256_file
    extra = cfg.evidence_root/'SOFTWARE'
    extra.write_bytes(b'synthetic hive')
    exp = make_export(cfg.evidence_root,'A','SrumECmd','mem.raw',{'x.json':jsonl([{'x':1}])},
                      source_inputs=[{'flag':'-r','path':'SOFTWARE','sha256':sha256_file(extra)}],argv=['SrumECmd','-r','C:/original/SOFTWARE'])
    eng = Engine(cfg)
    await eng.op_ez_import({'tool':'SrumECmd','path':exp})
    assert 'SOFTWARE' in evidence.load_registry(cfg)
    extra.write_bytes(b'changed')
    with pytest.raises(SafetyError):
        await eng.op_ez_import({'tool':'SrumECmd','path':exp})
