import pytest
from forensic_mcp import audit, results
from forensic_mcp.ops import Engine
from forensic_mcp import validation

@pytest.mark.anyio
async def test_sitrep_separates_findings_and_counts(cfg):
    for case in ['A', 'B']:
        folder = cfg.evidence_root / case
        folder.mkdir()
        (folder / 'case.toml').write_text(f'case="{case}"\nclassification="lab"')
        (folder/'mem.raw').write_bytes(b'synthetic')
        rid = (await Engine(cfg).call('vol_pslist',{'path':f'{case}/mem.raw'})).structured_content['result_id']
        await Engine(cfg).call('record_finding',{'kind':'recommendation','text':f'ONLY_{case}',
            'confidence':'high','citations':[{'result_id':rid,'row':1,'field':'PID','value':4}]})
        fid = 'F-0001' if case == 'A' else 'F-0002'
        validation.decide(cfg,fid,'validated','Synthetic test','synthetic test only')
    eng = Engine(cfg)
    for case, other in [('A','B'), ('B','A')]:
        out = await eng.op_sitrep_draft({'case':case,'audience':'technique'})
        text = (cfg.output_root / out.result_id / 'sitrep.md').read_text()
        assert f'ONLY_{case}' in text and f'ONLY_{other}' not in text
        assert '1 constats validés' in out.payload['summary']
