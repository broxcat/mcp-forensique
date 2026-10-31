import pytest
from forensic_mcp import results, validation
from forensic_mcp.ops import Engine
from forensic_mcp.safety import SafetyError

@pytest.mark.anyio
@pytest.mark.parametrize('file', ['rows.jsonl','meta.json','stdout.txt'])
async def test_tampering_refuses_citation_validation_and_export(cfg, file):
    eng = Engine(cfg)
    r = (await eng.call('vol_pslist',{'path':'mem.raw'})).structured_content
    rid = r['result_id']
    c = {'result_id':rid,'row':1,'field':'PID','value':4}
    await eng.call('record_finding',{'kind':'fact','text':'synthetic System PID 4',
                                   'confidence':'high','citations':[c]})
    validation.decide(cfg,'F-0001','validated','Synthetic test','synthetic test only')
    d = results.result_dir(cfg.output_root,rid)
    with (d/file).open('a') as fh:
        fh.write(' ')
    with pytest.raises(SafetyError,match='integrity'):
        eng._check(c)
    with pytest.raises(SafetyError,match='integrity'):
        validation.decide(cfg,'F-0001','validated','Synthetic test','synthetic test only')
    with pytest.raises(SafetyError,match='integrity'):
        await eng.op_report_export({'final':True})
