import pytest
from forensic_mcp import audit, results
from forensic_mcp.ops import Engine
from forensic_mcp.safety import SafetyError

@pytest.mark.anyio
@pytest.mark.parametrize('cls', ['client', 'internal', 'lab'])
async def test_findings_exports_and_later_queries(cfg, cls):
    (cfg.evidence_root / 'case.toml').write_text(f'case="A"\nclassification="{cls}"\nhosts=["SECRET_HOST"]')
    eng = Engine(cfg)
    rid = (await eng.call('vol_pslist', {'path':'mem.raw'})).structured_content['result_id']
    audit.append(cfg.audit_file, 'suggestion', {'kind':'llm'}, finding_id='F-0001',
                 kind='fact', text='SECRET_HOST', confidence='high', attack=[],
                 citations=[{'result_id':rid, '_row':1, 'field':'Host', 'value':'SECRET_HOST'}],
                 cross_check={'status':'passed','mismatches':[]}, status='à valider')
    report = (await eng.call('report_export', {})).structured_content
    cfg.llm_mode = 'cloud'
    for op, args in [(eng.op_list_findings, {}), (eng.op_report_export, {}),
                     (eng.op_query_results, {'result_id':report['result_id']})]:
        if cls == 'client':
            with pytest.raises(SafetyError):
                await op(args)
        else:
            out = await op(args)
            text = str(out.pseudo.redact(out.payload))
            assert ('SECRET_HOST' in text) == (cls == 'lab')
