import pytest
from forensic_mcp import audit, results
from forensic_mcp.ops import Engine

@pytest.mark.anyio
async def test_sitrep_separates_findings_and_counts(cfg):
    for case in ['A', 'B']:
        folder = cfg.evidence_root / case
        folder.mkdir()
        (folder / 'case.toml').write_text(f'case="{case}"\nclassification="lab"')
        rid, d = results.new_result(cfg.output_root, 'probe')
        results.write_meta(d, input_path=str(folder / 'mem.raw'))
        audit.append(cfg.audit_file, 'suggestion', {'kind':'llm'}, finding_id=f'F-{case}',
                     kind='recommendation', text=f'ONLY_{case}', confidence='high', attack=[],
                     citations=[{'result_id':rid, '_row':1,'field':'x','value':1}],
                     cross_check={'status':'passed','mismatches':[]}, status='à valider')
        audit.append(cfg.audit_file, 'validation', {'kind':'analyst','name':'Synthetic test'},
                     finding_id=f'F-{case}', decision='validated', comment='synthetic test only')
    eng = Engine(cfg)
    for case, other in [('A','B'), ('B','A')]:
        out = await eng.op_sitrep_draft({'case':case,'audience':'technique'})
        text = (cfg.output_root / out.result_id / 'sitrep.md').read_text()
        assert f'ONLY_{case}' in text and f'ONLY_{other}' not in text
        assert '1 constats validés' in out.payload['summary']
