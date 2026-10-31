import json
import pytest
from mcp.server.mcpserver.exceptions import ToolError
from forensic_mcp.ops import Engine

async def populate(cfg, classes):
    eng = Engine(cfg)
    for name, cls in classes:
        d = cfg.evidence_root/name
        d.mkdir()
        (d/'case.toml').write_text(f'case="{name}"\nclassification="{cls}"\nhosts=["{name}","{name}_HOST"]\nusers=["{name}_OWNER"]')
        await eng.call('crisis_add_event',dict(case=name,time_utc='2026-10-01T00:00:00Z',kind='event',
                       description=f'{name}_HOST incident',owner=f'{name}_OWNER',source=f'{name}_HOST source'))
        st = (await eng.call('stakeholder_upsert',dict(case=name,role='dpo',name=f'{name}_PERSON',owner=f'{name}_OWNER'))).structured_content['rows'][0]
        await eng.call('comms_log',dict(case=name,stakeholder_id=st['stakeholder_id'],direction='sortante',
                       at_utc='2026-10-01T00:00:00Z',summary=f'{name}_HOST message',source=f'{name}_HOST source'))
    return eng

@pytest.mark.anyio
@pytest.mark.parametrize('alias',['', '.', './', 'LAB/..'])
@pytest.mark.parametrize('tool',['crisis_timeline','stakeholder_list','sitrep_draft'])
async def test_global_views_refuse_client_contributors(cfg, alias, tool):
    eng = await populate(cfg,[('LAB','lab'),('INTERNAL','internal'),('CLIENT','client')])
    cfg.llm_mode = 'cloud'
    with pytest.raises(ToolError):
        await eng.call(tool,dict(case=alias,audience='technique'))

@pytest.mark.anyio
async def test_allowed_views_apply_each_case_and_preserve_counts(cfg):
    eng = await populate(cfg,[('LAB','lab'),('INTERNAL','internal')])
    cfg.llm_mode = 'cloud'
    for tool in ['crisis_timeline','stakeholder_list','sitrep_draft']:
        out = (await eng.call(tool,dict(case='.',audience='technique'))).structured_content
        text = json.dumps(out)
        assert 'INTERNAL_HOST' not in text and 'INTERNAL_OWNER' not in text
        assert 'INTERNAL_PERSON' not in text and '"INTERNAL"' not in text
        if tool == 'crisis_timeline':
            assert out['row_count'] == 6 and 'LAB_HOST' in text
        if tool == 'stakeholder_list':
            assert out['row_count'] == 2
    # A targeted case must not inherit unrelated contributors or their counts.
    await populate(cfg, [])
    out = (await eng.call('crisis_timeline',{'case':'LAB/./'})).structured_content
    assert out['row_count'] == 3 and 'INTERNAL' not in json.dumps(out)

@pytest.mark.anyio
async def test_targeted_views_and_persisted_global_sitrep(cfg):
    eng = await populate(cfg,[('LAB','lab'),('INTERNAL','internal'),('CLIENT','client')])
    sitrep = (await eng.call('sitrep_draft',{'case':'.','audience':'technique'})).structured_content
    cfg.llm_mode = 'cloud'
    for tool in ['crisis_timeline','stakeholder_list','sitrep_draft']:
        for case in ['LAB','INTERNAL']:
            out = (await eng.call(tool,dict(case=case,audience='technique'))).structured_content
            assert 'CLIENT' not in json.dumps(out)
        with pytest.raises(ToolError):
            await eng.call(tool,dict(case='CLIENT',audience='technique'))
    with pytest.raises(ToolError):
        await eng.call('query_results',{'result_id':sitrep['result_id']})
