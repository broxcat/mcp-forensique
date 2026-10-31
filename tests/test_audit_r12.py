import pytest
from forensic_mcp.ops import Engine

@pytest.mark.anyio
@pytest.mark.parametrize('tool,filters', [('evtx_query',{'event_ids':[4624]}),('mft_search',{'path_contains':'exe'})])
async def test_replay_reexecutes_parse_with_filters(cfg,tool,filters):
    eng = Engine(cfg)
    args = {'path':'mem.raw', 'limit':1, **filters}
    first = (await eng.call(tool,args)).structured_content
    replay = (await eng.call('replay',{'audit_id':first['audit_id']})).structured_content
    row = replay['rows'][0]
    assert row['match'] is True
    assert row['new_result_id'] != first['result_id']
