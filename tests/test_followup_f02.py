import json
import pytest
from mcp.server.mcpserver.exceptions import ToolError
from forensic_mcp import audit, results
from forensic_mcp.ops import Engine
from test_artefacts_disk import case, IMG

@pytest.mark.anyio
@pytest.mark.parametrize('change',['input_path','remove_provenance','provenance','rows','unsealed'])
@pytest.mark.parametrize('tool',['query_results','list_results','timeline'])
async def test_readers_refuse_untrusted_results(cfg, change, tool):
    eng = Engine(cfg)
    r = (await eng.call('vol_cmdline',{'path':'mem.raw'})).structured_content
    d = results.result_dir(cfg.output_root,r['result_id'])
    m = results.read_meta(d)
    if change == 'input_path':
        m['input_path'] = str(cfg.evidence_root/'other.raw')
    elif change == 'remove_provenance':
        m.pop('provenance')
    elif change == 'provenance':
        m['provenance'] = []
    elif change == 'rows':
        with (d/'rows.jsonl').open('a') as fh: fh.write('{"secret":"FORGED"}\n')
    else:
        # A result with no producer must not become trusted through a read.
        rid, d2 = results.new_result(cfg.output_root,'probe')
        (d2/'rows.jsonl').write_bytes((d/'rows.jsonl').read_bytes())
        results.write_meta(d2,**m)
        r['result_id'] = rid
    if change in ('input_path','remove_provenance','provenance'):
        results.write_meta(d,**m)
    cfg.llm_mode = 'cloud'
    args = {'query_results':{'result_id':r['result_id']},'list_results':{},
            'timeline':{'case':'.','around':'2026-10-06T14:31:00Z'}}[tool]
    with pytest.raises(ToolError) as err:
        await eng.call(tool,args)
    assert 'FORGED' not in str(err.value) and 'alice' not in str(err.value)
    assert list(audit.iter_events(cfg.audit_file))[-1]['outcome'] == 'refused'

@pytest.mark.anyio
async def test_client_metadata_cannot_reclassify_as_lab(cfg):
    (cfg.evidence_root/'case.toml').write_text('case="CLIENT"\nclassification="client"')
    eng = Engine(cfg)
    r = (await eng.call('vol_cmdline',{'path':'mem.raw'})).structured_content
    lab = cfg.evidence_root/'LAB'
    lab.mkdir()
    (lab/'case.toml').write_text('case="LAB"\nclassification="lab"')
    (lab/'mem.raw').write_bytes(b'lab')
    d = results.result_dir(cfg.output_root,r['result_id'])
    results.write_meta(d,**{**results.read_meta(d),'input_path':str(lab/'mem.raw'),'provenance':[]})
    cfg.llm_mode = 'cloud'
    with pytest.raises(ToolError):
        await eng.call('query_results',{'result_id':r['result_id']})

@pytest.mark.anyio
async def test_cache_and_aggregate_parent_integrity(cfg):
    eng = Engine(cfg)
    r = (await eng.call('evtx_query',{'path':'mem.raw'})).structured_content
    tl = (await eng.call('timeline',{'case':'.','around':'2026-10-06T14:31:00Z'})).structured_content
    with (cfg.output_root/r['result_id']/'meta.json').open('a') as fh: fh.write(' ')
    for tool,args in [('evtx_query',{'path':'mem.raw'}),('query_results',{'result_id':tl['result_id']})]:
        with pytest.raises(ToolError):
            await eng.call(tool,args)

@pytest.mark.anyio
async def test_intact_results_remain_readable(cfg):
    eng = Engine(cfg)
    r = (await eng.call('evtx_query',{'path':'mem.raw'})).structured_content
    for tool,args in [('query_results',{'result_id':r['result_id']}),('list_results',{}),('evtx_query',{'path':'mem.raw'})]:
        assert (await eng.call(tool,args)).structured_content['rows']

@pytest.mark.anyio
async def test_derived_parent_is_verified_before_reads_or_classification(case):
    eng = Engine(case)
    extracted = (await eng.call('disk_extract',dict(path=IMG,partition_offset=206848,targets=['mft']))).structured_content
    path = extracted['rows'][0]['path']
    parsed = (await eng.call('mft_search',{'path':path})).structured_content
    with (case.output_root/extracted['result_id']/'meta.json').open('a') as fh: fh.write(' ')
    for tool,args in [('query_results',{'result_id':parsed['result_id']}),
                      ('verify_evidence',{'path':path}),('mft_search',{'path':path})]:
        with pytest.raises(ToolError):
            await eng.call(tool,args)
