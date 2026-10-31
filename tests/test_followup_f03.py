import os
import re
import pytest
from forensic_mcp import audit, evidence, validation
from forensic_mcp.ops import Engine
from forensic_mcp.safety import SafetyError
from test_artefacts_disk import case, IMG
from export_helpers import make_export, jsonl
from forensic_mcp import results

async def finding(cfg, kind):
    eng = Engine(cfg)
    path = 'mem.raw'
    original = cfg.evidence_root/path
    if kind == 'derived':
        original = cfg.evidence_root/IMG
        path = IMG
        for _ in range(2):
            x = (await eng.call('disk_extract',dict(path=path,partition_offset=206848,targets=['mft']))).structured_content
            path = x['rows'][0]['path']
    r = (await eng.call('vol_pslist',{'path':path})).structured_content
    field = 'PID'
    if kind != 'direct':
        r = (await eng.call('timeline',dict(case='.',around='2026-10-06T14:31:00Z',window_minutes=5))).structured_content
        field = 'detail'
    row = r['rows'][0]
    await eng.call('record_finding',dict(kind='fact',text='Synthetic provenance regression',confidence='medium',
        citations=[dict(result_id=r['result_id'],row=row['_row'],field=field,value=row[field])]))
    validation.decide(cfg,'F-0001','validated','Synthetic analyst','synthetic test only')
    return eng, original

async def review_candidate(eng):
    with pytest.raises(SafetyError,match='candidate') as err:
        await eng.op_report_export({'final':True})
    rid = re.search(r'candidate (\S+):',str(err.value)).group(1)
    validation.review_report(eng.cfg,rid,'Synthetic senior','synthetic review only',True)
    return rid

@pytest.mark.anyio
@pytest.mark.parametrize('kind',['direct','timeline','derived'])
@pytest.mark.parametrize('phase',['before_candidate','after_review'])
@pytest.mark.parametrize('change',['modify','missing','unregistered'])
async def test_originals_are_checked_at_both_export_stages(case,kind,phase,change):
    eng, original = await finding(case,kind)
    if phase == 'after_review':
        await review_candidate(eng)
    if change == 'modify':
        st = original.stat()
        original.write_bytes(b'x'*st.st_size)
        os.utime(original,ns=(st.st_atime_ns,st.st_mtime_ns))
    elif change == 'missing':
        original.unlink()
    else:
        # Registry mutation is synthetic; no real journal or registry is touched.
        import json
        from forensic_mcp.evidence import _registry
        p = _registry(case)
        data = json.loads(p.read_text())
        del data[evidence.relpath(case,original)]
        p.write_text(json.dumps(data))
    with pytest.raises((SafetyError,FileNotFoundError)) as err:
        await eng.op_report_export({'final':True})
    assert 'candidate ' not in str(err.value)
    if change == 'modify':
        after = [e for e in audit.iter_events(case.audit_file) if e['type']=='evidence_verified'
                 and e.get('stage')=='after' and e['path']==evidence.relpath(case,original)]
        assert after and after[-1]['matches_registration'] is False

@pytest.mark.anyio
@pytest.mark.parametrize('kind',['direct','timeline','derived'])
async def test_intact_originals_are_deduplicated_rehashed_and_reported(case,kind):
    eng, original = await finding(case,kind)
    rid = await review_candidate(eng)
    before = len(list(audit.iter_events(case.audit_file)))
    final = await eng.op_report_export({'final':True})
    assert final.result_id == rid
    rel = evidence.relpath(case,original)
    after = [e for e in list(audit.iter_events(case.audit_file))[before:] if e['type']=='evidence_verified'
             and e.get('stage')=='after' and e['path']==rel]
    assert len(after) == 1 and after[0]['matches_registration']
    text = (case.output_root/rid/'report.md').read_text()
    assert rel in text and after[0]['sha256'] in text

@pytest.mark.anyio
async def test_import_auxiliary_and_export_sources_are_reverified(case):
    aux = case.evidence_root/'SOFTWARE'
    aux.write_bytes(b'synthetic hive')
    path = make_export(case.evidence_root,'WS-042','SrumECmd','mem.raw',{'x.json':jsonl([{'x':1}])},
        source_inputs=[dict(flag='-r',path='SOFTWARE',sha256=results.sha256_file(aux))],argv=['SrumECmd','-r','C:/SOFTWARE'])
    eng = Engine(case)
    r = (await eng.call('ez_import',dict(tool='SrumECmd',path=path))).structured_content
    await eng.call('record_finding',dict(kind='fact',text='Synthetic import',confidence='medium',
        citations=[dict(result_id=r['result_id'],row=1,field='x',value=1)]))
    validation.decide(case,'F-0001','validated','Synthetic analyst','synthetic test only')
    rid = await review_candidate(eng)
    text = (case.output_root/rid/'report.md').read_text()
    assert 'SOFTWARE' in text and 'manifest.json' in text and 'x.json' in text
    st = aux.stat()
    aux.write_bytes(b'x'*st.st_size)
    os.utime(aux,ns=(st.st_atime_ns,st.st_mtime_ns))
    with pytest.raises(SafetyError):
        await eng.op_report_export({'final':True})

@pytest.mark.anyio
async def test_directory_additions_invalidate_candidate(case):
    folder = case.evidence_root/'logs'
    folder.mkdir()
    (folder/'a.evtx').write_bytes(b'synthetic')
    eng = Engine(case)
    r = (await eng.call('evtx_query',{'path':'logs'})).structured_content
    row = r['rows'][0]
    field = next(k for k in row if k != '_row' and row[k] is not None)
    await eng.call('record_finding',dict(kind='fact',text='Synthetic directory',confidence='medium',
        citations=[dict(result_id=r['result_id'],row=row['_row'],field=field,value=row[field])]))
    validation.decide(case,'F-0001','validated','Synthetic analyst','synthetic test only')
    await review_candidate(eng)
    (folder/'new.evtx').write_bytes(b'new')
    with pytest.raises(SafetyError):
        await eng.op_report_export({'final':True})
