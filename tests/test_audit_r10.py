import runpy
from pathlib import Path
import pytest

match = runpy.run_path(str(Path(__file__).resolve().parents[1]/'eval'/'score.py'))['ioc_matches']
score = runpy.run_path(str(Path(__file__).resolve().parents[1]/'eval'/'score.py'))['score']

@pytest.mark.parametrize('kind,value,other',[
    ('ip','203.0.113.1','203.0.113.10'),('ip','2001:db8::1','2001:db8::10'),
    ('domain','evil.test','evil.test.example'),('sha256','a'*64,'a'*65),
    ('process','evil.exe','notevil.exe'),('url','https://evil.test/a','https://evil.test/ab')])
def test_ioc_uses_complete_typed_values(kind,value,other):
    ioc = {'type':kind,'value':value}
    assert match(ioc,'observed '+value+' during test')
    assert not match(ioc,'observed '+other+' during test')

@pytest.mark.parametrize('kind,value,decision,expected',[
    ('recommendation','203.0.113.1',None,0),('fact','4',None,0),
    ('fact','203.0.113.1','rejected',0),('fact','203.0.113.1','validated',1)])
def test_only_cited_facts_contribute_to_validated_iocs(kind,value,decision,expected):
    event = {'type':'suggestion','audit_id':1,'ts_utc':'2026-10-01T00:00:00Z',
             'finding_id':'F-0001','kind':kind,'confidence':'high','text':'203.0.113.1', 'status':'à valider',
             'citations':[{'result_id':'synthetic','_row':1,'field':'value','value':value}],
             'cross_check':{'status':'passed','mismatches':[]}}
    events = [event]
    if decision:
        events.append({'type':'validation','audit_id':2,'ts_utc':'2026-10-01T00:00:01Z',
                       'finding_id':'F-0001','decision':decision,'actor':{'name':'Synthetic test'}})
    gt = {'status':'filled','case':'A','steps':[{'step':1,'cdc_step':'synthetic',
          'expected_facts':[{'tool':'vol_pslist','description':'synthetic'}],
          'iocs':[{'type':'ip','value':'203.0.113.1'}]}]}
    result = score(gt,events)['iocs']
    assert result['validated'] == expected
    assert result['validated_recall'] == expected
