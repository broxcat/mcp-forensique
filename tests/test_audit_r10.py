import runpy
from pathlib import Path
import pytest

match = runpy.run_path(str(Path(__file__).resolve().parents[1]/'eval'/'score.py'))['ioc_matches']

@pytest.mark.parametrize('kind,value,other',[
    ('ip','203.0.113.1','203.0.113.10'),('ip','2001:db8::1','2001:db8::10'),
    ('domain','evil.test','evil.test.example'),('sha256','a'*64,'a'*65),
    ('process','evil.exe','notevil.exe'),('url','https://evil.test/a','https://evil.test/ab')])
def test_ioc_uses_complete_typed_values(kind,value,other):
    ioc = {'type':kind,'value':value}
    assert match(ioc,'observed '+value+' during test')
    assert not match(ioc,'observed '+other+' during test')
