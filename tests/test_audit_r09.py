import concurrent.futures
import subprocess
import sys
from forensic_mcp import audit

def test_processes_allocate_under_linux_lock(tmp_path):
    log = tmp_path / 'audit.jsonl'
    code = """import sys
from forensic_mcp import audit
for key, prefix in [('finding_id','F'),('crisis_id','C'),('stakeholder_id','S')]:
    for _ in range(10):
        audit.append(sys.argv[1], 'crisis_event', {'kind':'server'}, _allocate=(key,prefix),
                     time_utc='2026-10-01T00:00:00Z',kind='event',description='synthetic',owner='test',source='test')
"""
    def writer(_):
        subprocess.run([sys.executable,'-c',code,str(log)],check=True)
    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        list(pool.map(writer,range(4)))
    events = list(audit.iter_events(log))
    for key in ['finding_id','crisis_id','stakeholder_id']:
        ids = [e[key] for e in events if key in e]
        assert len(ids) == len(set(ids)) == 40
    assert audit.verify_report(log, check_schema=False)['ok']

def test_existing_duplicate_business_ids_are_refused(tmp_path):
    log = tmp_path/'audit.jsonl'
    for _ in range(2):
        audit.append(log,'crisis_event',{'kind':'server'},crisis_id='C-0001',
                     time_utc='2026-10-01T00:00:00Z',kind='event',description='test',owner='test',source='test')
    report = audit.verify_report(log)
    assert not report['ok'] and 'duplicate' in report['reason']
