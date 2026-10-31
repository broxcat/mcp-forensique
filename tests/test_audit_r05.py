import pytest
from forensic_mcp.ops import Engine
from forensic_mcp.safety import SafetyError

def test_parent_checks_every_child_before_registration(cfg):
    for name, cls in [('PUBLIC','lab'), ('SECRET','client')]:
        d = cfg.evidence_root / name
        d.mkdir()
        (d / 'case.toml').write_text(f'case="{name}"\nclassification="{cls}"')
        (d / 'a.evtx').write_bytes(b'synthetic')
    cfg.llm_mode = 'cloud'
    eng = Engine(cfg)
    for path in ['SECRET/a.evtx', '.', 'SECRET']:
        with pytest.raises(SafetyError):
            eng._ez_input({'path':path})
    assert not cfg.audit_file.exists()
