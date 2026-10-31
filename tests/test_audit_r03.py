import pytest
from forensic_mcp import redact, results
from forensic_mcp.safety import SafetyError

@pytest.mark.parametrize('tool', ['disk_extract', 'disk_extract_file', 'vol2_vaddump', 'vol3_windows.vadinfo', 'net_extract_pcap'])
@pytest.mark.parametrize('classification', ['lab', 'internal', 'client'])
def test_recursive_classification(cfg, tool, classification):
    (cfg.evidence_root / 'case.toml').write_text(f'case="A"\nclassification="{classification}"')
    parent = cfg.evidence_root / 'mem.raw'
    for _ in range(2):
        _, d = results.new_result(cfg.output_root, tool)
        results.write_meta(d, tool=tool, input_path=str(parent))
        parent = d / 'extracted' / 'sample'
        parent.parent.mkdir()
        parent.write_bytes(b'sample')
        assert redact.case_for(cfg, parent).classification == classification

def test_missing_provenance_refused(cfg):
    with pytest.raises(SafetyError):
        redact.case_for(cfg, cfg.output_root / 'unknown' / 'sample')
