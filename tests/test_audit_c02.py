import pytest
from forensic_mcp.redact import Pseudonymizer, Case
from forensic_mcp.ops import Engine
from mcp.server.mcpserver.exceptions import ToolError

def test_ipv6_and_encoded_representations_are_masked(tmp_path):
    ps = Pseudonymizer(tmp_path/'map.json', Case('A','internal'))
    text = ps.text('2001:db8::1 powershell -EncodedCommand UwBFAEMAUgBFAFQAXwBIAE8AUwBUAA==')
    assert '2001:db8::1' not in text and 'UwBFAE' not in text
    assert 'IP_EXT_' in text and '[ENCODED_REDACTED]' in text

@pytest.mark.anyio
async def test_cloud_error_does_not_echo_sensitive_paths(cfg):
    cfg.llm_mode = 'cloud'
    with pytest.raises(ToolError) as err:
        await Engine(cfg).call('verify_evidence',{'path':'CONFIDENTIAL_HOST_77'})
    assert 'CONFIDENTIAL_HOST_77' not in str(err.value)
