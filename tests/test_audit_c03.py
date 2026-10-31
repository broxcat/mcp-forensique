import re
import pytest
from forensic_mcp.ops import Engine
from forensic_mcp import validation
from forensic_mcp.safety import SafetyError

@pytest.mark.anyio
async def test_review_is_required_and_bound_to_exact_report(cfg):
    eng = Engine(cfg)
    with pytest.raises(SafetyError,match='senior review') as exc:
        await eng.op_report_export({'final':True})
    rid = re.search(r'candidate (\S+):',str(exc.value)).group(1)
    with pytest.raises(validation.ValidationError):
        validation.review_report(cfg,rid,'Synthetic senior','test',False)
    validation.review_report(cfg,rid,'Synthetic senior','synthetic test',True)
    ok = await eng.op_report_export({'final':True})
    assert ok.result_id == rid
    with (cfg.output_root/rid/'report.md').open('a') as fh:
        fh.write('altered')
    with pytest.raises(SafetyError,match='integrity'):
        await eng.op_report_export({'final':True})
