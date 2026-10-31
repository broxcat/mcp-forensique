import pytest
from forensic_mcp import contract

@pytest.mark.parametrize('field', ['anomalies','notes','decoded','iocs','summary','parameters'])
def test_nonrow_fields_cannot_exceed_budget(field):
    p = contract.build(tool='probe',engine='probe',parameters={},summary='',rows=[],row_count=0)
    p[field] = 'é<' * 100000
    with pytest.raises(ValueError, match='budget'):
        contract.fit(p,64)

def test_large_row_cannot_repeat_cursor():
    p = contract.build(tool='probe',engine='probe',parameters={},summary='',
                       rows=[{'_row':1,'value':'x'*100000}],row_count=1)
    with pytest.raises(ValueError, match='progress'):
        contract.fit(p,1)

def test_size_includes_both_transmitted_representations():
    p = contract.build(tool='probe',engine='probe',parameters={},summary='',rows=[],row_count=0)
    assert contract.size_kb(p)*1024 == len(contract.render(p).model_dump_json(by_alias=True).encode())
