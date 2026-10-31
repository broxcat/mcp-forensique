from forensic_mcp import __main__ as cli

def test_process_policy_defaults_cloud_and_requires_explicit_local(monkeypatch):
    modes = []
    class Server:
        async def run_stdio_async(self): pass
    def build(cfg):
        modes.append(cfg.llm_mode)
        return Server()
    monkeypatch.setattr(cli, 'build_server', build)
    cli.main(['--stdio'])
    cli.main(['--stdio','--llm-mode','local'])
    assert modes == ['cloud','local']
