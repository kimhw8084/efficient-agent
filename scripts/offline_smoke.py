#!/usr/bin/env python3
"""Full offline smoke test with network sockets disabled. No repository modifications."""
from pathlib import Path
import importlib.util
import os
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'core' / 'agent_efficiency_offline.py'
LAUNCHER = ROOT / 'scripts' / 'agent.py'

spec = importlib.util.spec_from_file_location('offline_core', CORE)
kit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kit)


def main():
    original = socket.socket
    def blocked(*args, **kwargs):
        raise RuntimeError('NETWORK DISABLED DURING OFFLINE TEST')
    with tempfile.TemporaryDirectory(prefix='oaek_e2e_') as td:
        repo = Path(td) / 'repo'
        repo.mkdir()
        (repo / 'app.py').write_text('def login(user):\n    return user.is_valid()\n\nlogin(1)\n', encoding='utf-8')
        (repo / '.env').write_text('SECRET=private\n', encoding='utf-8')
        (repo / '.gitignore').write_text('ignored.py\n', encoding='utf-8')
        (repo / 'ignored.py').write_text('def leak(): pass\n', encoding='utf-8')
        os.environ['OAEK_CACHE_DIR'] = str(Path(td) / 'cache')
        socket.socket = blocked
        try:
            assert 'app.py' in kit.context_pack(repo, 'login')
            assert 'SECRET=private' not in kit.context_pack(repo, 'SECRET')
            assert 'ignored.py' not in kit.repo_map(repo)
            assert 'login at 1-' in kit.python_ast_symbols(repo, 'app.py', 'login')
            assert 'possible invocation' in kit.python_ast_symbols(repo, 'app.py', 'login')
            assert 'app.py' in kit.indexed_map(repo)
            assert 'Git' in kit.git_changes(repo)
            calls = {'jsonrpc':'2.0','id':42,'method':'tools/call','params':{'name':'batch_inspect','arguments':{
               'operations':[{'op':'ast','file':'app.py','symbol':'login'},{'op':'search','query':'login'}]}}}
            result = kit.mcp_process(calls, repo)
            assert result['result']['isError'] is False
            assert 'app.py' in result['result']['content'][0]['text']
        finally:
            socket.socket = original
        # Reenter via subprocess to verify shipped launcher uses no online installs.
        env = dict(os.environ)
        ret = subprocess.run([sys.executable, str(LAUNCHER), 'pack', '--root', str(repo), 'login'],
                             capture_output=True, text=True, timeout=25, env=env)
        assert ret.returncode == 0, ret.stderr
        assert 'app.py' in ret.stdout
    print('PASS: network-blocked retrieval, secrets exclusions, ignored files, Python AST, local MCP batching, native fallback, launcher')
    return 0

if __name__ == '__main__':
    sys.exit(main())
