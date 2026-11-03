#!/usr/bin/env python3
"""Offline localhost/MCP/rollback checks. No internet, no company model calls."""
from pathlib import Path
import contextlib
import http.server
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

CORE = Path(__file__).resolve().parents[1] / 'core' / 'agent_efficiency_offline.py'
spec=importlib.util.spec_from_file_location('kit',CORE)
kit=importlib.util.module_from_spec(spec)
spec.loader.exec_module(kit)

class Model(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length','0')))
        output=json.dumps({'usage':{'prompt_tokens':123,'completion_tokens':34,
          'prompt_tokens_details':{'cached_tokens':21}}}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(output)))
        self.end_headers()
        self.wfile.write(output)
    def log_message(self,*args): pass


def main():
    with tempfile.TemporaryDirectory(prefix='oaek_integration_') as td:
        root=Path(td)
        ag=root/'AGENTS.md'
        ag.write_text('Important corporate security gates preserved.\n',encoding='utf-8')
        with contextlib.redirect_stdout(io.StringIO()):
            kit.install_rules('both','project',root,dry_run=True)
        assert 'OAEK-BEGIN' not in ag.read_text()
        with contextlib.redirect_stdout(io.StringIO()):
            kit.install_rules('both','project',root)
        assert 'OAEK-BEGIN' in ag.read_text() and 'corporate security gates' in ag.read_text()
        with contextlib.redirect_stdout(io.StringIO()):
            kit.install_rules('both','project',root,uninstall=True)
        assert 'OAEK-BEGIN' not in ag.read_text() and 'corporate security gates' in ag.read_text()
        (root/'main.py').write_text('def check():\n    return True\n')
        requests = [
          {'jsonrpc':'2.0','id':1,'method':'initialize','params':{}},
          {'jsonrpc':'2.0','id':2,'method':'tools/list'},
          {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'focused_context','arguments':{'query':'check'}}}
        ]
        launch=subprocess.run([sys.executable,str(CORE),'mcp','--root',str(root)],
          input='\n'.join(map(json.dumps,requests))+'\n', text=True,capture_output=True,timeout=15)
        assert launch.returncode == 0, launch.stderr
        responses=list(map(json.loads,launch.stdout.splitlines()))
        assert len(responses)==3 and 'main.py' in json.dumps(responses)
        fail=subprocess.run([sys.executable,str(CORE),'run','--max-chars','500','--',sys.executable,'-c',
                             'import sys;print("FAILED EXPLICITLY");sys.exit(37)'],capture_output=True,text=True,timeout=15)
        assert fail.returncode==37 and 'FULL FAILURE LOG' in fail.stdout
        up=http.server.ThreadingHTTPServer(('127.0.0.1',0),Model)
        threading.Thread(target=up.serve_forever,daemon=True).start()
        proxy=http.server.ThreadingHTTPServer(('127.0.0.1',0),
                  kit.make_handler(kit.ProxyState(f'http://127.0.0.1:{up.server_port}',12)))
        threading.Thread(target=proxy.serve_forever,daemon=True).start()
        try:
            req=urllib.request.Request(f'http://127.0.0.1:{proxy.server_port}/v1/chat/completions',data=b'{}',headers={'Content-Type':'application/json'})
            with urllib.request.urlopen(req,timeout=10) as res:
                assert json.loads(res.read())['usage']['prompt_tokens']==123
        finally:
            proxy.shutdown();proxy.server_close();up.shutdown();up.server_close()
    print('PASS: instruction install/rollback, subprocess MCP, failed-command evidence, localhost-only model-gateway round trip')

if __name__=='__main__':
    main()
