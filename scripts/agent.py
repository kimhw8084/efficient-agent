#!/usr/bin/env python3
"""Cross-platform offline launcher for OAEK. Python 3.9+ standard library only."""
from pathlib import Path
import os
import platform
import subprocess
import sys

HERE = Path(__file__).resolve().parents[1]
CORE = HERE / 'core' / 'agent_efficiency_offline.py'


def valid_rg(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        r = subprocess.run([str(path), '--version'], capture_output=True, timeout=4, check=False)
        return r.returncode == 0 and r.stdout.startswith(b'ripgrep ')
    except (OSError, subprocess.TimeoutExpired):
        return False


def main():
    env = dict(os.environ)
    # The bundled native binary is an *optional accelerator* only. Never fetch one.
    if 'OAEK_RG_PATH' not in env and platform.system() == 'Linux' and platform.machine().lower() in {'x86_64', 'amd64'}:
        candidate = HERE / 'tools' / 'linux-x86_64' / 'rg'
        if valid_rg(candidate):
            env['OAEK_RG_PATH'] = str(candidate)
    args = list(sys.argv[1:])
    if args and args[0] in {'search', 'pack'} and '--engine' not in args and env.get('OAEK_RG_PATH'):
        args.extend(['--engine', 'rg'])
    if os.name == 'posix':
        os.execvpe(sys.executable, [sys.executable, str(CORE), *args], env)
    # Windows Python installation has no dependable POSIX exec semantics.
    sys.exit(subprocess.call([sys.executable, str(CORE), *args], env=env))

if __name__ == '__main__':
    main()
