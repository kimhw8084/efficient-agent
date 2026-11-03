#!/usr/bin/env python3
"""Offline SHA-256 content verification. Requires Python 3.9+."""
from pathlib import Path
import hashlib
import sys

ROOT = Path(__file__).resolve().parents[1]
CHECKSUMS = ROOT / 'SHA256SUMS.txt'

def main():
    failures = []
    checks = 0
    for raw in CHECKSUMS.read_text('utf-8').splitlines():
        if not raw or raw.startswith('#'):
            continue
        digest, rel = raw.split('  ', 1)
        path = (ROOT / rel).resolve()
        if ROOT not in path.parents or not path.is_file():
            failures.append(rel + ': missing/invalid')
            continue
        h = hashlib.sha256()
        with path.open('rb') as f:
            for block in iter(lambda: f.read(131072), b''):
                h.update(block)
        if h.hexdigest() != digest:
            failures.append(rel + ': checksum mismatch')
        checks += 1
    # Detect extras in core/files not covered (user-generated cache files excluded).
    listed = set(row.split('  ', 1)[1] for row in CHECKSUMS.read_text('utf-8').splitlines() if '  ' in row)
    for path in ROOT.rglob('*'):
        if path.is_file() and path.name not in {'SHA256SUMS.txt'} and not any(part in {'.git', '__pycache__', '.cache'} for part in path.parts):
            if path.relative_to(ROOT).as_posix() not in listed:
                failures.append(path.relative_to(ROOT).as_posix() + ': not in manifest')
    print(f'Offline bundle integrity: {checks} files checked; {len(failures)} problems')
    for failure in failures:
        print('FAIL:', failure)
    return 0 if not failures else 1

if __name__ == '__main__':
    sys.exit(main())
