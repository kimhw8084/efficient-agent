#!/usr/bin/env python3
"""Offline Agent Efficiency Kit (OAEK) v2.1

One distributable Python 3.9+ standard-library file. No downloads at runtime.
Capabilities: install portable rules, local repo context/search/map, safe batch inspection,
read-only MCP stdio, deterministic process-output filtering, per-user model gateway
rate-limit proxy (opt-in), telemetry, A/B reporting, and built-in tests.

Security: read-only repository inspection by default; no shell commands invoked by MCP;
no credential or source content logging by proxy; no third-party package required.
This does not guarantee any fixed token/request reduction or substitute for native LSP.
"""
from __future__ import annotations
import argparse
import collections
import fnmatch
import heapq
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = '2.1.0'
MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 20000
SKIP_DIRS = {
    '.git', '.hg', '.svn', '.idea', '.vscode', 'node_modules', 'vendor', 'dist',
    'build', 'target', 'coverage', '.next', '.nuxt', '.venv', 'venv', '__pycache__',
    '.mypy_cache', '.pytest_cache', '.tox', '.gradle', '.terraform', '.turbo',
    '.cache', '.agent_efficiency', '.oaek', '.secrets', '.aws', '.ssh', 'Pods', 'bin', 'obj', 'out', '.output'
}
SKIP_FILES = [
    '.env', '.env.*', '*.pem', '*.key', '*.p12', '*.pfx', '*.jks', '*.keystore', '*.npmrc', '.pypirc', '*.tfstate', '*.tfvars', '*id_rsa*',
    '*id_ed25519*', '*secret*', '*credential*', '*token*', '*.lock', '*.min.js',
    '*.map', '*.svg', '*.png', '*.jpg', '*.jpeg', '*.gif', '*.webp', '*.ico',
    '*.pdf', '*.zip', '*.tar', '*.gz', '*.db', '*.sqlite', '*.mp4', '*.exe',
    '*.dll', '*.so', '*.dylib', '*.class', '*.pyc', '*.kdbx', '*.asc', '*.gpg', '*.ovpn', 'secrets.*', '*credentials*', 'config.private.*'
]
TEXT_EXTS = {
    '.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.go', '.rs', '.java',
    '.kt', '.kts', '.cs', '.cpp', '.cc', '.c', '.h', '.hpp', '.rb', '.php', '.swift',
    '.sh', '.bash', '.ps1', '.sql', '.html', '.css', '.scss', '.json', '.jsonc',
    '.yaml', '.yml', '.toml', '.xml', '.md', '.mdx', '.txt', '.gradle', '.graphql',
    '.proto', '.tf', '.dockerfile', '.vue', '.svelte', '.astro'
}
SPECIAL = {'Dockerfile', 'Makefile', 'Justfile', 'Gemfile', 'Procfile', 'CMakeLists.txt', 'BUILD', 'WORKSPACE'}
SYMBOLS = re.compile(
    r'^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:def|class|function|interface|type|enum|struct|trait|impl|fn|func|pub\s+fn|public\s+class|public\s+interface|export\s+const)\s+([A-Za-z_$][\w$]*)'
    r'|^\s*(?:public|private|protected|static|final|abstract|async|override|suspend|fun)\s+(?:(?:static|final|async|fun|suspend)\s+)*(?:[\w<>\[\],?]+\s+)?([A-Za-z_$][\w$]*)\s*\('
)
ERROR_LINE = re.compile(r'\b(error|failed|failure|exception|traceback|panic|fatal|assertion|warning|cannot find|not found|timed out)\b', re.I)
STOP_TERMS = {
    'the', 'and', 'for', 'with', 'from', 'that', 'this', 'which', 'when', 'where',
    'what', 'how', 'why', 'into', 'onto', 'about', 'should', 'could', 'would',
    'please', 'implement', 'modify', 'update', 'change', 'make', 'need', 'want',
    'fix', 'debug', 'resolve', 'repair', 'problem', 'explain', 'understand',
    'bug', 'issue', 'feature', 'correct', 'ensure', 'without', 'within',
    'code', 'file', 'files', 'project', 'repository', 'function', 'class', 'task',
    'test', 'tests', 'broken', 'using', 'used', 'related', 'same', 'there', 'does'
}


def query_terms(query: str):
    # Preserve exact identifiers, plus pieces of camelCase/snake_case names.
    words = re.findall(r'[A-Za-z_$][\w$]{1,80}', query)
    meaningful = [w.lower() for w in words if w.lower() not in STOP_TERMS]
    if not meaningful:
        meaningful = [w.lower() for w in words]
    expanded = list(meaningful)
    for word in words:
        pieces = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', word).replace('_', ' ').split()
        expanded.extend(x.lower() for x in pieces if len(x) >= 3 and x.lower() not in STOP_TERMS)
    return list(dict.fromkeys(expanded))[:12]

REDACT_HEADER_NAMES = {'authorization', 'proxy-authorization', 'cookie', 'set-cookie'}

RULES = """# Offline Agent Efficiency Rules v2.1 (additive)

Project-specific approved instructions, security controls, and quality gates take precedence.
Never trade correctness, security, accessibility or required verification for tokens.

- Optimize **verified task completion** per token/request and elapsed time, not shortest
  response or fewest calls in isolation. Avoid arbitrary call/step ceilings.
- Scope requirements once. Batch only independent investigation; keep dependencies,
  failure checks, authorization and review gates ordered. Avoid redundant narration,
  duplicate searches, repeated reads of unchanged files and unjustified subagents.
- Prefer narrow symbol/path searches and sufficient excerpts, then broaden when
  uncertain; full files are appropriate when required. Use local LSP/AST tools if
  available; lexical matches are not semantic or proof of completeness.
- When useful, use the offline kit's focused_context/batch_inspect MCP or local
  `pack`, `search`, `map`, `facts` and `run` commands. Do not add a tool call
  unless its value exceeds the overhead of simply using existing tools.
- Keep tool output bounded, but preserve exact failures, exit codes, relevant
  stack traces and access to original logs. Never claim unrun checks passed.
- Load optional skills and verbose standards only on demand; keep mandatory
  instructions active. Reuse only evidence-backed, source-checked knowledge.
- Detect failure loops: after repeated identical failures, change investigation
  using new evidence; do not skip tests or silently stop unfinished work.
- No public network calls, package downloads, cloud MCP, cloud telemetry or
  unapproved proxying. Only approved internal model endpoints are permitted.
- A 12-RPM user limit requires a shared routing controller for all relevant
  sessions; written instructions alone cannot enforce it.
- Report changes, verified checks, uncertainties and blockers succinctly. Judge
  efficiency with matched-task, quality-gated benchmarks, not claimed percentages.
"""


def is_safe_name(rel: str) -> bool:
    norm = rel.replace('\\', '/').strip('/')
    parts = norm.split('/')
    if not norm or any(p in {'', '.', '..'} for p in parts):
        return False
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return False
    if any(p.startswith('.') and p not in {'.github', '.gitlab'} for p in parts[:-1]):
        return False
    if any(fnmatch.fnmatch(parts[-1].lower(), pattern.lower()) for pattern in SKIP_FILES):
        return False
    if Path(parts[-1]).suffix.lower() not in TEXT_EXTS and parts[-1] not in SPECIAL:
        return False
    return True


def safe_path(root: Path, rel: str) -> Path:
    if not isinstance(rel, str) or not is_safe_name(rel) or is_ignored(root, rel):
        raise ValueError('file not eligible for repository inspection')
    base = root.resolve()
    unrevolved = base / rel
    # A superficially safe .py symlink must not alias a hidden/ignored secret.
    current = base
    for component in Path(rel.replace('\\', '/')).parts:
        current = current / component
        if current.is_symlink():
            raise ValueError('symlink paths are not eligible for scoped reads')
    dest = unrevolved.resolve()
    if dest != base and base not in dest.parents:
        raise ValueError('path outside repository')
    actual_rel = dest.relative_to(base).as_posix()
    if not is_safe_name(actual_rel) or is_ignored(base, actual_rel):
        raise ValueError('target file is excluded')
    if not dest.is_file() or dest.stat().st_size > MAX_FILE_BYTES:
        raise ValueError('file unavailable or exceeds size limit')
    return dest


def local_files(root: Path):
    root = root.resolve()
    # Avoid subprocesses and network: deterministic bounded traversal.
    count = 0
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and
                         (not d.startswith('.') or d in {'.github', '.gitlab'}) and
                         not (Path(folder) / d).is_symlink() and
                         not is_ignored(root, (Path(folder) / d).relative_to(root).as_posix() + '/'))
        for name in sorted(files):
            rel = (Path(folder) / name).relative_to(root).as_posix()
            if not is_safe_name(rel) or is_ignored(root, rel):
                continue
            p = Path(folder) / name
            try:
                if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield rel, p
            count += 1
            if count >= MAX_FILES:
                return


def read_text(p: Path) -> str:
    data = p.read_bytes()
    if b'\0' in data[:8192]:
        raise ValueError('binary file')
    return data.decode('utf-8', errors='replace')


def clip(s: str, size: int) -> str:
    size = max(64, min(int(size), 150000))
    if len(s) <= size:
        return s
    return s[:size - 90] + f'\n[OUTPUT TRUNCATED; {len(s)-size+90} chars omitted; request narrower context]\n'


def repo_map(root: Path, budget: int = 9000) -> str:
    rows = []
    for rel, p in local_files(root):
        try:
            lines = read_text(p).splitlines()
        except (OSError, ValueError):
            continue
        matches = []
        for i, line in enumerate(lines, 1):
            m = SYMBOLS.search(line)
            if m and (m.group(1) or m.group(2)):
                matches.append(f'{i}:{m.group(1) or m.group(2)}')
                if len(matches) >= 8:
                    break
        if matches or p.name in {'README.md', 'package.json', 'pyproject.toml', 'Cargo.toml', 'go.mod'}:
            rows.append(f'{rel}  ' + ', '.join(matches))
    return scrub(clip('Repository symbol outline (regex-derived; not an LSP):\n' + '\n'.join(rows), budget))


def focused_search(root: Path, query: str, budget: int = 10000, max_results: int = 14):
    terms = query_terms(query)
    if not terms:
        return 'No searchable query terms.'
    found = []
    visited = 0
    for rel, p in local_files(root):
        lowrel = rel.lower()
        try:
            lines = read_text(p).splitlines()
        except (OSError, ValueError):
            continue
        match_rows = []
        for i, ln in enumerate(lines):
            low = ln.lower()
            hits = sum(1 for x in terms if x in low)
            if not hits:
                continue
            score = hits * 3 + (3 if any(x in lowrel for x in terms) else 0)
            score += (2 if SYMBOLS.search(ln) else 0)
            match_rows.append((score, i))
        if match_rows:
            match_rows.sort(key=lambda r: (-r[0], r[1]))
            best = match_rows[:3]
            score = sum(x[0] for x in best) + sum(4 for t in terms if t in lowrel)
            # Bound memory to the highest-ranked candidates instead of holding every match.
            visited += 1
            item = (score, visited, rel, lines, best)
            if len(found) < max_results:
                heapq.heappush(found, item)
            elif score > found[0][0]:
                heapq.heapreplace(found, item)
    found.sort(key=lambda x: (-x[0], x[2]))
    out = [f'Focused lexical search for {query!r} (not semantic/type-aware):']
    for _, __, rel, lines, entries in found[:max_results]:
        out.append(f'\n### {rel}')
        used = set()
        for _, i in sorted(entries, key=lambda r: r[1]):
            for j in range(max(0, i-1), min(len(lines), i+2)):
                if j not in used:
                    out.append(f'{j+1}: {clip(lines[j], 360)}')
                    used.add(j)
        if sum(map(len, out)) > budget:
            break
    if not found:
        out.append('No matching code found; try an alternative query or full inspection.')
    return scrub(clip('\n'.join(out), budget))


def read_scoped(root: Path, rel: str, start: int = 1, count: int = 120, budget: int = 14000):
    p = safe_path(root, rel)
    lines = read_text(p).splitlines()
    start = max(1, int(start))
    count = max(1, min(300, int(count)))
    end = min(len(lines), start + count - 1)
    body = '\n'.join(f'{i+1}: {lines[i]}' for i in range(start-1, end))
    return scrub(clip(f'{rel} lines {start}-{end} of {len(lines)}:\n{body}', budget))


def context_pack(root: Path, query: str, budget: int = 12000):
    """Single-pass map + focused lexical retrieval to minimize local scanning latency."""
    budget = max(1000, min(150000, int(budget)))
    terms = query_terms(query)
    outline, candidates, seq = [], [], 0
    max_results = 14
    for rel, p in local_files(root):
        try:
            lines = read_text(p).splitlines()
        except (OSError, ValueError):
            continue
        symbols, matches = [], []
        lowrel = rel.lower()
        filename_bonus = sum(4 for t in terms if t in lowrel)
        for i, ln in enumerate(lines):
            if len(symbols) < 8:
                m = SYMBOLS.search(ln)
                if m and (m.group(1) or m.group(2)):
                    symbols.append(f'{i+1}:{m.group(1) or m.group(2)}')
            if terms:
                low = ln.lower()
                hits = sum(1 for t in terms if t in low)
                if hits:
                    score = hits * 3 + (3 if filename_bonus else 0) + (2 if SYMBOLS.search(ln) else 0)
                    matches.append((score, i))
        if symbols or p.name in {'README.md', 'package.json', 'pyproject.toml', 'Cargo.toml', 'go.mod'}:
            outline.append(f'{rel}  ' + ', '.join(symbols))
        if matches:
            matches.sort(key=lambda v: (-v[0], v[1]))
            best = matches[:3]
            score = sum(x[0] for x in best) + filename_bonus
            seq += 1
            item = (score, seq, rel, lines, best)
            if len(candidates) < max_results:
                heapq.heappush(candidates, item)
            elif score > candidates[0][0]:
                heapq.heapreplace(candidates, item)
    candidates.sort(key=lambda x: (-x[0], x[2]))
    outline.sort(key=lambda entry: (-sum(1 for t in terms if t in entry.lower()), entry))
    outline_text = clip('Repository outline (regex-derived; not LSP):\n' + '\n'.join(outline), budget // 4)
    matches_text = [f'Focused lexical matches for {query!r}:']
    for _, __, rel, lines, entries in candidates:
        matches_text.append(f'\n### {rel}')
        used = set()
        for _, i in sorted(entries, key=lambda v: v[1]):
            for j in range(max(0, i-1), min(len(lines), i+2)):
                if j not in used:
                    matches_text.append(f'{j+1}: {clip(lines[j], 360)}')
                    used.add(j)
        if sum(map(len, matches_text)) > budget - len(outline_text) - 200:
            break
    if not candidates:
        matches_text.append('No matching code found; inspect more broadly if needed.')
    # Source-hash-checked facts are optional, explicitly recorded and never authoritative.
    related_facts = []
    if terms:
        try:
            for f in facts_valid(root, limit=16):
                fact_text = (f['fact'] + ' ' + f['source']).lower()
                if any(t in fact_text for t in terms):
                    related_facts.append(f['source'] + ': ' + f['fact'] + ' [source-hash checked]')
                if len(related_facts) >= 2: break
        except (OSError, ValueError):
            pass
    facts_note = ('\nRelevant user-curated facts (verify before acting):\n' + '\n'.join(related_facts) + '\n') if related_facts else ''
    return scrub(clip(f'# Focused offline context\n# Task: {query}\n{facts_note}\n{outline_text}\n\n' + '\n'.join(matches_text), budget))


def batch_inspect(root: Path, operations, budget: int = 16000):
    if not isinstance(operations, list) or not 1 <= len(operations) <= 12:
        raise ValueError('operations must be a list of 1..12 items')
    budget = max(1000, min(150000, int(budget)))
    results = []
    each = max(300, budget // len(operations))
    for op in operations:
        if not isinstance(op, dict):
            results.append({'error': 'operation must be an object'})
            continue
        kind = op.get('op')
        try:
            if kind == 'search':
                value = rg_search(root, str(op.get('query', '')), each)
            elif kind == 'map':
                value = indexed_map(root, each)
            elif kind == 'read':
                value = read_scoped(root, str(op['file']), op.get('start', 1), op.get('count', 100), each)
            elif kind == 'pack':
                value = accelerated_pack(root, str(op.get('query', '')), each)
            elif kind == 'changes':
                value = git_changes(root, each)
            elif kind == 'ast':
                value = python_ast_symbols(root, str(op['file']), str(op.get('symbol', '')), each)
            else:
                raise ValueError('unknown read-only operation')
            results.append({'op': kind, 'result': value})
        except (KeyError, ValueError, OSError) as exc:
            results.append({'op': kind, 'error': str(exc)})
    return scrub(clip(json.dumps(results, ensure_ascii=False, indent=2), budget))


def filter_output(s: str, max_chars: int = 4000, failed: bool = False):
    max_chars = max(200, min(150000, int(max_chars)))
    if len(s) <= max_chars:
        return scrub(s)
    # Never silently compress actual failure evidence. Use 'run' to save full log.
    lines = s.splitlines()
    if failed:
        # Piped errors have no archive path; preserve them verbatim rather than hide data.
        return scrub(s)
    selected = []
    seen = set()
    keys = list(range(min(9, len(lines)))) + [i for i, line in enumerate(lines) if ERROR_LINE.search(line)] + list(range(max(0, len(lines)-18), len(lines)))
    for idx in keys:
        if idx not in seen:
            selected.append((idx, lines[idx]))
            seen.add(idx)
    selected.sort()
    body = '\n'.join(f'L{i+1}: {ln}' for i, ln in selected)
    info = f'[COMPRESSED SUCCESS LOG; {len(lines)} lines -> {len(selected)} retained; sha256={hashlib.sha256(s.encode()).hexdigest()[:16]}]\n'
    return scrub(clip(info + body, max_chars))


def run_local(argv, timeout: int = 300, max_chars: int = 5000):
    if not argv:
        raise ValueError('command required after --')
    # NO shell expansion. This operation is CLI-only, deliberately not exposed via MCP.
    with tempfile.NamedTemporaryFile(prefix='oaek_run_', suffix='.log', delete=False) as tmp:
        logname = tmp.name
        try:
            cp = subprocess.run(argv, stdout=tmp, stderr=subprocess.STDOUT, timeout=timeout, shell=False, check=False)
            status = cp.returncode
        except subprocess.TimeoutExpired:
            status = 124
            tmp.write(b'\n[PROCESS TIMED OUT]\n')
        except OSError as exc:
            status = 127
            tmp.write(f'\n[PROCESS FAILED TO START] {exc}\n'.encode())
    p = Path(logname)
    data = p.read_bytes()
    text = data.decode('utf-8', 'replace')
    if status == 0:
        result = filter_output(text, max_chars=max_chars, failed=False)
        p.unlink(missing_ok=True)
    else:
        # Failure always remains accessible as a local full log. Print tail/head,
        # preserve original exit code and path; do not discard error details.
        # Full failure output is preserved in the private local file noted below.
        failure_lines = text.splitlines()
        key_lines = list(range(min(15, len(failure_lines)))) + [i for i, line in enumerate(failure_lines) if ERROR_LINE.search(line)] + list(range(max(0, len(failure_lines)-45), len(failure_lines)))
        unique = sorted(set(key_lines))
        selected = '\n'.join(f'L{i+1}: {failure_lines[i]}' for i in unique)
        result = clip('[FAILED: representative diagnostics, see full log below]\n' + selected, max_chars)
        result += f'\n[FULL FAILURE LOG: {logname} ; bytes={len(data)} ; sha256={hashlib.sha256(data).hexdigest()}]\n'
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    sys.stdout.write(scrub(result) + ('\n' if not result.endswith('\n') else ''))
    return status


def print_agent_config():
    script_path = Path(__file__).resolve()
    launcher = script_path.parent.parent / 'scripts' / 'agent.py'
    script = str(launcher if launcher.is_file() else script_path)
    exe = str(Path(sys.executable).resolve())
    args = [exe, script, 'mcp', '--root', '/ABSOLUTE/PATH/TO/REPOSITORY']
    print('OpenCode V2 — merge under mcp.servers into existing opencode.jsonc:')
    print(json.dumps({'mcp': {'servers': {'offline_efficiency': {'type': 'local', 'command': args}}}}, indent=2))
    print('\nOpenCode V1 — merge under mcp into existing opencode.json/jsonc:')
    print(json.dumps({'mcp': {'offline_efficiency': {'type': 'local', 'command': args, 'enabled': True}}}, indent=2))
    print('\nCodex — merge into existing ~/.codex/config.toml:')
    print('[mcp_servers.offline_efficiency]')
    print('command = ' + json.dumps(exe))
    print('args = ' + json.dumps(args[1:]))
    print('\nAll require a preinstalled compatible agent and Python 3.9+; set the real repository path.')
    print('Do NOT overwrite existing security policy, MCP servers, or company configuration.')
    print('\nOptional gateway only for an explicitly approved OpenAI-compatible intranet model endpoint:')
    print(f'{json.dumps(exe)} {json.dumps(script)} proxy --upstream http://10.0.0.10:8000 --port 8765 --rpm 12')
    print('Point *all* relevant agent sessions to 127.0.0.1:8765; otherwise RPM is not enforced.')


def install_rules(target: str, scope: str, root: Path, dry_run=False, uninstall=False):
    """Versioned, reversible, additive AGENTS.md integration; never replace other rules."""
    if scope == 'project':
        destinations = [root.resolve() / 'AGENTS.md']
    else:
        destinations = []
        if target in {'codex', 'both'}:
            destinations.append(Path.home() / '.codex' / 'AGENTS.md')
        if target in {'opencode', 'both'}:
            destinations.append(Path.home() / '.config' / 'opencode' / 'AGENTS.md')
    script_path = Path(__file__).resolve()
    launcher = script_path.parent.parent / 'scripts' / 'agent.py'
    toolpath = str(launcher if launcher.is_file() else script_path)
    hint = ('\nOptional local program (Python 3.9+, no internet): '
            f'`python {json.dumps(toolpath)} pack --root . "task keywords"`; '
            'also provides `index`, `search`, `map`, `batch`, `run`, `facts`, and `config`. '
            'Use only when it saves work; never treat its summaries as complete evidence.\n')
    begin = '<!-- OAEK-BEGIN v2 -->'
    end = '<!-- OAEK-END -->'
    newblock = begin + '\n' + RULES + hint + '\n' + end
    oldblock = re.compile(r'<!-- OAEK-BEGIN v(?:1|2) -->.*?<!-- OAEK-END -->', re.S)
    for path in destinations:
        if path.is_symlink():
            raise RuntimeError(f'refusing to update symlink instructions: {path}')
        original = path.read_text('utf-8') if path.exists() else ''
        existing = oldblock.search(original)
        if uninstall:
            if not existing:
                print(f'No toolkit block: {path}')
                continue
            proposed = (original[:existing.start()] + original[existing.end():]).strip() + '\n'
        elif existing:
            proposed = original[:existing.start()] + newblock + original[existing.end():]
        else:
            proposed = original.rstrip() + ('\n\n' if original.strip() else '') + newblock + '\n'
        if proposed == original:
            print(f'Already current: {path}')
            continue
        if dry_run:
            print(f'Would {"remove" if uninstall else "install/upgrade"} toolkit block at {path} '
                  f'(old bytes={len(original.encode())}, new bytes={len(proposed.encode())})')
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            # Refuse clobbering a previously created backup.
            backup = path.with_name(path.name + '.oaek-before.bak')
            n = 1
            while backup.exists():
                backup = path.with_name(path.name + f'.oaek-before-{n}.bak')
                n += 1
            shutil.copy2(path, backup)
            print(f'Backup: {backup}')
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent, delete=False) as f:
            f.write(proposed)
            temp = Path(f.name)
        try:
            if path.exists():
                shutil.copymode(path, temp)
            else:
                os.chmod(temp, 0o600)
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)
        print(f'{"Removed toolkit instructions" if uninstall else "Installed/upgraded toolkit instructions"}: {path}')


MCP_TOOLS = [
    {'name': 'focused_context', 'description': 'Offline read-only focused repository context and symbol outline. Best when task needs multiple code locations; avoids full-file dumps.',
     'inputSchema': {'type': 'object', 'properties': {'query': {'type': 'string'}, 'budget': {'type': 'integer', 'minimum': 1000, 'maximum': 30000}}, 'required': ['query']}},
    {'name': 'batch_inspect', 'description': 'Offline read-only batched repository inspections (search/map/read/pack/changes/ast). No shell or code modification; small bounded output.',
     'inputSchema': {'type': 'object', 'properties': {'operations': {'type': 'array', 'items': {'type': 'object'}, 'minItems': 1, 'maxItems': 12}, 'budget': {'type': 'integer', 'minimum': 1000, 'maximum': 30000}}, 'required': ['operations']}}
]


def mcp_process(request: dict, root: Path):
    reqid = request.get('id')
    method = request.get('method')
    if reqid is None:
        return None
    if method == 'initialize':
        return {'jsonrpc': '2.0', 'id': reqid, 'result': {
            'protocolVersion': '2025-06-18', 'capabilities': {'tools': {'listChanged': False}},
            'serverInfo': {'name': 'offline-agent-efficiency-kit', 'version': VERSION},
            'instructions': 'Read-only offline focused repository inspection. Prefer one focused_context or batch_inspect call over repeated broad reads; verify source before editing.'}}
    if method == 'ping':
        return {'jsonrpc': '2.0', 'id': reqid, 'result': {}}
    if method == 'tools/list':
        return {'jsonrpc': '2.0', 'id': reqid, 'result': {'tools': MCP_TOOLS}}
    if method == 'tools/call':
        params = request.get('params') or {}
        args = params.get('arguments') or {}
        try:
            if params.get('name') == 'focused_context':
                out = accelerated_pack(root, str(args.get('query', '')), int(args.get('budget', 12000)))
            elif params.get('name') == 'batch_inspect':
                out = batch_inspect(root, args.get('operations'), int(args.get('budget', 16000)))
            else:
                raise ValueError('unknown tool')
            result = {'content': [{'type': 'text', 'text': out}], 'isError': False}
        except (ValueError, OSError, TypeError) as exc:
            result = {'content': [{'type': 'text', 'text': str(exc)}], 'isError': True}
        return {'jsonrpc': '2.0', 'id': reqid, 'result': result}
    return {'jsonrpc': '2.0', 'id': reqid, 'error': {'code': -32601, 'message': 'Method not found'}}


def mcp_server(root: Path):
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError('JSON-RPC request must be object')
            response = mcp_process(obj, root)
            if response is not None:
                sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(',', ':')) + '\n')
                sys.stdout.flush()
        except (ValueError, TypeError) as exc:
            sys.stderr.write(f'MCP parse error: {exc}\n')


class SlidingWindowLimiter:
    def __init__(self, rpm=12):
        self.max_calls = int(rpm)
        self.timestamps = collections.deque()
        self.cv = threading.Condition()

    def reserve(self):
        with self.cv:
            while True:
                now = time.monotonic()
                while self.timestamps and now - self.timestamps[0] >= 60.0:
                    self.timestamps.popleft()
                if len(self.timestamps) < self.max_calls:
                    self.timestamps.append(now)
                    return
                self.cv.wait(timeout=max(.01, 60.01 - (now - self.timestamps[0])))

    def snapshot(self):
        with self.cv:
            now = time.monotonic()
            return len([t for t in self.timestamps if now - t < 60])


class ProxyState:
    def __init__(self, upstream: str, rpm: int):
        self.upstream = upstream.rstrip('/')
        self.limiter = SlidingWindowLimiter(rpm)
        self.lock = threading.Lock()
        self.total = 0
        self.errors = 0
        self.usage_input = 0
        self.usage_output = 0
        self.usage_cached_input = 0
        self.streams_without_usage = 0
        self.started = time.time()

    def record(self, status: int, response: bytes = b''):
        try:
            body = json.loads(response) if response else {}
            usage = body.get('usage') or {}
            itok = int(usage.get('prompt_tokens', usage.get('input_tokens', 0)) or 0)
            otok = int(usage.get('completion_tokens', usage.get('output_tokens', 0)) or 0)
            extra = usage.get('prompt_tokens_details') or usage.get('input_tokens_details') or {}
            ctok = int(extra.get('cached_tokens', 0) or 0)
        except (ValueError, TypeError, AttributeError):
            itok = otok = ctok = 0
        with self.lock:
            self.total += 1
            self.errors += int(status >= 400)
            self.usage_input += itok
            self.usage_output += otok
            self.usage_cached_input += ctok

    def stats(self):
        with self.lock:
            return {'requests_routed': self.total, 'errors': self.errors,
                    'input_tokens_reported': self.usage_input,
                    'output_tokens_reported': self.usage_output,
                    'cached_input_tokens_reported': self.usage_cached_input,
                    'streams_without_provider_usage': self.streams_without_usage,
                    'in_flight_window': self.limiter.snapshot(),
                    'uptime_seconds': int(time.time()-self.started),
                    'note': 'Stream usage may not be available; other sessions must route through this same proxy.'}


def assert_private_endpoint(url: str):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('upstream must be an http(s) URL without credentials/query/fragment')
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
    except OSError as exc:
        raise ValueError(f'cannot resolve upstream: {exc}') from exc
    if not addresses or any(not (ipaddress.ip_address(a[4][0]).is_private or ipaddress.ip_address(a[4][0]).is_loopback)
                            for a in addresses):
        raise ValueError('public/nonprivate upstream forbidden; only an approved intranet endpoint is allowed')


def make_handler(state: ProxyState):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'

        def log_message(self, *_):
            # No request paths, prompts or authorization headers in logs.
            pass

        def do_GET(self):
            if self.path not in {'/oaek-health', '/oaek-stats'}:
                # Model-list/discovery GET is not a model-generation request, so
                # forward it without consuming one of the 12 POST RPM slots.
                headers = {k: v for k, v in self.headers.items()
                           if k.lower() not in {'host', 'connection', 'transfer-encoding', 'proxy-connection'}}
                request = urllib.request.Request(state.upstream + self.path, headers=headers, method='GET')
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
                try:
                    response = opener.open(request, timeout=30)
                except urllib.error.HTTPError as exc:
                    response = exc
                except (OSError, urllib.error.URLError):
                    self.send_error(502, 'intranet upstream unavailable')
                    return
                with response:
                    body = response.read()
                    self.send_response(response.status)
                    self.send_header('Content-Type', response.headers.get('Content-Type', 'application/json'))
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                return
            b = json.dumps({'status': 'ok', 'version': VERSION} if self.path == '/oaek-health' else state.stats()).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):
            size = int(self.headers.get('Content-Length', '0') or '0')
            if size <= 0 or size > 10_000_000:
                self.send_error(413, 'request size invalid')
                return
            data = self.rfile.read(size)
            # Do not log/store prompts or credentials.
            state.limiter.reserve()
            url = state.upstream + self.path
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in {'host', 'content-length', 'connection', 'accept-encoding', 'transfer-encoding', 'proxy-connection'}}
            req = urllib.request.Request(url, data=data, headers=headers, method='POST')
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            try:
                response = opener.open(req, timeout=300)
            except urllib.error.HTTPError as exc:
                response = exc
            except (OSError, urllib.error.URLError) as exc:
                b = json.dumps({'error': {'message': f'intranet upstream unavailable: {type(exc).__name__}', 'type': 'proxy_error'}}).encode()
                state.record(502)
                self.send_response(502)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(b)))
                self.end_headers()
                self.wfile.write(b)
                return
            with response:
                status = response.status
                content_type = response.headers.get('Content-Type', 'application/json')
                is_stream = 'text/event-stream' in content_type
                self.send_response(status)
                for k, v in response.headers.items():
                    if k.lower() in {'content-type', 'cache-control', 'retry-after', 'x-request-id'}:
                        self.send_header(k, v)
                self.send_header('Connection', 'close')
                self.end_headers()
                if is_stream:
                    # Pass SSE bytes unchanged while reading optional usage in event payloads.
                    # If upstream does not send usage, leave counts unavailable, not zero-cost.
                    tail = b''
                    latest_usage = None
                    try:
                        while True:
                            chunk = getattr(response, 'read1', response.read)(16384)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            self.wfile.flush()
                            tail += chunk
                            if len(tail) > 262144:
                                tail = tail[-32768:]
                            while b'\n' in tail:
                                raw, tail = tail.split(b'\n', 1)
                                if not raw.lstrip().startswith(b'data:'):
                                    continue
                                try:
                                    item = json.loads(raw.split(b':', 1)[1].strip())
                                    if isinstance(item, dict) and isinstance(item.get('usage'), dict):
                                        latest_usage = item['usage']
                                except (ValueError, UnicodeError):
                                    continue
                    finally:
                        counted = json.dumps({'usage': latest_usage or {}}).encode()
                        state.record(status, counted)
                        if latest_usage is None:
                            with state.lock:
                                state.streams_without_usage += 1
                else:
                    body = response.read()
                    state.record(status, body)
                    self.wfile.write(body)
                self.close_connection = True

    return H


def run_proxy(upstream, port, rpm):
    if not 1 <= int(rpm) <= 120:
        raise ValueError('rpm must be in 1..120')
    assert_private_endpoint(upstream)
    state = ProxyState(upstream, rpm)
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', int(port)), make_handler(state))
    print(f'Offline per-user proxy on 127.0.0.1:{port}; upstream {upstream}; limit {rpm} RPM. Ctrl-C to stop.', file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


def compare_bench(path: Path):
    groups = collections.defaultdict(list)
    for i, line in enumerate(path.read_text('utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            if row['variant'] not in {'baseline', 'optimized'}:
                raise ValueError('variant must be baseline or optimized')
            groups[row['variant']].append(row)
        except (ValueError, KeyError) as exc:
            raise ValueError(f'bad benchmark JSONL row {i}: {exc}') from exc
    def agg(rs):
        if not rs:
            return {'runs': 0}
        passed = [r for r in rs if r.get('verified_pass') is True]
        def total(k, seq):
            return sum(float(r.get(k, 0) or 0) for r in seq)
        return {'runs': len(rs), 'verified_passes': len(passed),
                'verified_pass_rate': round(len(passed)/len(rs), 3),
                'tokens_total': total('input_tokens', rs)+total('output_tokens', rs),
                'requests_total': total('model_requests', rs),
                'elapsed_seconds_total': total('elapsed_seconds', rs),
                'requests_per_verified_pass': round(total('model_requests', rs)/len(passed), 3) if passed else None,
                'tokens_per_verified_pass': round((total('input_tokens', rs)+total('output_tokens', rs))/len(passed), 3) if passed else None}
    base, opt = agg(groups['baseline']), agg(groups['optimized'])
    def change(k):
        a, b = base.get(k), opt.get(k)
        return round((b/a-1)*100, 2) if a and b is not None else None
    result = {'baseline': base, 'optimized': opt,
              'change_percent': {k: change(k) for k in ['requests_per_verified_pass', 'tokens_per_verified_pass', 'verified_pass_rate']},
              'caution': 'Compare matched tasks and repeat runs. Quality, safety, and test coverage must be independently assessed; no causal guarantee.'}
    print(json.dumps(result, indent=2))


def doctor():
    print(json.dumps({'version': VERSION, 'python': sys.version.split()[0],
                      'script': str(Path(__file__).resolve()),
                      'offline_core': True, 'third_party_python_packages_required': False,
                      'tools_found_locally': tool_inventory(),
                      'capabilities': ['instructions', 'lexical_search', 'repository_outline',
                            'batch_inspection', 'local_MCP', 'bounded_logs', 'change_aware_index',
                            'verified_facts', 'python_AST_locations', 'git_change_summary', 'opt_in_proxy', 'matched_task_benchmark', 'offline_selftest'],
                      'limitations': ['Not a bundled LSP/tree-sitter/RTK/Serena binary',
                          'No transparent agent hooks in the Python file',
                          'No cross-session RPM enforcement if requests bypass gateway',
                          'No universal complete secret detection',
                          'Company agent/model compatibility and benchmark not tested']}, indent=2))


def selftest():
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        (root / 'src').mkdir()
        (root / '.env').write_text('PASSWORD=supersecret')
        (root / 'src' / 'agent.py').write_text('def calculate_total(price):\n    return price + 1\n\ndef unused():\n    return 0\n')
        (root / 'src' / 'tests.py').write_text('def test_total():\n    assert calculate_total(1) == 2\n')
        assert 'calculate_total' in focused_search(root, 'calculate_total')
        assert 'calculate_total' in focused_search(root, 'please fix the calculate_total bug')
        assert 'calculate_total' in repo_map(root)
        assert 'calculate_total' in context_pack(root, 'calculate_total')
        assert 'PASSWORD=supersecret' not in context_pack(root, 'supersecret')
        assert 'def calculate_total' in read_scoped(root, 'src/agent.py')
        try:
            read_scoped(root, '../etc/passwd')
            raise AssertionError('path traversal not rejected')
        except ValueError:
            pass
        result = batch_inspect(root, [{'op': 'search', 'query': 'calculate_total'}, {'op': 'read', 'file': 'src/tests.py'}])
        assert 'test_total' in result
        ans = mcp_process({'jsonrpc': '2.0', 'id': 4, 'method': 'tools/list'}, root)
        assert len(ans['result']['tools']) == 2
        ans = mcp_process({'jsonrpc': '2.0', 'id': 5, 'method': 'tools/call',
                           'params': {'name': 'focused_context', 'arguments': {'query': 'calculate_total'}}}, root)
        assert 'calculate_total' in ans['result']['content'][0]['text']
        log = '\n'.join('OK build item %d' % i for i in range(300))
        assert 'COMPRESSED SUCCESS LOG' in filter_output(log, 1000)
        assert filter_output('crash' * 1000, 200, True) == 'crash' * 1000
        assert SlidingWindowLimiter(12).snapshot() == 0
        p = root / 'bench.jsonl'
        p.write_text('\n'.join([json.dumps({'variant': 'baseline', 'verified_pass': True, 'model_requests': 12, 'input_tokens': 10000, 'output_tokens': 2000}),
                               json.dumps({'variant': 'optimized', 'verified_pass': True, 'model_requests': 6, 'input_tokens': 5500, 'output_tokens': 1500})]))
        # Synthetic benchmark fixture checks parsing only; it is NOT a saving estimate.
        import contextlib
        import io
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink):
            compare_bench(p)
        assert 'change_percent' in sink.getvalue()
    assert 'PASS' in offline_audit(root)
    print('SELFTEST PASS: offline repository search, bounded context, traversal defense, MCP, filtering, rate limiter, benchmark')


# --- Offline v2 extensions (standard library only) ---
import sqlite3
import statistics

# Security is defense-in-depth, not a proof that arbitrary source files contain no secrets.
SECRET_ASSIGN = re.compile(
    r'(?i)(\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|'
    r'private[_-]?key|password|passwd|authorization|x-api-key)\b\s*[:=]\s*)'
    r'(["\'])([^"\'\r\n]{4,})(\2)')
SECRET_BEARER = re.compile(r'(?i)(\bBearer\s+)[A-Za-z0-9_.\-/+=]{12,}')
SECRET_KEY = re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bsk-[A-Za-z0-9_-]{16,}\b')
PRIVATE_BEGIN = re.compile(r'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----')
_IGNORE_CACHE = {}


def scrub(value: str) -> str:
    """Redact recognizable credentials in model-facing text (not comprehensive DLP)."""
    value = SECRET_ASSIGN.sub(lambda m: m.group(1) + m.group(2) + '[REDACTED]' + m.group(4), value)
    value = SECRET_BEARER.sub(r'\1[REDACTED]', value)
    value = SECRET_KEY.sub('[REDACTED-KEY]', value)
    if PRIVATE_BEGIN.search(value):
        value = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----',
                       '[REDACTED PRIVATE KEY BLOCK]', value, flags=re.S)
    return value


def _ignore_patterns(path: Path):
    try:
        stamp = (path.stat().st_mtime_ns, path.stat().st_size)
    except OSError:
        return ()
    cached = _IGNORE_CACHE.get(str(path))
    if cached and cached[0] == stamp:
        return cached[1]
    lines = []
    if stamp[1] <= 150_000:
        for line in path.read_text('utf-8', errors='replace').splitlines():
            rule = line.strip()
            if not rule or rule.startswith('#') or rule.startswith('!'):
                continue  # Conservative: do not re-include previously ignored files.
            lines.append(rule)
    _IGNORE_CACHE[str(path)] = (stamp, tuple(lines))
    return tuple(lines)


def is_ignored(root: Path, rel: str):
    """Conservative .gitignore subset; does not reinclude ! rules (fail-closed)."""
    parts = rel.strip('/').split('/')
    if not parts or parts == ['']:
        return False
    for depth in range(len(parts)):
        prefix = parts[:depth]
        nested = Path(root, *prefix) / '.gitignore'
        childparts = parts[depth:]
        child = '/'.join(childparts)
        for raw in _ignore_patterns(nested):
            rule = raw.replace('\\', '/')
            isdir = rule.endswith('/')
            rule = rule.strip('/')
            if not rule:
                continue
            # Anchored paths and patterns with '/' are relative to this gitignore.
            if '/' in rule or raw.startswith('/'):
                matched = fnmatch.fnmatchcase(child, rule) or child.startswith(rule + '/')
            else:
                matched = any(fnmatch.fnmatchcase(x, rule) for x in childparts)
            if matched and (not isdir or len(childparts) > 1 or rel.endswith('/')):
                return True
    return False


def tool_inventory():
    names = {
        'rg': 'ripgrep (fast ignore-aware lexical search)',
        'ast-grep': 'ast-grep (syntax-aware structural search)',
        'ctags': 'Universal Ctags (polyglot symbol navigation)',
        'rtk': 'RTK (native tool-output proxy; use approved integration)',
        'sqz': 'sqz (local tool-result compression and deduplication)',
        'context-mode': 'Context Mode (tool output sandbox and SQLite memory)',
        'headroom': 'Headroom (context compression/proxy)',
        'lazy-tool': 'lazy-tool (local MCP discovery proxy)',
        'xerj': 'XERJ (local code/docs retrieval engine)',
        'git': 'Git (local repository status/history)',
        'clangd': 'clangd (C/C++ LSP)',
        'gopls': 'gopls (Go LSP)',
        'rust-analyzer': 'rust-analyzer (Rust LSP)',
        'pyright-langserver': 'Pyright (Python LSP)',
        'basedpyright-langserver': 'basedpyright (Python LSP)',
        'typescript-language-server': 'TypeScript LSP',
        'jdtls': 'Eclipse JDT Language Server',
    }
    return [{'tool': name, 'installed': bool(shutil.which(name)), 'path': shutil.which(name),
             'purpose': purpose} for name, purpose in names.items()]


OFFLINE_CANDIDATES = [
 {'name': 'ripgrep', 'source': 'https://github.com/BurntSushi/ripgrep',
  'offline': 'yes, with matching locally installed binary', 'benefit': 'fast scoped search; .gitignore semantics',
  'bundled': False},
 {'name': 'ast-grep', 'source': 'https://github.com/ast-grep/ast-grep',
  'offline': 'yes, if executable and parsers are bundled', 'benefit': 'AST structural code search',
  'bundled': False},
 {'name': 'Universal Ctags', 'source': 'https://github.com/universal-ctags/ctags',
  'offline': 'yes, when compiled for workstation', 'benefit': 'symbol catalog across languages',
  'bundled': False},
 {'name': 'Serena', 'source': 'https://github.com/oraios/serena',
  'offline': 'conditional: prepare Python env, language servers and related assets offline',
  'benefit': 'LSP symbol references/navigation MCP', 'bundled': False, 'license_note': 'GPL-3.0-or-later application; evaluate compliance'},
 {'name': 'RTK', 'source': 'https://github.com/rtk-ai/rtk',
  'offline': 'yes, compiled native binary and matching agent integration bundled',
  'benefit': 'compress CLI output with hooks', 'bundled': False, 'license_note': 'RTK editions differ: Apache-2.0 / BUSL-1.1 components'},
 {'name': 'TokenEconomizer', 'source': 'https://github.com/microsoft/TokenEconomizer',
  'offline': 'conditional: agent hooks installed; model-driven features use approved intranet model',
  'benefit': 'repository facts, tool pruning, failure-loop detection', 'bundled': False, 'license_note': 'Apache-2.0 (review all bundled components)'},
 {'name': 'Aider RepoMap', 'source': 'https://aider.chat/docs/repomap.html',
  'offline': 'conditional: local tree-sitter and Python dependencies prepared',
  'benefit': 'dependency-ranked symbol context', 'bundled': False},
 {'name': 'Repomix', 'source': 'https://github.com/yamadashy/repomix',
  'offline': 'conditional: Node dependencies prepared and patched version security-reviewed',
  'benefit': 'repository packaging', 'bundled': False, 'security_note': 'Review 2026 GitHub security advisories; do not use unpatched versions'},
 {'name': 'fd', 'source': 'https://github.com/sharkdp/fd',
  'offline': 'yes, matching native binary', 'benefit': 'fast file discovery', 'bundled': False},
 {'name': 'git', 'source': 'https://git-scm.com/', 'offline': 'yes, already installed and local only',
  'benefit': 'diff-first investigation', 'bundled': False},
 {'name': 'clangd/gopls/rust-analyzer/Pyright', 'source': 'https://microsoft.github.io/language-server-protocol/',
  'offline': 'conditional: matching complete local language-server installation',
  'benefit': 'precise semantic/navigation operations', 'bundled': False},
 {'name': 'sqz', 'source': 'https://github.com/ojuschugh1/sqz',
  'offline': 'yes, if a correct prebuilt Rust CLI/MCP binary and required hooks are staged',
  'benefit': 'loss-aware tool output deduplication/compression with local restoration',
  'bundled': False, 'license_note': 'Current repository MIT OR Apache-2.0; older releases ELv2'},
 {'name': 'Context Mode', 'source': 'https://github.com/mksglu/context-mode',
  'offline': 'conditional: Node >=22.5 or Bun plus complete locally installed package/native assets',
  'benefit': 'tool-result sandbox, local SQLite FTS, session memory and agent hooks',
  'bundled': False},
 {'name': 'Headroom', 'source': 'https://github.com/headroomlabs-ai/headroom',
  'offline': 'conditional: local Python environment plus optional models/assets as relevant',
  'benefit': 'context compression for tool output and JSON; local proxy/MCP',
  'bundled': False, 'license_note': 'Apache-2.0 project; verify component dependencies'},
 {'name': 'lazy-tool', 'source': 'https://github.com/mcp-shark/lazy-tool',
  'offline': 'yes, locally compiled matching Go binary and configured local MCP sources',
  'benefit': 'on-demand MCP tool discovery, schema deferral, local SQLite catalog',
  'bundled': False, 'license_note': 'MIT; vendor-reported small benchmark needs local verification'},
 {'name': 'XERJ', 'source': 'https://github.com/xerj-org/xerj',
  'offline': 'conditional: check local-only mode and all index/model assets; disable remote corpus downloads',
  'benefit': 'local BM25/hybrid retrieval over code/docs/logs', 'bundled': False},
 {'name': 'OpenCode V2 Code Mode', 'source': 'https://opencode.ai/v2/docs/tools',
  'offline': 'built into approved OpenCode V2 runtime if enabled and configured',
  'benefit': 'programmatic tool orchestration without exposing every intermediate result',
  'bundled': False},
 {'name': 'OpenCode V2 Compaction', 'source': 'https://opencode.ai/v2/docs/compaction',
  'offline': 'conditional: local/intranet model configured for summaries; native provider support varies',
  'benefit': 'adaptive long-session context shortening', 'bundled': False},
 {'name': 'This single-file toolkit', 'source': 'embedded', 'offline': 'yes, tested core with Python 3.9+',
  'benefit': 'safe context, batch MCP, output filtering, facts, measurements', 'bundled': True},
]


def _cache_dir(root: Path):
    digest = hashlib.sha256(str(root.resolve()).encode('utf-8')).hexdigest()[:24]
    base = Path(os.environ.get('OAEK_CACHE_DIR', str(Path.home() / '.cache' / 'oaek'))).expanduser()
    location = base / digest
    location.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != 'nt':
        os.chmod(location, 0o700)
    return location


def filehash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def index_db(root: Path):
    loc = _cache_dir(root) / 'index.sqlite3'
    db = sqlite3.connect(str(loc), timeout=15)
    db.execute('CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, size INTEGER, mtime_ns INTEGER, sha TEXT, symbols TEXT)')
    db.execute('CREATE INDEX IF NOT EXISTS files_mtime ON files(mtime_ns)')
    if os.name != 'nt':
        os.chmod(loc, 0o600)
    return db


def index_refresh(root: Path):
    """Index only hashes and regex-derived symbols; never store full source or embeddings."""
    started = time.monotonic()
    updated, unchanged, paths = 0, 0, set()
    with index_db(root) as db:
        existing = {r[0]: (r[1], r[2]) for r in db.execute('SELECT path,size,mtime_ns FROM files')}
        for rel, path in local_files(root):
            paths.add(rel)
            st = path.stat()
            if existing.get(rel) == (st.st_size, st.st_mtime_ns):
                unchanged += 1
                continue
            try:
                src = read_text(path)
                items = []
                if path.suffix.lower() == '.py':
                    try:
                        import ast
                        tree = ast.parse(src)
                        for node in ast.walk(tree):
                            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                                items.append(f'{node.lineno}:{node.name}')
                                if len(items) >= 30: break
                    except SyntaxError:
                        pass
                if not items:
                    for line_no, line in enumerate(src.splitlines(), 1):
                        m = SYMBOLS.search(line)
                        if m:
                            items.append(f'{line_no}:{m.group(1) or m.group(2)}')
                            if len(items) >= 30: break
                db.execute('INSERT OR REPLACE INTO files VALUES (?,?,?,?,?)',
                           (rel, st.st_size, st.st_mtime_ns, filehash(path), json.dumps(items)))
                updated += 1
            except (OSError, ValueError):
                continue
        removed = 0
        for rel in existing.keys() - paths:
            db.execute('DELETE FROM files WHERE path=?', (rel,))
            removed += 1
    return {'updated': updated, 'unchanged': unchanged, 'removed': removed,
            'total': len(paths), 'elapsed_seconds': round(time.monotonic()-started, 3),
            'note': 'Incremental metadata/symbol index; no source text stored; timestamps determine refresh.'}


def indexed_map(root: Path, budget: int = 9000):
    loc = _cache_dir(root) / 'index.sqlite3'
    if not loc.exists():
        return repo_map(root, budget)
    with index_db(root) as db:
        rows = db.execute('SELECT path, size, mtime_ns, symbols FROM files ORDER BY path').fetchall()
    if not rows:
        return repo_map(root, budget)
    # Never silently use stale index; refreshing only parses changed entries.
    lookup = {r[0]: r for r in rows}
    current = {rel: p.stat() for rel, p in local_files(root)}
    if set(current) != set(lookup) or any(
        current[k].st_size != lookup[k][1] or current[k].st_mtime_ns != lookup[k][2]
        for k in current):
        index_refresh(root)
        with index_db(root) as db:
            rows = db.execute('SELECT path,size,mtime_ns,symbols FROM files ORDER BY path').fetchall()
    outline = []
    for rel, size, mtime_ns, symbols in rows:
        try:
            symbol_list = json.loads(symbols)
        except (ValueError, TypeError):
            symbol_list = []
        if symbol_list or rel in {'README.md', 'pyproject.toml', 'package.json'}:
            outline.append(rel + '  ' + ', '.join(symbol_list[:8]))
    return scrub(clip('Cached repository symbol outline (Python AST / regex, not type-aware):\n' + '\n'.join(outline), budget))




def rg_executable():
    """Allow opt-in, preflight-validated local rg, never download it at runtime."""
    explicit = os.environ.get('OAEK_RG_PATH')
    if explicit:
        p = Path(explicit)
        return str(p) if p.is_file() and os.access(p, os.X_OK) else None
    return shutil.which('rg')


def git_changes(root: Path, budget: int = 5000):
    """Read-only, filename-only change summary. Does not print code diffs or secrets."""
    git = shutil.which('git')
    if not git:
        return 'Git unavailable: use focused repository inspection.'
    try:
        cp = subprocess.run([git, '-C', str(root), 'status', '--porcelain=v1', '-z', '--untracked-files=normal'],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=8, check=False,
                            env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0'})
    except (OSError, subprocess.TimeoutExpired):
        return 'Unable to inspect local Git status.'
    if cp.returncode != 0:
        return 'Git working tree unavailable; no claim made about changes.'
    entries = cp.stdout.decode('utf-8', errors='replace').split('\0')
    result = []
    for entry in entries:
        if not entry or len(entry) < 4:
            continue
        status = entry[:2]
        candidate = entry[3:]
        if candidate and is_safe_name(candidate) and not is_ignored(root, candidate):
            result.append(f'{status} {candidate}')
    return scrub(clip('Local Git changes (source-eligible paths only; no file contents):\n' +
                      ('\n'.join(result) if result else 'No eligible changes found.'), budget))


def python_ast_symbols(root: Path, rel: str, symbol: str = '', budget: int = 6000):
    """Precise Python AST locations, never described as type-aware navigation."""
    if Path(rel).suffix.lower() != '.py':
        raise ValueError('Python AST inspection accepts .py files only')
    import ast
    path = safe_path(root, rel)
    src = read_text(path)
    try:
        tree = ast.parse(src, filename=rel)
    except SyntaxError as exc:
        return f'Python parse error: {exc}; use scoped text read.'
    defs = []
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if symbol and node.name != symbol:
                continue
            kind = type(node).__name__
            defs.append(f'{kind} {node.name} at {getattr(node,"lineno",0)}-{getattr(node,"end_lineno",getattr(node,"lineno",0))}')
        if symbol and isinstance(node, ast.Call):
            f = node.func
            if (isinstance(f, ast.Name) and f.id == symbol) or (isinstance(f, ast.Attribute) and f.attr == symbol):
                calls.append(f'possible invocation at {node.lineno} (not resolved/type-aware)')
    header = f'Python AST structure: {rel} (AST locations, not LSP)\n'
    return scrub(clip(header + '\n'.join(defs[:100]) + ('\n' + '\n'.join(calls[:50]) if calls else ''), budget))


def rg_search(root: Path, query: str, budget: int = 10000, max_results: int = 14):
    """Optional local `rg` accelerator; no shell, no runtime package installation."""
    exe = rg_executable()
    if not exe:
        return focused_search(root, query, budget, max_results)
    terms = query_terms(query)
    if not terms:
        return 'No searchable query terms.'
    # Use the repo's ignore rules; only emit explicitly safe source-file matches.
    command = [exe, '--no-config', '--json', '--fixed-strings', '--ignore-case',
               '--max-count', '4', '--max-filesize', '512K', '--no-messages']
    for term in terms[:8]:
        command.extend(['-e', term])
    command.append('.')
    env = dict(os.environ)
    env['RIPGREP_CONFIG_PATH'] = os.devnull
    try:
        cp = subprocess.run(command, cwd=str(root), env=env, capture_output=True,
                            shell=False, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return focused_search(root, query, budget, max_results)
    if cp.returncode not in (0, 1):
        return focused_search(root, query, budget, max_results)
    # Bounded parsing: excessive results may require narrowing, not a giant model dump.
    if len(cp.stdout) > 12_000_000:
        return focused_search(root, query, budget, max_results)
    records = collections.defaultdict(list)
    for line in cp.stdout.splitlines():
        try:
            obj = json.loads(line)
            if obj.get('type') != 'match': continue
            d = obj['data']
            rel = str(d['path'].get('text', '')).lstrip('./').replace('\\', '/')
            if not is_safe_name(rel) or is_ignored(root, rel): continue
            path = safe_path(root, rel)
            # Never trust a malformed or unapproved search path from a binary.
            line_no = int(d['line_number'])
            txt = d['lines'].get('text', '').rstrip('\n\r')
            records[rel].append((line_no, txt))
        except (ValueError, TypeError, KeyError, OSError):
            continue
    weighted = []
    for rel, rows in records.items():
        score = sum(4 for x in terms if x in rel.lower()) + sum(
            sum(1 for x in terms if x in txt.lower()) for _,txt in rows)
        weighted.append((score, rel, rows[:4]))
    weighted.sort(key=lambda x: (-x[0], x[1]))
    out = ['Offline ripgrep results for ' + repr(query) + ' (lexical, not semantic):']
    for _, rel, rows in weighted[:max_results]:
        out.append('\n### ' + rel)
        out.extend(f'{n}: {clip(txt, 360)}' for n, txt in rows)
        if sum(len(x) for x in out) >= budget: break
    if not weighted:
        out.append('No matching source; broaden scope if appropriate.')
    return scrub(clip('\n'.join(out), budget))


def accelerated_pack(root: Path, query: str, budget: int = 12000):
    """Opt-in ripgrep-backed pack; fast, lexical, not complete semantic evidence."""
    if not rg_executable():
        return context_pack(root, query, budget)
    budget = max(1000, min(150000, int(budget)))
    outline = indexed_map(root, max(350, budget // 4))
    matches = rg_search(root, query, max(600, budget - len(outline) - 300))
    if 'No matching source' in matches:
        return context_pack(root, query, budget)
    related = []
    terms = query_terms(query)
    for item in facts_valid(root, 16):
        if any(t in (item['fact'] + ' ' + item['source']).lower() for t in terms):
            related.append(item['source'] + ': ' + item['fact'] + ' [source-hash checked]')
        if len(related) >= 2: break
    fact_note = ('User-curated verified facts (verify before acting):\n' + '\n'.join(related) + '\n') if related else ''
    return scrub(clip('Offline accelerated context (rg lexical, broaden search for completeness):\n'
           + fact_note + outline + '\n' + matches, budget))


def _facts_file(root: Path):
    return _cache_dir(root) / 'verified_facts.json'


def facts_load(root: Path):
    path = _facts_file(root)
    if not path.exists():
        return []
    try:
        content = json.loads(path.read_text('utf-8'))
    except (ValueError, OSError):
        return []
    return content if isinstance(content, list) else []


def facts_valid(root: Path, limit: int = 3):
    valid = []
    for fact in facts_load(root):
        try:
            p = safe_path(root, fact['file'])
            if filehash(p) == fact['sha256']:
                valid.append({'fact': fact['fact'], 'source': fact['file'],
                              'evidence': fact['evidence'], 'verified_against_source': True})
        except (ValueError, KeyError, OSError, TypeError):
            continue
    return valid[:limit]


def facts_add(root: Path, rel: str, fact: str, evidence: str):
    if not isinstance(fact, str) or not (8 <= len(fact) <= 250):
        raise ValueError('fact must be 8..250 characters')
    if not isinstance(evidence, str) or not (3 <= len(evidence) <= 120):
        raise ValueError('evidence must be 3..120 characters')
    if scrub(fact) != fact or scrub(evidence) != evidence:
        raise ValueError('fact/evidence looks like it contains a credential')
    p = safe_path(root, rel)
    factrow = {'file': rel, 'sha256': filehash(p), 'fact': fact, 'evidence': evidence}
    rows = [r for r in facts_load(root) if r.get('file') != rel or r.get('fact') != fact]
    rows.append(factrow)
    path = _facts_file(root)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent, delete=False) as f:
        json.dump(rows[-100:], f, indent=2, ensure_ascii=False)
        temp = Path(f.name)
    if os.name != 'nt': os.chmod(temp, 0o600)
    os.replace(temp, path)
    return {'status': 'recorded; provenance source hash attached; invalidate on source change',
            'source': rel, 'facts_total': len(rows[-100:])}


def offline_audit(root: Path):
    """Exercise core inspect operations with sockets blocked, proving no required network."""
    import unittest.mock
    with tempfile.TemporaryDirectory() as tmp:
        prior_cache = os.environ.get('OAEK_CACHE_DIR')
        os.environ['OAEK_CACHE_DIR'] = str(Path(tmp) / 'cache')
        r = Path(tmp) / 'repo'
        (r / 'src').mkdir(parents=True)
        (r / 'src' / 'example.py').write_text('def add(a, b):\n    return a+b\n')
        (r / '.env').write_text('MY_SECRET=should_not_leak')
        (r / '.gitignore').write_text('ignored.txt\n')
        (r / 'ignored.txt').write_text('PRIVATE=ignored_data')
        with unittest.mock.patch.object(socket.socket, 'connect', side_effect=AssertionError('unexpected outbound connection')):
            assert 'def add' in context_pack(r, 'add')
            assert 'add' in indexed_map(r)
            assert index_refresh(r)['updated'] == 1
            assert index_refresh(r)['updated'] == 0
            assert '### ignored.txt' not in focused_search(r, 'ignored_data')
            assert 'should_not_leak' not in context_pack(r, 'secret')
            assert len(facts_valid(r)) == 0
            facts_add(r, 'src/example.py', 'This file defines a basic addition function.', 'reviewed source')
            assert len(facts_valid(r)) == 1
            (r / 'src' / 'example.py').write_text('def add(a, b):\n    return a-b\n')
            assert len(facts_valid(r)) == 0
    if prior_cache is None:
        os.environ.pop('OAEK_CACHE_DIR', None)
    else:
        os.environ['OAEK_CACHE_DIR'] = prior_cache
    return 'OFFLINE AUDIT PASS: sockets blocked; core inspection/index and fact invalidation succeed'


def matched_benchmark(path: Path):
    bytask = collections.defaultdict(lambda: collections.defaultdict(list))
    for i, line in enumerate(path.read_text('utf-8').splitlines(), 1):
        if not line.strip(): continue
        row = json.loads(line)
        if row.get('variant') not in {'baseline', 'optimized'}:
            raise ValueError(f'row {i}: variant must be baseline/optimized')
        task = str(row.get('task_id') or '')
        if not task:
            raise ValueError(f'row {i}: task_id is required; cannot claim matched evidence otherwise')
        if not isinstance(row.get('verified_pass'), bool):
            raise ValueError(f'row {i}: verified_pass must be boolean')
        for metric in ('input_tokens', 'output_tokens', 'model_requests', 'elapsed_seconds'):
            if metric not in row or not isinstance(row[metric], (int, float)) or row[metric] < 0:
                raise ValueError(f'row {i}: missing/invalid {metric}')
        bytask[task][row['variant']].append(row)
    pairs = {k: v for k,v in bytask.items() if v.get('baseline') and v.get('optimized')}
    if not pairs:
        raise ValueError('No paired baseline and optimized tasks; require matching task_id')
    outcome = {'matched_tasks': len(pairs), 'unmatched_excluded': len(bytask)-len(pairs),
               'metrics': {}, 'comparison_is_observational': True}
    for metric in ('input_tokens', 'output_tokens', 'model_requests', 'elapsed_seconds'):
        b = [statistics.median(r[metric] for r in groups['baseline']) for groups in pairs.values()]
        o = [statistics.median(r[metric] for r in groups['optimized']) for groups in pairs.values()]
        bsum, osum = sum(b), sum(o)
        outcome['metrics'][metric] = {
            'baseline_paired_sum': round(bsum, 3), 'optimized_paired_sum': round(osum, 3),
            'change_pct': round((osum/bsum-1)*100, 2) if bsum else None}
    rates = {}
    for variant in ('baseline','optimized'):
        arr = [r['verified_pass'] for groups in pairs.values() for r in groups[variant]]
        rates[variant] = {'passed': sum(arr), 'runs': len(arr), 'rate': round(sum(arr)/len(arr), 4)}
    outcome['verified_success'] = rates
    outcome['interpretation'] = ('Matched tasks, median within task. Assess quality/security tests, '
       'variance and statistical power; no improvement guaranteed and no live company benchmark performed.')
    return outcome




GUIDE = """OFFLINE AGENT EFFICIENCY KIT v2 — OPERATOR GUIDE

Prerequisite: approved Python 3.9+ runtime and an existing OpenCode or Codex
installation with access to the company-approved intranet model (not public web).
The core requires NO pip/npm downloads, cloud APIs, external binaries, or internet.

1. Offline smoke test:
   python agent_efficiency_offline.py selftest
   python agent_efficiency_offline.py offline-audit
   python agent_efficiency_offline.py doctor

2. Install compact additive guidance (requires authorization to edit AGENTS.md):
   python agent_efficiency_offline.py install --scope project --root . --dry-run
   python agent_efficiency_offline.py install --scope project --root .
   # Restore toolkit rule block only, preserving other project rules:
   python agent_efficiency_offline.py install --scope project --root . --uninstall

3. Prefer existing native tools. Optional compact local MCP (read-only):
   python agent_efficiency_offline.py config
   # Follow the OpenCode V1 or V2 syntax or Codex TOML example; do not overwrite.

4. Offline repository investigation:
   python agent_efficiency_offline.py pack --root . "task identifier"
   python agent_efficiency_offline.py search --root . "task identifier"
   python agent_efficiency_offline.py pack --engine rg --root . "task identifier"
   python agent_efficiency_offline.py search --engine rg --root . "task identifier"
   # rg requires approved local binary; no automatic download.
   python agent_efficiency_offline.py index --root .
   python agent_efficiency_offline.py map --root .

5. Execute approved deterministic checks, retaining exit codes and failure log:
   python agent_efficiency_offline.py run -- python -m pytest -q

6. Optional explicit source-hash checked facts; no AI calls to create them:
   python agent_efficiency_offline.py facts show --root .
   python agent_efficiency_offline.py facts add --root . --file src/app.py --fact "Verified local architecture fact" --evidence "reviewed code and tests"

7. Measure verified real work, not invented percentages:
   python agent_efficiency_offline.py bench tasks.jsonl
   # Each JSONL run: task_id, variant (baseline/optimized), verified_pass (boolean),
   # input_tokens, output_tokens, model_requests, elapsed_seconds.

8. Optional model request proxy: only use after company approval. Supports an
   OpenAI-compatible endpoint at private/loopback host. All model traffic must
   route through the same per-user process to enforce a shared 12 RPM window.
   No public upstream override exists. Model/provider differences may prevent use.

   python agent_efficiency_offline.py proxy --upstream http://10.0.0.10:8000 --rpm 12

Available offline tools report:
   python agent_efficiency_offline.py inventory
   python agent_efficiency_offline.py research

LIMITS: Not an actual RTK/Serena/TokenEconomizer installation. No native automatic
command hooks; no true LSP cross-language semantics without optional installed
language servers; no guarantee of savings or quality without company benchmarks;
credential redaction is best-effort, not a comprehensive secret scanner.
"""


def main():
    parser = argparse.ArgumentParser(description='One-file offline-first real-tool efficiency kit for OpenCode/Codex; Python 3.9+ only.')
    sub = parser.add_subparsers(dest='cmd', required=True)
    sub.add_parser('doctor', help='show capabilities and limitations')
    sub.add_parser('guide', help='print offline install and operating guide')
    sub.add_parser('selftest', help='run offline built-in tests')
    sub.add_parser('offline-audit', help='prove network-free inspection with blocked sockets')
    sub.add_parser('inventory', help='list available preinstalled offline-native tools')
    sub.add_parser('research', help='show offline integration catalog, without bundled binaries')
    sub.add_parser('config', help='print optional MCP and proxy integration config')
    p = sub.add_parser('rules', help='print self-contained AGENTS.md text')
    p = sub.add_parser('install', help='add rules without replacing existing AGENTS.md; backup on modification')
    p.add_argument('--target', choices=['codex', 'opencode', 'both'], default='both')
    p.add_argument('--scope', choices=['user', 'project'], default='project')
    p.add_argument('--root', default='.')
    p.add_argument('--dry-run', action='store_true', help='print proposed change without writing')
    p.add_argument('--uninstall', action='store_true', help='remove only the toolkit block; backup original')
    for name in ['map', 'search', 'pack', 'read', 'batch', 'mcp', 'changes', 'ast']:
        p = sub.add_parser(name)
        p.add_argument('--root', default='.')
        if name in ['search', 'pack']:
            p.add_argument('query')
        if name in {'search', 'pack'}:
            p.add_argument('--engine', choices=['builtin', 'rg'], default='builtin', help='opt-in approved preinstalled ripgrep binary')
        if name in {'read', 'ast'}:
            p.add_argument('file')
            p.add_argument('--start', type=int, default=1)
            p.add_argument('--count', type=int, default=120)
        if name == 'ast':
            p.add_argument('--symbol', default='')
        if name != 'mcp':
            p.add_argument('--budget', type=int, default=12000)
        if name == 'batch':
            p.add_argument('--json', help='JSON list of read-only operations; else read stdin')
    p = sub.add_parser('filter', help='filter successful tool output from stdin without hiding error evidence')
    p.add_argument('--max-chars', type=int, default=4000)
    p.add_argument('--failed', action='store_true')
    p = sub.add_parser('run', help='execute trusted local process, compress success logs, keep full failure logs')
    p.add_argument('--timeout', type=int, default=300)
    p.add_argument('--max-chars', type=int, default=5000)
    p.add_argument('command', nargs=argparse.REMAINDER)
    p = sub.add_parser('proxy', help='opt-in per-user local rate-limiting HTTP gateway for approved intranet model')
    p.add_argument('--upstream', required=True)
    p.add_argument('--port', type=int, default=8765)
    p.add_argument('--rpm', type=int, default=12)
    p = sub.add_parser('index', help='refresh persistent local symbol metadata (no source text persisted)')
    p.add_argument('--root', default='.')
    p = sub.add_parser('facts', help='source-hash-backed local repository knowledge; explicit add only')
    p.add_argument('--root', default='.')
    p.add_argument('action', choices=['show', 'add'])
    p.add_argument('--file')
    p.add_argument('--fact')
    p.add_argument('--evidence')
    p = sub.add_parser('bench', help='matched task JSONL A/B comparison with required task_id')
    p.add_argument('jsonl')
    args = parser.parse_args()
    root = Path(getattr(args, 'root', '.')).resolve()
    try:
        if args.cmd == 'doctor': doctor()
        elif args.cmd == 'guide': print(GUIDE)
        elif args.cmd == 'offline-audit': print(offline_audit(root))
        elif args.cmd == 'inventory': print(json.dumps(tool_inventory(), indent=2))
        elif args.cmd == 'research': print(json.dumps(OFFLINE_CANDIDATES, indent=2))
        elif args.cmd == 'index': print(json.dumps(index_refresh(root), indent=2))
        elif args.cmd == 'facts':
            if args.action == 'show': print(json.dumps(facts_valid(root), indent=2))
            else: print(json.dumps(facts_add(root, args.file, args.fact, args.evidence), indent=2))
        elif args.cmd == 'selftest': selftest()
        elif args.cmd == 'config': print_agent_config()
        elif args.cmd == 'rules': print(RULES)
        elif args.cmd == 'install': install_rules(args.target, args.scope, root, args.dry_run, args.uninstall)
        elif args.cmd == 'map': print(indexed_map(root, args.budget))
        elif args.cmd == 'changes': print(git_changes(root, args.budget))
        elif args.cmd == 'ast': print(python_ast_symbols(root, args.file, args.symbol, args.budget))
        elif args.cmd == 'search': print(rg_search(root, args.query, args.budget) if args.engine == 'rg' else focused_search(root, args.query, args.budget))
        elif args.cmd == 'pack': print(accelerated_pack(root, args.query, args.budget) if args.engine == 'rg' else context_pack(root, args.query, args.budget))
        elif args.cmd == 'read': print(read_scoped(root, args.file, args.start, args.count, args.budget))
        elif args.cmd == 'batch':
            ops = json.loads(args.json if args.json else sys.stdin.read())
            print(batch_inspect(root, ops, args.budget))
        elif args.cmd == 'mcp': mcp_server(root)
        elif args.cmd == 'filter': print(filter_output(sys.stdin.read(), args.max_chars, args.failed))
        elif args.cmd == 'run':
            a = args.command
            if a and a[0] == '--': a = a[1:]
            sys.exit(run_local(a, args.timeout, args.max_chars))
        elif args.cmd == 'proxy': run_proxy(args.upstream, args.port, args.rpm)
        elif args.cmd == 'bench': print(json.dumps(matched_benchmark(Path(args.jsonl)), indent=2))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f'OAEK error: {exc}', file=sys.stderr)
        sys.exit(2)

if __name__ == '__main__':
    main()
