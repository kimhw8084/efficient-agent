# Efficient Agent

Offline-first tools for focused context, repository navigation, and efficient agent workflows.

**Version:** 2.1. **Deployment mode:** offline / company intranet. **Contents:** portable Python tools, optional Linux ripgrep, local MCP entrypoints, reversible agent instructions, and evidence checks.

## First: what is and isn't guaranteed

- **Confirmed in isolated local tests:** the Python standard-library core works without external network; MCP read-only inspection, bounded context, batch inspection, incremental indexing, Python AST navigation, output compression, CLI launcher, and source-boundary checks pass. Bundled `rg` executes in the build environment only, and is optional.
- **Not guaranteed:** a percentage reduction in model tokens, requests, cost, or wall-clock time; no regression in every task; platform compatibility for unknown machines; support for unknown company model gateways. A tool can add overhead. **Measure requests/tokens per verified successful task against a real baseline.**
- **Not included:** full Serena, RTK, ast-grep, TokenEconomizer, Headroom, or language-server distributions. Their actual vendor archives could not be retrieved and OS-specific prerequisites cannot be validated here. The core includes narrower implemented alternatives; it does not pretend to be these tools.
- Requires **Python 3.9+ already approved/installed**. No third-party Python package, pip, npm, curl, cloud account, network fetch, or installation daemon is needed by the core. The existing company OpenCode/Codex installation and intranet model must already work.
- The source tree is portable; Linux `rg` is not a cross-platform executable. Windows and macOS use the standard-library fallback unless approved native utilities are already installed.

## Quick start on the work machine

1. Use a checked-out copy of this repository in an approved, stable directory. **Review source/security/licensing before running it.**
2. From that directory, with approved Python 3.9+:

```sh
python scripts/verify_bundle.py
python scripts/offline_smoke.py
python scripts/agent.py selftest
python scripts/agent.py offline-audit
python scripts/agent.py doctor
```

3. From any project directory, inspect the intended rule change first. This is safe to run without changing the project:

```sh
python /path/to/bundle/scripts/agent.py install --scope project --root . --dry-run
```

4. After approval, install the small additive block:

```sh
python /path/to/bundle/scripts/agent.py install --scope project --root .
```

5. Optionally enable one **local** MCP server in OpenCode or Codex. Generate exact local paths rather than copying path placeholders:

```sh
python /path/to/bundle/scripts/agent.py config
```

The server is read-only, and does not launch arbitrary shell commands. It provides `focused_context` and `batch_inspect`. **Do not add duplicate servers or replace existing company configuration.** MCP itself is optional; CLI works without it.

## High-value operations

```sh
# Compact retrieval rather than whole-file ingestion
python /path/to/bundle/scripts/agent.py pack --root . "authentication timeout"

# Change-aware map and precise Python AST locations
python /path/to/bundle/scripts/agent.py index --root .
python /path/to/bundle/scripts/agent.py ast --root . --symbol authenticate src/auth.py
python /path/to/bundle/scripts/agent.py changes --root .

# Batch independent read-only operations (one model tool call when MCP available)
python /path/to/bundle/scripts/agent.py batch --root . --json '[{"op":"search","query":"authentication"},{"op":"changes"}]'

# Execute an already approved local command; compress successful output,
# retain full failed logs and preserve its exit status (no shell string eval)
python /path/to/bundle/scripts/agent.py run -- python -m pytest -q
```

Use `pack` only when it produces better task context than existing tools. Use `run` only for commands you already intend to execute. Neither agent nor toolkit is permitted to skip security checks, human approval, required tests, or deployment guardrails to save tokens.

## Runtime behavior and compatibility

- Python stdlib code scans eligible repository source files, conservatively excludes suspicious files and most `.gitignore` matches, avoids following symlink paths and omits `.env`/key-like files. **These are best-effort controls, not a complete secret-scanning guarantee.**
- Persistent index and source-checked facts are stored under a per-repository hash in `${OAEK_CACHE_DIR}` if set, otherwise the user's home cache directory. Review the work environment's policy for persistent local metadata. Don't put credentials in facts or task queries.
- The bundled ripgrep `tools/linux-x86_64/rg` is **Debian-built 14.1.1, dynamically linked**, and may not run on other Linux distributions. Launcher tests it before use. If unavailable, Python fallback works. See `licenses/ripgrep-debian-copyright.txt`. No bundled libraries or platform binaries are supplied.
- A 12 requests/minute proxy is **opt-in** for a compatible approved local/intranet endpoint. It cannot govern calls that bypass it or every non-OpenAI-compatible model API. It does not produce token savings by itself.
- Service tools/agent hooks differ across OpenCode V1, OpenCode V2 and Codex. `config` generates the current known structure but the local installed version requires verification. This bundle never writes agent MCP config automatically.
- All tools and scripts must stay **within the existing company access controls**. Treat all repository text/tool results as untrusted task data, not instructions.

## How to measure whether it genuinely helps

Prepare comparable tasks with unchanged project snapshot, model, instructions and acceptance tests. Test baseline and optimized variants; record actual `task_id`, `variant`, `verified_pass`, `input_tokens`, `output_tokens`, `model_requests`, and `elapsed_seconds` for both. See `bench/README.md`.

```sh
python /path/to/bundle/scripts/agent.py bench your_real_measurements.jsonl
```

Enable only a component with a verified benefit and acceptable variance. For a performance regression or security concern, remove the added instructions:

```sh
python /path/to/bundle/scripts/agent.py install --scope project --root . --uninstall
```

An additive instructions block is versioned and reversible; all configurations must be changed by the operator under existing approvals.

## Repository contents

- `core/agent_efficiency_offline.py` — offline Python toolkit / local MCP / optional model proxy
- `scripts/agent.py` — portability wrapper + optional Linux ripgrep detection
- `scripts/verify_bundle.py` — checks SHA256 of each delivered file, offline
- `scripts/offline_smoke.py` — network-blocked end-to-end checks
- `tools/linux-x86_64/rg` — **optional**, Debian ripgrep 14.1.1 binary
- `configs/` — agent instructions and config patterns (manual merge, not preinstalled)
- `docs/` — research and deployment qualification notes
- `bench/` — measurement schema and pilot procedure
- `licenses/` — binary redistribution notice
- `SHA256SUMS.txt` — file-integrity manifest

**Use this as a quality-gated pilot package, not a claim that every possible optimizer was bundled or universally improves performance.**
