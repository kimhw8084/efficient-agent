# Company intranet deployment checklist

- [ ] Company approval for Python/script execution, Git, optional redistributable `rg`, and MCP extension.
- [ ] Company model already accessible on approved intranet (no external cloud dependency).
- [ ] Review source code, licenses, SHA256 manifest; run `scripts/verify_bundle.py`.
- [ ] Run `scripts/offline_smoke.py` and `scripts/agent.py offline-audit` without network.
- [ ] Confirm actual OS/architecture, Python 3.9+, Codex/OpenCode version, installed MCP support.
- [ ] Back up original `AGENTS.md`, preview additive rules with `install --dry-run`.
- [ ] Keep existing mandatory engineering and project quality gates.
- [ ] Opt-in one MCP instance per project only if it reduces overall requests and context.
- [ ] Avoid unapproved auto-hook modifications; no downloads, updates, or telemetry.
- [ ] Keep full failed test output and logs; never claim quality without checks.
- [ ] Measure matched-task baseline/optimized results; check quality, total tokens, model requests, total TAT.
- [ ] If regression, disable MCP, uninstall additive rules, restore any unrelated manual config changes.
