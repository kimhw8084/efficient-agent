# Offline-first optimization candidates and qualification — 2026-11-03

This is a procurement and compatibility record, not a claim that unavailable binaries have been bundled or tested. Practical value depends on repo type, model API, OS and agent version.

| Component | Where it helps | Offline operation | This package |
|---|---|---|---|
| Focused local repository retrieval | Reduce broad source dumps | Tested standard library | **Bundled + tested** |
| Incremental index + source-bound facts | Avoid repeated rediscovery | Tested standard library | **Bundled + tested** |
| Python AST + local Git change summary | Precise Python locations, scoped inspection | Tested standard library, Git optional | **Bundled + tested** |
| Batch MCP + local tool execution | Reduce redundant tool-round-trip context | Tested local stdio/CLI | **Bundled + tested** |
| Successful-log compression | Reduce command output, preserve failure diagnostics | Tested standard library | **Bundled + tested** |
| Per-user gateway | Smooth 12 RPM where all compatible calls routed | Requires approved intranet OpenAI-compatible endpoint | **Bundled, not certified for company model** |
| ripgrep | Fast ignore-aware lexical search | Offline native | **Linux x64 binary bundled; other platforms fallback** |
| ast-grep | Tree-sitter structural matching | Offline with matching binary | Not bundled — platform binary and license verification needed |
| Serena | LSP-backed semantic navigation | Conditional: local language servers/dependencies | Not bundled — large multi-language dependency tree |
| TokenEconomizer | Verified micro-skills, tool pruning, loopguard | Conditional: hooks supported; some features invoke model | Not bundled — requires correct upstream version, agent hook approval |
| RTK / RTK OSS | Native command output compression | Offline native; editions have different licenses | Not bundled — output-compression behavior implemented independently |
| Context Mode / Headroom / sqz | Context sandbox and compression | Conditional on downloaded dependencies/runtime | Not bundled — overlapping hooks and tool costs need benchmarking |
| Aider RepoMap | Ranked tree-sitter repository map | Conditional on tree-sitter assets | Not bundled; Python-only outline implemented instead |
| Prompt prefix caching | Lower input billing/cost, may improve latency | Provider/gateway dependent | Not implementable by offline CLI alone |
| Effort tuning | Lower model output or reasoning tokens | Provider dependent | Not universally available |
| OpenCode V2 Code Mode | Programmatic tool chaining and filtering | Built into installed agent if enabled | Use existing capability; no second copy |

### Research sources

- Microsoft TokenEconomizer v0.1.0 docs/release: https://github.com/microsoft/TokenEconomizer/releases/tag/v0.1.0 ; plugin documentation https://github.com/microsoft/TokenEconomizer/blob/main/plugin/README.md ; Apache-2.0, Python 3.10+; OpenCode support experimental and version-specific.
- ripgrep releases: https://github.com/BurntSushi/ripgrep/releases ; this bundle instead carries verified local Debian 14.1.1 binary with its distribution notice.
- ast-grep releases: https://github.com/ast-grep/ast-grep/releases ; not available as a complete downloaded binary in this build environment.
- RTK editions/licensing: https://github.com/rtk-ai/rtk ; OSS edition Apache-2.0; standard engine has additional BUSL licensing. Do not assume edition equivalence.
- OpenCode V2 MCP: https://opencode.ai/v2/docs/mcp-servers ; older OpenCode MCP: https://docs.opencode.ai/docs/mcp-servers/ .
- Codex local MCP CLI: https://learn.chatgpt.com/docs/developer-commands .

### Why not install all tools simultaneously?

They overlap. Multiple wrappers may compress or hide important diagnostics, multiple MCP servers expand tool catalogs, and repeated indexing increases task completion time. Vendor token-reduction claims generally concern narrow operations, not matched end-to-end task success. This bundle has **no auto-enable** for high-risk or overlapping options. Add further tools only when complete dependencies, licenses, security and paired-task evidence are verified in the approved intranet.

### Compatibility assertions

- Portable core needs preinstalled Python 3.9+ and filesystem permission. Tested locally in an isolated Python environment.
- Linux x86_64 accelerator is tested on the build machine but **not guaranteed across Linux libc/library versions**. Non-Linux always falls back.
- Agent MCP integration and model proxy rely on the installed agent and approved model. Local MCP wire-level functions were tested, but not on actual company OpenCode/Codex versions.
- Security controls are conservative, not a comprehensive protection against malicious source code, prompts, or credentials.
