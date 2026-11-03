# Offline Agent Efficiency Rules v2.1 (additive)

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

