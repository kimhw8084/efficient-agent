# Paired-task performance evaluation — real measurements only

The toolkit does **not** contain invented benchmark improvements. Create a `results.jsonl` file with one JSON object per run:

```json
{"task_id":"REAL-ISSUE-ID","variant":"baseline","verified_pass":true,"input_tokens":0,"output_tokens":0,"model_requests":0,"elapsed_seconds":0}
{"task_id":"REAL-ISSUE-ID","variant":"optimized","verified_pass":true,"input_tokens":0,"output_tokens":0,"model_requests":0,"elapsed_seconds":0}
```

**These are schema illustrations with zero placeholders, not benchmark results.** Replace every value with real telemetry before running analysis. Repeat tasks where possible using an independent project reset and counterbalanced ordering.

```sh
python scripts/agent.py bench results.jsonl
```

For each task, verify: exact acceptance criteria, executed tests, required security/accessibility checks, no unauthorized edits, no external network, and no defects concealed by compressed logs. Compare input/output tokens (and cache charges separately where known), total model requests, verified success, elapsed time, and rework. Only retain optimizations that prove net benefit at acceptable quality and TAT. Beware of additional MCP overhead and model turns caused by excessively verbose agent rules.
