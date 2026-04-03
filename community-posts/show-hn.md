# Show HN: agent-audit – Security scanner for MCP servers (OWASP checks)

**Title:** Show HN: agent-audit – Security scanner for MCP servers (OWASP checks)

**URL:** https://github.com/piiiico/agent-audit

**Text (for the HN comment, post immediately after submitting):**

We scanned 12 popular MCP servers — including Anthropic's official reference servers — and every single one had findings. 22 critical, 13 high (after excluding test files and false positives). The MCP ecosystem has no security baseline.

The biggest patterns:

- **34 command injection patterns.** Template literal `exec()` calls are the #1 CVE pattern — 43% of the 30+ MCP CVEs filed Jan-Feb 2026. The chain from user prompt → AI agent → MCP tool → shell command is a direct prompt-to-RCE pipeline.

- **17 hardcoded credentials** in production code (excluding test files and documentation placeholders). API keys and OAuth secrets as default parameter values. When an AI agent connects to a compromised MCP server with embedded cloud credentials, that server becomes a pivot point into your infrastructure.

- **20 instances of SSL/TLS verification disabled** — all in test code (zero in production). Good news, but the command injection surface is the real concern.

agent-audit does static analysis on your MCP server configs and source code. It checks for prompt injection (hidden instructions in tool descriptions, zero-width Unicode), command injection, credential exposure, auth bypass patterns, and excessive permissions. Maps to OWASP Agentic AI Top 10.

```bash
npx @piiiico/agent-audit --auto
```

It auto-detects your Claude Desktop config, clones the server repos, and scans source files. JSON output + exit codes for CI/CD.

The more capable the model, the more vulnerable it is to tool poisoning — o1-mini shows 72.8% attack success rate (MCPTox benchmark). 5 connected MCP servers → 78% attack success (Palo Alto). This is a structural problem that needs tooling, not just awareness.

Open source, MIT licensed. Written in TypeScript. Feedback welcome — especially on false positive rates and missing rule patterns.

Full findings report: https://github.com/piiiico/agent-audit/blob/main/FINDINGS.md
