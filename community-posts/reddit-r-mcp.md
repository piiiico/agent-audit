# r/mcp Post

**Title:** We built a security scanner for MCP servers — scanned 12 popular servers, all had findings

**Body:**

We built [agent-audit](https://github.com/piiiico/agent-audit), a static analysis tool specifically for MCP server security. Think `npm audit` but for your MCP setup.

**What it does:**

Point it at your Claude Desktop config (or any MCP config) and it:
1. Parses server configurations for dangerous patterns (shell interpreters, hardcoded secrets, path traversal)
2. Clones server repos and scans source code for command injection, credential exposure, SSL issues
3. Checks tool descriptions for prompt injection / tool poisoning patterns (hidden instructions, zero-width Unicode, role hijacking)

**Example output:**

```
  MCP Server Security Audit

  Scanning: my-mcp-server

  🔴 CRITICAL  Credential extraction instruction in tool description
  🔴 CRITICAL  Template literal in exec() call — command injection risk
  🟠 HIGH      Secret value hardcoded in MCP server config
  🟠 HIGH      Shell interpreter as MCP server command
  🟡 MEDIUM    Tool missing input schema

  Summary: 2 critical, 2 high, 1 medium
```

**What we found scanning 12 popular servers:**

- 100% had at least one finding
- 22 critical findings, 13 high (after excluding test files and FPs)
- 34 command injection patterns (template literal `exec()` is the #1 CVE pattern)
- 17 hardcoded credentials in production code
- 0 SSL/TLS verification disabled in production (20 in test code only)

Full findings write-up: [FINDINGS.md](https://github.com/piiiico/agent-audit/blob/main/FINDINGS.md)

**Quick start:**

```bash
# Auto-detect Claude Desktop config
npx @piiiico/agent-audit --auto

# CI/CD mode
npx @piiiico/agent-audit --auto --json --min-severity high
```

Maps to OWASP Agentic AI Top 10 categories. MIT licensed.

We'd love feedback on:
- False positive patterns you encounter
- Rule ideas we're missing
- MCP servers you'd like us to scan

GitHub: https://github.com/piiiico/agent-audit
