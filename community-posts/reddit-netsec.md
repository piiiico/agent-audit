# We Scanned 12 Popular MCP Servers Using Static Analysis — Every One Had Security Findings

**Cross-post to: r/netsec**

---

**Title:** We Scanned 12 Popular MCP Servers Using Static Analysis — Every One Had Security Findings

**Body:**

MCP (Model Context Protocol) is the protocol that lets AI agents connect to external tools — databases, shell commands, filesystems, APIs. Thousands of servers are being deployed. Nobody has been systematically auditing them.

We cloned 12 popular, public MCP repositories from GitHub (including Anthropic's official reference servers) and ran static analysis across 1,130 source files. Results:

**Key numbers:**
- 12/12 repos had findings
- 22 critical findings (excluding test files and documented false positives)
- 13 high findings (excluding test files)
- 34 command injection patterns (exec() with template literals, subprocess.run(shell=True), child_process without execFile)
- 17 hardcoded credentials in production code (API keys, OAuth secrets, proxy tokens)
- 0 SSL/TLS verification disabled in production

**The command injection pattern is the most concerning:**

```javascript
exec(`git commit -m "${commitMsg}"`);
```

This is the #1 pattern in the MCP CVE cluster (30+ CVEs filed Jan-Feb 2026, 43% command injection). The attack chain: user prompt → AI agent → MCP tool → shell command. Direct prompt-to-RCE.

**What's missing across the ecosystem:**
- No MCP-specific security scanning in any CI pipeline we checked
- No input validation on tool parameters (most accept freeform string input)
- No rate limiting or resource controls on tools that execute commands or access filesystems
- No dependency auditing that understands MCP-specific attack patterns

**On false positives:** We removed a "commented-out authentication" rule that had ~85% FP rate. The credential findings were reviewed manually — FastMCP's `client_secret="your-client-secret"` documentation placeholders were excluded. The 17 production instances are real.

**Tool:** We open-sourced the scanner — [github.com/piiiico/agent-audit](https://github.com/piiiico/agent-audit)

```bash
npx @piiiico/agent-audit --auto
```

We deliberately don't name specific repos — ecosystem pattern is more important than shaming individual maintainers. Happy to answer methodology questions.

---

**Suggested tags:** mcp, ai-security, static-analysis, prompt-injection, supply-chain
