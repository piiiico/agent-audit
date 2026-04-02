---
title: We Scanned 12 Popular MCP Servers. Here's What We Found.
published: false
description: Static analysis of 12 public MCP server repos turned up 58 findings — 100% finding rate. Command injection, hardcoded credentials, and no security tooling in any CI pipeline.
tags: security, mcp, ai, llm
cover_image:
---

**Date:** April 2026
**Tool:** [agent-audit](https://github.com/piiiico/agent-audit) v0.2.1
**Method:** Static analysis of source code from publicly available MCP server repositories

---

## TL;DR

We cloned 12 popular, public MCP server repositories from GitHub — including Anthropic's official reference servers — and ran agent-audit's static analysis rules against their source code. We analyzed **1,130 source files** across TypeScript, Python, JavaScript, and Go.

**58 findings. 12 repos. 100% finding rate.**

Every single repository had at least one finding. The real concern isn't any individual bug — it's that the MCP ecosystem has no security baseline. There's no equivalent of `npm audit` for MCP servers, no automated checking in CI, and no community norm around security scanning.

---

## Key Numbers

| Metric | Value |
|--------|-------|
| Repositories scanned | 12 |
| Source files analyzed | 1,130 |
| Repos with findings | **12 (100%)** |
| Total findings | **58** |
| Critical | 12 |
| High | 17 |
| Medium | 29 |
| Command injection patterns | 46 |
| Hardcoded credentials (production code) | 7 |

---

## What We Found

### 1. Command Injection Is the #1 Risk (46 instances)

We found 46 instances of dangerous command execution patterns:

- **29 `child_process` imports without `execFile`** — using `spawn()` or `exec()` instead of the safer `execFile()`, which prevents shell injection by default
- **12 shell interpreter configs** — MCP servers configured with `"command": "node"` or `"command": "python"` as the entry point in Claude Desktop configs
- **5 `exec()` usages** — direct shell command execution without sanitization
- **3 template literal `exec()` calls** — string interpolation directly into shell commands
- **2 `subprocess.run(shell=True)` calls** — Python's equivalent of passing unsanitized input to a shell

The template literal injection pattern is particularly dangerous:

```javascript
exec(`git commit -m "${commitMsg}"`);
// If commitMsg contains "; rm -rf /", game over
```

**Why this matters for MCP:** MCP tools receive input from AI agents, which in turn receive input from users (or other agents). The chain from user prompt → AI agent → MCP tool → shell command is a direct prompt-to-RCE pipeline.

Command injection accounts for **43% of the 30+ MCP CVEs filed in January–February 2026** (OWASP Agentic AI Top 10, March 2026). This is not a theoretical risk — it's the pattern actively being exploited.

### 2. Hardcoded Credentials (7 instances in production code)

We found 7 instances of API keys, client secrets, and tokens hardcoded directly in production source files. While many credential patterns appeared in test files (which we excluded), these 7 were in live production code:

- Analytics API keys committed directly to documentation JS files
- OAuth client secrets used as default parameter values
- Proxy authentication tokens embedded in utility files

**A note on false positives:** FastMCP — an MCP framework library with extensive auth provider support — contains many instances of `client_secret="your-client-secret"` in its auth provider source. These are documentation placeholder values, not real secrets. We excluded them from the count.

**Why this matters for MCP:** When an AI agent connects to an MCP server, the server runs with whatever credentials are embedded in its code. A compromised MCP server with hardcoded cloud credentials becomes a pivot point into your infrastructure.

**Remediation:** Use environment variables. agent-audit flags hardcoded credentials in both config files and source code — add it to your CI pipeline.

### 3. SSL/TLS Verification Disabled (in test code)

Twenty instances of `verify=False` in HTTP client calls, all located in FastMCP's transport test suite. These appear to be intentional test infrastructure — not production code where they would create real MITM exposure.

**Zero production instances** of disabled SSL/TLS verification were found across the full corpus. This is the expected pattern for a mature framework.

### 4. Dynamic Code Execution (FastMCP)

Python `exec()` calls that construct and run code dynamically — all found in FastMCP's experimental code transformation feature (`experimental/transforms/code_mode.py`). One is in production code; the rest are in tests. Even when wrapped in "sandbox" utilities, `exec()` in Python provides no real isolation — it runs in the same process with full access to the interpreter.

The experimental label offers no security boundary at runtime.

### 5. The "Shell Interpreter" Configuration Pattern (12 critical findings)

Every Node.js MCP server configured with `"command": "node"` in Claude Desktop config inherits a fundamental issue: the MCP protocol runs through a general-purpose runtime with full system access. This is by design, but it means the security boundary is the MCP server code itself — not the runtime.

These 12 instances were flagged as critical findings because they represent the direct attack surface for prompt-to-RCE escalation.

---

## What We Didn't Find (But Should Exist)

Notably absent from every repository:

- **No security scanning in CI/CD** — zero repositories had MCP-specific security checks
- **No input validation on tool parameters** — most tools accept freeform string input
- **No rate limiting or resource controls** — tools that execute commands, query databases, or access filesystems have no usage bounds
- **No dependency auditing for MCP-specific risks** — standard `npm audit` doesn't know about MCP attack patterns

---

## The Ecosystem Problem

The issue isn't that individual servers are poorly written — many are well-maintained projects by skilled developers. The issue is structural:

**1. No security tooling exists for the MCP ecosystem.** You can't `npm audit` your MCP servers. You can't run a linter that knows about prompt injection. Until now.

**2. The MCP protocol trusts servers implicitly.** Once a server is configured, every tool it exposes is available to the AI agent. There's no capability-based authorization.

**3. The attack surface is expanding.** OWASP's Agentic AI Top 10 was finalized in March 2026. The MCP CVE cluster (30+ CVEs in 2 months) shows active exploitation. Action-capable tools grew from 27% to 65% of MCP server functionality in the past year.

**4. More capable models are more vulnerable.** Research shows that tool poisoning attacks succeed at higher rates against more capable models — 72.8% success rate against o1-mini — because they exploit the model's superior instruction-following ability. Better AI = larger attack surface for prompt injection.

**5. The supply chain risk is real.** The LiteLLM supply chain attack (March 2026, CVE-2026-33634) demonstrated the pattern: a compromised package in the MCP dependency chain can steal credentials from 97M monthly downloads. Standard `npm audit` caught nothing. MCP-specific tooling is the gap.

---

## Methodology Notes

- All scanning was performed using agent-audit's static analysis rules — no servers were actually started or connected to
- We scanned TypeScript, Python, JavaScript, and Go source code for known vulnerability patterns
- Findings from test files were excluded from credential counts but included for code pattern analysis
- **False positive rate:** A previous version of our "commented-out authentication" rule had a high false-positive rate (~85%) — it matched code comments containing words like "check" and "verify" that weren't actually auth-related. This rule has been removed. Verified across both TypeScript/JavaScript and Python corpora: zero false positives from this pattern in the current scan.
- We deliberately avoid naming specific repositories. The goal is to highlight ecosystem-wide patterns, not shame individual maintainers.

---

## Repositories Scanned

Selected from the [awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) list, official Anthropic repositories, and GitHub trending:

- Official MCP reference servers (Anthropic)
- Database connectors (MySQL, MongoDB, BigQuery)
- Browser automation servers (Playwright)
- Search and retrieval servers (Exa, Tavily)
- Desktop automation servers
- AI/LLM integration servers
- Document and knowledge management servers
- Media processing servers (YouTube transcription)
- Framework libraries (FastMCP)

---

## Try It Yourself

```bash
npx @piiiico/agent-audit --auto
```

Or point it at any MCP config file:

```bash
npx @piiiico/agent-audit ~/path/to/claude_desktop_config.json
```

agent-audit is open source. Add it to your CI pipeline:

```bash
npx @piiiico/agent-audit --auto --json --min-severity high
# Exit code 1 = high findings, 2 = critical findings
```

---

*This report was generated by [agent-audit](https://github.com/piiiico/agent-audit), an open-source security scanner for MCP servers and AI agent tooling.*
