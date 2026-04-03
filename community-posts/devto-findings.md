# We Scanned 12 Popular MCP Servers — Every Single One Had Security Findings

**Date:** April 1, 2026
**Method:** Static analysis of 1,130 source files across TypeScript, Python, JavaScript, and Go

---

MCP (Model Context Protocol) is growing fast. Thousands of servers are being built to give AI agents access to databases, filesystems, shell commands, and external APIs. But nobody's been systematically checking whether they're secure.

So we did.

## TL;DR

We cloned 12 popular, public MCP server repositories from GitHub — including Anthropic's official reference servers — and ran static security analysis across their source code.

**Every single repository had at least one finding.**

The real concern isn't any individual bug. It's that the MCP ecosystem has no security baseline. There's no equivalent of `npm audit` for MCP servers, no automated security checking in CI, and no community norm around security scanning.

## Key Numbers

| Metric | Value |
|--------|-------|
| Repositories scanned | 12 |
| Source files analyzed | 1,130 |
| Repos with findings | **12 (100%)** |
| Critical findings (excl. test files & FPs) | 22 |
| High findings (excl. test files) | 13 |
| Command injection patterns found | 34 |
| Hardcoded credentials in production code | 17 |
| SSL/TLS verification disabled (production) | 0 |

---

## What We Found

### 1. Hardcoded Credentials Are Everywhere

17 instances of API keys, client secrets, and tokens hardcoded directly in production source code.

Examples:
- Analytics API keys committed directly to documentation JS files
- OAuth client secrets used as default parameter values in production code
- Proxy authentication tokens embedded in utility files

**Why this matters for MCP:** When an AI agent connects to an MCP server, the server runs with whatever credentials are embedded in its code. A compromised MCP server with hardcoded cloud credentials becomes a pivot point into your infrastructure.

**Note on false positives:** FastMCP (an MCP framework library) contains many `client_secret="your-client-secret"` placeholder patterns in its auth provider documentation code. We excluded these from the production count. FastMCP still had one real finding: an analytics API key hardcoded in a documentation JS file.

### 2. Command Injection Patterns (34 instances)

This is the #1 CVE pattern in the MCP ecosystem — 43% of the 30+ CVEs filed in January-February 2026.

We found:
- **3 template literal `exec()` calls** — string interpolation directly into shell commands
- **2 `subprocess.run(shell=True)` calls** — Python's equivalent of passing unsanitized input to a shell
- **29 `child_process` imports without `execFile`** — using `spawn()` or `exec()` instead of the safer `execFile()`

The template literal injection pattern is particularly dangerous:

```javascript
exec(`git commit -m "${commitMsg}"`);
// If commitMsg contains "; rm -rf /", game over
```

**Why this matters for MCP:** MCP tools receive input from AI agents, which receive input from users (or other agents). The chain from user prompt → AI agent → MCP tool → shell command is a direct prompt-to-RCE pipeline.

### 3. SSL/TLS Verification Disabled (20 instances in test code)

20 instances of `verify=False` in HTTP client calls, all in FastMCP's transport test suite — intentional test infrastructure, not production code.

**Zero production instances** of disabled SSL/TLS verification. This is the expected pattern for a mature framework.

### 4. Dynamic Code Execution (5 instances)

Python `exec()` calls in FastMCP's experimental code transformation feature. One is in production code; four are in tests.

Even when wrapped in "sandbox" utilities, `exec()` in Python provides no real isolation — it runs in the same process with full interpreter access. The "experimental" label offers no security boundary at runtime.

---

## What We Didn't Find (But Should Exist)

Notably absent across most repositories:

- **No security scanning in CI/CD** — zero repositories had MCP-specific security checks
- **No input validation on tool parameters** — most tools accept freeform string input
- **No rate limiting or resource controls** — tools that execute commands, query databases, or access filesystems have no usage bounds
- **No dependency auditing for MCP-specific risks** — standard `npm audit` doesn't know about MCP attack patterns

---

## The Structural Problem

The issue isn't that individual servers are poorly written — many are well-maintained projects by skilled developers. The issue is structural:

**1. No security tooling exists for the MCP ecosystem.**
You can't `npm audit` your MCP servers. You can't run a linter that knows about prompt injection patterns specific to AI agent tooling.

**2. The MCP protocol trusts servers implicitly.**
Once a server is configured, every tool it exposes is available to the AI agent. There's no capability-based authorization.

**3. The attack surface is expanding.**
OWASP's Agentic AI Top 10 was finalized in March 2026. 30+ MCP CVEs were filed in just two months. Action-capable tools grew from 27% to 65% of MCP server functionality in the past year.

**4. More capable models are more vulnerable.**
Research shows tool poisoning attacks succeed at higher rates against more capable models — 72.8% success against o1-mini — because they exploit superior instruction-following. Better AI = larger attack surface.

---

## Repositories Scanned

We selected from the [awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) list, official Anthropic repositories, and GitHub trending:

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

## Methodology

- Static analysis only — no servers were started or connected to
- Scanned TypeScript, Python, and JavaScript source code for known vulnerability patterns
- Findings from test files excluded from credential counts, included for code pattern analysis
- We deliberately avoided naming specific repositories — the goal is to highlight ecosystem patterns, not shame individual maintainers
- False positive rate: A previous "commented-out authentication" rule was removed after ~85% FP rate. Current scan: zero false positives from this pattern (verified across both TypeScript/JavaScript and Python corpora)

---

## Try It Yourself

We open-sourced the scanner. Run it against your own MCP setup:

```bash
npx @piiiico/agent-audit --auto
```

Or point it at any MCP config file:

```bash
npx @piiiico/agent-audit ~/path/to/claude_desktop_config.json
```

Add it to your CI pipeline:

```bash
npx @piiiico/agent-audit --auto --json --min-severity high
# Exit code 1 = high findings, 2 = critical findings
```

agent-audit is open source: [github.com/piiiico/agent-audit](https://github.com/piiiico/agent-audit)

---

*If you're building MCP servers, scan them. If you're using MCP servers, ask your providers whether they do. The ecosystem is moving fast — security tooling needs to keep pace.*
