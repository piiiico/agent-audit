# We Scanned 13 Popular MCP Servers. Here's What We Found.

**Date:** April 1, 2026
**Tool:** [agent-audit](https://github.com/piiiico/agent-audit) v0.1.0
**Method:** Static analysis of source code from publicly available MCP server repositories

---

## TL;DR

We cloned 13 popular, public MCP server repositories from GitHub — including Anthropic's official reference servers — and ran agent-audit's static analysis rules against their source code. We analyzed **1,166 source files** across TypeScript, Python, JavaScript, and Go.

**Every single repository** had at least one finding. The real concern isn't any individual bug — it's that the MCP ecosystem has no security baseline. There's no equivalent of `npm audit` for MCP servers, no automated checking in CI, and no community norm around security scanning.

## Key Numbers

| Metric | Value |
|--------|-------|
| Repositories scanned | 13 |
| Source files analyzed | 1,166 |
| Repos with findings | **13 (100%)** |
| Critical findings (excl. test files) | 54 |
| High findings (excl. test files & false positives) | 25 |
| Command injection patterns found | 34 |
| Hardcoded credentials in production code | 51 |
| SSL/TLS verification disabled | 20 |

## What We Found

### 1. Hardcoded Credentials Are Everywhere (51 instances in production code)

The most common finding across all repositories: API keys, client secrets, and tokens hardcoded directly in source files. While many of these were in test files (which we excluded from the count), **51 instances appeared in production source code**.

Examples include:
- GA4 API secrets committed directly to telemetry modules
- OAuth client secrets used as default parameter values in auth provider implementations
- Proxy authentication tokens embedded in utility files

**Why this matters for MCP:** When an AI agent connects to an MCP server, the server runs with whatever credentials are embedded in its code. A compromised MCP server with hardcoded cloud credentials becomes a pivot point into your infrastructure.

**Remediation:** Use environment variables. agent-audit flags hardcoded credentials in both config files and source code — add it to your CI pipeline.

### 2. Command Injection Patterns (34 instances)

We found 34 instances of dangerous command execution patterns:

- **3 template literal `exec()` calls** — string interpolation directly into shell commands. This is the #1 CVE pattern in the MCP ecosystem (43% of 30+ CVEs filed Jan-Feb 2026).
- **2 `subprocess.run(shell=True)` calls** — Python's equivalent of passing unsanitized input to a shell.
- **29 `child_process` imports without `execFile`** — using `spawn()` or `exec()` instead of the safer `execFile()` which prevents shell injection by default.

The template literal injection pattern is particularly dangerous:
```javascript
exec(`git commit -m "${commitMsg}"`);  // If commitMsg contains "; rm -rf /", game over
```

**Why this matters for MCP:** MCP tools receive input from AI agents, which in turn receive input from users (or other agents). The chain from user prompt → AI agent → MCP tool → shell command is a direct prompt-to-RCE pipeline.

### 3. SSL/TLS Verification Disabled (20 instances)

Twenty instances of `verify=False` in HTTP client calls across authentication and OAuth provider code. This makes the server vulnerable to man-in-the-middle attacks.

When this pattern appears in **auth provider code** — which is where we found it — it means the token exchange that grants the MCP server its permissions can be intercepted.

### 4. Dynamic Code Execution (5 instances)

Python `exec()` calls that construct and run code dynamically. Even when wrapped in "sandbox" utilities, `exec()` in Python provides no real isolation — it runs in the same process with full access to the interpreter.

### 5. The "Shell Interpreter" Configuration Pattern

Every Node.js MCP server configured with `"command": "node"` in Claude Desktop config inherits a fundamental issue: the MCP protocol runs through a general-purpose runtime with full system access. This is by design, but it means the security boundary is the MCP server code itself — not the runtime.

## What We Didn't Find (But Should Exist)

Notably absent from most repositories:
- **No security scanning in CI/CD** — zero repositories had MCP-specific security checks
- **No input validation on tool parameters** — most tools accept freeform string input
- **No rate limiting or resource controls** — tools that execute commands, query databases, or access filesystems have no usage bounds
- **No dependency auditing for MCP-specific risks** — standard `npm audit` doesn't know about MCP attack patterns

## The Ecosystem Problem

The issue isn't that individual servers are poorly written — many are well-maintained projects by skilled developers. The issue is structural:

1. **No security tooling exists** for the MCP ecosystem. You can't `npm audit` your MCP servers. You can't run a linter that knows about prompt injection. Until now.

2. **The MCP protocol trusts servers implicitly.** Once a server is configured, every tool it exposes is available to the AI agent. There's no capability-based authorization.

3. **The attack surface is expanding.** OWASP's Agentic AI Top 10 was finalized in March 2026. The MCP CVE cluster (30+ CVEs in 2 months) shows active exploitation. And action-capable tools grew from 27% to 65% of MCP server functionality in the past year.

4. **More capable models are more vulnerable.** Research shows that tool poisoning attacks succeed at higher rates against more capable models (72.8% success rate against o1-mini) because they exploit the model's superior instruction-following ability.

## Methodology Notes

- All scanning was performed using agent-audit's static analysis rules — no servers were actually started or connected to
- We scanned source code (TypeScript, Python, JavaScript) for known vulnerability patterns
- Findings from test files were excluded from credential counts but included for code pattern analysis
- We deliberately avoid naming specific repositories. The goal is to highlight ecosystem-wide patterns, not shame individual maintainers
- False positive rate: Our "commented-out authentication" rule had a high false-positive rate (~85%) in this scan — it matched code comments containing words like "check" and "verify" that weren't actually auth-related. We're tightening this pattern.

## Repositories Scanned

We selected repositories from the [awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) list, official Anthropic repositories, and GitHub trending. The scan included:

- Official MCP reference servers (Anthropic)
- Database connectors (MySQL, MongoDB, BigQuery)
- Browser automation servers (Playwright)
- Search and retrieval servers (Exa, Tavily)
- Desktop automation servers
- AI/LLM integration servers
- Document and knowledge management servers
- Media processing servers (YouTube transcription)
- Framework libraries (FastMCP)

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

*This report was generated by [agent-audit](https://github.com/piiiico/agent-audit), an open-source security scanner for MCP servers and AI agent tooling. Built by [Piiiico](https://github.com/piiiico).*
