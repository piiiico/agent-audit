# agent-audit

**Security scanner for MCP servers and AI agent tooling.**

Catch prompt injection, command injection, hardcoded secrets, and excessive permissions in your MCP server configurations — before attackers do.

```
🔴 CRITICAL  Credential extraction instruction in tool description
🟠 HIGH      Secret value hardcoded in MCP server config
🟠 HIGH      Shell interpreter as MCP server command
🟡 MEDIUM    Tool missing input schema
```

## Why

MCP (Model Context Protocol) servers extend what AI agents can do. This power comes with risk:

- **30+ CVEs filed Jan–Feb 2026**, 43% were command injection
- **Tool poisoning attacks** hide instructions in tool descriptions that hijack LLM behavior
- **Hardcoded secrets** in MCP configs are stored in plaintext at `~/.config/claude/`
- **5 connected MCP servers → 78% attack success rate** (Palo Alto Research, 2026)
- More capable models are *more* vulnerable — o1-mini shows 72.8% attack success against poisoned tools (MCPTox benchmark)

Most security tools don't understand MCP. `agent-audit` does.

## Install

```bash
npm install -g @piiiico/agent-audit
# or
npx @piiiico/agent-audit --auto
```

## Usage

```bash
# Auto-detect Claude Desktop config
agent-audit --auto

# Scan a specific config file
agent-audit ~/Library/Application\ Support/Claude/claude_desktop_config.json

# JSON output for CI/CD
agent-audit --auto --json

# Only report high and critical findings
agent-audit --auto --min-severity high

# Skip source file scanning (faster)
agent-audit --auto --no-source
```

## What It Checks

### Prompt Injection (OWASP A01)
Scans tool names, descriptions, and parameter descriptions for:
- Classic instruction overrides ("ignore previous instructions")
- Hidden system prompt injection
- Zero-width / invisible Unicode characters
- Role hijacking patterns
- Credential extraction instructions
- Jailbreak patterns (DAN, unrestricted mode)
- XML/HTML injection tags (`<instruction>`, `<system>`)

### Command Injection (OWASP A03)
- Shell interpreters (`bash`, `sh`, `python`, `node`) as MCP server commands
- Template literals in `exec()` calls in source files
- `subprocess.run(shell=True)` in Python
- `eval()` and `new Function()` usage
- `child_process` without `execFile()`
- Path traversal in server arguments (`../`)

### Credential Exposure (OWASP A07)
- Hardcoded secrets in MCP server `env` config
- AWS Access Key IDs (`AKIA...`)
- GitHub tokens (`ghp_...`, `ghs_...`)
- npm tokens (`npm_...`)
- Generic API keys, passwords, and bearer tokens in source files

### Auth Bypass (OWASP A05)
- Commented-out authentication checks
- SSL/TLS verification disabled
- Always-false conditionals blocking security checks

### Excessive Permissions (OWASP A05)
- Shell execution, filesystem, database, and network access tools
- Missing input schemas (no validation possible)
- Empty/permissive input schemas
- High concentration of privileged tools in a single server

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical or high findings |
| 1 | High severity findings detected |
| 2 | Critical findings detected |

Use with `--json` for CI/CD integration:

```yaml
# GitHub Actions
- name: Audit MCP servers
  run: npx agent-audit --auto --json --min-severity high > mcp-audit.json
  continue-on-error: false
```

## Programmatic API

```typescript
import { scan, parseClaudeDesktopConfig } from "agent-audit";

const servers = parseClaudeDesktopConfig("/path/to/claude_desktop_config.json");
const result = await scan(servers, "my-app");

console.log(result.summary);
// { critical: 0, high: 2, medium: 1, low: 3, info: 0 }

for (const finding of result.findings) {
  console.log(finding.rule, finding.severity, finding.title);
}
```

## References

- [OWASP Agentic AI Top 10](https://owasp.org/www-project-agentic-ai-top-10/)
- [MCPTox: Tool Poisoning Attacks on MCP](https://arxiv.org/abs/2508.14925)
- [MCP Security CVE Analysis (Jan–Feb 2026)](https://github.com/invariantlabs-ai/mcp-scan)
- [Palo Alto: MCP Security Research](https://unit42.paloaltonetworks.com/)

## License

MIT
