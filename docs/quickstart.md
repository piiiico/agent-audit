# Scan your MCP config in 30 seconds

No install. One command. Works on any MCP config file.

## What you need

Node.js 18+ (comes with `npx`). That's it.

## Find your config file

**Claude Desktop**
```
# macOS
~/Library/Application Support/Claude/claude_desktop_config.json

# Windows
%APPDATA%\Claude\claude_desktop_config.json

# Linux
~/.config/claude/claude_desktop_config.json
```

**Cursor**
```
~/.cursor/mcp.json
```

**Auto-detect both**
```bash
npx @piiiico/agent-audit@latest --auto
```

## Run the scan

```bash
# Auto-detect Claude Desktop or Cursor
npx @piiiico/agent-audit@latest --auto

# Scan a specific file
npx @piiiico/agent-audit@latest ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

The scan takes 2-4 seconds. No network calls, nothing sent anywhere.

## Read the results

| Severity | Meaning |
|----------|---------|
| 🔴 CRITICAL | Fix before using this config. Real attack surface. |
| 🟠 HIGH | Significant risk. Fix soon. |
| 🟡 MEDIUM | Worth addressing. Low exploitability. |

## Fix common issues

**1. Hardcoded secrets**

Bad:
```json
"env": { "API_KEY": "sk-abc123..." }
```
Good:
```json
"env": { "API_KEY": "$MY_API_KEY" }
```
Set the real value in your shell environment, not in the config.

**2. Unscoped database access**

A tool like `execute_sql(query: string)` lets an agent run any SQL, including `DROP TABLE`. Replace it with purpose-built tools like `get_user_by_id(id)`. Parameterized queries only.

**3. Prompt injection in tool descriptions**

If a tool description contains instruction-like language ("ignore previous instructions", "you are now..."), an attacker who controls that text can hijack your agent. Review descriptions from third-party servers before adding them to your config.

## Add to CI

Fails the build if any critical findings are found:

```bash
npx @piiiico/agent-audit@latest --auto --min-severity critical && echo "passed"
```

GitHub Actions:
```yaml
- name: Scan MCP config
  run: npx --yes @piiiico/agent-audit@latest --auto --min-severity high
```
