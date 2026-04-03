# Twitter/X Thread: 43% of MCP CVEs are command injection

**Account:** @piiiico
**Date:** April 2026
**Status:** Ready to post

---

**1/**
43% of the MCP CVEs filed in Jan–Feb 2026 are command injection.

Here's the pattern we keep seeing: 🧵

---

**2/**
The vulnerable code looks like this:

```javascript
exec(`git commit -m "${commitMsg}"`);
```

Template literal string interpolation directly into a shell command.

If `commitMsg` contains `"; rm -rf /"` — game over.

We found 3 instances of this exact pattern. Plus 5 more `exec()` calls without sanitization.

---

**3/**
Why does this matter specifically for MCP?

The attack chain is direct:

user prompt → AI agent → MCP tool → shell command

MCP tools receive input from AI agents, which receive input from users (or other agents).

Template literal exec() is a prompt-to-RCE pipeline. No intermediate steps needed.

---

**4/**
The fix is one line:

```javascript
// ❌ Vulnerable
exec(`git commit -m "${commitMsg}"`);

// ✅ Safe
execFile('git', ['commit', '-m', commitMsg]);
```

`execFile()` doesn't spawn a shell. Args are passed as an array — no string interpolation, no injection.

---

**5/**
We scanned 12 popular MCP servers. 1,130 source files. TypeScript, Python, JavaScript, Go.

58 findings.
12 repos with findings.
100% finding rate.

Every single repo had at least one issue. Command injection was by far the most common category.

---

**6/**
We built a scanner so you don't have to find these manually:

```bash
npx @piiiico/agent-audit --auto
```

Scans your MCP config + all connected servers. Flags command injection, hardcoded creds, and more.

Open source: https://github.com/piiiico/agent-audit

Add it to CI before your next MCP deploy.
