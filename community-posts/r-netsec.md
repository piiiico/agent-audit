# r/netsec Post Draft

**Suggested title:** Static analysis of 12 MCP servers: command injection dominant, 100% finding rate

---

**Body:**

We did a static analysis pass over 12 popular MCP (Model Context Protocol) server repositories — 1,130 source files across TypeScript, Python, JavaScript, and Go. Selected from [awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers), Anthropic's official repos, and GitHub trending. Every repo had at least one finding.

## Numbers

| Category | Count |
|----------|-------|
| Repositories scanned | 12 |
| Source files analyzed | 1,130 |
| Repos with findings | 12 (100%) |
| Critical findings | 22 |
| High findings | 13 |
| Command injection patterns | 34 |
| Hardcoded credentials (prod code only) | 17 |
| SSL/TLS disabled in production | 0 |

Test files and documentation placeholders (e.g., FastMCP's `client_secret="your-client-secret"` patterns) excluded from credential counts.

## Findings breakdown

**Command injection (34 instances):** The dominant pattern. Three categories:

1. Template literal injection into `exec()` — the most dangerous:

```javascript
exec(`git commit -m "${commitMsg}"`);
```

When `commitMsg` comes from an AI agent processing user prompts, this is a prompt-to-RCE pipeline. 3 instances.

2. `subprocess.run(shell=True)` in Python — 2 instances.

3. `child_process` imports using `spawn()`/`exec()` instead of `execFile()` — 29 instances. `execFile()` prevents shell injection by default because it doesn't invoke a shell interpreter. Many of these are likely safe in practice (depends on how arguments are constructed), but they represent the wrong default in a context where tool inputs originate from AI model outputs.

This tracks with the broader ecosystem: 43% of the 30+ MCP CVEs filed in Jan-Feb 2026 were command injection ([OWASP Agentic AI Top 10](https://owasp.org/www-project-agentic-ai-top-10/), finalized March 2026).

**Hardcoded credentials (17 instances in production code):** Analytics API keys in documentation JS, OAuth client secrets as default parameters, proxy auth tokens in utility files. When an MCP server runs with embedded credentials, a compromise pivots directly into whatever services those credentials access.

**Dynamic code execution (5 instances):** Python `exec()` calls in FastMCP's experimental code transformation module (`experimental/transforms/code_mode.py`). One in production code, four in tests. Python's `exec()` provides no isolation — same process, full interpreter access. The "experimental" label doesn't create a security boundary at runtime.

**SSL/TLS disabled (20 instances, all test code):** `verify=False` in FastMCP's transport test suite. Zero production instances. Noted for completeness.

## The structural issue

The individual findings are unremarkable — you'd find similar patterns in any sufficiently large sample of Node.js or Python projects. What's notable is the combination of factors specific to MCP:

1. **The input chain is adversarial by default.** MCP tool inputs come from AI models, which process user prompts (and potentially prompts from other agents). Unlike a traditional web API where you control the client, MCP tool inputs pass through a model that can be manipulated via prompt injection. Every unsanitized `exec()` call is one injection away from RCE.

2. **More capable models are more exploitable.** Palo Alto's research shows tool poisoning succeeds at 72.8% against o1-mini — because it exploits instruction-following ability. 5 connected servers → 78% attack success rate. This inverts the usual assumption about model capability and safety.

3. **No ecosystem security tooling.** Zero of the 12 repos had MCP-specific security scanning in CI. `npm audit` and `pip audit` don't cover MCP-specific patterns (tool description poisoning, MCP config credential exposure, shell interpreter configs). There's no community baseline.

4. **Supply chain is actively being exploited.** The LiteLLM incident (March 2026, CVE-2026-33634) demonstrated the pattern: compromised Trivy → stolen PyPI token → malicious packages in the MCP dependency chain → credential stealer affecting 97M monthly downloads. Standard package auditing caught nothing.

## Methodology and limitations

This is static analysis, with all the usual caveats:

- **No runtime testing.** Servers were never started or connected to. We don't know which of these patterns are actually reachable at runtime.
- **Pattern matching, not taint analysis.** We flag `child_process` imports without `execFile`, but we don't trace whether user-controlled input actually reaches the dangerous call. Some of the 29 `child_process` findings may be safe in practice.
- **No tool description analysis in this scan.** The scanner supports checking for prompt injection patterns in MCP tool descriptions (zero-width Unicode, XML/HTML injection tags, role hijacking), but this scan focused on source code patterns, not tool description content.
- **We removed a bad rule.** An earlier "commented-out authentication" check had an ~85% false positive rate — it matched code comments containing words like "check" and "verify" that weren't auth-related. We dropped it entirely. Current scan has zero false positives from that pattern class, verified across both TS/JS and Python corpora.
- **We don't name specific repositories.** The goal is ecosystem-level patterns. We don't think shaming individual maintainers serves anyone — especially when the root cause is missing tooling, not negligence.
- **Selection bias.** 12 repos from trending/popular lists. This is not a representative sample of the full MCP ecosystem. It's directional.

## The scanner

We open-sourced the tool we used: [agent-audit](https://github.com/piiiico/agent-audit). Static analysis for MCP server configs and source code.

```bash
npx @piiiico/agent-audit --auto
```

Checks for: command injection patterns, credential exposure (configs and source), tool description poisoning (zero-width chars, XML injection, role hijacking), dynamic code execution, disabled TLS, shell interpreter configs. Maps findings to OWASP Agentic AI Top 10 categories.

CI integration:

```bash
npx @piiiico/agent-audit --auto --json --min-severity high
# Exit 1 = high findings, 2 = critical
```

MIT licensed. Issues and rule contributions welcome — especially false positive reports.

Full findings data: [FINDINGS.md](https://github.com/piiiico/agent-audit/blob/main/FINDINGS.md)

## References

- [OWASP Agentic AI Top 10](https://owasp.org/www-project-agentic-ai-top-10/) (March 2026)
- [MCP CVE cluster tracking](https://github.com/invariantlabs-ai/mcp-scan)
- [Palo Alto: cross-tool attack surface scaling](https://unit42.paloaltonetworks.com/) (5 servers → 78% success)
