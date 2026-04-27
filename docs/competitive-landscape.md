# Competitive Landscape — agent-audit

_Last updated: April 2026_

This document covers how agent-audit relates to other tools in the MCP/agent security space. The goal is honest positioning, not marketing copy.

---

## agent-audit in one sentence

Static analysis for MCP server configurations — runs before deployment, zero cost, no network calls, no API tokens consumed.

---

## ship-safe

**What it is:** A CLI security scanner built for the agentic era. 23 AI agents run in parallel to audit your full codebase for LLM vulnerabilities, MCP config issues, RAG poisoning, Claude Managed Agent misconfigs, secrets, and dependency CVEs. MIT-licensed; free CLI with optional paid cloud dashboard.

**GitHub:** [asamassekou10/ship-safe](https://github.com/asamassekou10/ship-safe)

**What it does well:**
- Comprehensive coverage: CI/CD misconfigs, supply chain attacks, DMCA-flagged AI dependencies, red team (80+ attack classes)
- Works across the full codebase, not just MCP configs
- Framework-agnostic: LangChain, CrewAI, Claude Managed Agents, etc.

**How it differs from agent-audit:**

| Dimension | ship-safe | agent-audit |
|-----------|-----------|-------------|
| Scope | Full codebase + agent security | MCP configs only |
| Engine | 23 LLM agents in parallel | Pure static analysis |
| Runtime cost | Real $ in API tokens per scan | Zero cost |
| Scan time | Minutes (LLM calls) | ~3 seconds |
| Network required | Yes (LLM API) | No |
| CI integration | Yes | Yes (exit codes, JSON) |

**When to use ship-safe:** Full codebase security audit, CI/CD pipeline hardening, comprehensive agent security including non-MCP components.

**When to use agent-audit:** Quick pre-flight for MCP configs, zero-cost continuous scanning, offline environments, fast CI gates where you only need MCP-specific checks.

These are complementary tools at different points of the developer workflow. Ship-safe for the full audit; agent-audit for the fast, focused MCP check.

---

## Microsoft Agent Governance Toolkit (AGT)

**What it is:** Open-source runtime governance framework for autonomous AI agents. Released April 2, 2026 (MIT). Seven packages across Python, TypeScript, Rust, Go, and .NET. Addresses all 10 OWASP Agentic AI risks via deterministic sub-millisecond policy enforcement at the application layer.

**GitHub:** [microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit)

**What it does well:**
- Runtime interception — every agent action checked before execution
- Sub-millisecond latency (p99 < 0.1ms) vs. 26.67% violation rate for prompt-based safety
- Framework-agnostic hooks: LangChain callbacks, CrewAI task decorators, Google ADK plugins
- Policy engines: YAML, OPA (Rego), Cedar — matches enterprise compliance workflows
- Designed for regulatory context: EU AI Act (Aug 2026), Colorado AI Act (June 2026)

**How it differs from agent-audit:**

| Dimension | Microsoft AGT | agent-audit |
|-----------|--------------|-------------|
| Phase | Runtime (enforcement during execution) | Pre-deployment (static analysis) |
| Weight | Heavyweight: 7 packages, YAML/OPA/Cedar policies, Azure-integrated | Lightweight: single CLI, zero dependencies |
| Setup time | Hours (policy authoring, framework integration) | 30 seconds (`npx @piiiico/agent-audit --auto`) |
| Target | Enterprise agents in production | Developers auditing MCP configs locally |
| Vendor tie | Azure-oriented, Microsoft ecosystem | Fully independent |

**When to use Microsoft AGT:** Production agents where runtime enforcement is required, enterprise compliance workflows, Azure-deployed agents.

**When to use agent-audit:** Developer workstation, pre-deployment check, catching obvious MCP config mistakes before they reach production. Think of it as the linter that runs before the runtime guard activates.

The framing: AGT is the firewall; agent-audit is the configuration review before you go live. Both are necessary.

---

## Manual Review

**What it is:** A security engineer or developer manually reads MCP server configs, source code, and tool definitions to identify risks.

**What it does well:**
- No false positives from pattern matching
- Can catch semantic issues no static analyzer would find
- Required for compliance certifications (SOC2, ISO 27001 auditors need human signoff)

**How it differs from agent-audit:**

| Dimension | Manual review | agent-audit |
|-----------|--------------|-------------|
| Coverage | As thorough as the reviewer | Automated, consistent |
| Time | Hours–days per config | ~3 seconds |
| Cost | $$$–$$$$ (consultant or staff time) | Free |
| Repeatability | Depends on reviewer | Identical results every run |
| CI integration | No | Yes |

**When to use manual review:** Compliance audits, complex semantic analysis, final signoff before production.

**When to use agent-audit:** Every PR that touches an MCP config. Catch the obvious stuff automatically; let human reviewers focus on the judgment calls.

---

## MCP-Shield

**What it is:** Runtime tool-call monitoring for MCP (134pts on HN). Inspects tool calls as they happen.

**How it differs from agent-audit:** Same lifecycle gap as AGT — runtime vs. pre-deployment. agent-audit runs before your agent connects; MCP-Shield monitors while it runs.

---

## Summary

agent-audit's position: **shift-left for MCP security**. Like ESLint before your code hits CI, or Dockerfile linting before image build. The pre-deployment check that's fast enough to run on every save, cheap enough to run on every PR, and focused enough to produce useful output without tuning.

The alternatives are either heavier (AGT, manual review), broader (ship-safe), or later in the lifecycle (MCP-Shield). None of them are wrong choices — they operate at different points in the security lifecycle. agent-audit fills the gap that exists before any of them activates.
