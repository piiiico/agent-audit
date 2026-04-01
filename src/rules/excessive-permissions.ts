/**
 * Excessive Permissions Detection
 *
 * Detects MCP tools that request or provide more capabilities than necessary,
 * violating the principle of least privilege.
 *
 * References:
 * - OWASP Agentic AI Top 10: A05 - Excessive Agency / Permissions
 * - "5 connected MCP servers → 78% attack success" (Palo Alto, 2026)
 * - BVP model: Visibility → Configuration → Runtime (still gap)
 */

import type { MCPTool, MCPServer, Finding } from "../types.js";

/** Tool names that suggest broad/dangerous capabilities */
const HIGH_RISK_TOOL_PATTERNS: Array<{
  pattern: RegExp;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium";
  remediation: string;
}> = [
  {
    pattern: /(?:run|exec|execute|shell|bash|cmd|command|terminal|subprocess)/i,
    title: "Shell execution tool",
    description:
      "This tool appears to provide shell command execution capabilities. If not strictly scoped, this gives the agent (and any prompt injector) arbitrary code execution.",
    severity: "critical",
    remediation:
      "Scope the tool to specific allowed commands. Use allowlists, not blocklists. Consider whether a shell execution tool is necessary at all.",
  },
  {
    pattern: /(?:file|fs|filesystem|read|write|delete|rm|mv|cp|mkdir|chmod)\b/i,
    title: "Filesystem access tool",
    description:
      "This tool provides filesystem access. Without path restrictions, it can read/write any file accessible to the MCP server process.",
    severity: "high",
    remediation:
      "Restrict filesystem tools to specific directories. Implement path validation and canonicalization.",
  },
  {
    pattern: /(?:network|http|fetch|request|download|upload|curl|wget)\b/i,
    title: "Network access tool",
    description:
      "This tool provides outbound network access. This could be abused for data exfiltration or SSRF attacks.",
    severity: "medium",
    remediation:
      "Implement allowlists for permitted domains/IPs. Log all outbound requests. Consider whether arbitrary URL fetching is necessary.",
  },
  {
    pattern: /(?:database|db|sql|query|mongo|redis|postgres|mysql)\b/i,
    title: "Database access tool",
    description:
      "This tool provides direct database access. Without parameterized queries, this may allow SQL injection.",
    severity: "high",
    remediation:
      "Use parameterized queries only. Restrict the database user to minimum required privileges. Implement rate limiting.",
  },
  {
    pattern: /(?:admin|root|sudo|privilege|elevat|superuser)/i,
    title: "Administrative privilege tool",
    description:
      "This tool's name suggests it operates with elevated or administrative privileges.",
    severity: "critical",
    remediation:
      "Administrative tools should require explicit human confirmation before execution. Use separate service accounts with minimal permissions.",
  },
  {
    pattern: /(?:credential|password|secret|token|key|auth)\b/i,
    title: "Credential/secrets management tool",
    description:
      "This tool handles credentials or secrets. If compromised, it could expose all managed secrets.",
    severity: "high",
    remediation:
      "Implement strict access controls. Log all secret access. Consider whether agents need credential access at all, or if a proxy service is safer.",
  },
  {
    pattern: /(?:email|mail|smtp|send|message|notify|webhook)/i,
    title: "Messaging/notification tool",
    description:
      "This tool can send messages or notifications. If abused (via prompt injection), it can be used for phishing or data exfiltration via email.",
    severity: "medium",
    remediation:
      "Restrict allowed recipients. Implement content filtering. Require human approval for external communications.",
  },
];

/** Check for tools with missing input validation (no schema = no validation) */
export function scanToolForExcessivePermissions(
  tool: MCPTool,
  server: MCPServer
): Finding[] {
  const findings: Finding[] = [];

  // Check tool name and description against high-risk patterns
  const toolText = `${tool.name} ${tool.description ?? ""}`;
  for (const check of HIGH_RISK_TOOL_PATTERNS) {
    if (check.pattern.test(toolText)) {
      findings.push({
        rule: "excessive-permissions/high-risk-capability",
        title: check.title,
        description: `Tool '${tool.name}' in server '${server.name}': ${check.description}`,
        severity: check.severity,
        location: {
          source: server.name,
          field: `tools.${tool.name}`,
          snippet: tool.description?.slice(0, 200) ?? tool.name,
        },
        owasp: "A05:2025 - Excessive Agency",
        remediation: check.remediation,
      });
      break; // One finding per tool for this check
    }
  }

  // Check for missing input schema (no validation possible without schema)
  if (!tool.inputSchema) {
    findings.push({
      rule: "excessive-permissions/missing-input-schema",
      title: "Tool missing input schema",
      description: `Tool '${tool.name}' has no inputSchema defined. Without a schema, inputs cannot be validated by the MCP framework.`,
      severity: "medium",
      location: {
        source: server.name,
        field: `tools.${tool.name}.inputSchema`,
        snippet: tool.name,
      },
      owasp: "A03:2025 - Insufficient Input/Output Validation",
      remediation:
        "Add a JSON Schema inputSchema to define and validate all tool parameters.",
    });
  } else if (
    tool.inputSchema.type === "object" &&
    !tool.inputSchema.properties &&
    !tool.inputSchema.required
  ) {
    // Empty schema — accepts anything
    findings.push({
      rule: "excessive-permissions/empty-input-schema",
      title: "Tool has empty/permissive input schema",
      description: `Tool '${tool.name}' declares type:object but has no properties or required fields defined, effectively accepting arbitrary input.`,
      severity: "medium",
      location: {
        source: server.name,
        field: `tools.${tool.name}.inputSchema`,
        snippet: JSON.stringify(tool.inputSchema).slice(0, 200),
      },
      owasp: "A03:2025 - Insufficient Input/Output Validation",
      remediation:
        "Define all expected parameters in inputSchema.properties and mark required ones in inputSchema.required.",
    });
  }

  return findings;
}

/** Evaluate aggregate risk of all tools in a server */
export function scanServerForExcessivePermissions(
  server: MCPServer
): Finding[] {
  const findings: Finding[] = [];

  if (!server.tools || server.tools.length === 0) return findings;

  // Count high-risk tools
  const criticalTools = server.tools.filter((t) =>
    HIGH_RISK_TOOL_PATTERNS.some(
      (p) => p.severity === "critical" && p.pattern.test(`${t.name} ${t.description ?? ""}`)
    )
  );

  if (criticalTools.length > 3) {
    findings.push({
      rule: "excessive-permissions/tool-concentration",
      title: "High concentration of privileged tools in single server",
      description: `Server '${server.name}' has ${criticalTools.length} high-risk tools. Concentrating privileged capabilities increases blast radius if the server is compromised or if a connected LLM is manipulated.`,
      severity: "high",
      location: {
        source: server.name,
        field: "tools",
        snippet: criticalTools.map((t) => t.name).join(", "),
      },
      owasp: "A05:2025 - Excessive Agency",
      remediation:
        "Split privileged tools into separate MCP servers with minimal permissions each. Apply principle of least privilege at the server level.",
    });
  }

  return findings;
}
