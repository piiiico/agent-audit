/**
 * Prompt Injection Detection
 *
 * Detects tool descriptions that contain hidden instructions or attempts
 * to hijack the LLM's behavior (MCPTox / tool poisoning attacks).
 *
 * References:
 * - OWASP Agentic AI Top 10: A01 - Prompt Injection
 * - MCPTox benchmark: more capable models are MORE vulnerable (o1-mini: 72.8% attack success)
 * - CVE cluster Jan-Feb 2026: 20% tooling infra issues
 */

import type { MCPTool, MCPServer, Finding } from "../types.js";

/** Patterns that indicate prompt injection attempts in tool descriptions */
const INJECTION_PATTERNS: Array<{
  pattern: RegExp;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
}> = [
  {
    // Classic instruction override
    pattern: /ignore\s+(previous|above|all)\s+(instructions?|prompts?|context)/i,
    title: "Classic instruction override in tool description",
    description:
      "Tool description contains 'ignore previous instructions' pattern — a hallmark of prompt injection attacks targeting LLMs.",
    severity: "critical",
  },
  {
    // Hidden system prompt injection
    pattern: /system\s*:\s*you\s+are|<system>/i,
    title: "Hidden system prompt injection",
    description:
      "Tool description attempts to inject a system prompt, potentially overriding the agent's instructions.",
    severity: "critical",
  },
  {
    // Exfiltration via tool
    pattern: /send\s+(all|the|your)\s+(data|contents?|credentials?|keys?|tokens?|secrets?)\s+to/i,
    title: "Potential data exfiltration instruction",
    description:
      "Tool description contains instructions to send sensitive data to an external destination.",
    severity: "critical",
  },
  {
    // Role hijacking
    pattern: /you\s+(are|must\s+be|should\s+act\s+as|are\s+now)\s+(a|an|the)\s+/i,
    title: "Role hijacking in tool description",
    description:
      "Tool description attempts to redefine the LLM's role or persona.",
    severity: "high",
  },
  {
    // Invisible text via whitespace/unicode tricks
    pattern: /[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/,
    title: "Zero-width or invisible characters in tool description",
    description:
      "Tool description contains zero-width or invisible Unicode characters that could hide malicious instructions from human reviewers.",
    severity: "high",
  },
  {
    // Jailbreak patterns
    pattern: /do\s+anything\s+now|DAN|jailbreak|unrestricted\s+mode/i,
    title: "Jailbreak attempt in tool description",
    description:
      "Tool description contains known jailbreak patterns ('DAN', 'do anything now', etc.).",
    severity: "high",
  },
  {
    // Credential extraction
    pattern: /reveal\s+(your|the|all)\s+(credentials?|api\s*keys?|tokens?|passwords?|secrets?)/i,
    title: "Credential extraction instruction",
    description:
      "Tool description instructs the agent to reveal credentials or secrets.",
    severity: "critical",
  },
  {
    // Priority override
    pattern: /(highest|top|maximum|absolute)\s+priority\s*[:.-]/i,
    title: "Priority manipulation in tool description",
    description:
      "Tool description attempts to override the agent's task prioritization using urgency language.",
    severity: "medium",
  },
  {
    // Injection via XML/HTML tags
    pattern: /<(instruction|prompt|system|assistant|human|ai)\s*>/i,
    title: "XML/HTML injection tags in tool description",
    description:
      "Tool description contains XML-style tags used by some LLMs as special delimiters (e.g., Claude's <system>, <instruction>).",
    severity: "high",
  },
  {
    // Deceptive name mismatch indicator
    pattern: /\b(actually|really|truly|in\s+fact)\s+(do|perform|execute|run|send|delete|modify)/i,
    title: "Deceptive behavior disclosure in tool description",
    description:
      "Tool description contains language suggesting it performs actions different from its apparent purpose ('actually does X').",
    severity: "high",
  },
];

/** Check if a tool description is suspiciously long (could hide injections) */
const DESCRIPTION_LENGTH_THRESHOLD = 2000;

/** Check for misleading tool names (tool name vs description mismatch patterns) */
const SUSPICIOUS_NAME_PATTERNS = [
  /\b(safe|trusted|official|verified|secure|auth)\b/i,
];

export function scanToolForPromptInjection(
  tool: MCPTool,
  server: MCPServer
): Finding[] {
  const findings: Finding[] = [];
  const source = server.name;

  // Check tool description
  if (tool.description) {
    for (const check of INJECTION_PATTERNS) {
      const match = tool.description.match(check.pattern);
      if (match) {
        findings.push({
          rule: "prompt-injection/tool-description",
          title: check.title,
          description: check.description,
          severity: check.severity,
          location: {
            source,
            field: `tools.${tool.name}.description`,
            snippet: tool.description.slice(
              Math.max(0, match.index! - 30),
              match.index! + match[0].length + 30
            ),
          },
          owasp: "A01:2025 - Prompt Injection",
          remediation:
            "Review this tool description carefully. If this is a third-party MCP server, consider whether you trust the provider. Remove any tool with unexpected instruction-like language.",
        });
      }
    }

    // Check description length
    if (tool.description.length > DESCRIPTION_LENGTH_THRESHOLD) {
      findings.push({
        rule: "prompt-injection/excessive-description-length",
        title: "Unusually long tool description",
        description: `Tool '${tool.name}' has a description of ${tool.description.length} characters (threshold: ${DESCRIPTION_LENGTH_THRESHOLD}). Long descriptions are a common vector for hiding injected instructions.`,
        severity: "low",
        location: {
          source,
          field: `tools.${tool.name}.description`,
          snippet: `[${tool.description.length} chars] ${tool.description.slice(0, 200)}...`,
        },
        owasp: "A01:2025 - Prompt Injection",
        remediation:
          "Review the full tool description for hidden instructions. Prefer tools with concise, purposeful descriptions.",
      });
    }
  }

  // Check parameter descriptions in inputSchema
  if (tool.inputSchema?.properties) {
    for (const [paramName, param] of Object.entries(tool.inputSchema.properties)) {
      if (param.description) {
        for (const check of INJECTION_PATTERNS) {
          const match = param.description.match(check.pattern);
          if (match) {
            findings.push({
              rule: "prompt-injection/parameter-description",
              title: `${check.title} (in parameter description)`,
              description: check.description,
              severity: check.severity,
              location: {
                source,
                field: `tools.${tool.name}.inputSchema.properties.${paramName}.description`,
                snippet: param.description.slice(
                  Math.max(0, match.index! - 30),
                  match.index! + match[0].length + 30
                ),
              },
              owasp: "A01:2025 - Prompt Injection",
              remediation:
                "Parameter descriptions should only describe what value to provide, not contain instructions.",
            });
          }
        }
      }
    }
  }

  // Check for suspicious tool name patterns
  for (const pattern of SUSPICIOUS_NAME_PATTERNS) {
    if (pattern.test(tool.name)) {
      findings.push({
        rule: "prompt-injection/misleading-tool-name",
        title: "Potentially misleading tool name",
        description: `Tool name '${tool.name}' contains trust-signaling words that could be used to manipulate LLM tool selection.`,
        severity: "low",
        location: {
          source,
          field: `tools.${tool.name}.name`,
          snippet: tool.name,
        },
        owasp: "A01:2025 - Prompt Injection",
        remediation:
          "Verify this tool is from a trusted source. Names like 'safe_execute', 'trusted_fetch' are common in tool poisoning attacks.",
      });
    }
  }

  return findings;
}
