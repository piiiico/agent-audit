/**
 * Command Injection Detection
 *
 * Scans MCP server source files and configurations for command injection
 * vulnerabilities — the #1 vulnerability class in the MCP CVE cluster.
 *
 * References:
 * - 43% of 30+ CVEs filed Jan-Feb 2026 were command injection
 * - OWASP Agentic AI Top 10: A03 - Insufficient Input/Output Validation
 * - OWASP Top 10 Web: A03:2021 - Injection
 */

import { readFileSync } from "fs";
import type { MCPServer, Finding } from "../types.js";

/** Dangerous shell execution patterns in source code */
const SHELL_EXECUTION_PATTERNS: Array<{
  pattern: RegExp;
  language: string[];
  title: string;
  description: string;
  severity: "critical" | "high" | "medium";
  remediation: string;
}> = [
  // JavaScript / TypeScript
  {
    pattern: /\bexec\s*\(\s*`[^`]*\$\{/,
    language: ["js", "ts", "mjs", "cjs"],
    title: "Template literal in exec() call",
    description:
      "User input concatenated into a shell exec() call via template literal. This allows arbitrary command execution.",
    severity: "critical",
    remediation:
      "Use execFile() with an argument array instead of exec() with a string. Never pass user input directly to shell commands.",
  },
  {
    pattern: /\bexec\s*\(\s*(?:req|input|args?|params?|body|query|data|tool|cmd|command)\./,
    language: ["js", "ts", "mjs", "cjs"],
    title: "User-controlled input in exec()",
    description:
      "exec() called with what appears to be user-controlled input. This likely allows command injection.",
    severity: "critical",
    remediation:
      "Use execFile() with a fixed command and sanitized argument array. Validate and whitelist all inputs.",
  },
  {
    pattern: /\bspawn\s*\(\s*`[^`]*\$\{/,
    language: ["js", "ts", "mjs", "cjs"],
    title: "Template literal in spawn() call",
    description:
      "Template literal with interpolation used as spawn() command argument.",
    severity: "high",
    remediation:
      "Pass arguments as an array to spawn(), not as a shell-interpolated string.",
  },
  {
    pattern: /\beval\s*\(/,
    language: ["js", "ts", "mjs", "cjs"],
    title: "eval() usage",
    description:
      "eval() executes arbitrary JavaScript. If any user input reaches this call, it allows code injection.",
    severity: "high",
    remediation:
      "Remove eval() usage. If dynamic execution is needed, use safer alternatives like Function constructors with strict input validation, or restructure the logic.",
  },
  {
    pattern: /new\s+Function\s*\(/,
    language: ["js", "ts", "mjs", "cjs"],
    title: "Dynamic Function constructor",
    description:
      "new Function() creates executable code from strings, similar to eval(). Dangerous if user input reaches it.",
    severity: "high",
    remediation:
      "Audit all inputs to new Function(). Prefer static code over dynamic code generation.",
  },
  {
    pattern: /child_process\b(?!.*execFile)/,
    language: ["js", "ts", "mjs", "cjs"],
    title: "child_process module import (non-execFile)",
    description:
      "child_process is imported without using execFile(). exec() and spawn() with shell:true are common injection vectors.",
    severity: "medium",
    remediation:
      "Prefer execFile() over exec(). Never use { shell: true } with user-controlled input.",
  },
  // Python
  {
    pattern: /\bos\.system\s*\(/,
    language: ["py"],
    title: "os.system() usage",
    description:
      "os.system() passes arguments to a shell. Any user input in the command string allows command injection.",
    severity: "critical",
    remediation:
      "Use subprocess.run() with a list of arguments and shell=False (the default).",
  },
  {
    pattern: /\bsubprocess\.[a-z]+\s*\(.*shell\s*=\s*True/,
    language: ["py"],
    title: "subprocess with shell=True",
    description:
      "subprocess called with shell=True. This passes the command to /bin/sh, allowing injection via shell metacharacters.",
    severity: "critical",
    remediation:
      "Remove shell=True. Pass the command as a list: subprocess.run(['cmd', 'arg1', 'arg2']).",
  },
  {
    pattern: /\beval\s*\(/,
    language: ["py"],
    title: "eval() usage",
    description:
      "Python eval() executes arbitrary code. If any user input reaches this, it allows code injection.",
    severity: "high",
    remediation:
      "Replace eval() with ast.literal_eval() for data parsing, or restructure to avoid dynamic execution.",
  },
  {
    pattern: /\bexec\s*\(/,
    language: ["py"],
    title: "exec() usage",
    description:
      "Python exec() executes arbitrary code strings. Dangerous if any user input can reach it.",
    severity: "high",
    remediation:
      "Remove exec() usage. If dynamic execution is needed, use a sandboxed environment.",
  },
];

/** Patterns indicating dangerous MCP server command configurations */
const DANGEROUS_COMMAND_PATTERNS: Array<{
  pattern: RegExp;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium";
  remediation: string;
}> = [
  {
    // Shell interpreters as MCP server command
    pattern: /^(sh|bash|zsh|fish|cmd|powershell|pwsh|python|node|ruby|perl)$/,
    title: "Shell interpreter as MCP server command",
    description:
      "MCP server runs a shell interpreter directly. This provides maximum attack surface for command injection via tool arguments.",
    severity: "high",
    remediation:
      "Use a specific application binary as the command, not a shell interpreter. The application should validate all inputs.",
  },
  {
    // Wildcards in args
    pattern: /[*?]|\.\.\//,
    title: "Wildcard or path traversal in server args",
    description:
      "Server arguments contain wildcards (*?) or path traversal sequences (../). These may allow filesystem access beyond intended boundaries.",
    severity: "high",
    remediation:
      "Remove wildcards and path traversal from server configuration. Use absolute paths.",
  },
];

/** File extensions we can scan */
const SCANNABLE_EXTENSIONS = new Set([
  "js", "ts", "mjs", "cjs", "py", "rb", "go",
]);

function getExtension(filePath: string): string {
  return filePath.split(".").pop()?.toLowerCase() ?? "";
}

export function scanSourceFileForCommandInjection(
  filePath: string,
  serverName: string
): Finding[] {
  const findings: Finding[] = [];
  const ext = getExtension(filePath);

  if (!SCANNABLE_EXTENSIONS.has(ext)) {
    return findings;
  }

  let content: string;
  try {
    content = readFileSync(filePath, "utf-8");
  } catch {
    return findings;
  }

  const lines = content.split("\n");

  for (const check of SHELL_EXECUTION_PATTERNS) {
    if (!check.language.includes(ext)) continue;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const match = line.match(check.pattern);
      if (match) {
        findings.push({
          rule: "command-injection/source-pattern",
          title: check.title,
          description: check.description,
          severity: check.severity,
          location: {
            source: filePath,
            line: i + 1,
            field: "source_code",
            snippet: line.trim().slice(0, 200),
          },
          owasp: "A03:2025 - Insufficient Input/Output Validation",
          cve: [],
          remediation: check.remediation,
        });
      }
    }
  }

  return findings;
}

export function scanServerConfigForCommandInjection(
  server: MCPServer
): Finding[] {
  const findings: Finding[] = [];

  if (!server.command) return findings;

  // Check the command itself
  const commandBase = server.command.split("/").pop() ?? server.command;
  for (const check of DANGEROUS_COMMAND_PATTERNS) {
    if (check.pattern.test(commandBase)) {
      findings.push({
        rule: "command-injection/server-command",
        title: check.title,
        description: `${check.description} (server: ${server.name}, command: ${server.command})`,
        severity: check.severity,
        location: {
          source: server.name,
          field: "command",
          snippet: server.command,
        },
        owasp: "A03:2025 - Insufficient Input/Output Validation",
        remediation: check.remediation,
      });
    }
  }

  // Check args for path traversal and wildcards
  for (const arg of server.args ?? []) {
    for (const check of DANGEROUS_COMMAND_PATTERNS) {
      if (check.pattern.test(arg)) {
        findings.push({
          rule: "command-injection/server-args",
          title: `${check.title} (in args)`,
          description: `${check.description} (server: ${server.name}, arg: ${arg})`,
          severity: check.severity,
          location: {
            source: server.name,
            field: "args",
            snippet: arg,
          },
          owasp: "A03:2025 - Insufficient Input/Output Validation",
          remediation: check.remediation,
        });
      }
    }
  }

  return findings;
}
