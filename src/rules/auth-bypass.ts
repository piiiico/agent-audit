/**
 * Auth Bypass Detection
 *
 * Detects authentication bypass vulnerabilities in MCP servers.
 * 13% of MCP CVEs filed Jan-Feb 2026 were auth bypass issues.
 *
 * References:
 * - OWASP Agentic AI Top 10: A05 - Excessive Permissions / A09 - Misinformation
 * - OWASP Top 10 API: A02:2023 - Broken Authentication
 */

import { readFileSync } from "fs";
import type { MCPServer, Finding } from "../types.js";

/** Hardcoded credential patterns */
const HARDCODED_CREDENTIAL_PATTERNS: Array<{
  pattern: RegExp;
  title: string;
  severity: "critical" | "high";
}> = [
  {
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'](?!.*\$\{)[^"']{4,}["']/i,
    title: "Hardcoded password",
    severity: "critical",
  },
  {
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["'][A-Za-z0-9+/=_\-]{8,}["']/i,
    title: "Hardcoded API key",
    severity: "critical",
  },
  {
    pattern: /(?:secret|token|bearer)\s*[:=]\s*["'][A-Za-z0-9+/=_\-.]{12,}["']/i,
    title: "Hardcoded secret or token",
    severity: "critical",
  },
  {
    pattern: /(?:private[_-]?key|client[_-]?secret)\s*[:=]\s*["'][^"']{8,}["']/i,
    title: "Hardcoded private key or client secret",
    severity: "critical",
  },
  {
    // AWS-style keys
    pattern: /AKIA[0-9A-Z]{16}/,
    title: "AWS Access Key ID detected",
    severity: "critical",
  },
  {
    // GitHub personal access token
    pattern: /gh[pousr]_[A-Za-z0-9]{36,}/,
    title: "GitHub token detected",
    severity: "critical",
  },
  {
    // npm token
    pattern: /npm_[A-Za-z0-9]{36}/,
    title: "npm token detected",
    severity: "critical",
  },
];

/** Auth bypass code patterns */
const AUTH_BYPASS_PATTERNS: Array<{
  pattern: RegExp;
  language: string[];
  title: string;
  description: string;
  severity: "critical" | "high" | "medium";
  remediation: string;
}> = [
  {
    // Commented-out auth function call (JS/TS).
    // Requires code-like syntax: commented-out function invocation of a known auth function.
    // Matches:  // await checkAuth(req)
    //           // verifyToken(token)
    //           // authMiddleware(req, res, next)
    // Does NOT match: // No auth concept here   // Start authorization flow   // auth callback path
    pattern: /\/\/\s*(?:await\s+)?(?:check(?:Auth|Authentication|Authorization|Token|Session|Permission)|verify(?:Token|Auth|Session|Identity|Access)|authenticate(?:User|Request)?|authorize(?:User|Request)?|require(?:Auth|Login|Permission|Role)|validate(?:Token|Auth|Session|Credential)|auth(?:Middleware|Guard|Handler|Check|Filter|Interceptor)|isAuthenticated|isAuthorized|ensureAuthenticated|passport\.authenticate)\s*\(/i,
    language: ["js", "ts", "mjs", "cjs"],
    title: "Commented-out authentication check",
    description:
      "An authentication function call appears to be commented out. This may indicate a temporarily disabled security control.",
    severity: "high",
    remediation:
      "Restore the authentication check. Never ship code with commented-out security controls.",
  },
  {
    // Commented-out auth function call (Python).
    // Same logic as JS/TS variant but for # comments.
    pattern: /#\s*(?:await\s+)?(?:check_?(?:auth|authentication|authorization|token|session|permission)|verify_?(?:token|auth|session|identity|access)|authenticate(?:_user|_request)?|authorize(?:_user|_request)?|require_?(?:auth|login|permission|role)|validate_?(?:token|auth|session|credential)|auth_?(?:middleware|guard|handler|check|filter)|is_?authenticated|is_?authorized|ensure_?authenticated)\s*\(/i,
    language: ["py"],
    title: "Commented-out authentication check (Python)",
    description:
      "An authentication function call appears to be commented out in Python code.",
    severity: "high",
    remediation:
      "Restore the authentication check. Never deploy code with commented-out security controls.",
  },
  {
    // Explicit auth bypass / skip comment (JS/TS).
    // Matches intentional bypass language like "// TODO: add auth" or "// disabled auth for now".
    // Does NOT match prose like "no auth concept" — requires unambiguous bypass verbs.
    pattern: /\/\/.*(?:skip(?:ping)?|disabl(?:ed?|ing)|bypass(?:ing|ed)?|remov(?:ed?|ing)|TODO|FIXME|HACK|XXX)\s+(?:auth(?:entication|orization)?|login\s+check|token\s+(?:verif|check|validat))/i,
    language: ["js", "ts", "mjs", "cjs"],
    title: "Intentional authentication bypass comment",
    description:
      "A comment explicitly indicates authentication is being skipped, disabled, or bypassed.",
    severity: "high",
    remediation:
      "Restore proper authentication. Never deploy with intentional auth bypasses.",
  },
  {
    // Explicit auth bypass / skip comment (Python).
    pattern: /#.*(?:skip(?:ping)?|disabl(?:ed?|ing)|bypass(?:ing|ed)?|remov(?:ed?|ing)|TODO|FIXME|HACK|XXX)\s+(?:auth(?:entication|orization)?|login\s+check|token\s+(?:verif|check|validat))/i,
    language: ["py"],
    title: "Intentional authentication bypass comment (Python)",
    description:
      "A comment explicitly indicates authentication is being skipped, disabled, or bypassed.",
    severity: "high",
    remediation:
      "Restore proper authentication. Never deploy with intentional auth bypasses.",
  },
  {
    // if (false) or always-false auth check
    pattern: /if\s*\(\s*false\s*\)|if\s*\(0\)/,
    language: ["js", "ts", "mjs", "cjs"],
    title: "Always-false conditional (possible auth bypass)",
    description:
      "Code contains if(false) or if(0) which permanently disables the block. If this block contains a security check, it is bypassed.",
    severity: "high",
    remediation:
      "Review why this condition is hardcoded to false. Restore proper conditional logic.",
  },
  {
    // Token validation disabled
    pattern: /verify\s*=\s*false|ssl[_-]?verify\s*=\s*false|verify_ssl\s*=\s*false/i,
    language: ["js", "ts", "mjs", "cjs", "py"],
    title: "SSL/TLS verification disabled",
    description:
      "SSL certificate verification is explicitly disabled. This makes the connection vulnerable to man-in-the-middle attacks.",
    severity: "high",
    remediation:
      "Enable SSL verification. If you need to trust a custom CA, use the ca option instead of disabling verification.",
  },
  {
    // No auth on all routes
    pattern: /app\.use\s*\(\s*['"]\/['"]\s*,.*route|router\.all\s*\(\s*['"]\/\*['"]/,
    language: ["js", "ts", "mjs", "cjs"],
    title: "Catch-all route without visible authentication middleware",
    description:
      "A route handler that matches all paths is defined. Verify authentication middleware is applied before it.",
    severity: "medium",
    remediation:
      "Ensure authentication middleware is applied to all MCP routes. Prefer allowlisting authenticated routes over blocklisting.",
  },
];

/** Check for env variables used as secrets (acceptable) vs hardcoded (bad) */
const ENV_VAR_PATTERN = /process\.env\.[A-Z_]+|os\.environ|getenv/;

/**
 * Test/example file path patterns to exclude from commented-out auth checks.
 * These files commonly contain auth function names in describe/it blocks, mock setups,
 * and documentation comments — not real bypasses.
 */
const TEST_FILE_PATTERNS = [
  /\.(test|spec)\.[jt]sx?$/i,
  /\/(test|tests|__tests__|__mocks__|fixtures|examples?|demo|docs?)\//i,
  /\/(test|tests|__tests__|__mocks__|fixtures|examples?|demo|docs?)\/?$/i,
];

function isTestOrExampleFile(filePath: string): boolean {
  return TEST_FILE_PATTERNS.some((p) => p.test(filePath));
}

function getExtension(filePath: string): string {
  return filePath.split(".").pop()?.toLowerCase() ?? "";
}

export function scanSourceFileForAuthBypass(
  filePath: string,
  serverName: string
): Finding[] {
  const findings: Finding[] = [];
  const ext = getExtension(filePath);

  const scannable = new Set(["js", "ts", "mjs", "cjs", "py", "rb"]);
  if (!scannable.has(ext)) return findings;

  let content: string;
  try {
    content = readFileSync(filePath, "utf-8");
  } catch {
    return findings;
  }

  const lines = content.split("\n");
  const isTestFile = isTestOrExampleFile(filePath);

  // Check for hardcoded credentials
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip lines that use environment variables (those are fine)
    if (ENV_VAR_PATTERN.test(line)) continue;

    for (const check of HARDCODED_CREDENTIAL_PATTERNS) {
      const match = line.match(check.pattern);
      if (match) {
        // Redact the actual credential in the snippet
        const redacted = line.replace(match[0], match[0].slice(0, 10) + "...[REDACTED]");
        findings.push({
          rule: "auth-bypass/hardcoded-credentials",
          title: check.title,
          description: `Hardcoded credential found in source file. This credential is embedded in the code and will be exposed in source control.`,
          severity: check.severity,
          location: {
            source: filePath,
            line: i + 1,
            field: "source_code",
            snippet: redacted.trim().slice(0, 200),
          },
          owasp: "A07:2025 - Insecure Credential Storage",
          remediation:
            "Move credentials to environment variables or a secrets manager. Never commit credentials to source control.",
        });
      }
    }

    // Check for auth bypass patterns
    // Skip commented-out-code patterns in test/example files to avoid FPs from
    // test describe blocks, mock setups, and documentation examples.
    for (const check of AUTH_BYPASS_PATTERNS) {
      if (!check.language.includes(ext)) continue;
      // Skip commented-out auth patterns in test/example/docs files
      if (
        isTestFile &&
        (check.title.includes("Commented-out") || check.title.includes("Intentional"))
      ) {
        continue;
      }
      const match = line.match(check.pattern);
      if (match) {
        findings.push({
          rule: "auth-bypass/source-pattern",
          title: check.title,
          description: check.description,
          severity: check.severity,
          location: {
            source: filePath,
            line: i + 1,
            field: "source_code",
            snippet: line.trim().slice(0, 200),
          },
          owasp: "A05:2025 - Broken Access Control",
          remediation: check.remediation,
        });
      }
    }
  }

  return findings;
}

/** Check server env configuration for exposed secrets */
export function scanServerEnvForSecrets(server: MCPServer): Finding[] {
  const findings: Finding[] = [];

  if (!server.env) return findings;

  for (const [key, value] of Object.entries(server.env)) {
    // Flag if the value looks like a real secret (not a placeholder/variable reference)
    const looksLikeSecret =
      key.match(/(?:key|secret|token|password|credential|auth)/i) &&
      !value.startsWith("$") &&
      !value.startsWith("${") &&
      value.length > 8;

    if (looksLikeSecret) {
      findings.push({
        rule: "auth-bypass/env-secret-in-config",
        title: "Secret value hardcoded in MCP server config",
        description: `Environment variable '${key}' in server '${server.name}' appears to contain a hardcoded secret value. MCP configs are typically stored in plaintext at ~/.config/claude/.`,
        severity: "high",
        location: {
          source: server.name,
          field: `env.${key}`,
          snippet: `${key}=${value.slice(0, 4)}...[REDACTED]`,
        },
        owasp: "A07:2025 - Insecure Credential Storage",
        remediation:
          "Use a shell variable reference ($MY_SECRET) or a secrets manager instead of hardcoding values in the MCP config file. The config file is stored in plaintext.",
      });
    }
  }

  return findings;
}
