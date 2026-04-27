/**
 * Database Safety Detection
 *
 * Detects MCP tools that expose dangerous database operations without safeguards.
 * Inspired by the "AI agent deleted our production database" incident (Apr 2026,
 * 429pts HN) — caused by an agent with unscoped database write access.
 *
 * References:
 * - OWASP Agentic AI Top 10: A05 - Excessive Agency / Permissions
 * - HN: "AI agent deleted our production database" (front page Apr 27 2026)
 */

import type { MCPTool, MCPServer, Finding } from "../types.js";

/** Patterns indicating database write/mutation operations */
const DB_WRITE_PATTERNS =
  /\b(?:write|insert|update|delete|drop|truncate|alter|create|upsert|replace|put|set|save|modify|mutate|execute|exec|run_query|execute_sql|run_sql)\b/i;

/** Patterns indicating destructive operations that cannot be undone */
const DB_DESTRUCTIVE_PATTERNS =
  /\b(?:drop|truncate|delete.?all|wipe|reset|destroy|purge|nuke|erase|clear.?table|remove.?all)\b/i;

/** Patterns indicating read-only / safe access */
const READONLY_PATTERNS =
  /\b(?:read.?only|readonly|select.?only|read_only|immutable|non.?mut|no.?write)\b/i;

/** Patterns indicating user confirmation is required */
const CONFIRMATION_PATTERNS =
  /\b(?:confirm|confirmation|approve|approval|review|authorize|authorization|verify|double.?check|human.?in.?the.?loop|require_approval)\b/i;

/** Patterns for tools that accept arbitrary/generic SQL queries */
const ARBITRARY_SQL_PATTERNS =
  /\b(?:query|execute|exec|run_query|execute_sql|run_sql|arbitrary|raw.?sql|raw.?query|sql.?string|query.?string)\b/i;

/** Whether a tool is database-related */
function isDatabaseTool(tool: MCPTool): boolean {
  const text = `${tool.name} ${tool.description ?? ""}`;
  return /\b(?:database|db|sql|postgres|mysql|sqlite|mongo|redis|dynamo|cassandra|query|table|schema|record|row)\b/i.test(
    text
  );
}

/** Whether a tool has write/mutation capabilities */
function isWriteTool(tool: MCPTool): boolean {
  const text = `${tool.name} ${tool.description ?? ""}`;
  return DB_WRITE_PATTERNS.test(text);
}

/** Stringify inputSchema for pattern checks */
function schemaText(tool: MCPTool): string {
  if (!tool.inputSchema) return "";
  try {
    return JSON.stringify(tool.inputSchema);
  } catch {
    return "";
  }
}

/**
 * Scan a single tool for database safety issues.
 * Returns per-tool findings.
 */
export function scanToolForDatabaseSafety(
  tool: MCPTool,
  server: MCPServer
): Finding[] {
  const findings: Finding[] = [];
  const toolText = `${tool.name} ${tool.description ?? ""}`;

  // ── Rule 1: database-write-without-readonly ──────────────────────────────
  // DB write tool with no read-only flag anywhere in name, description, or schema
  if (isDatabaseTool(tool) && isWriteTool(tool) && !READONLY_PATTERNS.test(toolText)) {
    findings.push({
      rule: "database-safety/database-write-without-readonly",
      title: "Database tool allows mutations without read-only mode",
      description: `Tool '${tool.name}' in server '${server.name}' allows database mutations (write/insert/update/delete/etc.) but declares no read-only mode or flag. An agent with this tool can modify data without any safe-mode constraint.`,
      severity: "critical",
      location: {
        source: server.name,
        field: `tools.${tool.name}`,
        snippet: (tool.description ?? tool.name).slice(0, 200),
      },
      owasp: "A05:2025 - Excessive Agency",
      remediation:
        "Add a read_only parameter (default: true) that must be explicitly set to false for writes. Consider splitting into separate read and write tools.",
    });
  }

  // ── Rule 2: database-destructive-operations ──────────────────────────────
  // Tool exposes DROP, TRUNCATE, DELETE ALL, or equivalent
  if (DB_DESTRUCTIVE_PATTERNS.test(toolText)) {
    findings.push({
      rule: "database-safety/database-destructive-operations",
      title: "Database tool exposes destructive operations (DROP, TRUNCATE, DELETE ALL)",
      description: `Tool '${tool.name}' in server '${server.name}' exposes destructive database operations. These cannot be undone — an agent (or prompt injector) invoking this tool can cause irreversible data loss.`,
      severity: "critical",
      location: {
        source: server.name,
        field: `tools.${tool.name}`,
        snippet: (tool.description ?? tool.name).slice(0, 200),
      },
      owasp: "A05:2025 - Excessive Agency",
      remediation:
        "Remove destructive operations from agent-accessible tools entirely, or gate them behind explicit human confirmation and backup verification.",
    });
  }

  // ── Rule 4: unscoped-database-access ────────────────────────────────────
  // Tool accepts arbitrary SQL queries (generic query/execute tools)
  if (
    isDatabaseTool(tool) &&
    ARBITRARY_SQL_PATTERNS.test(tool.name) &&
    tool.inputSchema
  ) {
    const schema = schemaText(tool);
    const hasAllowlist =
      /\b(?:allowlist|allow_list|whitelist|white_list|permitted|allowed.?queries|allowed.?operations)\b/i.test(
        schema + toolText
      );
    if (!hasAllowlist) {
      findings.push({
        rule: "database-safety/unscoped-database-access",
        title: "Tool accepts arbitrary database queries without scope restriction",
        description: `Tool '${tool.name}' in server '${server.name}' accepts arbitrary SQL/queries with no allowlist restriction. Any SQL statement — including DROP TABLE, DELETE FROM, or data exfiltration queries — can be passed directly to the database.`,
        severity: "critical",
        location: {
          source: server.name,
          field: `tools.${tool.name}.inputSchema`,
          snippet: schema.slice(0, 200),
        },
        owasp: "A05:2025 - Excessive Agency",
        remediation:
          "Replace arbitrary query execution with scoped, purpose-built tools (e.g., get_user_by_id). If a query tool is required, implement an operation allowlist and use parameterized queries exclusively.",
      });
    }
  }

  return findings;
}

/**
 * Scan a server-level for database safety issues.
 * Returns server-level findings (e.g., multiple write tools without confirmation).
 */
export function scanServerForDatabaseSafety(server: MCPServer): Finding[] {
  const findings: Finding[] = [];

  if (!server.tools || server.tools.length === 0) return findings;

  // ── Rule 3: database-no-confirmation ────────────────────────────────────
  // More than 1 DB write tool, and none of them require confirmation
  const dbWriteTools = server.tools.filter(
    (t) => isDatabaseTool(t) && isWriteTool(t)
  );

  if (dbWriteTools.length > 1) {
    const anyHasConfirmation = dbWriteTools.some((t) => {
      const text = `${t.name} ${t.description ?? ""} ${schemaText(t)}`;
      return CONFIRMATION_PATTERNS.test(text);
    });

    if (!anyHasConfirmation) {
      findings.push({
        rule: "database-safety/database-no-confirmation",
        title: "Multiple database write tools without confirmation flow",
        description: `Server '${server.name}' exposes ${dbWriteTools.length} database write tools (${dbWriteTools.map((t) => t.name).join(", ")}) with no confirmation or approval step in any of them. A manipulated agent can chain these tools to make large-scale irreversible changes without human oversight.`,
        severity: "critical",
        location: {
          source: server.name,
          field: "tools",
          snippet: dbWriteTools.map((t) => t.name).join(", "),
        },
        owasp: "A05:2025 - Excessive Agency",
        remediation:
          "Add a confirmation parameter to each write tool, or introduce a separate confirm_operation tool that must be called before any mutation is applied. Implement human-in-the-loop for bulk or destructive operations.",
      });
    }
  }

  return findings;
}
