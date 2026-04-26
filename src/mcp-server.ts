#!/usr/bin/env node
/**
 * agent-audit MCP Server
 *
 * Exposes agent-audit security scanning capabilities as an MCP server,
 * allowing Claude Desktop and other MCP clients to audit configs directly.
 *
 * Usage (add to Claude Desktop config):
 *   "agent-audit": {
 *     "command": "npx",
 *     "args": ["-y", "@piiiico/agent-audit", "--mcp"]
 *   }
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  findDefaultConfig,
  findAllConfigs,
  parseAnyConfig,
  parseClaudeDesktopConfig,
} from "./parsers/mcp-config.js";
import { scan } from "./scanner.js";
import type { MCPServer, Severity } from "./types.js";

const VERSION = "0.3.4";

const server = new Server(
  { name: "agent-audit", version: VERSION },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "audit_config",
      description:
        "Scan an MCP server configuration file for security vulnerabilities. " +
        "Use this tool to audit a specific config file path, or let it auto-detect the Claude Desktop configuration when no path is provided. " +
        "Checks each configured MCP server for: prompt injection patterns in tool descriptions, command injection in server source code, hardcoded secrets in environment variables, and excessive permissions (shell execution, filesystem access). " +
        "Returns a structured security report with findings grouped by severity (critical/high/medium/low/info). Each finding includes the vulnerable location, a code snippet, OWASP category, and remediation guidance. " +
        "Use this when auditing a single config file. Use audit_all_configs instead when you want to scan all detected configs at once.",
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description:
              "Path to the MCP config file to scan (Claude Desktop JSON format or Cursor mcp.json). If omitted, auto-detects the Claude Desktop configuration from default OS locations.",
          },
          min_severity: {
            type: "string",
            enum: ["critical", "high", "medium", "low", "info"],
            description:
              "Minimum severity level to include in the report. Use 'critical' to see only the most serious issues, 'low' (default) for a comprehensive report, or 'info' for all findings.",
          },
          skip_source_scan: {
            type: "boolean",
            description:
              "Set to true to skip scanning server source files for command injection patterns, returning results faster. Default is false (full scan including source analysis).",
          },
        },
        required: [],
        additionalProperties: false,
      },
    },
    {
      name: "audit_all_configs",
      description:
        "Scan all detected MCP configuration files (Claude Desktop and Cursor) for security vulnerabilities in a single operation. " +
        "Automatically discovers config files in standard OS locations, scans all configured MCP servers in each file, and combines the results into one report. " +
        "Each finding includes severity, the vulnerable location, a code snippet, and remediation guidance. " +
        "Use this for a comprehensive security audit across all MCP configurations without specifying individual paths. " +
        "Use audit_config instead when you only need to scan a specific file or a non-standard config location.",
      inputSchema: {
        type: "object",
        properties: {
          min_severity: {
            type: "string",
            enum: ["critical", "high", "medium", "low", "info"],
            description:
              "Minimum severity level to include in the combined report. Defaults to 'low' (comprehensive). Use 'critical' or 'high' for CI/CD pipelines where you only care about blocking issues.",
          },
        },
        required: [],
        additionalProperties: false,
      },
    },
    {
      name: "scan_server",
      description:
        "Scan a single MCP server definition for security vulnerabilities without requiring a full configuration file. " +
        "Provide the server's command, arguments, and environment variables directly to evaluate it before adding it to your MCP config. " +
        "Performs the same security checks as audit_config but for a single inline server definition. Source file scanning is skipped for speed. " +
        "Use this when evaluating an unfamiliar MCP server before trusting it, or when testing a server definition that is not yet in a config file. " +
        "Use audit_config or audit_all_configs when the server is already in a config file.",
      inputSchema: {
        type: "object",
        properties: {
          name: {
            type: "string",
            description:
              "A label for this server used to identify findings in the results. Required.",
          },
          command: {
            type: "string",
            description:
              "The executable to run the server, e.g. 'npx', 'node', or 'python'. For HTTP servers, omit this and use 'url' instead.",
          },
          args: {
            type: "array",
            items: { type: "string" },
            description:
              "Command-line arguments passed to the executable, e.g. ['-y', '@some/mcp-server']. The tool scans these for injection patterns.",
          },
          env: {
            type: "object",
            description:
              "Environment variables passed to the server process, e.g. {\"API_KEY\": \"...\"}. The tool checks these for hardcoded secrets.",
            additionalProperties: { type: "string" },
          },
          url: {
            type: "string",
            description:
              "Base URL for HTTP-based (SSE or streamable) MCP servers. Use this instead of 'command' for remote servers.",
          },
        },
        required: ["name"],
        additionalProperties: false,
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    if (name === "audit_config") {
      const configPath = args?.path as string | undefined;
      const minSeverity = (args?.min_severity as Severity) || "low";
      const skipSourceScan = (args?.skip_source_scan as boolean) || false;

      let servers: MCPServer[];
      let target: string;

      if (configPath) {
        servers = await parseAnyConfig(configPath);
        target = configPath;
      } else {
        const detected = findDefaultConfig();
        if (!detected) {
          return {
            content: [
              {
                type: "text",
                text: "No MCP config file detected. Provide a path or ensure Claude Desktop is installed.",
              },
            ],
            isError: true,
          };
        }
        servers = await parseAnyConfig(detected);
        target = detected;
      }

      const result = await scan(servers, target, {
        minSeverity,
        skipSourceScan,
      });

      return {
        content: [
          {
            type: "text",
            text: formatScanResult(result),
          },
        ],
      };
    }

    if (name === "audit_all_configs") {
      const minSeverity = (args?.min_severity as Severity) || "low";
      const configs = findAllConfigs();

      if (configs.length === 0) {
        return {
          content: [
            {
              type: "text",
              text: "No MCP config files detected. Install Claude Desktop or Cursor.",
            },
          ],
          isError: true,
        };
      }

      const results = [];
      for (const configPath of configs) {
        const servers = await parseAnyConfig(configPath);
        const result = await scan(servers, configPath, { minSeverity });
        results.push(result);
      }

      const combined = results.map((r) => formatScanResult(r)).join("\n\n---\n\n");
      return {
        content: [
          {
            type: "text",
            text: `Scanned ${configs.length} config(s):\n\n${combined}`,
          },
        ],
      };
    }

    if (name === "scan_server") {
      const serverDef: MCPServer = {
        name: args?.name as string,
        command: args?.command as string | undefined,
        args: args?.args as string[] | undefined,
        env: args?.env as Record<string, string> | undefined,
        url: args?.url as string | undefined,
      };

      const result = await scan([serverDef], `server:${serverDef.name}`, {
        skipSourceScan: true,
      });

      return {
        content: [
          {
            type: "text",
            text: formatScanResult(result),
          },
        ],
      };
    }

    return {
      content: [{ type: "text", text: `Unknown tool: ${name}` }],
      isError: true,
    };
  } catch (err) {
    return {
      content: [{ type: "text", text: `Error: ${err}` }],
      isError: true,
    };
  }
});

function formatScanResult(result: ReturnType<typeof scan> extends Promise<infer T> ? T : never): string {
  const { target, findings, summary, durationMs } = result;
  const total = Object.values(summary).reduce((a, b) => a + b, 0);

  if (total === 0) {
    return `✅ No findings in ${target} (scanned in ${durationMs}ms)`;
  }

  const lines = [
    `🔍 Scan results for: ${target}`,
    `⏱  Duration: ${durationMs}ms`,
    `📊 Summary: ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low, ${summary.info} info`,
    "",
  ];

  for (const finding of findings) {
    const icon =
      finding.severity === "critical"
        ? "🔴"
        : finding.severity === "high"
        ? "🟠"
        : finding.severity === "medium"
        ? "🟡"
        : finding.severity === "low"
        ? "🔵"
        : "⚪";
    lines.push(`${icon} [${finding.severity.toUpperCase()}] ${finding.title}`);
    lines.push(`   Rule: ${finding.rule}`);
    lines.push(`   Location: ${finding.location.source}${finding.location.field ? ` > ${finding.location.field}` : ""}`);
    if (finding.location.snippet) {
      lines.push(`   Snippet: ${finding.location.snippet.slice(0, 100)}`);
    }
    lines.push(`   ${finding.description}`);
    if (finding.remediation) {
      lines.push(`   Fix: ${finding.remediation}`);
    }
    if (finding.owasp) {
      lines.push(`   OWASP: ${finding.owasp}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

export async function startMcpServer() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`agent-audit MCP server v${VERSION} started\n`);
}

// Run as standalone entry point (only when executed directly, not imported)
const isDirectRun =
  process.argv[1]?.endsWith("mcp-server.js") ||
  process.argv[1]?.endsWith("mcp-server.ts") ||
  process.argv[1]?.endsWith("agent-audit-mcp");

if (isDirectRun) {
  startMcpServer().catch((err) => {
    process.stderr.write(`Fatal: ${err}\n`);
    process.exit(1);
  });
}

// Smithery sandbox export — allows Smithery to scan available tools
export function createSandboxServer() {
  return server;
}

export default createSandboxServer;
