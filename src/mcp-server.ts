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

const VERSION = "0.3.2";

const server = new Server(
  { name: "agent-audit", version: VERSION },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "audit_config",
      description:
        "Scan an MCP config file for security vulnerabilities. If no path is provided, auto-detects Claude Desktop config. Returns a JSON security report with findings grouped by severity.",
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description:
              "Optional path to MCP config file (Claude Desktop JSON or Cursor mcp.json). If omitted, auto-detects Claude Desktop config.",
          },
          min_severity: {
            type: "string",
            enum: ["critical", "high", "medium", "low", "info"],
            description: "Minimum severity to report (default: low)",
          },
          skip_source_scan: {
            type: "boolean",
            description:
              "Skip source file scanning for faster results (default: false)",
          },
        },
        required: [],
      },
    },
    {
      name: "audit_all_configs",
      description:
        "Scan all detected MCP configs (Claude Desktop + Cursor) for security vulnerabilities. Returns a combined JSON report.",
      inputSchema: {
        type: "object",
        properties: {
          min_severity: {
            type: "string",
            enum: ["critical", "high", "medium", "low", "info"],
            description: "Minimum severity to report (default: low)",
          },
        },
        required: [],
      },
    },
    {
      name: "scan_server",
      description:
        "Scan a specific MCP server definition for security issues. Useful for testing a single server before adding it to your config.",
      inputSchema: {
        type: "object",
        properties: {
          name: {
            type: "string",
            description: "Server name (for display in results)",
          },
          command: {
            type: "string",
            description: "Command to run the server (e.g. 'npx', 'node')",
          },
          args: {
            type: "array",
            items: { type: "string" },
            description: "Command arguments (e.g. ['-y', 'some-mcp-server'])",
          },
          env: {
            type: "object",
            description: "Environment variables for the server",
            additionalProperties: { type: "string" },
          },
          url: {
            type: "string",
            description: "URL for HTTP-based MCP servers",
          },
        },
        required: ["name"],
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
