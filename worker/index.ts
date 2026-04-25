/**
 * agent-audit MCP Server — Cloudflare Worker
 *
 * Implements MCP Streamable HTTP transport (2025-03-26 spec).
 * Stateless — no session management needed.
 *
 * POST /mcp  → JSON-RPC request → JSON-RPC response
 * GET  /mcp  → SSE (not implemented — no server-initiated notifications)
 * GET  /     → Health check / info page
 */

// Import directly from individual rule files to avoid pulling in fs-dependent modules
import { scanToolForPromptInjection } from "../src/rules/prompt-injection.js";
import {
  scanServerConfigForCommandInjection,
} from "../src/rules/command-injection.js";
import { scanServerEnvForSecrets } from "../src/rules/auth-bypass.js";
import {
  scanToolForExcessivePermissions,
  scanServerForExcessivePermissions,
} from "../src/rules/excessive-permissions.js";
import type { MCPServer, MCPTool, Finding, Severity, ScanResult } from "../src/types.js";

const VERSION = "0.3.3";
const SERVER_INFO = { name: "agent-audit", version: VERSION };

// --- MCP Protocol Types ---

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

// --- Tools Definition ---

const TOOLS = [
  {
    name: "scan_server",
    description:
      "Scan a specific MCP server definition for security issues. Useful for testing a single server before adding it to your config.",
    inputSchema: {
      type: "object" as const,
      properties: {
        name: { type: "string", description: "Server name (for display in results)" },
        command: { type: "string", description: "Command to run the server (e.g. 'npx', 'node')" },
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
        url: { type: "string", description: "URL for HTTP-based MCP servers" },
        tools: {
          type: "array",
          description: "Tool definitions to scan for prompt injection and permission issues",
          items: {
            type: "object",
            properties: {
              name: { type: "string" },
              description: { type: "string" },
              inputSchema: { type: "object" },
            },
          },
        },
      },
      required: ["name"],
    },
  },
  {
    name: "audit_config",
    description:
      "Scan MCP server definitions from a config object for security vulnerabilities. Pass the mcpServers object from your Claude Desktop or Cursor config. Returns a JSON security report with findings grouped by severity.",
    inputSchema: {
      type: "object" as const,
      properties: {
        config: {
          type: "object",
          description:
            'The mcpServers object from your MCP config file. Example: {"my-server": {"command": "npx", "args": ["-y", "some-server"], "env": {"API_KEY": "sk-..."}}}',
          additionalProperties: {
            type: "object",
            properties: {
              command: { type: "string" },
              args: { type: "array", items: { type: "string" } },
              env: { type: "object", additionalProperties: { type: "string" } },
              url: { type: "string" },
            },
          },
        },
        min_severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low", "info"],
          description: "Minimum severity to report (default: low)",
        },
      },
      required: ["config"],
    },
  },
];

// --- Scanner (subset that works without filesystem) ---

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function scanServers(
  servers: MCPServer[],
  target: string,
  minSeverity: Severity = "low"
): ScanResult {
  const start = Date.now();
  const allFindings: Finding[] = [];

  for (const server of servers) {
    allFindings.push(...scanServerConfigForCommandInjection(server));
    allFindings.push(...scanServerEnvForSecrets(server));

    for (const tool of server.tools ?? []) {
      allFindings.push(...scanToolForPromptInjection(tool, server));
      allFindings.push(...scanToolForExcessivePermissions(tool, server));
    }

    allFindings.push(...scanServerForExcessivePermissions(server));
    // Note: source file scanning is not available in the hosted version
  }

  const findings = allFindings
    .filter((f) => SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[minSeverity])
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;

  return {
    timestamp: new Date().toISOString(),
    target,
    findings,
    summary,
    durationMs: Date.now() - start,
  };
}

function formatScanResult(result: ScanResult): string {
  const { target, findings, summary, durationMs } = result;
  const total = Object.values(summary).reduce((a, b) => a + b, 0);

  if (total === 0) return `No findings in ${target} (scanned in ${durationMs}ms)`;

  const lines = [
    `Scan results for: ${target}`,
    `Duration: ${durationMs}ms`,
    `Summary: ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low, ${summary.info} info`,
    "",
  ];

  for (const f of findings) {
    lines.push(`[${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`  Rule: ${f.rule}`);
    lines.push(
      `  Location: ${f.location.source}${f.location.field ? ` > ${f.location.field}` : ""}`
    );
    if (f.location.snippet) lines.push(`  Snippet: ${f.location.snippet.slice(0, 100)}`);
    lines.push(`  ${f.description}`);
    if (f.remediation) lines.push(`  Fix: ${f.remediation}`);
    if (f.owasp) lines.push(`  OWASP: ${f.owasp}`);
    lines.push("");
  }

  return lines.join("\n");
}

// --- JSON-RPC Handlers ---

function handleInitialize(req: JsonRpcRequest): JsonRpcResponse {
  return {
    jsonrpc: "2.0",
    id: req.id ?? null,
    result: {
      protocolVersion: "2025-03-26",
      capabilities: { tools: {} },
      serverInfo: SERVER_INFO,
    },
  };
}

function handleListTools(req: JsonRpcRequest): JsonRpcResponse {
  return {
    jsonrpc: "2.0",
    id: req.id ?? null,
    result: { tools: TOOLS },
  };
}

function handleCallTool(req: JsonRpcRequest): JsonRpcResponse {
  const params = req.params as { name: string; arguments?: Record<string, unknown> };
  const toolName = params?.name;
  const args = params?.arguments ?? {};

  try {
    if (toolName === "scan_server") {
      const serverDef: MCPServer = {
        name: (args.name as string) || "unknown",
        command: args.command as string | undefined,
        args: args.args as string[] | undefined,
        env: args.env as Record<string, string> | undefined,
        url: args.url as string | undefined,
        tools: args.tools as MCPTool[] | undefined,
      };

      const result = scanServers([serverDef], `server:${serverDef.name}`);
      return {
        jsonrpc: "2.0",
        id: req.id ?? null,
        result: {
          content: [{ type: "text", text: formatScanResult(result) }],
        },
      };
    }

    if (toolName === "audit_config") {
      const config = args.config as Record<string, Record<string, unknown>> | undefined;
      const minSeverity = (args.min_severity as Severity) || "low";

      if (!config || typeof config !== "object") {
        return {
          jsonrpc: "2.0",
          id: req.id ?? null,
          result: {
            content: [{ type: "text", text: "Error: 'config' parameter is required. Pass your mcpServers object." }],
            isError: true,
          },
        };
      }

      // Parse config object into MCPServer array
      const servers: MCPServer[] = Object.entries(config).map(([name, def]) => ({
        name,
        command: def.command as string | undefined,
        args: def.args as string[] | undefined,
        env: def.env as Record<string, string> | undefined,
        url: def.url as string | undefined,
        tools: def.tools as MCPTool[] | undefined,
      }));

      const result = scanServers(servers, "config", minSeverity);
      return {
        jsonrpc: "2.0",
        id: req.id ?? null,
        result: {
          content: [{ type: "text", text: formatScanResult(result) }],
        },
      };
    }

    return {
      jsonrpc: "2.0",
      id: req.id ?? null,
      result: {
        content: [{ type: "text", text: `Unknown tool: ${toolName}` }],
        isError: true,
      },
    };
  } catch (err) {
    return {
      jsonrpc: "2.0",
      id: req.id ?? null,
      result: {
        content: [{ type: "text", text: `Error: ${err}` }],
        isError: true,
      },
    };
  }
}

function handleNotification(_req: JsonRpcRequest): null {
  // Notifications (no id) don't get responses
  return null;
}

function routeRequest(req: JsonRpcRequest): JsonRpcResponse | null {
  // Notifications have no id
  if (req.id === undefined || req.id === null) {
    return handleNotification(req);
  }

  switch (req.method) {
    case "initialize":
      return handleInitialize(req);
    case "tools/list":
      return handleListTools(req);
    case "tools/call":
      return handleCallTool(req);
    case "resources/list":
      return { jsonrpc: "2.0", id: req.id, result: { resources: [] } };
    case "prompts/list":
      return { jsonrpc: "2.0", id: req.id, result: { prompts: [] } };
    case "ping":
      return { jsonrpc: "2.0", id: req.id, result: {} };
    default:
      return {
        jsonrpc: "2.0",
        id: req.id,
        error: { code: -32601, message: `Method not found: ${req.method}` },
      };
  }
}

// --- Cloudflare Worker Entry ---

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // CORS headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, Mcp-Session-Id",
      "Access-Control-Expose-Headers": "Mcp-Session-Id",
    };

    // Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // Health check / info
    if (url.pathname === "/" && request.method === "GET") {
      return new Response(
        JSON.stringify({
          name: "agent-audit",
          version: VERSION,
          description: "MCP security scanner — audits MCP server configs for vulnerabilities",
          transport: "streamable-http",
          endpoint: "/mcp",
        }),
        {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // MCP Streamable HTTP endpoint
    if (url.pathname === "/mcp") {
      if (request.method === "POST") {
        const contentType = request.headers.get("content-type") || "";
        if (!contentType.includes("application/json")) {
          return new Response(
            JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Content-Type must be application/json" } }),
            { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        let body: unknown;
        try {
          body = await request.json();
        } catch {
          return new Response(
            JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }),
            { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        // Handle batch requests
        if (Array.isArray(body)) {
          const responses = (body as JsonRpcRequest[])
            .map((req) => routeRequest(req))
            .filter((r): r is JsonRpcResponse => r !== null);

          if (responses.length === 0) {
            return new Response(null, { status: 204, headers: corsHeaders });
          }

          return new Response(JSON.stringify(responses), {
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }

        // Single request
        const response = routeRequest(body as JsonRpcRequest);
        if (response === null) {
          // Notification — no response needed
          return new Response(null, { status: 204, headers: corsHeaders });
        }

        return new Response(JSON.stringify(response), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // GET /mcp — SSE endpoint (not needed for stateless server)
      if (request.method === "GET") {
        return new Response("SSE not supported — this is a stateless server", {
          status: 405,
          headers: corsHeaders,
        });
      }

      // DELETE /mcp — session termination (not needed for stateless)
      if (request.method === "DELETE") {
        return new Response(null, { status: 204, headers: corsHeaders });
      }
    }

    return new Response("Not Found", { status: 404, headers: corsHeaders });
  },
};
