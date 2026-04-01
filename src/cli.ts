#!/usr/bin/env node
/**
 * agent-audit CLI
 *
 * Security scanner for MCP servers and AI agent tooling.
 *
 * Usage:
 *   agent-audit [config-path]          Scan MCP servers from config file
 *   agent-audit --auto                 Auto-detect Claude Desktop config
 *   agent-audit --help                 Show help
 *   agent-audit --json                 Output JSON report
 */

import { findDefaultConfig, parseClaudeDesktopConfig, parseCustomConfig } from "./parsers/mcp-config.js";
import { scan } from "./scanner.js";
import { renderTerminalReport, getExitCode } from "./reporters/terminal.js";
import { renderJsonReport } from "./reporters/json.js";
import type { Severity } from "./types.js";

const VERSION = "0.1.0";

function printHelp() {
  console.log(`
agent-audit v${VERSION}
Security scanner for MCP servers and AI agent tooling

USAGE
  agent-audit [options] [config-path]

OPTIONS
  --auto            Auto-detect Claude Desktop config file
  --json            Output JSON report (for CI/CD integration)
  --min-severity    Minimum severity to report: critical|high|medium|low|info
                    (default: low)
  --no-source       Skip source file scanning (faster)
  --version         Show version
  --help            Show this help

EXAMPLES
  # Scan auto-detected Claude Desktop config
  agent-audit --auto

  # Scan a specific config file
  agent-audit ~/Library/Application\\ Support/Claude/claude_desktop_config.json

  # CI mode: exit 1 on high+ findings, output JSON
  agent-audit --auto --json --min-severity high

CHECKS
  • Prompt injection in tool descriptions (OWASP A01)
  • Command injection in server source files (OWASP A03)
  • Hardcoded credentials in config and source files (OWASP A07)
  • Auth bypass patterns in source code (OWASP A05)
  • Excessive permissions and missing input schemas (OWASP A05)
  • Suspicious tool names and misleading descriptions

SEVERITY EXIT CODES
  0 — No critical or high findings
  1 — High severity findings detected
  2 — Critical findings detected

`);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    process.exit(0);
  }

  if (args.includes("--version") || args.includes("-v")) {
    console.log(`agent-audit v${VERSION}`);
    process.exit(0);
  }

  const jsonOutput = args.includes("--json");
  const autoDetect = args.includes("--auto");
  const skipSource = args.includes("--no-source");

  const minSeverityArg = args.find((a) => a.startsWith("--min-severity="))?.split("=")[1]
    ?? (args.indexOf("--min-severity") !== -1 ? args[args.indexOf("--min-severity") + 1] : null);
  const minSeverity = (minSeverityArg as Severity | null) ?? "low";

  // Find config path
  const nonFlagArgs = args.filter((a) => !a.startsWith("-"));
  const configPath = nonFlagArgs[0] ?? null;

  let resolvedPath: string | null = null;

  if (configPath) {
    resolvedPath = configPath;
  } else if (autoDetect) {
    resolvedPath = findDefaultConfig();
    if (!resolvedPath) {
      console.error(
        "❌ Could not find Claude Desktop config. Try specifying the path explicitly."
      );
      console.error("   Searched locations:");
      console.error("     ~/Library/Application Support/Claude/claude_desktop_config.json");
      console.error("     ~/.config/claude/claude_desktop_config.json");
      process.exit(1);
    }
    if (!jsonOutput) {
      console.log(`ℹ️  Auto-detected config: ${resolvedPath}`);
    }
  } else {
    // No config specified — try auto-detect silently
    resolvedPath = findDefaultConfig();
    if (!resolvedPath) {
      console.error("❌ No config file specified and none found automatically.");
      console.error("   Run with --auto to search common locations, or provide a path.");
      printHelp();
      process.exit(1);
    }
    if (!jsonOutput) {
      console.log(`ℹ️  Using config: ${resolvedPath}`);
    }
  }

  // Parse config
  let servers;
  try {
    servers = parseClaudeDesktopConfig(resolvedPath);
  } catch {
    try {
      servers = parseCustomConfig(resolvedPath);
    } catch (err2) {
      console.error(`❌ Failed to parse config: ${err2}`);
      process.exit(1);
    }
  }

  if (servers.length === 0) {
    if (!jsonOutput) {
      console.log("ℹ️  No MCP servers found in config. Nothing to scan.");
    }
    process.exit(0);
  }

  if (!jsonOutput) {
    console.log(`🔍 Scanning ${servers.length} MCP server(s)...`);
  }

  // Run scan
  const result = await scan(servers, resolvedPath, {
    skipSourceScan: skipSource,
    minSeverity,
  });

  // Output report
  if (jsonOutput) {
    console.log(renderJsonReport(result));
  } else {
    renderTerminalReport(result);
  }

  process.exit(getExitCode(result));
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
