/**
 * MCP Configuration Parser
 *
 * Parses Claude Desktop config files, Cursor config files, and other MCP
 * server configuration formats to extract server definitions for scanning.
 */

import { readFileSync, existsSync } from "fs";
import { homedir } from "os";
import { join, resolve, dirname } from "path";
import type { MCPServer } from "../types.js";

/** Claude Desktop config format */
interface ClaudeDesktopConfig {
  mcpServers?: Record<
    string,
    {
      command?: string;
      args?: string[];
      env?: Record<string, string>;
      url?: string;
    }
  >;
}

/**
 * Cursor MCP config format.
 * Cursor uses ~/.cursor/mcp.json with an identical mcpServers structure,
 * but may include a top-level "version" field.
 * Reference: https://docs.cursor.com/context/model-context-protocol
 */
interface CursorMcpConfig {
  version?: number;
  mcpServers?: Record<
    string,
    {
      command?: string;
      args?: string[];
      env?: Record<string, string>;
      url?: string;
      /** Cursor-specific: transport type (stdio | sse) */
      transport?: "stdio" | "sse";
    }
  >;
}

/** Common locations for Claude Desktop config */
function getClaudeDesktopConfigPaths(): string[] {
  const home = homedir();
  return [
    // macOS
    join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
    // Linux
    join(home, ".config", "claude", "claude_desktop_config.json"),
    // Windows
    join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
    // Generic fallback
    join(home, ".claude", "claude_desktop_config.json"),
  ];
}

/** Common locations for Cursor MCP config */
function getCursorConfigPaths(): string[] {
  const home = homedir();
  return [
    // Primary location (all platforms)
    join(home, ".cursor", "mcp.json"),
    // Windows alternate
    join(home, "AppData", "Roaming", "Cursor", "mcp.json"),
    // macOS alternate (some versions)
    join(home, "Library", "Application Support", "Cursor", "mcp.json"),
  ];
}

/**
 * Find the default MCP config file on the current system.
 * Checks both Claude Desktop and Cursor locations.
 * Returns the first found path, preferring Claude Desktop.
 */
export function findDefaultConfig(): string | null {
  for (const path of [...getClaudeDesktopConfigPaths(), ...getCursorConfigPaths()]) {
    if (existsSync(path)) return path;
  }
  return null;
}

/**
 * Find all MCP config files on the current system (Claude Desktop + Cursor).
 * Returns all found paths, useful for multi-client scanning.
 */
export function findAllConfigs(): string[] {
  const found: string[] = [];
  for (const path of [...getClaudeDesktopConfigPaths(), ...getCursorConfigPaths()]) {
    if (existsSync(path)) found.push(path);
  }
  return found;
}

/**
 * Detect whether a config file is likely a Cursor MCP config.
 * Cursor configs may have a "version" field or lack Claude-specific keys.
 */
export function isCursorConfig(configPath: string): boolean {
  try {
    const raw = readFileSync(configPath, "utf-8");
    const config = JSON.parse(raw) as CursorMcpConfig;
    // Cursor configs have a numeric "version" field, or the path itself is a signal
    if (typeof config.version === "number") return true;
    if (configPath.includes(".cursor") || configPath.toLowerCase().includes("cursor")) return true;
    return false;
  } catch {
    return false;
  }
}

/**
 * Parse a Cursor MCP config file (~/.cursor/mcp.json) and return the list of MCP servers.
 * Cursor uses the same mcpServers structure as Claude Desktop, with optional extras.
 */
export function parseCursorConfig(configPath: string): MCPServer[] {
  let raw: string;
  try {
    raw = readFileSync(configPath, "utf-8");
  } catch (err) {
    throw new Error(`Cannot read Cursor config file at ${configPath}: ${err}`);
  }

  let config: CursorMcpConfig;
  try {
    config = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid JSON in Cursor config file ${configPath}: ${err}`);
  }

  if (!config.mcpServers) {
    throw new Error(`Cursor config at ${configPath} does not contain mcpServers field`);
  }

  const configDir = dirname(resolve(configPath));

  return Object.entries(config.mcpServers).map(([name, def]) => {
    const server: MCPServer = {
      name,
      command: def.command,
      args: def.args,
      env: def.env,
      url: def.url,
    };

    server.sourceFiles = resolveSourceFiles(def.command, def.args ?? [], configDir);

    return server;
  });
}

/**
 * Auto-detect and parse any supported MCP config format.
 * Tries Claude Desktop format first, then Cursor format.
 */
export function parseAnyConfig(configPath: string): MCPServer[] {
  if (isCursorConfig(configPath)) {
    return parseCursorConfig(configPath);
  }
  return parseClaudeDesktopConfig(configPath);
}

/**
 * Parse a Claude Desktop config file and return the list of MCP servers
 */
export function parseClaudeDesktopConfig(configPath: string): MCPServer[] {
  let raw: string;
  try {
    raw = readFileSync(configPath, "utf-8");
  } catch (err) {
    throw new Error(`Cannot read config file at ${configPath}: ${err}`);
  }

  let config: ClaudeDesktopConfig;
  try {
    config = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid JSON in config file ${configPath}: ${err}`);
  }

  if (!config.mcpServers) {
    throw new Error(`Config file does not contain mcpServers field (may be a different format)`);
  }

  const configDir = dirname(resolve(configPath));

  return Object.entries(config.mcpServers).map(([name, def]) => {
    const server: MCPServer = {
      name,
      command: def.command,
      args: def.args,
      env: def.env,
      url: def.url,
    };

    // Try to resolve source files from the command + args
    server.sourceFiles = resolveSourceFiles(def.command, def.args ?? [], configDir);

    return server;
  });
}

/**
 * Attempt to resolve source file paths from a server's command and args.
 * This is best-effort — not all servers will have resolvable source files.
 */
function resolveSourceFiles(
  command?: string,
  args: string[] = [],
  baseDir?: string
): string[] {
  const sourceFiles: string[] = [];

  if (!command) return sourceFiles;

  const isNodeInterpreter = ["node", "bun", "deno", "ts-node", "tsx"].includes(
    command.split("/").pop() ?? ""
  );
  const isPythonInterpreter = ["python", "python3", "python3.x"].some((p) =>
    (command.split("/").pop() ?? "").startsWith(p)
  );

  if (isNodeInterpreter || isPythonInterpreter) {
    // First non-flag arg is usually the script
    for (const arg of args) {
      if (!arg.startsWith("-")) {
        const resolved = baseDir ? join(baseDir, arg) : arg;
        if (existsSync(resolved)) {
          sourceFiles.push(resolved);
        } else if (existsSync(arg)) {
          sourceFiles.push(arg);
        }
        break;
      }
    }
  }

  return sourceFiles;
}

/**
 * Parse an arbitrary JSON file as an MCP server list
 * (for custom config formats)
 */
export function parseCustomConfig(configPath: string): MCPServer[] {
  let raw: string;
  try {
    raw = readFileSync(configPath, "utf-8");
  } catch (err) {
    throw new Error(`Cannot read config file at ${configPath}: ${err}`);
  }

  let config: unknown;
  try {
    config = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid JSON in config file ${configPath}: ${err}`);
  }

  // Try Claude Desktop format
  if (
    typeof config === "object" &&
    config !== null &&
    "mcpServers" in config
  ) {
    return parseClaudeDesktopConfig(configPath);
  }

  // Try array of server definitions
  if (Array.isArray(config)) {
    return config
      .filter(
        (s) => typeof s === "object" && s !== null && "name" in s
      )
      .map((s) => s as MCPServer);
  }

  throw new Error(
    `Unknown config format in ${configPath}. Expected Claude Desktop format or array of server definitions.`
  );
}
