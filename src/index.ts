/**
 * agent-audit public API
 *
 * Use this to embed agent-audit scanning in your own tools.
 */

export { scan } from "./scanner.js";
export type { ScanOptions } from "./scanner.js";
export type { MCPServer, MCPTool, Finding, ScanResult, Severity } from "./types.js";
export {
  parseClaudeDesktopConfig,
  parseCursorConfig,
  parseAnyConfig,
  parseCustomConfig,
  findDefaultConfig,
  findAllConfigs,
  isCursorConfig,
} from "./parsers/mcp-config.js";
export { renderTerminalReport, getExitCode } from "./reporters/terminal.js";
export { renderJsonReport } from "./reporters/json.js";
