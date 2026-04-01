/**
 * Main Scanner Orchestrator
 *
 * Coordinates all scan rules against a set of MCP servers.
 */

import type { MCPServer, ScanResult, Finding, Severity } from "./types.js";
import {
  scanToolForPromptInjection,
  scanSourceFileForCommandInjection,
  scanServerConfigForCommandInjection,
  scanSourceFileForAuthBypass,
  scanServerEnvForSecrets,
  scanToolForExcessivePermissions,
  scanServerForExcessivePermissions,
} from "./rules/index.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export interface ScanOptions {
  /** Skip source file scanning (faster but misses code-level issues) */
  skipSourceScan?: boolean;
  /** Only report findings at or above this severity */
  minSeverity?: Severity;
}

/**
 * Scan a list of MCP servers and return the aggregated results
 */
export async function scan(
  servers: MCPServer[],
  target: string,
  options: ScanOptions = {}
): Promise<ScanResult> {
  const start = Date.now();
  const allFindings: Finding[] = [];

  for (const server of servers) {
    // 1. Scan server command config
    allFindings.push(...scanServerConfigForCommandInjection(server));

    // 2. Scan env for secrets
    allFindings.push(...scanServerEnvForSecrets(server));

    // 3. Scan tools
    for (const tool of server.tools ?? []) {
      allFindings.push(...scanToolForPromptInjection(tool, server));
      allFindings.push(...scanToolForExcessivePermissions(tool, server));
    }

    // 4. Server-level permission analysis
    allFindings.push(...scanServerForExcessivePermissions(server));

    // 5. Source file scanning (if enabled)
    if (!options.skipSourceScan && server.sourceFiles) {
      for (const filePath of server.sourceFiles) {
        allFindings.push(...scanSourceFileForCommandInjection(filePath, server.name));
        allFindings.push(...scanSourceFileForAuthBypass(filePath, server.name));
      }
    }
  }

  // Sort by severity
  const findings = allFindings
    .filter((f) => {
      if (!options.minSeverity) return true;
      return SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[options.minSeverity];
    })
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  // Build summary
  const summary: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) {
    summary[f.severity]++;
  }

  return {
    timestamp: new Date().toISOString(),
    target,
    findings,
    summary,
    durationMs: Date.now() - start,
  };
}
