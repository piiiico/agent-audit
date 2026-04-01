/**
 * JSON Reporter
 *
 * Outputs scan results as machine-readable JSON for CI/CD integration.
 */

import type { ScanResult } from "../types.js";

export function renderJsonReport(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
