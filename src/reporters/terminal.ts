/**
 * Terminal Reporter
 *
 * Renders scan results to the terminal with color-coded severity.
 */

import type { ScanResult, Finding, Severity } from "../types.js";

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "\x1b[41m\x1b[97m", // Red background, white text
  high: "\x1b[31m",             // Red
  medium: "\x1b[33m",           // Yellow
  low: "\x1b[36m",              // Cyan
  info: "\x1b[37m",             // White
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";

function colorize(text: string, color: string): string {
  return `${color}${text}${RESET}`;
}

function severityBadge(severity: Severity): string {
  const icon = SEVERITY_ICONS[severity];
  const color = SEVERITY_COLORS[severity];
  return `${icon} ${colorize(severity.toUpperCase(), color + BOLD)}`;
}

export function renderTerminalReport(result: ScanResult): void {
  const { findings, summary, target, timestamp, durationMs } = result;

  console.log();
  console.log(colorize(`${"─".repeat(60)}`, DIM));
  console.log(
    `${BOLD}agent-audit${RESET} — MCP Security Scanner`
  );
  console.log(colorize(`${"─".repeat(60)}`, DIM));
  console.log(`${DIM}Target:${RESET}    ${target}`);
  console.log(`${DIM}Scanned:${RESET}   ${timestamp}`);
  console.log(`${DIM}Duration:${RESET}  ${durationMs}ms`);
  console.log(colorize(`${"─".repeat(60)}`, DIM));
  console.log();

  if (findings.length === 0) {
    console.log(`✅ ${BOLD}No findings${RESET} — scan completed cleanly.`);
    console.log();
    return;
  }

  // Group by severity
  const grouped = new Map<Severity, Finding[]>();
  for (const f of findings) {
    if (!grouped.has(f.severity)) grouped.set(f.severity, []);
    grouped.get(f.severity)!.push(f);
  }

  // Render each finding
  let count = 1;
  for (const severity of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    const group = grouped.get(severity);
    if (!group) continue;

    for (const finding of group) {
      console.log(`${DIM}[${count++}]${RESET} ${severityBadge(finding.severity)}`);
      console.log(`    ${BOLD}${finding.title}${RESET}`);
      console.log(`    ${DIM}Rule:${RESET} ${finding.rule}`);
      console.log(`    ${DIM}Location:${RESET} ${finding.location.source}${finding.location.field ? ` → ${finding.location.field}` : ""}${finding.location.line ? `:${finding.location.line}` : ""}`);

      if (finding.location.snippet) {
        const snippet = finding.location.snippet.replace(/\n/g, " ");
        console.log(`    ${DIM}Snippet:${RESET} ${colorize(snippet, DIM)}`);
      }

      if (finding.owasp) {
        console.log(`    ${DIM}OWASP:${RESET} ${finding.owasp}`);
      }

      console.log();
      console.log(`    ${finding.description}`);
      console.log();

      if (finding.remediation) {
        console.log(`    ${colorize("▶ Fix:", BOLD)} ${finding.remediation}`);
      }

      console.log(colorize(`    ${"─".repeat(56)}`, DIM));
      console.log();
    }
  }

  // Summary
  console.log(colorize(`${"─".repeat(60)}`, DIM));
  console.log(`${BOLD}Summary${RESET}`);
  console.log(colorize(`${"─".repeat(60)}`, DIM));

  let hasFindings = false;
  for (const [severity, count] of Object.entries(summary) as [Severity, number][]) {
    if (count > 0) {
      console.log(
        `  ${severityBadge(severity)} ${colorize(count.toString(), BOLD)}`
      );
      hasFindings = true;
    }
  }

  if (!hasFindings) {
    console.log("  No findings.");
  }

  console.log();

  // Exit code hint
  const critical = summary.critical ?? 0;
  const high = summary.high ?? 0;
  if (critical > 0) {
    console.log(
      colorize(`⛔ ${critical} critical finding(s) require immediate attention.`, SEVERITY_COLORS.critical)
    );
  } else if (high > 0) {
    console.log(
      colorize(`⚠️  ${high} high severity finding(s) detected.`, SEVERITY_COLORS.high)
    );
  } else {
    console.log(`✅ No critical or high severity findings.`);
  }

  console.log();
  console.log(`⭐ If agent-audit helps you, star the repo: https://github.com/piiiico/agent-audit`);
  console.log();
}

export function getExitCode(result: ScanResult): number {
  if (result.summary.critical > 0) return 2;
  if (result.summary.high > 0) return 1;
  return 0;
}
