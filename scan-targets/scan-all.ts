#!/usr/bin/env bun
/**
 * Scan all cloned MCP server repos with agent-audit.
 * Creates temporary configs pointing to each repo's source files,
 * runs the scanner, and aggregates results.
 */

import { readdirSync, statSync, writeFileSync, readFileSync } from "fs";
import { join, resolve } from "path";
import { scan } from "../src/scanner.js";
import type { MCPServer, ScanResult, Finding } from "../src/types.js";

const SCAN_DIR = resolve(import.meta.dir);
const EXTENSIONS = new Set(["js", "ts", "mjs", "cjs", "py", "rb", "go"]);
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "__pycache__", ".venv", "venv", ".next"]);

function findSourceFiles(dir: string, depth = 0): string[] {
  if (depth > 5) return [];
  const files: string[] = [];
  try {
    for (const entry of readdirSync(dir)) {
      if (SKIP_DIRS.has(entry) || entry.startsWith(".")) continue;
      const full = join(dir, entry);
      try {
        const stat = statSync(full);
        if (stat.isDirectory()) {
          files.push(...findSourceFiles(full, depth + 1));
        } else if (stat.isFile()) {
          const ext = entry.split(".").pop()?.toLowerCase() ?? "";
          if (EXTENSIONS.has(ext)) {
            files.push(full);
          }
        }
      } catch { /* skip inaccessible */ }
    }
  } catch { /* skip inaccessible */ }
  return files;
}

interface RepoResult {
  name: string;
  sourceFileCount: number;
  scanResult: ScanResult;
}

async function main() {
  const repos = readdirSync(SCAN_DIR)
    .filter(d => {
      if (d === "scan-all.ts" || d.endsWith(".json") || d.endsWith(".md")) return false;
      try { return statSync(join(SCAN_DIR, d)).isDirectory(); } catch { return false; }
    });

  console.log(`Found ${repos.length} repos to scan\n`);

  const results: RepoResult[] = [];

  for (const repo of repos) {
    const repoPath = join(SCAN_DIR, repo);
    console.log(`Scanning: ${repo}...`);

    const sourceFiles = findSourceFiles(repoPath);
    console.log(`  Found ${sourceFiles.length} source files`);

    if (sourceFiles.length === 0) {
      console.log(`  Skipping (no source files)\n`);
      continue;
    }

    // Create an MCPServer object pointing to the source files
    const server: MCPServer = {
      name: repo,
      command: "node",
      args: ["index.js"],
      sourceFiles,
    };

    const result = await scan([server], repoPath, { minSeverity: "low" });
    results.push({ name: repo, sourceFileCount: sourceFiles.length, scanResult: result });

    console.log(`  Findings: ${JSON.stringify(result.summary)}`);
    console.log();
  }

  // Aggregate
  const aggregate = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
    totalFindings: 0,
    totalRepos: results.length,
    totalSourceFiles: 0,
    reposWithFindings: 0,
    findingsByRule: {} as Record<string, number>,
    findingsByRepo: [] as Array<{
      name: string;
      sourceFiles: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
      findings: Finding[];
    }>,
  };

  for (const r of results) {
    aggregate.totalSourceFiles += r.sourceFileCount;
    const s = r.scanResult.summary;
    aggregate.critical += s.critical;
    aggregate.high += s.high;
    aggregate.medium += s.medium;
    aggregate.low += s.low;
    aggregate.info += s.info;
    aggregate.totalFindings += r.scanResult.findings.length;

    if (r.scanResult.findings.length > 0) {
      aggregate.reposWithFindings++;
    }

    for (const f of r.scanResult.findings) {
      aggregate.findingsByRule[f.rule + ": " + f.title] =
        (aggregate.findingsByRule[f.rule + ": " + f.title] || 0) + 1;
    }

    aggregate.findingsByRepo.push({
      name: r.name,
      sourceFiles: r.sourceFileCount,
      critical: s.critical,
      high: s.high,
      medium: s.medium,
      low: s.low,
      info: s.info,
      findings: r.scanResult.findings,
    });
  }

  // Write raw results
  writeFileSync(
    join(SCAN_DIR, "scan-results.json"),
    JSON.stringify({ aggregate, results: results.map(r => ({ name: r.name, sourceFileCount: r.sourceFileCount, ...r.scanResult })) }, null, 2)
  );

  console.log("\n=== AGGREGATE RESULTS ===");
  console.log(`Repos scanned: ${aggregate.totalRepos}`);
  console.log(`Source files analyzed: ${aggregate.totalSourceFiles}`);
  console.log(`Repos with findings: ${aggregate.reposWithFindings} (${Math.round(aggregate.reposWithFindings / aggregate.totalRepos * 100)}%)`);
  console.log(`\nTotal findings: ${aggregate.totalFindings}`);
  console.log(`  Critical: ${aggregate.critical}`);
  console.log(`  High: ${aggregate.high}`);
  console.log(`  Medium: ${aggregate.medium}`);
  console.log(`  Low: ${aggregate.low}`);
  console.log(`  Info: ${aggregate.info}`);
  console.log(`\nFindings by type:`);
  for (const [rule, count] of Object.entries(aggregate.findingsByRule).sort((a, b) => b[1] - a[1])) {
    console.log(`  ${rule}: ${count}`);
  }

  console.log("\nResults saved to scan-results.json");
}

main().catch(console.error);
