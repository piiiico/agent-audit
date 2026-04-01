/** Severity levels matching CVSS conventions */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** A single finding from the scanner */
export interface Finding {
  /** Rule that triggered this finding */
  rule: string;
  /** Short human-readable title */
  title: string;
  /** Detailed description of the issue */
  description: string;
  /** Severity of the finding */
  severity: Severity;
  /** Location of the finding */
  location: {
    /** File path or server name */
    source: string;
    /** Line number if applicable */
    line?: number;
    /** Specific field (e.g., "description", "inputSchema") */
    field?: string;
    /** Snippet of the matching content */
    snippet?: string;
  };
  /** OWASP category reference */
  owasp?: string;
  /** CVE references if applicable */
  cve?: string[];
  /** Remediation guidance */
  remediation?: string;
}

/** A parsed MCP tool definition */
export interface MCPTool {
  name: string;
  description?: string;
  inputSchema?: {
    type?: string;
    properties?: Record<string, {
      type?: string;
      description?: string;
      [key: string]: unknown;
    }>;
    required?: string[];
    [key: string]: unknown;
  };
}

/** A parsed MCP server from config */
export interface MCPServer {
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string; // For HTTP-based servers
  tools?: MCPTool[];
  /** Path to the server implementation file(s) */
  sourceFiles?: string[];
}

/** The full scan result */
export interface ScanResult {
  /** When the scan ran */
  timestamp: string;
  /** What was scanned */
  target: string;
  /** All findings, sorted by severity */
  findings: Finding[];
  /** Summary counts by severity */
  summary: Record<Severity, number>;
  /** Total scan duration in ms */
  durationMs: number;
}
