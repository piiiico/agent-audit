/**
 * SSRF Incomplete Validator Detection
 *
 * Detects MCP server source files that make outbound HTTP requests with a
 * URL validator that relies solely on string matching. Four verified bypass
 * vectors are checked: IPv6 loopback, Docker bridge CIDR, octal/hex/decimal
 * encoding, and DNS rebinding.
 *
 * References:
 * - GHSA-4rp9-6x65-rqqm; desiorac engagement (qpd-v/mcp-ragdocs#10)
 * - CWE-918: Server-Side Request Forgery (SSRF)
 * - OWASP Agentic AI Top 10: A05 - Excessive Agency
 */

import { readFileSync } from "fs";
import type { Finding } from "../types.js";

/** Patterns indicating outbound HTTP requests */
const OUTBOUND_FETCH_PATTERNS = [
  /\bfetch\s*\(/,
  /axios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(/,
  /\bgot\s*\(/,
  /undici\s*\.\s*(?:fetch|request)\s*\(/,
];

/** Naive string-based URL hostname validation patterns */
const NAIVE_HOST_CHECK_PATTERNS = [
  /\.hostname\s*(?:===?|!==?)\s*['"]localhost['"]/,
  /\.hostname\s*(?:===?|!==?)\s*['"]127\.0\.0\.1['"]/,
  /\.hostname\.includes\s*\(\s*['"]localhost['"]/,
  /\.hostname\.includes\s*\(\s*['"]127\.0\.0\.1['"]/,
  /\.hostname\.startsWith\s*\(\s*['"]127\./,
  /\.hostname\.startsWith\s*\(\s*['"]localhost['"]/,
  /isSafe(?:Url|URL|Host)\s*[=({]/,
  /isValid(?:Url|URL|Host)\s*[=({]/,
];

const SSRF_FILTER_PKG = /['"]ssrf-req-filter['"]/;
const IPV6_CHECK      = /\[::1\]|(?<![a-z])::1(?!\w)|fe80::|net\.isIPv6\s*\(/;
const PRIVATE_CIDR_CHECK = /172\.(?:1[6-9]|2\d|3[01])\.|(?<!\d)10\.\d+\.\d+|192\.168\.|169\.254\.|isPrivate/;
const IP_FORMAT_CHECK = /net\.isIPv4\s*\(|net\.isIPv6\s*\(|isIP\s*\(|ipaddr\.parse/;
const DNS_RESOLVE     = /dns\.(?:lookup|resolve|promises)|dnsPromises\.|await\s+dns/;

const SCANNABLE_EXTENSIONS = new Set(["js", "ts", "mjs", "cjs"]);

function getExtension(fp: string): string {
  return fp.split(".").pop()?.toLowerCase() ?? "";
}

function missingVectors(content: string): string[] {
  if (SSRF_FILTER_PKG.test(content)) return [];
  if (DNS_RESOLVE.test(content) && IP_FORMAT_CHECK.test(content)) return [];

  const missing: string[] = [];
  if (!IPV6_CHECK.test(content)) missing.push("IPv6 loopback (::1/[::1]/fe80::)");
  if (!PRIVATE_CIDR_CHECK.test(content)) missing.push("Docker bridge CIDR (172.16.0.0/12)");
  if (!IP_FORMAT_CHECK.test(content)) missing.push("octal/hex/decimal IP encoding");
  if (!DNS_RESOLVE.test(content)) missing.push("DNS rebinding (no pre-resolve)");
  return missing;
}

export function scanSourceFileForSSRFIncompleteValidator(
  filePath: string,
  serverName: string
): Finding[] {
  const ext = getExtension(filePath);
  if (!SCANNABLE_EXTENSIONS.has(ext)) return [];

  let content: string;
  try {
    content = readFileSync(filePath, "utf-8");
  } catch {
    return [];
  }

  const hasOutboundFetch = OUTBOUND_FETCH_PATTERNS.some((p) => p.test(content));
  if (!hasOutboundFetch) return [];

  const hasNaiveCheck = NAIVE_HOST_CHECK_PATTERNS.some((p) => p.test(content));
  if (!hasNaiveCheck) return [];

  const missing = missingVectors(content);
  if (missing.length === 0) return [];

  const lines = content.split("\n");
  let fetchLine = 1;
  for (let i = 0; i < lines.length; i++) {
    if (OUTBOUND_FETCH_PATTERNS.some((p) => p.test(lines[i]))) {
      fetchLine = i + 1;
      break;
    }
  }

  const remediation = `## SSRF Mitigation Stack (3 required layers)

### Layer 1 — Pre-resolve + private-CIDR blocklist
Resolve the hostname to an IP **before** launching any request or browser, then
reject private ranges. String/hostname checks are bypassed by IPv6 loopback (\`::1\`,
\`[::1]\`), Docker bridge CIDRs (\`172.16.0.0/12\`), and encoded IPs (\`0177.0.0.1\`,
\`0x7f000001\`, \`2130706433\`).

\`\`\`ts
import dns from "node:dns/promises";
import net from "node:net";
const PRIVATE = /^(127\\.|10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.|169\\.254\\.|::1|fe80:)/i;
const { address } = await dns.lookup(hostname, { family: 4 });
if (PRIVATE.test(address)) throw new Error("SSRF blocked: private IP");
\`\`\`

### Layer 2 — Chromium --host-resolver-rules (Playwright/CDP callers only)
After pre-resolving, **pin DNS for the browser session** so a DNS rebind mid-flight
cannot redirect to a new IP. Pass the resolved IP as a static MAP rule:

\`\`\`ts
const browser = await chromium.launch({
  args: [\`--host-resolver-rules=MAP \${hostname} \${resolvedIp}\`],
});
\`\`\`

> "These mappings only apply to the host resolver."
> — Chromium command-line reference: https://peter.sh/experiments/chromium-command-line-switches/
>
> Without this pin, a fast DNS TTL flip (DNS rebinding) can reroute Playwright
> fetches to \`127.0.0.1\` after your Layer 1 check has already passed.

### Layer 3 — ssrf-req-filter on HTTP-layer fetches
For any direct \`fetch()\` / \`axios\` / \`got\` call (not browser-driven), wrap with
\`ssrf-req-filter\` to catch IP-literal URLs and \`file://\` schemes that bypass
hostname parsing entirely:

\`\`\`ts
import SsrfReqFilter from "ssrf-req-filter";
const agent = new SsrfReqFilter(url);
const response = await fetch(url, { agent });
\`\`\`

If arbitrary URLs are not a product requirement, replace with an **explicit
domain allowlist** — that eliminates the attack surface entirely.

References: CWE-918; GHSA-4rp9-6x65-rqqm; mcp-ragdocs#10`;

  return [
    {
      rule: "ssrf-incomplete-validator/bypass-vectors",
      title: `Incomplete SSRF validator: missing ${missing.join(", ")}`,
      description:
        `'${filePath}' makes outbound HTTP requests protected only by string-based hostname checks. ` +
        `Missing bypass-vector coverage: ${missing.join("; ")}. ` +
        `In MCP context, SSRF lets attackers fetch cloud metadata (169.254.169.254), ` +
        `Docker bridge services, or internal APIs. (CWE-918; mcp-ragdocs#10)`,
      severity: "high",
      location: {
        source: filePath,
        line: fetchLine,
        field: "source_code",
        snippet: lines[fetchLine - 1]?.trim().slice(0, 200) ?? "",
      },
      owasp: "A10:2021 - Server-Side Request Forgery (SSRF)",
      remediation,
    },
  ];
}
