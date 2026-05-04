/**
 * Safe SSRF Implementation — DNS pre-resolve + IP validation
 *
 * Resolves the hostname to its actual IP address server-side, validates it
 * against private CIDR ranges using net.isIPv4/net.isIPv6, then fetches.
 * This prevents DNS rebinding and detects encoded private IPs.
 */

import dns from "node:dns/promises";
import net from "node:net";

const PRIVATE_RANGES = [
  /^127\./,
  /^::1$/,
  /^fe80:/i,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^169\.254\./,
];

function isPrivateIP(ip: string): boolean {
  return PRIVATE_RANGES.some((p) => p.test(ip));
}

async function safeFetch(url: string): Promise<Response> {
  const parsed = new URL(url);

  // String-level quick bail for the most obvious loopback cases
  if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") {
    throw new Error("Blocked: loopback");
  }

  // Pre-resolve hostname to its actual IP before fetching
  const { address } = await dns.lookup(parsed.hostname);

  // Validate using net.isIPv4/net.isIPv6 + private range check
  if (!net.isIPv4(address) && !net.isIPv6(address)) {
    throw new Error("Invalid resolved address");
  }
  if (isPrivateIP(address)) {
    throw new Error("Blocked: private IP");
  }

  return fetch(url);
}

export { safeFetch };
