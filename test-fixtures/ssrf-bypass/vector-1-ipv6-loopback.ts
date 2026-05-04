/**
 * SSRF Bypass Vector 1: IPv6 Loopback
 *
 * A naive URL validator that only blocks "localhost" and "127.0.0.1"
 * (IPv4 literals) misses IPv6 representations of the same loopback
 * address. Attackers can supply an IPv6-encoded URL to bypass the check.
 */

async function fetchUrl(url: string): Promise<Response> {
  const parsed = new URL(url);

  // Incomplete validator: only tests known IPv4 loopback string literals
  if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") {
    throw new Error("Access denied: loopback address");
  }

  // Missing: no check for IPv6 loopback or link-local ranges
  return fetch(url);
}

export { fetchUrl };
