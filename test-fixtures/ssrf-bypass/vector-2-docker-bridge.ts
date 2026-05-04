/**
 * SSRF Bypass Vector 2: Docker Bridge Network
 *
 * A naive URL validator that blocks 127.x and localhost ignores the default
 * Docker bridge network. An attacker can target internal services on that
 * network by supplying an address in the bridge range, which passes this check.
 */

async function fetchResource(url: string): Promise<Response> {
  const parsed = new URL(url);

  // Incomplete check: blocks loopback only, ignores other private address spaces
  if (parsed.hostname.startsWith("127.") || parsed.hostname === "localhost") {
    throw new Error("Blocked: loopback address");
  }

  // Missing: no check for RFC1918 private ranges or cloud metadata addresses
  return fetch(url);
}

export { fetchResource };
