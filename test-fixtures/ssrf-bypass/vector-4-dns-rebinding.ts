/**
 * SSRF Bypass Vector 4: DNS Rebinding
 *
 * The hostname string check happens before network resolution. An attacker
 * controls a domain whose DNS record returns a public IP for the initial
 * check, then switches to an internal IP when the request is made inside
 * fetch(). Because the hostname is only validated once, the second
 * resolution is not re-checked.
 */

async function makeRequest(targetUrl: string): Promise<unknown> {
  const parsed = new URL(targetUrl);

  // String-based check only — no pre-resolution to a canonical IP address
  if (parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost") {
    throw new Error("Blocked: loopback");
  }

  // Missing: hostname is not pre-resolved before calling fetch
  const response = await fetch(targetUrl);
  return response.json();
}

export { makeRequest };
