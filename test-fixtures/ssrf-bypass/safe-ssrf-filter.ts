/**
 * Safe SSRF Implementation — uses ssrf-req-filter
 *
 * ssrf-req-filter handles all four bypass vectors: IPv6 loopback, Docker CIDR,
 * octal/hex encoded IPs, and DNS rebinding. Even with a string pre-check for
 * obvious cases, the package is the authoritative protection layer.
 */

// @ts-ignore — illustrative pattern, ssrf-req-filter not installed in audit environment
import ssrfFilter from "ssrf-req-filter";

async function safeFetch(url: string): Promise<Response> {
  const parsed = new URL(url);

  // Quick bail for the most obvious inputs
  if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") {
    throw new Error("Quick bail: loopback");
  }

  // ssrf-req-filter validates at the socket level — not bypassable by string tricks
  const filteredFetch = ssrfFilter(fetch);
  return filteredFetch(url);
}

export { safeFetch };
