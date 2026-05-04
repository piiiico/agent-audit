/**
 * Tests for SSRF Incomplete Validator rule
 *
 * 4 positive tests — one per bypass vector (IPv6, Docker CIDR, octal/hex, DNS rebinding)
 * 2 negative tests — ssrf-req-filter and pre-resolve+IP-validate patterns
 */

import { describe, test, expect } from "bun:test";
import { join } from "node:path";
import { scanSourceFileForSSRFIncompleteValidator } from "./ssrf-incomplete-validator.js";

const FIXTURES = join(import.meta.dir, "../../test-fixtures/ssrf-bypass");

describe("SSRF incomplete validator detection", () => {
  // ─── Positive tests (rule SHOULD fire) ────────────────────────────────────

  test("detects missing IPv6 loopback coverage (vector 1)", () => {
    const findings = scanSourceFileForSSRFIncompleteValidator(
      join(FIXTURES, "vector-1-ipv6-loopback.ts"),
      "test-server"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].rule).toBe("ssrf-incomplete-validator/bypass-vectors");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].title).toContain("IPv6");
  });

  test("detects missing Docker bridge CIDR coverage (vector 2)", () => {
    const findings = scanSourceFileForSSRFIncompleteValidator(
      join(FIXTURES, "vector-2-docker-bridge.ts"),
      "test-server"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].rule).toBe("ssrf-incomplete-validator/bypass-vectors");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].title).toContain("Docker");
  });

  test("detects missing octal/hex encoding coverage (vector 3)", () => {
    const findings = scanSourceFileForSSRFIncompleteValidator(
      join(FIXTURES, "vector-3-octal-hex.ts"),
      "test-server"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].rule).toBe("ssrf-incomplete-validator/bypass-vectors");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].title).toContain("encoding");
  });

  test("detects missing DNS rebinding protection (vector 4)", () => {
    const findings = scanSourceFileForSSRFIncompleteValidator(
      join(FIXTURES, "vector-4-dns-rebinding.ts"),
      "test-server"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].rule).toBe("ssrf-incomplete-validator/bypass-vectors");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].title).toContain("DNS");
  });

  // ─── Remediation field tests ──────────────────────────────────────────────

  test("finding includes a remediation field", () => {
    const findings = scanSourceFileForSSRFIncompleteValidator(
      join(FIXTURES, "vector-1-ipv6-loopback.ts"),
      "test-server"
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(typeof findings[0].remediation).toBe("string");
    expect(findings[0].remediation!.length).toBeGreaterThan(50);
  });

  test("remediation references all 3 mitigation layers", () => {
    const findings = scanSourceFileForSSRFIncompleteValidator(
      join(FIXTURES, "vector-4-dns-rebinding.ts"),
      "test-server"
    );
    expect(findings.length).toBeGreaterThan(0);
    const r = findings[0].remediation ?? "";
    // Layer 1 — pre-resolve + CIDR blocklist
    expect(r).toContain("dns.lookup");
    // Layer 2 — Chromium --host-resolver-rules MAP rule
    expect(r).toContain("--host-resolver-rules");
    // Layer 3 — ssrf-req-filter
    expect(r).toContain("ssrf-req-filter");
  });

  // ─── Negative tests (rule should NOT fire) ────────────────────────────────

  test("does not flag ssrf-req-filter usage", () => {
    const findings = scanSourceFileForSSRFIncompleteValidator(
      join(FIXTURES, "safe-ssrf-filter.ts"),
      "test-server"
    );
    expect(findings.length).toBe(0);
  });

  test("does not flag pre-resolve + net.isIPv4/net.isIPv6 pattern", () => {
    const findings = scanSourceFileForSSRFIncompleteValidator(
      join(FIXTURES, "safe-pre-resolve.ts"),
      "test-server"
    );
    expect(findings.length).toBe(0);
  });
});
