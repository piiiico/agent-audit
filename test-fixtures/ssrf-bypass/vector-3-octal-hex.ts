/**
 * SSRF Bypass Vector 3: Octal / Hex / Decimal IP Encoding
 *
 * String matching on the hostname cannot detect alternative IP representations:
 *   - Octal:   http://0177.0.0.1/   (0177 = 127 in decimal)
 *   - Hex:     http://0x7f000001/   (0x7f000001 = 127.0.0.1)
 *   - Decimal: http://2130706433/   (decimal value of 127.0.0.1)
 *
 * Without resolving the hostname to a canonical IP and validating it,
 * all three bypass the checks below.
 */

// @ts-ignore — illustrative pattern, axios not installed in audit environment
import axios from "axios";

function isSafeUrl(url: string): boolean {
  const parsed = new URL(url);
  // Flawed: string comparison cannot detect encoded IP representations
  return parsed.hostname !== "localhost" && !parsed.hostname.includes("127.0.0.1");
}

async function fetchData(url: string) {
  if (!isSafeUrl(url)) {
    throw new Error("Unsafe URL rejected");
  }
  // Missing: no net.isIPv4/isIPv6 call to validate the resolved IP
  return axios.get(url);
}

export { fetchData };
