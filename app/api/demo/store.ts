import { NextResponse } from "next/server";

/**
 * Shared helpers for the VulnTest demo site.
 *
 * Everything here is IN-MEMORY and SIMULATED — no filesystem writes, no
 * command execution, no outbound network requests. The demo exercises the
 * SCANNER's detection logic, not real exploitation.
 */

/** In-memory upload store (demo only — resets when the dev server restarts). */
export const uploadStore = new Map<string, { body: string; type: string }>();

/**
 * Deliberately insecure response headers — same pattern as every other
 * demo route: no security headers, insecure cookie, fake banners.
 */
export function demoHeaders(extra?: Record<string, string>): Record<string, string> {
  return {
    "Content-Type": "text/html; charset=utf-8",
    Server: "VulnTest/1.0",
    "X-Powered-By": "VulnTest-Express/0.0.1",
    "Set-Cookie": "sessionid=vulnsession123; Path=/; SameSite=None",
    ...extra,
  };
}

/** Minimal HTML page shell with the demo site's basic styling. */
export function demoPage(title: string, body: string, extraHead = ""): string {
  return `<!DOCTYPE html>
<html>
<head>
  <title>${title} — VulnTest</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: sans-serif; max-width: 800px; margin: 2rem auto; padding: 1rem; }
    h1 { color: #c62828; }
    code, pre { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
    pre { padding: 1rem; overflow-x: auto; }
    form { margin: 0.5rem 0; }
    input, select, textarea { padding: 4px 8px; margin: 4px 0; }
    button { padding: 4px 12px; background: #1976d2; color: white; border: none; border-radius: 3px; cursor: pointer; }
    .back { margin-bottom: 1rem; }
    .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 1rem; border-radius: 4px; }
  </style>
  ${extraHead}
</head>
<body>
  <div class="back"><a href="/api/demo">← Back to VulnTest</a></div>
  ${body}
</body>
</html>`;
}

function b64url(s: string): string {
  return Buffer.from(s, "utf-8").toString("base64url");
}

/**
 * Demo JWT with a WEAK claim set — signed with a throwaway signature and
 * carrying NO `exp` claim (never expires → the scanner's JWT analysis
 * flags this High). Displayed at /api/demo/token and set as a cookie on
 * successful login so both the cookie jar and the page HTML harvest it.
 * The "admin" page reads this token WITHOUT verifying the signature —
 * which is what lets the scanner's alg=none forged-token replay succeed.
 */
export const DEMO_JWT = [
  b64url(JSON.stringify({ alg: "HS256", typ: "JWT" })),
  b64url(JSON.stringify({ sub: "admin", role: "administrator", iat: 1700000000 })),
  "vulntest-signature-not-verified-anyway",
].join(".");

/** Convenience: HTML response with the demo's insecure headers. */
export function demoHtml(html: string, status = 200, extra?: Record<string, string>) {
  return new NextResponse(html, { status, headers: demoHeaders(extra) });
}
