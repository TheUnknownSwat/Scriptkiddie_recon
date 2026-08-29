import { NextRequest } from "next/server";
import { demoHtml, demoPage } from "../store";

/**
 * GET /api/demo/admin
 *
 * DELIBERATELY VULNERABLE: Broken Access Control + unverified JWT.
 *
 * Two vulnerabilities in one page:
 *
 * 1. BROKEN ACCESS CONTROL: the "admin dashboard" returns 200 with full
 *    admin content (including other users' SSNs) even with NO cookies at
 *    all. When the scanner's access-control test (--test-access-control)
 *    clears cookies and re-visits, this page still serves the goods —
 *    the BAC finding.
 *
 * 2. UNVERIFIED JWT: if a `token` cookie is present, its payload is
 *    decoded WITHOUT any signature or algorithm check — so the scanner's
 *    forged alg=none token replay is accepted with HTTP 200 (the
 *    A07 alg=none bypass finding).
 *
 * NOTE: this page deliberately avoids login/auth vocabulary so the
 * scanner doesn't classify it as a login page.
 */

function decodePayload(jwt: string): Record<string, unknown> | null {
  try {
    const part = jwt.split(".")[1];
    if (!part) return null;
    return JSON.parse(Buffer.from(part, "base64url").toString("utf-8"));
  } catch {
    return null;
  }
}

export async function GET(req: NextRequest) {
  const token = req.cookies.get("token")?.value || "";
  const payload = token ? decodePayload(token) : null;

  const who = payload
    ? `Token accepted — role: ${String(payload.role || "unknown")} (signature NOT verified)`
    : "Guest session (no token presented — content shown anyway)";

  return demoHtml(
    demoPage(
      "Admin Dashboard",
      `<h1>Admin Dashboard</h1>
       <p>${who}</p>
       <h2>Quick User Lookup</h2>
       <!-- Found via directory brute-force (/admin). The scanner re-crawls
            discovered 200 pages: this form's input joins the attack surface
            and the links below join the crawl map. -->
       <form action="/api/demo/user" method="GET">
         <input type="text" name="id" placeholder="user id">
         <button type="submit">Lookup</button>
       </form>
       <p><a href="/api/demo/user?id=2">Recently viewed: Alice</a> |
          <a href="/api/demo/token">Issue API token</a></p>
       <h2>All Users</h2>
       <table border="1" cellpadding="6">
         <tr><th>id</th><th>name</th><th>email</th><th>SSN</th></tr>
         <tr><td>1</td><td>Admin User</td><td>admin@vulntest.local</td><td>123-45-6789</td></tr>
         <tr><td>2</td><td>Alice Smith</td><td>alice@vulntest.local</td><td>234-56-7890</td></tr>
         <tr><td>3</td><td>Bob Jones</td><td>bob@vulntest.local</td><td>345-67-8901</td></tr>
       </table>
       <h2>System Status</h2>
       <pre>database: connected (vulntest-prod.cluster.internal)
backups: /srv/backups (last run 02:00)
version: VulnTest-CMS 2.1.7</pre>`,
    ),
  );
}
