import { demoHeaders, demoPage, DEMO_JWT } from "../store";
import { NextResponse } from "next/server";

/**
 * GET /api/demo/token
 *
 * DELIBERATELY VULNERABLE: Weak JWT.
 *
 * Displays the session's API token (a JWT with NO exp claim — it never
 * expires) in the page HTML AND sets it as a cookie, so the scanner
 * harvests it from both the cookie jar and the page body. The JWT
 * analysis phase then flags the missing expiry (High).
 *
 * The token is also accepted by /api/demo/admin WITHOUT signature
 * verification — which is what makes the alg=none forged-token replay
 * succeed (see the admin route).
 */
export async function GET() {
  const html = demoPage(
    "API Token",
    `<h1>Your API Token</h1>
     <p>This token does not expire. Treat it carefully.</p>
     <pre>${DEMO_JWT}</pre>
     <p>Use it against the <a href="/api/demo/admin">admin dashboard</a>.</p>`,
  );
  const res = new NextResponse(html, { status: 200, headers: demoHeaders() });
  res.headers.append("Set-Cookie", `token=${DEMO_JWT}; Path=/; SameSite=None`);
  return res;
}
