import { NextRequest, NextResponse } from "next/server";
import { demoHtml, demoPage } from "../store";

/**
 * GET /api/demo/redirect?url=...
 *
 * DELIBERATELY VULNERABLE: Open Redirect.
 *
 * The "logout redirect" / "continue to" parameter is used verbatim in the
 * Location header with no allowlist — the classic unvalidated redirect.
 * The scanner's open-redirect check looks for its payload host
 * (evil.com) in the Location header of the response.
 */
export async function GET(req: NextRequest) {
  const url = req.nextUrl.searchParams.get("url") || "";
  if (!url) {
    return demoHtml(
      demoPage(
        "Redirect",
        `<h1>Redirect Service</h1>
         <form action="/api/demo/redirect" method="GET">
           <input type="text" name="url" placeholder="https://example.com/next">
           <button type="submit">Continue</button>
         </form>`,
      ),
    );
  }
  // VULNERABILITY: absolute URLs (and protocol-relative //host) are
  // redirected to verbatim — an attacker-controlled destination.
  if (/^https?:\/\//i.test(url) || url.startsWith("//")) {
    return new NextResponse(null, {
      status: 302,
      headers: {
        Location: url,
        Server: "VulnTest/1.0",
        "X-Powered-By": "VulnTest-Express/0.0.1",
      },
    });
  }
  // Relative URLs are "safe" — redirect within the site.
  return new NextResponse(null, {
    status: 302,
    headers: { Location: "/api/demo", Server: "VulnTest/1.0" },
  });
}
