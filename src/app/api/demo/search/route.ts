import { NextRequest, NextResponse } from "next/server";

/**
 * GET /api/demo/search?q=...
 *
 * DELIBERATELY VULNERABLE: Reflected XSS.
 *
 * The `q` parameter is reflected directly into the HTML without any
 * output encoding. This means <script>alert(1)</script> in the query
 * string will execute in the browser.
 *
 * The scanner should detect this via its XSS reflection regex patterns.
 */

export async function GET(req: NextRequest) {
  const q = req.nextUrl.searchParams.get("q") || "";

  // VULNERABILITY: no encoding of `q` before injecting into HTML.
  // A secure implementation would use: q.replace(/[<>&"']/g, c => ({...})[c])
  const html = `<!DOCTYPE html>
<html>
<head>
  <title>Search: ${q}</title>
  <style>
    body { font-family: sans-serif; max-width: 800px; margin: 2rem auto; padding: 1rem; }
    .result { padding: 0.5rem; border-bottom: 1px solid #eee; }
    .back { margin-bottom: 1rem; }
  </style>
</head>
<body>
  <div class="back"><a href="/api/demo">← Back to VulnTest</a></div>
  <h1>Search Results</h1>
  <form action="/api/demo/search" method="GET">
    <input type="text" name="q" value="${q}" placeholder="Search...">
    <button type="submit">Search</button>
  </form>
  <h2>You searched for: ${q}</h2>
  <div class="result">No results found for "${q}".</div>
</body>
</html>`;

  return new NextResponse(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      // Deliberately missing security headers.
      "Server": "VulnTest/1.0",
      "X-Powered-By": "VulnTest-Express/0.0.1",
    },
  });
}

// POST handler that also reflects (some apps reflect POST params too).
export async function POST(req: NextRequest) {
  const formData = await req.formData().catch(() => new FormData());
  const q = String(formData.get("q") || "");
  // Same XSS vulnerability via POST.
  return GET(new NextRequest(new URL(`/api/demo/search?q=${encodeURIComponent(q)}`, req.url)));
}
