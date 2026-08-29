import { NextRequest } from "next/server";
import { demoHeaders, demoPage } from "../store";
import { NextResponse } from "next/server";

/**
 * GET /api/demo/fetch?url=...
 *
 * DELIBERATELY VULNERABLE: Server-Side Request Forgery (SSRF) — SIMULATED.
 *
 * The "URL preview" feature fetches a user-supplied URL server-side.
 * Nothing is actually fetched (airgap-safe); the responses mimic what a
 * vulnerable fetch would return so the scanner's SSRF detection fires:
 *   - cloud metadata URLs (169.254.169.254) → IMDS JSON content
 *   - file:// URLs → local file content (/etc/passwd)
 *   - internal hosts → leaked connection errors (ECONNREFUSED / getaddrinfo)
 */

const FAKE_PASSWD = [
  "root:x:0:0:root:/root:/bin/bash",
  "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
  "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
].join("\n");

export async function GET(req: NextRequest) {
  const url = req.nextUrl.searchParams.get("url") || "";
  if (!url) {
    return new NextResponse(
      demoPage(
        "URL Preview",
        `<h1>URL Preview Tool</h1>
         <p>Fetches a URL server-side and shows the response (simulated).</p>
         <form action="/api/demo/fetch" method="GET">
           <input type="text" name="url" placeholder="http://internal-service/api" style="width:400px">
           <button type="submit">Fetch</button>
         </form>`,
      ),
      { status: 200, headers: demoHeaders() },
    );
  }

  let body: string;
  if (url.includes("169.254.169.254")) {
    // Cloud metadata endpoint reachable from the server — critical leak.
    body = JSON.stringify(
      {
        "ami-id": "ami-0b3f5d81a5c4e2f90",
        "instance-id": "i-0abc123def4567890",
        "instance-type": "t2.micro",
        "local-ipv4": "172.31.42.10",
        "iam": { "security-credentials": { "AccessKeyId": "AKIAVULNTEST12345678" } },
      },
      null,
      2,
    );
  } else if (url.startsWith("file:///etc/passwd") || url.includes("etc/passwd")) {
    body = FAKE_PASSWD;
  } else if (/localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\./.test(url)) {
    // Internal host — the fetch error itself leaks that the server
    // attempted an internal connection.
    body = `Error: connect ECONNREFUSED 127.0.0.1:8080\n    at TCPConnectWrap.afterConnect (node:net:1595:16)`;
  } else {
    body = `Fetched ${url} — 0 bytes (nothing to preview).`;
  }

  return new NextResponse(
    demoPage("URL Preview", `<h1>Preview of ${url}</h1><pre>${body}</pre>`),
    { status: 200, headers: demoHeaders() },
  );
}
