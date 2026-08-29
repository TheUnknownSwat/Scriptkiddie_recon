import { NextRequest, NextResponse } from "next/server";
import { demoHeaders, demoPage } from "../store";

/**
 * GET/POST /api/demo/xml
 *
 * DELIBERATELY VULNERABLE: XML External Entity (XXE) — SIMULATED.
 *
 * The "XML import" feature parses raw XML bodies with external entity
 * resolution enabled (simulated — no real XML parser runs). The scanner
 * POSTs XXE payloads with Content-Type: application/xml; when the body
 * contains a DOCTYPE/ENTITY referencing /etc/passwd, the response
 * includes the "file contents" so the XXE detection (passwd markers or
 * echoed DOCTYPE/ENTITY) fires.
 */

const FAKE_PASSWD = [
  "root:x:0:0:root:/root:/bin/bash",
  "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
].join("\n");

export async function GET() {
  return new NextResponse(
    demoPage(
      "XML Import",
      `<h1>XML Import API</h1>
       <p>Accepts raw XML documents (Content-Type: application/xml).</p>
       <pre>&lt;?xml version="1.0"?&gt;
&lt;order&gt;&lt;item&gt;...&lt;/item&gt;&lt;/order&gt;</pre>`,
    ),
    { status: 200, headers: demoHeaders() },
  );
}

export async function POST(req: NextRequest) {
  const body = await req.text().catch(() => "");
  const hasDoctype = /<!DOCTYPE/i.test(body);
  const hasEntity = /<!ENTITY/i.test(body);

  let xml: string;
  if (hasDoctype && hasEntity && /etc\/passwd|file:\/\//i.test(body)) {
    // Entity resolved — the external file's contents land in the response.
    xml = `<response><status>imported</status><content>${FAKE_PASSWD}</content></response>`;
  } else if (hasDoctype && hasEntity) {
    // Entity declared (echoed back) even if the target file is unknown.
    xml = `<response><status>imported</status><content>${body.replace(/[<]content[>]|<\/content>/g, "")}</content></response>`;
  } else {
    xml = `<response><status>imported</status><bytes>${body.length}</bytes></response>`;
  }

  return new NextResponse(xml, {
    status: 200,
    headers: demoHeaders({ "Content-Type": "application/xml" }),
  });
}
