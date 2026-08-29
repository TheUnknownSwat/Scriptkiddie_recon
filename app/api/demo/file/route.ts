import { NextRequest, NextResponse } from "next/server";

/**
 * GET /api/demo/file?name=...
 *
 * DELIBERATELY VULNERABLE: Path Traversal.
 *
 * The `name` parameter is used to construct a file path without any
 * sanitisation. A request like ?name=../../../../etc/passwd will attempt
 * to read a file outside the intended directory.
 *
 * We simulate file reads with an in-memory map (no actual filesystem
 * access) to avoid security issues in the demo environment. But the
 * response mimics what a real vulnerable app would return.
 */

const FILES: Record<string, string> = {
  "readme.txt": "Welcome to VulnTest! This is a deliberately vulnerable demo site.",
  "about.txt": "VulnTest v1.0 — Built for testing the ScriptKiddie-Recon scanner.",
  "config.txt": "DB_HOST=localhost\nDB_USER=admin\nDB_PASS=s3cr3t123",
};

export async function GET(req: NextRequest) {
  const name = req.nextUrl.searchParams.get("name") || "readme.txt";

  // VULNERABILITY: No path sanitisation. We check if the input contains
  // traversal sequences and simulate the response a real vulnerable app
  // would give.
  if (name.includes("..") || name.startsWith("/")) {
    // Simulate reading /etc/passwd (path traversal succeeded).
    const passwdContent = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
admin:x:1000:1000:Admin User:/home/admin:/bin/bash`;

    const html = `<!DOCTYPE html>
<html>
<head>
  <title>File: ${name} — VulnTest</title>
  <style>
    body { font-family: sans-serif; max-width: 800px; margin: 2rem auto; padding: 1rem; }
    pre { background: #1a1a1a; color: #00ff00; padding: 1rem; border-radius: 4px; overflow-x: auto; }
    .back { margin-bottom: 1rem; }
    .warning { color: #c62828; font-size: 0.8em; }
  </style>
</head>
<body>
  <div class="back"><a href="/api/demo">← Back to VulnTest</a></div>
  <h1>File: ${name}</h1>
  <p class="warning">⚠ Path traversal succeeded — file contents exposed!</p>
  <pre>${passwdContent}</pre>
</body>
</html>`;

    return new NextResponse(html, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Server": "VulnTest/1.0",
        "X-Powered-By": "VulnTest-PHP/5.6.40",
      },
    });
  }

  // Normal file read.
  const content = FILES[name];
  const html = `<!DOCTYPE html>
<html>
<head>
  <title>File: ${name} — VulnTest</title>
  <style>
    body { font-family: sans-serif; max-width: 800px; margin: 2rem auto; padding: 1rem; }
    pre { background: #f5f5f5; padding: 1rem; border-radius: 4px; overflow-x: auto; }
    .back { margin-bottom: 1rem; }
  </style>
</head>
<body>
  <div class="back"><a href="/api/demo">← Back to VulnTest</a></div>
  <h1>File: ${name}</h1>
  <pre>${content || "File not found."}</pre>
</body>
</html>`;

  return new NextResponse(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Server": "VulnTest/1.0",
      "X-Powered-By": "VulnTest-PHP/5.6.40",
    },
  });
}
