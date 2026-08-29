import { NextResponse } from "next/server";

/**
 * GET /api/demo
 *
 * Deliberately vulnerable test site for ScriptKiddie-Recon.
 *
 * This endpoint serves the landing page linking to every vulnerable
 * endpoint. The vulnerabilities are INTENTIONAL, SIMULATED (no real
 * execution / fetching / filesystem access) and exist ONLY for testing
 * the scanner. NEVER deploy this to a production server.
 *
 * Endpoints (see README "Demo walkthrough" for the feature mapping):
 *   - /api/demo/search?q=        → Reflected XSS
 *   - /api/demo/login            → SQL injection + form login + JWT cookie
 *   - /api/demo/user?id=         → IDOR
 *   - /api/demo/file?name=       → Path traversal
 *   - /api/demo/ping?host=       → Command injection (simulated output)
 *   - /api/demo/redirect?url=    → Open redirect
 *   - /api/demo/render?tpl=      → SSTI
 *   - /api/demo/fetch?url=       → SSRF (simulated metadata/internal leaks)
 *   - /api/demo/xml              → XXE (raw XML POST)
 *   - /api/demo/theme?color=     → CSS injection
 *   - /api/demo/upload           → Unrestricted file upload
 *   - /api/demo/token            → Weak JWT (no exp) shown + as cookie
 *   - /api/demo/admin            → Broken access control + unverified JWT
 *   - /api/demo/profile          → Rich form surface (select/textarea/
 *                                  checkbox/radio/hidden value=admin)
 *   - /api/demo/docs             → Docs hub (crawl-depth chain)
 *   - /api/demo/static/*.js      → Planted vulnerable JS + jQuery fingerprint
 *   - /api/demo/.git/config, .env, swagger.json, debug, actuator
 *                                → Directory brute-force finds
 *   - /api/demo/phpmyadmin (403), graphql (401), wp-admin (302)
 *
 * All responses deliberately:
 *   - Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
 *   - Set an insecure cookie (no Secure, no HttpOnly, SameSite=None)
 *   - Expose Server + X-Powered-By banners
 */

const LANDING_HTML = `<!DOCTYPE html>
<html>
<head>
  <title>VulnTest — Deliberately Vulnerable Demo Site</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="generator" content="VulnTest-CMS 2.1.7">
  <style>
    body { font-family: sans-serif; max-width: 800px; margin: 2rem auto; padding: 1rem; }
    h1 { color: #c62828; }
    .vuln { border: 1px solid #ffcdd2; padding: 1rem; margin: 1rem 0; border-radius: 4px; background: #fff5f5; }
    .vuln h3 { margin-top: 0; color: #c62828; }
    code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
    form { margin: 0.5rem 0; }
    input[type=text], input[type=password] { padding: 4px 8px; margin: 4px 0; }
    button { padding: 4px 12px; background: #1976d2; color: white; border: none; border-radius: 3px; cursor: pointer; }
    .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 1rem; border-radius: 4px; }
    ul { margin: 0.25rem 0; }
  </style>
  <script src="/api/demo/static/jquery-3.6.0.min.js"></script>
  <script src="/api/demo/static/analytics.js" defer></script>
</head>
<body>
  <h1>⚠ VulnTest Demo Site</h1>
  <div class="warning">
    <strong>WARNING:</strong> This site is deliberately vulnerable. It exists
    ONLY for testing the ScriptKiddie-Recon scanner. Never deploy to production.
  </div>

  <!-- DEV NOTE (remove before prod): the staging environment lives at
       http://192.168.1.50:5000 — don't share externally. -->
  <!-- TODO: remove the hardcoded API key sk-vulntest-9f8e7d6c5b4a3210abcdef
       from analytics.js before the client review. -->
  <!-- FIXME: /api/demo/debug is still enabled in production and dumps DB
       credentials. Also remember the admin backup password: Adm1nB4ckup! -->

  <h2>Vulnerable Endpoints</h2>

  <div class="vuln">
    <h3>1. Reflected XSS — Search</h3>
    <p>The search parameter is reflected in the page without encoding.</p>
    <form action="/api/demo/search" method="GET">
      <input type="text" name="q" placeholder="Search..." value="">
      <button type="submit">Search</button>
    </form>
    <p>Try: <code>?q=&lt;script&gt;alert(1)&lt;/script&gt;</code></p>
  </div>

  <div class="vuln">
    <h3>2. SQL Injection — Login</h3>
    <p>The login form uses a vulnerable SQL query that returns errors.</p>
    <form action="/api/demo/login" method="POST">
      <input type="text" name="username" placeholder="username" value="admin">
      <input type="password" name="password" placeholder="password" value="password">
      <button type="submit">Login</button>
    </form>
    <p>Try: <code>username = ' OR '1'='1</code></p>
  </div>

  <div class="vuln">
    <h3>3. IDOR — User Profile</h3>
    <p>Any user ID returns a profile (no access control).</p>
    <p><a href="/api/demo/user?id=1">View user 1</a> | <a href="/api/demo/user?id=2">View user 2</a> | <a href="/api/demo/user?id=999">View user 999</a></p>
  </div>

  <div class="vuln">
    <h3>4. Path Traversal — File Viewer</h3>
    <p>The file parameter reads from disk without sanitisation.</p>
    <p><a href="/api/demo/file?name=readme.txt">View readme.txt</a></p>
    <p>Try: <code>?name=../../../../etc/passwd</code></p>
  </div>

  <div class="vuln">
    <h3>5. Command Injection — Network Tools</h3>
    <p>The ping utility passes the host parameter to a shell (simulated).</p>
    <form action="/api/demo/ping" method="GET">
      <input type="text" name="host" placeholder="hostname or IP" value="">
      <button type="submit">Ping</button>
    </form>
    <p>Try: <code>?host=127.0.0.1; id</code></p>
  </div>

  <div class="vuln">
    <h3>6. Open Redirect — Continue</h3>
    <p>Redirects to any absolute URL from the url parameter.</p>
    <form action="/api/demo/redirect" method="GET">
      <input type="text" name="url" placeholder="https://example.com/next" value="">
      <button type="submit">Continue</button>
    </form>
  </div>

  <div class="vuln">
    <h3>7. SSTI — Email Template Preview</h3>
    <p>Evaluates template expressions from user input.</p>
    <form action="/api/demo/render" method="GET">
      <input type="text" name="tpl" placeholder="Hello {{name}}!" value="">
      <button type="submit">Preview</button>
    </form>
    <p>Try: <code>?tpl={{7*7}}</code></p>
  </div>

  <div class="vuln">
    <h3>8. SSRF — URL Preview</h3>
    <p>Fetches arbitrary URLs server-side (simulated), including internal hosts.</p>
    <form action="/api/demo/fetch" method="GET">
      <input type="text" name="url" placeholder="http://internal-service/api" style="width:400px" value="">
      <button type="submit">Fetch</button>
    </form>
  </div>

  <div class="vuln">
    <h3>9. XXE — XML Import</h3>
    <p>Accepts raw XML with external entity resolution enabled.</p>
    <p><a href="/api/demo/xml">Open XML import API</a></p>
  </div>

  <div class="vuln">
    <h3>10. CSS Injection — Theme Customizer</h3>
    <p>Reflects the color parameter into a &lt;style&gt; block.</p>
    <form action="/api/demo/theme" method="GET">
      <input type="text" name="color" placeholder="#ffffff or red" value="">
      <button type="submit">Apply</button>
    </form>
  </div>

  <div class="vuln">
    <h3>11. Unrestricted File Upload — Avatar</h3>
    <p>Accepts any file with no extension/MIME/content validation.</p>
    <p><a href="/api/demo/upload">Open upload form</a></p>
  </div>

  <div class="vuln">
    <h3>12. Weak JWT — API Token</h3>
    <p>Issues a token that never expires, shown in the page and set as a cookie.</p>
    <p><a href="/api/demo/token">View your API token</a></p>
  </div>

  <div class="vuln">
    <h3>13. Broken Access Control — Admin Dashboard</h3>
    <p>Full admin content (incl. user SSNs) served without any session.</p>
    <p><a href="/api/demo/admin">Open admin dashboard</a></p>
  </div>

  <div class="vuln">
    <h3>14. Rich Form — Profile Settings</h3>
    <p>Selects, textareas, checkboxes, radios and a hidden role field.</p>
    <p><a href="/api/demo/profile">Open profile settings</a></p>
  </div>

  <h2>More</h2>
  <ul>
    <li><a href="/api/demo/docs">Documentation hub</a></li>
    <li><a href="/api/demo/static/analytics.js">analytics.js</a> (planted vulnerable JavaScript)</li>
    <li><a href="/api/demo/static/jquery-3.6.0.min.js">jquery-3.6.0.min.js</a></li>
  </ul>

  <h2>Scanner Hints</h2>
  <p>To test the scanner against this site:</p>
  <ol>
    <li>Go to <strong>New Scan</strong> and click the blue <strong>Fill demo target</strong> button
        (configures the full-feature demo scan)</li>
    <li>Optionally use <strong>Launch Browser to Login</strong> first and log in as
        <code>admin / admin123</code> to demo the authenticated flow</li>
    <li>Launch the scan</li>
  </ol>
</body>
</html>`;

export async function GET() {
  // Deliberately missing ALL security headers + setting an insecure cookie.
  // This is the "vulnerability" the scanner should detect.
  return new NextResponse(LANDING_HTML, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      // Deliberately NO: Strict-Transport-Security, Content-Security-Policy,
      // X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
      "Server": "VulnTest/1.0 (Deliberately Vulnerable)",
      "X-Powered-By": "VulnTest-Express/0.0.1",
      // Insecure cookie: no Secure, no HttpOnly, SameSite=None.
      "Set-Cookie": "sessionid=vulnsession123; Path=/; SameSite=None",
    },
  });
}
