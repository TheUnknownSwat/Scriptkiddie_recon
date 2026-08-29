import { NextRequest, NextResponse } from "next/server";
import { demoHeaders, demoPage, uploadStore } from "../store";

/**
 * GET /api/demo/[...path]
 *
 * Catch-all serving the demo site's "hidden" content — everything the
 * directory brute-force phase probes for, plus the planted vulnerable
 * JavaScript files, plus uploaded files. Specific routes (search, login,
 * user, file, ping, …) take precedence over this catch-all.
 *
 * Everything is fake/simulated:
 *   - static/analytics.js         → planted vulnerable JS (eval sink,
 *                                   innerHTML of dynamic data, postMessage
 *                                   without origin check, hardcoded API key,
 *                                   hidden debug command) — for the
 *                                   "Analyze JS with AI" feature
 *   - static/jquery-3.6.0.min.js  → version fingerprint target (Inventory)
 *   - .git/config, .env, swagger.json, debug → classic dir-brute finds
 *   - uploads/<name>              → files accepted by /api/demo/upload
 *   - phpmyadmin → 403, graphql → 401, wp-admin → 302 (status-code variety
 *     in the Dir Brute tab)
 *   - anything else → honest 404
 */

const ANALYTICS_JS = `// VulnTest analytics v0.9 — DO NOT SHIP TO PRODUCTION
var apiKey = "sk-vulntest-9f8e7d6c5b4a3210abcdef";

function trackEvent(e) {
  // eval sink fed with dynamic data (XSS / code injection context)
  try { eval("window.__track(" + JSON.stringify(e) + ")"); } catch (_) {}
}

// DOM XSS sink: attacker-controlled hash written straight into the DOM
window.addEventListener("hashchange", function () {
  var el = document.getElementById("out");
  if (el) el.innerHTML = location.hash.slice(1);
});

// postMessage handler with NO origin check — anyone can message us
window.addEventListener("message", function (ev) {
  if (ev.data && ev.data.cmd === "exec") { eval(ev.data.code); }
}, false);

// hidden debug backdoor behind a magic query param
if (location.search.indexOf("debugkey=vulntest") !== -1) {
  console.log("[analytics] backdoor active, key:", apiKey);
}

// session data exfiltration surface
fetch("/api/demo/collect?d=" + encodeURIComponent(document.cookie));
`;

const JQUERY_STUB = `/*! jQuery v3.6.0 | (c) OpenJS Foundation and other contributors | jquery.org/license */
// VulnTest stub bundle — demo fingerprint target for the Software Inventory.
window.jQuery = function (sel) { return document.querySelector(sel); };
`;

const GIT_CONFIG = `[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = https://git.vulntest.local/internal/vulntest-web.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[user]
\tname = VulnTest Dev
\temail = dev@vulntest.local
`;

const ENV_FILE = `APP_ENV=production
APP_DEBUG=true
DB_HOST=192.168.1.50
DB_USER=admin
DB_PASS=s3cr3t123
STRIPE_KEY=sk-vulntest-9f8e7d6c5b4a3210abcdef
MAIL_HOST=mail.vulntest.local
`;

const SWAGGER = JSON.stringify(
  {
    openapi: "3.0.0",
    info: { title: "VulnTest API", version: "2.1.7", description: "Internal API documentation (should not be public)" },
    servers: [{ url: "https://api.vulntest.local/v2" }],
    paths: {
      "/users": { get: { summary: "List all users (no access control)", responses: { "200": { description: "ok" } } } },
      "/admin/export": { get: { summary: "Export user data incl. SSNs", responses: { "200": { description: "ok" } } } },
    },
  },
  null,
  2,
);

const DEBUG_PAGE = demoPage(
  "Debug Console",
  `<h1>Debug Console (development)</h1>
   <pre>APP_ENV=production  APP_DEBUG=true
DB_HOST=192.168.1.50  DB_USER=admin  DB_PASS=s3cr3t123
session_store=/tmp/sessions
last_error=TypeError: cannot read property 'ssn' of undefined at /srv/app/user.js:42</pre>`,
);

function text(body: string, contentType: string, status = 200): NextResponse {
  return new NextResponse(body, {
    status,
    headers: { ...demoHeaders(), "Content-Type": contentType },
  });
}

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ path: string[] }> },
) {
  const { path } = await params;
  const p = path.join("/");

  switch (p) {
    case "static/analytics.js":
      return text(ANALYTICS_JS, "application/javascript; charset=utf-8");
    case "static/jquery-3.6.0.min.js":
      return text(JQUERY_STUB, "application/javascript; charset=utf-8");
    case ".git/config":
      return text(GIT_CONFIG, "text/plain; charset=utf-8");
    case ".env":
      return text(ENV_FILE, "text/plain; charset=utf-8");
    case "swagger.json":
      return text(SWAGGER, "application/json; charset=utf-8");
    case "debug":
      return text(DEBUG_PAGE, "text/html; charset=utf-8");
    case "actuator":
      return text(
        JSON.stringify({ _links: { self: { href: "/api/demo/actuator" } }, status: { db: "up", mail: "up" } }, null, 2),
        "application/json; charset=utf-8",
      );
    case "phpmyadmin":
      return text(demoPage("403", "<h1>403 — Forbidden</h1><p>You do not have access to this resource.</p>"), "text/html; charset=utf-8", 403);
    case "graphql":
      return text(JSON.stringify({ errors: [{ message: "Access denied — credentials required" }] }), "application/json; charset=utf-8", 401);
    case "wp-admin":
    case "wp-login.php":
      return new NextResponse(null, {
        status: 302,
        headers: { Location: "/api/demo/login", Server: "VulnTest/1.0" },
      });
    default: {
      if (p.startsWith("uploads/")) {
        const name = decodeURIComponent(p.slice("uploads/".length));
        const stored = uploadStore.get(name);
        if (stored) {
          // Serve the stored bytes (defaulting to text/plain so nothing
          // uploaded by the demo ever executes in the browser).
          const safeType = stored.type.startsWith("text/") ? stored.type : "text/plain; charset=utf-8";
          return text(stored.body, safeType);
        }
        return text(demoPage("404", `<h1>404</h1><p>Upload "${name}" not found (store resets on server restart).</p>`), "text/html; charset=utf-8", 404);
      }
      return text(demoPage("404", "<h1>404 — Not Found</h1>"), "text/html; charset=utf-8", 404);
    }
  }
}
