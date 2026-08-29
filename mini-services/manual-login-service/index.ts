/**
 * Manual Login Service
 *
 * A standalone Bun server that manages a Playwright HEADED (visible) browser
 * for manual authentication. The user logs in manually (handling CAPTCHA,
 * 2FA, SSO), then clicks "Capture Session & Continue" in the web UI, which
 * tells this service to save the browser's cookies + localStorage to a
 * state.json file.
 *
 * Endpoints:
 *   POST /start    — launch a headed browser + navigate to the login URL
 *   POST /capture  — save cookies + localStorage to state.json, close browser
 *   GET  /status   — check if a browser session is active
 *   POST /cancel   — close the browser without saving
 *
 * The service runs on port 3001. The Next.js API proxies requests to it
 * via the XTransformPort query param (Caddy gateway requirement).
 *
 * WHY A SEPARATE SERVICE: Playwright's headed browser is a long-running
 * process that can't live inside a Next.js API route (which is request-
 * scoped). The mini-service pattern keeps the browser alive between
 * requests and lets the user interact with it for as long as needed.
 */

import { chromium, Browser, BrowserContext, Page } from "playwright";

const PORT = 3001;

// In-memory state — only one manual login session at a time (single-user tool).
let activeBrowser: Browser | null = null;
let activeContext: BrowserContext | null = null;
let activePage: Page | null = null;
let sessionInfo: {
  loginUrl: string;
  scanId: string;
  startedAt: string;
  statePath: string;
} | null = null;

const server = Bun.serve({
  port: PORT,
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const method = req.method;
    const path = url.pathname;

    // CORS headers (the Next.js app is on port 3000).
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    // Handle CORS preflight.
    if (method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // POST /start — launch a headed browser + navigate to the login URL.
      if (path === "/start" && method === "POST") {
        // If a browser is already open, close it first.
        if (activeBrowser) {
          await closeBrowser();
        }

        const body = await req.json();
        const loginUrl = body.loginUrl;
        const scanId = body.scanId;
        const statePath = body.statePath;

        if (!loginUrl || !scanId || !statePath) {
          return Response.json(
            { error: "loginUrl, scanId, and statePath are required" },
            { status: 400, headers: corsHeaders },
          );
        }

        console.log(`[manual-login] Starting headed browser for ${loginUrl}`);

        // Launch a HEADED browser (headless: false) so the user can see
        // and interact with it. We use chromium because it's the most
        // widely installed.
        activeBrowser = await chromium.launch({
          headless: false,
          args: [
            "--disable-blink-features=AutomationControlled",
            "--no-first-run",
            "--no-default-browser-check",
          ],
        });

        // Create a new context with a realistic viewport.
        activeContext = await activeBrowser.newContext({
          viewport: { width: 1280, height: 800 },
          userAgent:
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        });

        activePage = await activeContext.newPage();

        // Navigate to the login URL.
        try {
          await activePage.goto(loginUrl, { waitUntil: "domcontentloaded", timeout: 30000 });
        } catch (e) {
          console.log(`[manual-login] Navigation warning: ${e}`);
        }

        sessionInfo = {
          loginUrl,
          scanId,
          startedAt: new Date().toISOString(),
          statePath,
        };

        console.log(`[manual-login] Browser ready. User can now log in manually.`);

        return Response.json(
          { ok: true, message: "Browser launched. Log in manually, then click 'Capture Session & Continue'." },
          { headers: corsHeaders },
        );
      }

      // POST /capture — save cookies + localStorage + sessionStorage to state.json.
      if (path === "/capture" && method === "POST") {
        if (!activePage || !activeContext || !sessionInfo) {
          return Response.json(
            { error: "No active browser session. Click 'Launch Browser to Login' first." },
            { status: 400, headers: corsHeaders },
          );
        }

        console.log(`[manual-login] Capturing session state...`);

        // Capture the full browser state (cookies + localStorage + sessionStorage).
        // Playwright's storageState() returns a JSON object with cookies + origins
        // (each origin has localStorage entries).
        const state = await activeContext.storageState();

        // Also capture sessionStorage (Playwright's storageState doesn't include it).
        // We evaluate JS in the page to extract sessionStorage per origin.
        let sessionStorage: Record<string, Record<string, string>> = {};
        try {
          // Get the current origin's sessionStorage.
          const origin = new URL(activePage.url()).origin;
          const ss = await activePage.evaluate(() => {
            const items: Record<string, string> = {};
            for (let i = 0; i < sessionStorage.length; i++) {
              const key = sessionStorage.key(i)!;
              items[key] = sessionStorage.getItem(key)!;
            }
            return items;
          });
          if (Object.keys(ss).length > 0) {
            sessionStorage[origin] = ss;
          }
        } catch (e) {
          console.log(`[manual-login] sessionStorage capture warning: ${e}`);
        }

        // Build the state object. This is the format scanner.py's --load-state
        // flag expects (Playwright storageState format + sessionStorage).
        const fullState = {
          ...state,
          sessionStorage,
          capturedAt: new Date().toISOString(),
          scanId: sessionInfo.scanId,
          loginUrl: sessionInfo.loginUrl,
        };

        // Write to the state path.
        const statePath = sessionInfo.statePath;
        await Bun.write(statePath, JSON.stringify(fullState, null, 2));

        console.log(`[manual-login] State saved to ${statePath}`);
        console.log(`[manual-login]   cookies: ${state.cookies.length}`);
        console.log(`[manual-login]   origins with localStorage: ${state.origins.length}`);
        console.log(`[manual-login]   origins with sessionStorage: ${Object.keys(sessionStorage).length}`);

        // Close the browser.
        await closeBrowser();

        return Response.json(
          {
            ok: true,
            message: "Session captured successfully. The scan will continue with this state.",
            cookiesCount: state.cookies.length,
            localStorageOrigins: state.origins.length,
            sessionStorageOrigins: Object.keys(sessionStorage).length,
            statePath,
          },
          { headers: corsHeaders },
        );
      }

      // GET /status — check if a browser session is active.
      if (path === "/status" && method === "GET") {
        return Response.json(
          {
            active: activeBrowser !== null,
            sessionInfo,
          },
          { headers: corsHeaders },
        );
      }

      // POST /cancel — close the browser without saving.
      if (path === "/cancel" && method === "POST") {
        await closeBrowser();
        return Response.json(
          { ok: true, message: "Browser closed without saving." },
          { headers: corsHeaders },
        );
      }

      // Health check.
      if (path === "/" && method === "GET") {
        return Response.json(
          { ok: true, service: "manual-login", port: PORT },
          { headers: corsHeaders },
        );
      }

      return Response.json(
        { error: "Not found" },
        { status: 404, headers: corsHeaders },
      );
    } catch (e) {
      console.error(`[manual-login] Error:`, e);
      return Response.json(
        { error: e instanceof Error ? e.message : String(e) },
        { status: 500, headers: corsHeaders },
      );
    }
  },
});

async function closeBrowser(): Promise<void> {
  try {
    if (activePage) await activePage.close().catch(() => {});
    if (activeContext) await activeContext.close().catch(() => {});
    if (activeBrowser) await activeBrowser.close().catch(() => {});
  } catch (e) {
    console.error(`[manual-login] Error closing browser:`, e);
  } finally {
    activeBrowser = null;
    activeContext = null;
    activePage = null;
    sessionInfo = null;
  }
}

console.log(`[manual-login] Service running on port ${PORT}`);
console.log(`[manual-login] Endpoints:`);
console.log(`  POST /start    — launch headed browser`);
console.log(`  POST /capture  — save session state + close browser`);
console.log(`  GET  /status   — check if session is active`);
console.log(`  POST /cancel   — close browser without saving`);
