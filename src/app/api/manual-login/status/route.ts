import { NextResponse } from "next/server";

/**
 * GET /api/manual-login/status
 *
 * Standalone version — proxies to the manual-login mini-service to check
 * whether a browser session is currently active. Used by the New Scan form
 * to know whether to show "Launch Browser" or "Capture Session".
 */
export async function GET() {
  try {
    const resp = await fetch("http://localhost:3001/status");
    const data = await resp.json();
    return NextResponse.json(data);
  } catch (e) {
    return NextResponse.json(
      {
        active: false,
        error:
          "Manual-login service not running. Start it with: cd mini-services/manual-login-service && bun run dev",
        detail: e instanceof Error ? e.message : String(e),
      },
      { status: 502 },
    );
  }
}
