import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import path from "path";
import { scanOutputDir } from "@/lib/scanner-paths";

/**
 * POST /api/scans/[id]/manual-login/start
 *
 * Starts a HEADED Playwright browser for manual login. The user logs in
 * manually (handles CAPTCHA, 2FA, SSO), then clicks "Capture Session &
 * Continue" which calls the /capture endpoint.
 *
 * This route PROXIES to the manual-login mini-service on port 3001.
 * The mini-service manages the long-lived browser instance (which can't
 * live inside a Next.js API route due to request-scoping).
 *
 * Request body (JSON):
 *   loginUrl: string  (the URL to navigate to — usually the target's login page)
 *
 * The scan record's manualLoginStatePath is set to
 * scan-output/<id>/manual_login_state.json — this is where the captured
 * state will be saved.
 */
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;

  const scan = await db.scan.findUnique({ where: { id } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  let body: { loginUrl?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const loginUrl = body.loginUrl || scan.targetUrl;
  if (!loginUrl) {
    return NextResponse.json({ error: "loginUrl is required" }, { status: 400 });
  }

  // The state file path — this is where the mini-service will save the
  // captured cookies + localStorage.
  const outputDir = await scanOutputDir(id);
  const statePath = path.join(outputDir, "manual_login_state.json");

  // Update the scan record to indicate manual login is in progress.
  await db.scan.update({
    where: { id },
    data: {
      manualLoginState: true,
      manualLoginStatePath: statePath,
    },
  });

  // Proxy to the manual-login mini-service on port 3001.
  // We use the XTransformPort query param so Caddy forwards to port 3001.
  try {
    const resp = await fetch(
      `http://localhost:3001/start`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          loginUrl,
          scanId: id,
          statePath,
        }),
      },
    );
    const data = await resp.json();
    if (!resp.ok) {
      return NextResponse.json(
        { error: data.error || "Failed to start browser" },
        { status: resp.status },
      );
    }
    return NextResponse.json(data);
  } catch (e) {
    return NextResponse.json(
      {
        error:
          "Failed to connect to the manual-login service. Is it running? Start it with: cd mini-services/manual-login-service && bun run dev",
        detail: e instanceof Error ? e.message : String(e),
      },
      { status: 502 },
    );
  }
}
