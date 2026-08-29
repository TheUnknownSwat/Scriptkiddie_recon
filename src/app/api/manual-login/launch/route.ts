import { NextRequest, NextResponse } from "next/server";
import path from "path";
import fs from "fs/promises";
import { randomUUID } from "crypto";

/**
 * POST /api/manual-login/launch
 *
 * Standalone version of /api/scans/[id]/manual-login/start — used by the
 * New Scan form BEFORE a scan record exists. Generates a unique session ID,
 * creates a directory under scan-output/_manual-login/<sessionId>/, and
 * asks the manual-login mini-service (port 3001) to open a headed browser
 * at the given loginUrl.
 *
 * After the user logs in manually, the frontend calls
 * /api/manual-login/capture to save the storageState to
 * scan-output/_manual-login/<sessionId>/manual_login_state.json. The
 * frontend then includes that path in the POST /api/scans body so the
 * scanner-runner passes it to scanner.py via --load-state.
 *
 * Request body (JSON):
 *   loginUrl: string  (required — the URL the browser should open)
 *
 * Response (JSON):
 *   { ok: true, sessionId, statePath }
 *   { ok: false, error }
 */
export async function POST(req: NextRequest) {
  let body: { loginUrl?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const loginUrl = body.loginUrl?.trim();
  if (!loginUrl) {
    return NextResponse.json({ error: "loginUrl is required" }, { status: 400 });
  }
  if (!/^https?:\/\//i.test(loginUrl)) {
    return NextResponse.json(
      { error: "loginUrl must start with http:// or https://" },
      { status: 400 },
    );
  }

  // Generate a unique session ID + directory for the state file.
  const sessionId = randomUUID().slice(0, 12);
  const sessionDir = path.join(
    process.cwd(),
    "scan-output",
    "_manual-login",
    sessionId,
  );
  await fs.mkdir(sessionDir, { recursive: true });
  const statePath = path.join(sessionDir, "manual_login_state.json");

  // Proxy to the manual-login mini-service on port 3001.
  try {
    const resp = await fetch("http://localhost:3001/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        loginUrl,
        scanId: `_manual-login-${sessionId}`,
        statePath,
      }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      return NextResponse.json(
        { error: data.error || "Failed to start browser" },
        { status: resp.status },
      );
    }
    return NextResponse.json({ ok: true, sessionId, statePath });
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
