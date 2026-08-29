import { NextResponse } from "next/server";

/**
 * POST /api/manual-login/capture
 *
 * Standalone version of /api/scans/[id]/manual-login/capture — used by the
 * New Scan form. Asks the manual-login mini-service to save the current
 * browser's storageState (cookies + localStorage) to the statePath that
 * was returned by /api/manual-login/launch.
 *
 * The frontend should call this AFTER the user has finished logging in
 * manually in the popup browser.
 *
 * Response (JSON):
 *   { ok: true, statePath }
 *   { ok: false, error }
 */
export async function POST() {
  try {
    const resp = await fetch("http://localhost:3001/capture", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    const data = await resp.json();
    if (!resp.ok) {
      return NextResponse.json(
        { error: data.error || "Failed to capture session" },
        { status: resp.status },
      );
    }
    // The mini-service returns { ok, statePath } — pass it through.
    return NextResponse.json({
      ok: true,
      statePath: data.statePath,
    });
  } catch (e) {
    return NextResponse.json(
      {
        error:
          "Failed to connect to the manual-login service. Is it running?",
        detail: e instanceof Error ? e.message : String(e),
      },
      { status: 502 },
    );
  }
}
