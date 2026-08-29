import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

/**
 * POST /api/scans/[id]/manual-login/capture
 *
 * Captures the current browser session (cookies + localStorage +
 * sessionStorage) and saves it to the state file. The user clicks
 * "Capture Session & Continue" in the UI after manually logging in.
 *
 * After capture, the scan can be launched (or resumed) — the scanner
 * will load the captured state via --load-state.
 *
 * Proxies to the manual-login mini-service on port 3001.
 */
export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;

  const scan = await db.scan.findUnique({ where: { id } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  try {
    const resp = await fetch(
      `http://localhost:3001/capture`,
      { method: "POST", headers: { "Content-Type": "application/json" } },
    );
    const data = await resp.json();
    if (!resp.ok) {
      return NextResponse.json(
        { error: data.error || "Failed to capture session" },
        { status: resp.status },
      );
    }

    // Update the scan record to indicate the state was captured.
    await db.scan.update({
      where: { id },
      data: {
        manualLoginState: true,
        loginSucceeded: true,
      },
    });

    return NextResponse.json(data);
  } catch (e) {
    return NextResponse.json(
      {
        error: "Failed to connect to the manual-login service.",
        detail: e instanceof Error ? e.message : String(e),
      },
      { status: 502 },
    );
  }
}
