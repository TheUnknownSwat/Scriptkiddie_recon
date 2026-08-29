import { NextRequest, NextResponse } from "next/server";

/**
 * GET /api/scans/[id]/manual-login/status
 *
 * Checks if a manual-login browser session is currently active.
 * Proxies to the manual-login mini-service on port 3001.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id: _id } = await params;

  try {
    const resp = await fetch(`http://localhost:3001/status`);
    const data = await resp.json();
    return NextResponse.json(data);
  } catch (e) {
    return NextResponse.json(
      {
        active: false,
        error: "Manual-login service not reachable",
        detail: e instanceof Error ? e.message : String(e),
      },
      { status: 200 },  // return 200 so the UI doesn't error — just shows "not active"
    );
  }
}
