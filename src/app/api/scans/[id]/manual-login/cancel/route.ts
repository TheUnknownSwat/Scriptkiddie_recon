import { NextRequest, NextResponse } from "next/server";

/**
 * POST /api/scans/[id]/manual-login/cancel
 *
 * Cancels a manual-login browser session (closes the browser without
 * saving). Proxies to the manual-login mini-service on port 3001.
 */
export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id: _id } = await params;

  try {
    const resp = await fetch(
      `http://localhost:3001/cancel`,
      { method: "POST", headers: { "Content-Type": "application/json" } },
    );
    const data = await resp.json();
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
