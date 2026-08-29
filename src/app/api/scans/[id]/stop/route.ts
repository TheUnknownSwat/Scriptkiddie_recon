import { NextRequest, NextResponse } from "next/server";
import { stopScan } from "@/lib/scanner-runner";
import { db } from "@/lib/db";

/**
 * POST /api/scans/[id]/stop
 *
 * Stop a running scan gracefully. Sends SIGTERM to the scanner subprocess,
 * which triggers its emergency-stop handler (saves partial evidence,
 * renders a partial report). The DB row's status is updated to
 * 'interrupted' by the runner's exit handler.
 *
 * Returns 200 if the signal was sent, 404 if the scan isn't running,
 * 409 if the scan is already finished.
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
  if (scan.status !== "running" && scan.status !== "pending") {
    return NextResponse.json(
      { error: `Scan is already ${scan.status}` },
      { status: 409 },
    );
  }
  const sent = await stopScan(id);
  if (!sent) {
    return NextResponse.json(
      { error: "Scan subprocess not found (it may have already exited)" },
      { status: 404 },
    );
  }
  return NextResponse.json({ ok: true, message: "SIGTERM sent" });
}
