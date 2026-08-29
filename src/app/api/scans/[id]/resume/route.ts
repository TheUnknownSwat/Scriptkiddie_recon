import { NextRequest, NextResponse } from "next/server";
import { resumeScan } from "@/lib/scanner-runner";
import { db } from "@/lib/db";
import fs from "fs/promises";
import path from "path";

/**
 * POST /api/scans/[id]/resume
 *
 * Resume a previously interrupted/failed scan. Creates a new scan record
 * with the same config and spawns the scanner with --resume pointing to
 * the original scan's output directory. The scanner loads scan_state.json
 * and skips completed phases.
 *
 * Returns 201 with { id, status: 'running' } on success.
 * Returns 404 if the original scan doesn't exist.
 * Returns 409 if the original scan is still running (can't resume a running scan).
 * Returns 400 if scan_state.json doesn't exist (nothing to resume from).
 */
export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;

  const original = await db.scan.findUnique({ where: { id } });
  if (!original) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // Can't resume a scan that's still running.
  if (original.status === "running" || original.status === "pending") {
    return NextResponse.json(
      { error: "Cannot resume a scan that is still running" },
      { status: 409 },
    );
  }

  // Check that scan_state.json exists in the output dir.
  const statePath = path.join(
    process.cwd(),
    "scan-output",
    id,
    "scan_state.json",
  );
  try {
    await fs.access(statePath);
  } catch {
    return NextResponse.json(
      {
        error: "No scan_state.json found",
        detail:
          "This scan has no saved state to resume from. This happens if the scan was interrupted before the first phase completed, or if the state file was deleted.",
      },
      { status: 400 },
    );
  }

  try {
    const newScanId = await resumeScan(id);
    return NextResponse.json(
      { id: newScanId, status: "running", resumedFrom: id },
      { status: 201 },
    );
  } catch (e) {
    return NextResponse.json(
      {
        error: "Failed to resume scan",
        detail: e instanceof Error ? e.message : String(e),
      },
      { status: 500 },
    );
  }
}
