import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { isScanRunning } from "@/lib/scanner-runner";
import path from "path";
import fs from "fs/promises";

/**
 * DELETE /api/scans/[id]
 *
 * Deletes a scan from the database + removes its scan-output directory.
 *
 * Safety checks:
 *   - Cannot delete a running scan (returns 409)
 *   - Removes the DB row first, then the output directory
 *   - If the output directory deletion fails, the DB row is already gone
 *     (so the scan disappears from the dashboard) — the orphaned dir
 *     can be manually deleted later.
 */
export async function DELETE(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const scan = await db.scan.findUnique({ where: { id } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // Can't delete a running scan.
  if (scan.status === "running" || scan.status === "pending") {
    return NextResponse.json(
      { error: "Cannot delete a scan that is still running. Stop it first." },
      { status: 409 },
    );
  }

  // Delete the DB row.
  await db.scan.delete({ where: { id } });

  // Delete the scan-output directory.
  const outputDir = path.join(process.cwd(), "scan-output", id);
  try {
    await fs.rm(outputDir, { recursive: true, force: true });
  } catch (e) {
    // Non-fatal — the DB row is already deleted, so the scan won't
    // appear in the dashboard. The orphaned directory can be cleaned
    // up manually.
    console.error(`[delete] Failed to remove ${outputDir}:`, e);
  }

  return NextResponse.json({ ok: true, deleted: id });
}
