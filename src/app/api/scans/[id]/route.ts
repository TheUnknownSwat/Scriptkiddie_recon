import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { isScanRunning } from "@/lib/scanner-runner";
import fs from "fs/promises";
import path from "path";
import { evidenceDir, safeEvidencePath } from "@/lib/scanner-paths";

/**
 * GET /api/scans/[id]
 *
 * Get a single scan's status + metadata. Includes the list of evidence
 * files (so the UI can render a file browser without a separate round-trip).
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const scan = await db.scan.findUnique({ where: { id } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // Enumerate evidence files (if the evidence dir exists).
  let evidenceFiles: Array<{
    name: string;
    sizeBytes: number;
    modified: string;
  }> = [];
  try {
    const dir = evidenceDir(id);
    const entries = await fs.readdir(dir);
    for (const name of entries) {
      const full = path.join(dir, name);
      const stat = await fs.stat(full);
      evidenceFiles.push({
        name,
        sizeBytes: stat.size,
        modified: stat.mtime.toISOString(),
      });
    }
    // Sort by modification time, newest first.
    evidenceFiles.sort((a, b) => b.modified.localeCompare(a.modified));
  } catch {
    // Evidence dir doesn't exist yet (scan still running or no active checks).
  }

  return NextResponse.json({
    scan: {
      ...scan,
      isRunning: isScanRunning(id),
    },
    evidenceFiles,
  });
}
