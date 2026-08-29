import { NextRequest, NextResponse } from "next/server";
import fs from "fs/promises";
import path from "path";

/**
 * GET /api/scans/[id]/directory
 *
 * Serves the directory_findings.json file (directory brute-forcing results).
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const filePath = path.join(process.cwd(), "scan-output", id, "directory_findings.json");
  try {
    const content = await fs.readFile(filePath, "utf-8");
    return NextResponse.json({ findings: JSON.parse(content) });
  } catch {
    return NextResponse.json({ findings: [], error: "Not found" }, { status: 404 });
  }
}
