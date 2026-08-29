import { NextRequest, NextResponse } from "next/server";
import fs from "fs/promises";
import path from "path";

/**
 * GET /api/scans/[id]/inventory
 *
 * Serves the software_inventory.json file (passive fingerprinting results).
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const filePath = path.join(process.cwd(), "scan-output", id, "software_inventory.json");
  try {
    const content = await fs.readFile(filePath, "utf-8");
    return NextResponse.json(JSON.parse(content));
  } catch {
    return NextResponse.json({ items: [], summary: {}, error: "Not found" }, { status: 404 });
  }
}
