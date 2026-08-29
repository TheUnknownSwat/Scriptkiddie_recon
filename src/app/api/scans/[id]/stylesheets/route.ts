import { NextRequest, NextResponse } from "next/server";
import fs from "fs/promises";
import path from "path";

/**
 * GET /api/scans/[id]/stylesheets
 *
 * Serves stylesheets.json — the list of <link rel=stylesheet> URLs the
 * scanner collected from the sitemap pages. Each entry:
 * {url, found_on[], external, filename, local_source}.
 * Used by the CSS tab so the engineer can SEE every stylesheet the app loads.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const filePath = path.join(process.cwd(), "scan-output", id, "stylesheets.json");
  try {
    const content = await fs.readFile(filePath, "utf-8");
    return NextResponse.json(JSON.parse(content));
  } catch {
    return NextResponse.json(
      { items: [], error: "No stylesheets collected yet (scan may not have reached the sitemap sweep phase)." },
      { status: 404 },
    );
  }
}
