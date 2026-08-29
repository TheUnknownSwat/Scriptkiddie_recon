import { NextRequest, NextResponse } from "next/server";
import fs from "fs/promises";
import path from "path";

/**
 * GET /api/scans/[id]/javascripts
 *
 * Serves javascripts.json — the list of <script src> URLs the scanner
 * collected from the crawled page HTML. Each entry: {url, found_on[], external, filename}.
 * Used by the JavaScripts tab so the engineer can SEE every JS file the app loads.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const filePath = path.join(process.cwd(), "scan-output", id, "javascripts.json");
  try {
    const content = await fs.readFile(filePath, "utf-8");
    return NextResponse.json(JSON.parse(content));
  } catch {
    return NextResponse.json(
      { items: [], error: "No JavaScripts collected yet (scan may not have reached the crawl phase)." },
      { status: 404 },
    );
  }
}
