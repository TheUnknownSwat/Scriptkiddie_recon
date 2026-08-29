import { NextRequest, NextResponse } from "next/server";
import fs from "fs/promises";
import path from "path";

/**
 * GET /api/scans/[id]/attack-surface
 *
 * Serves attack_surface.json (every discovered input — what active fuzzing
 * actually targeted, including dir-brute re-crawl additions) + crawl_map.json
 * (every crawled URL with depth/source/in-scope). For the Attack Surface tab.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const base = path.join(process.cwd(), "scan-output", id);

  let inputs: Array<Record<string, unknown>> = [];
  try {
    const parsed = JSON.parse(
      await fs.readFile(path.join(base, "attack_surface.json"), "utf-8"),
    );
    if (Array.isArray(parsed)) inputs = parsed;
  } catch {
    // not written yet
  }

  let crawlMap: Array<Record<string, unknown>> = [];
  try {
    const parsed = JSON.parse(
      await fs.readFile(path.join(base, "crawl_map.json"), "utf-8"),
    );
    if (Array.isArray(parsed)) crawlMap = parsed;
  } catch {
    // not written yet
  }

  if (inputs.length === 0 && crawlMap.length === 0) {
    return NextResponse.json(
      {
        inputs: [],
        crawlMap: [],
        error: "Attack surface not found",
        detail:
          "attack_surface.json / crawl_map.json haven't been written yet — they appear after the crawl phase.",
      },
      { status: 404 },
    );
  }

  return NextResponse.json({ inputs, crawlMap });
}
