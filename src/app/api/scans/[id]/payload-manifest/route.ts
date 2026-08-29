import { NextRequest, NextResponse } from "next/server";
import fs from "fs/promises";
import path from "path";

/**
 * GET /api/scans/[id]/payload-manifest
 *
 * Serves payload_manifest.json — the per-scan audit record of EXACTLY what
 * was sent to the target (fuzzing payloads incl. LLM-appended ones, the
 * directory wordlist incl. llm_discovered_additions, file-upload probes,
 * JWT-forge + auth flags, data-flow note). Written near the end of the scan.
 *
 * Also returns the harvested JWT tokens (jwt_tokens.json) under `jwt_tokens`
 * for the Manifest tab's Auth & JWT section — masked display + copy for
 * manual testing. These are the user's own scan results, local-only.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const manifestPath = path.join(
    process.cwd(), "scan-output", id, "payload_manifest.json",
  );

  let manifest: unknown = null;
  try {
    manifest = JSON.parse(await fs.readFile(manifestPath, "utf-8"));
  } catch {
    return NextResponse.json(
      {
        manifest: null,
        jwt_tokens: [],
        error: "Payload manifest not found",
        detail:
          "The manifest is written near the END of the scan — it appears once the scan completes (or force-completes with report generation).",
      },
      { status: 404 },
    );
  }

  // JWT tokens (optional — collected during the passive phase).
  let jwt_tokens: Array<Record<string, unknown>> = [];
  try {
    const tokens = JSON.parse(
      await fs.readFile(
        path.join(process.cwd(), "scan-output", id, "jwt_tokens.json"),
        "utf-8",
      ),
    );
    if (Array.isArray(tokens)) jwt_tokens = tokens;
  } catch {
    // No tokens collected — fine.
  }

  return NextResponse.json({ manifest, jwt_tokens });
}
