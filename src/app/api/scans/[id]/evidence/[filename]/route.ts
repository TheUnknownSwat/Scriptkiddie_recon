import { NextRequest, NextResponse } from "next/server";
import fs from "fs/promises";
import { safeEvidencePath } from "@/lib/scanner-paths";

/**
 * GET /api/scans/[id]/evidence/[filename]
 *
 * Serve an evidence file (raw .txt request/response pairs or screenshots)
 * from a scan's evidence directory. Used by the Raw Evidence Vault tab
 * when the engineer clicks "View" on a file.
 *
 * SECURITY: We use safeEvidencePath() to prevent path traversal — the
 * filename is resolved and verified to be inside the scan's evidence
 * directory before we read it.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string; filename: string }> },
) {
  const { id, filename } = await params;

  // Decode URL-encoded filenames (e.g. spaces, special chars).
  const decodedName = decodeURIComponent(filename);
  const safePath = safeEvidencePath(id, decodedName);
  if (!safePath) {
    return NextResponse.json(
      { error: "Invalid filename (path traversal blocked)" },
      { status: 400 },
    );
  }

  let content: Buffer;
  try {
    content = await fs.readFile(safePath);
  } catch {
    return NextResponse.json(
      { error: "File not found" },
      { status: 404 },
    );
  }

  // Determine content type from extension. Evidence files are either
  // .txt (raw request/response) or .png (screenshots).
  const ext = decodedName.toLowerCase().split(".").pop();
  let contentType = "text/plain; charset=utf-8";
  if (ext === "png") contentType = "image/png";
  else if (ext === "jpg" || ext === "jpeg") contentType = "image/jpeg";

  return new NextResponse(content, {
    status: 200,
    headers: {
      "Content-Type": contentType,
      // Allow inline display (for images) and download (for text).
      "Content-Disposition": `inline; filename="${decodedName}"`,
    },
  });
}
