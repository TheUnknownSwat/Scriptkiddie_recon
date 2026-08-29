import { NextRequest, NextResponse } from "next/server";
import fs from "fs/promises";
import { reportPath } from "@/lib/scanner-paths";
import { db } from "@/lib/db";

/**
 * GET /api/scans/[id]/report
 *
 * Serve the generated report.html for a scan. Returns 404 if the report
 * hasn't been generated yet (scan still running or failed before rendering).
 *
 * We return the HTML with Content-Type: text/html so the browser renders
 * it directly. The report is fully self-contained (no external deps), so
 * it can be displayed in an iframe or a new tab.
 *
 * Query param:
 *   ?download=1  → serve as a file attachment (Content-Disposition: attachment)
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const scan = await db.scan.findUnique({ where: { id } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const filePath = reportPath(id);
  let content: string;
  try {
    content = await fs.readFile(filePath, "utf-8");
  } catch {
    return NextResponse.json(
      {
        error: "Report not yet generated",
        detail:
          scan.status === "running"
            ? "Scan is still running. The report is generated at the end of the scan."
            : scan.status === "failed"
              ? `Scan failed: ${scan.errorMsg || "unknown error"}`
              : "The report file could not be found.",
      },
      { status: 404 },
    );
  }

  const isDownload = new URL(req.url).searchParams.get("download") === "1";
  const headers: Record<string, string> = {
    "Content-Type": "text/html; charset=utf-8",
    // The report uses inline <style> tags for CSS (needs 'unsafe-inline'
    // for style-src) and inline <script> tags for the tab-switching JS
    // (needs 'unsafe-inline' for script-src). However, we do NOT want
    // XSS payloads embedded in the JSON data blocks to execute — the
    // _sanitize_json_for_html() function in scanner.py handles that by
    // escaping </script> in the JSON. This CSP is a defence-in-depth
    // layer: if sanitization fails, the CSP blocks external connections.
    "Content-Security-Policy":
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none';",
  };
  if (isDownload) {
    const safeUrl = scan.targetUrl.replace(/[^a-z0-9.-]/gi, "_");
    headers["Content-Disposition"] = `attachment; filename="webrecon-report-${safeUrl}-${id.slice(-8)}.html"`;
  }

  return new NextResponse(content, { status: 200, headers });
}
