import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { stopScan } from "@/lib/scanner-runner";
import { readFindingsCounts, SCANNER_PATH } from "@/lib/scanner-paths";
import { findPythonWithPlaywright } from "@/lib/scanner-runner";
import path from "path";
import fs from "fs/promises";
import { execFileSync } from "child_process";

/**
 * POST /api/scans/[id]/force-complete
 *
 * Force-completes a running scan. Unlike /stop (which marks the scan as
 * "interrupted"), this endpoint:
 *   1. Sends SIGTERM (then SIGKILL after 10s) to stop the scanner subprocess
 *   2. Waits for the subprocess to exit
 *   3. If a report.html already exists (from the scanner's partial render),
 *      marks the scan as "completed" instead of "interrupted"
 *   4. If no report exists, runs the scanner's finalize step manually
 *      by calling the report generation endpoint
 *
 * Use case: The scan is taking too long or is stuck, but the user wants
 * to keep whatever findings were collected so far AND have a proper
 * "completed" status (not "interrupted") so the report is easy to find.
 */
export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const scan = await db.scan.findUnique({ where: { id } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // If the scan is already completed, just return OK.
  // NOTE: We do NOT early-return on "failed" — the user may want to
  // force-complete a failed scan to generate a report from whatever
  // partial findings were collected before the crash.
  if (scan.status === "completed") {
    return NextResponse.json({
      ok: true,
      message: `Scan is already completed`,
      status: scan.status,
    });
  }

  // Stop the subprocess if it might still be running.
  // This covers: running, pending, paused, AND interrupted (in case
  // the supervisor restarted a scanner that's still running but the
  // DB shows "interrupted").
  if (scan.status === "running" || scan.status === "pending" ||
      scan.status === "paused" || scan.status === "interrupted") {
    try {
      await stopScan(id);
    } catch {}
    // Give the subprocess a moment to exit and write its final state
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }

  // Kill ANY orphaned Chrome processes. If the scanner was frozen and
  // stopScan() killed the Python process, Chrome may still be running
  // as an orphan. This ensures a clean slate.
  try {
    const { execSync } = await import("child_process");
    execSync(
      "pkill -9 -f chromium 2>/dev/null; pkill -9 -f chrome 2>/dev/null; "
      + "pkill -9 -f headless 2>/dev/null; "
      + "pkill -9 -f chrome-headless-shell 2>/dev/null; "
      + "pkill -9 -f remote-debugging-pipe 2>/dev/null; echo done",
      { timeout: 5000, encoding: "utf-8" }
    );
  } catch {}

  // Check if the scanner already wrote a report.html
  const reportPath = path.join(
    process.cwd(),
    "scan-output",
    id,
    "report.html",
  );
  let hasReport = false;
  try {
    const stat = await fs.stat(reportPath);
    hasReport = stat.size > 0;
  } catch {
    hasReport = false;
  }

  // If no report exists, regenerate the FULL styled report from the JSON
  // files on disk via the scanner's --report-only mode (no browser, no
  // network, no LLM). This produces the same tabbed report a normal scan
  // gets — Executive Summary, Headers, SSL/TLS, OWASP, Evidence — instead
  // of the minimal "table + raw logs" HTML the route used to write inline.
  if (!hasReport) {
    try {
      const outputDir = path.join(process.cwd(), "scan-output", id);
      const pyBin = findPythonWithPlaywright();
      execFileSync(
        pyBin,
        [SCANNER_PATH, "--url", scan.targetUrl, "--output", outputDir, "--report-only"],
        { cwd: outputDir, stdio: ["ignore", "pipe", "pipe"], encoding: "utf-8", timeout: 60000 },
      );
      // Verify it actually wrote something.
      try {
        const stat = await fs.stat(reportPath);
        hasReport = stat.size > 0;
      } catch {}
    } catch (e) {
      // Report regeneration failed (e.g. python not found, no JSON files).
      // Fall back to marking no-report; the scan is still completed below.
      hasReport = false;
    }
  }

  // Parse the trail for urls/inputs (NOT findings — see note below).
  const trailPath = path.join(
    process.cwd(),
    "scan-output",
    id,
    "execution_trail.jsonl",
  );
  let urlsCrawled = 0;
  let inputsDiscovered = 0;
  try {
    const content = await fs.readFile(trailPath, "utf-8");
    for (const line of content.split("\n")) {
      if (!line.trim()) continue;
      try {
        const entry = JSON.parse(line);
        if (entry.action === "crawl_done") {
          const m = String(entry.result || "").match(/visited (\d+) URLs/);
          if (m) urlsCrawled = parseInt(m[1], 10);
        }
        else if (entry.action === "attack_surface_done") {
          const m = String(entry.result || "").match(/total inputs=(\d+)/);
          if (m) inputsDiscovered = parseInt(m[1], 10);
        }
      } catch {
        /* skip malformed lines */
      }
    }
  } catch {
    /* trail not found — leave counts at 0 */
  }

  // Derive finding counts from findings.json (the SAME source the
  // findings list UI uses). Previously this counted `active_match`
  // trail events, which over-counts because the scanner emits one
  // event per matched PATTERN, not per Finding. A single Finding that
  // matched 11 patterns would show "11" in the badge but only 1 row
  // in the findings list — now both numbers come from findings.json
  // and always agree.
  const counts = await readFindingsCounts(id);
  const findingsCount = counts.findingsCount;
  const findingsHigh = counts.findingsHigh;
  const findingsMedium = counts.findingsMedium;
  const findingsLow = counts.findingsLow;

  // Mark the scan as completed (not interrupted) since we have a report
  await db.scan.update({
    where: { id },
    data: {
      status: "completed",
      endedAt: new Date(),
      findingsCount,
      findingsHigh,
      findingsMedium,
      findingsLow,
      urlsCrawled,
      inputsDiscovered,
      // Clear any paused state
      pausedForRelogin: false,
      pauseReason: `Force-completed by user at ${new Date().toISOString()}`,
      errorMsg: hasReport
        ? null
        : "Force-completed by user before scan finished. Partial report may be incomplete.",
    },
  });

  return NextResponse.json({
    ok: true,
    status: "completed",
    hasReport,
    findingsCount,
    message: hasReport
      ? "Scan force-completed. Report is available in the Report tab."
      : "Scan force-completed. No report was generated (scan ended too early).",
  });
}
