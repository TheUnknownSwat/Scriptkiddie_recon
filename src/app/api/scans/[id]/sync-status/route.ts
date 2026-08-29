import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { readFindingsCounts } from "@/lib/scanner-paths";
import path from "path";
import fs from "fs/promises";

/**
 * POST /api/scans/[id]/sync-status
 *
 * Reconciles the scan's on-disk state with the database.
 *
 * USE CASE: When the external supervisor (bin/supervisor.py) kills + restarts
 * the scanner, the new scanner process is NOT tracked by scanner-runner.ts
 * (the supervisor spawns it via subprocess.Popen, not launchScan()). This
 * means:
 *   - The scan stays "interrupted" in the DB even after the new scanner
 *     completes successfully.
 *   - The report.html + findings.json may be on disk but the DB doesn't
 *     know about them.
 *
 * This endpoint reads the execution_trail.jsonl to determine the ACTUAL
 * scan status:
 *   - If "scan_complete" is in the trail → scan finished, update DB to
 *     "completed" + parse finding counts from findings.json.
 *   - If "scan_complete" is NOT in the trail but the trail was recently
 *     updated (within last 60s) → scan is still running (supervisor
 *     restarted it). Return status "running".
 *   - If the trail was NOT recently updated → scan is genuinely
 *     interrupted. Return status "interrupted".
 *
 * The UI calls this when the user clicks "Sync Status" on the scan
 * detail page.
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

  const trailPath = path.join(
    process.cwd(), "scan-output", id, "execution_trail.jsonl",
  );

  // Read the trail file
  let trailContent = "";
  try {
    trailContent = await fs.readFile(trailPath, "utf-8");
  } catch {
    return NextResponse.json({
      ok: true,
      status: scan.status,
      message: "No trail file found — scan may not have started.",
    });
  }

  // Parse the trail to find:
  //   - scan_complete event
  //   - last timestamp
  //   - supervisor_restart events
  //   - crawl_done / attack_surface_done for URL/input counts
  let scanComplete = false;
  let lastTimestamp: string | null = null;
  let supervisorRestarts = 0;
  let urlsCrawled = 0;
  let inputsDiscovered = 0;

  const lines = trailContent.split("\n");
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      if (entry.action === "scan_complete") {
        scanComplete = true;
      }
      if (entry.ts) {
        lastTimestamp = entry.ts;
      }
      if (entry.action === "supervisor_restart") {
        supervisorRestarts++;
      }
      if (entry.action === "crawl_done") {
        const m = String(entry.result || "").match(/visited (\d+) URLs/);
        if (m) urlsCrawled = parseInt(m[1], 10);
      }
      if (entry.action === "attack_surface_done") {
        const m = String(entry.result || "").match(/total inputs=(\d+)/);
        if (m) inputsDiscovered = parseInt(m[1], 10);
      }
    } catch {}
  }

  // Determine the actual status
  let actualStatus: string = scan.status;
  let message: string = "";

  if (scanComplete) {
    // Scan completed successfully — update DB
    actualStatus = "completed";

    // Read finding counts from findings.json (same source as the list)
    const counts = await readFindingsCounts(id);

    await db.scan.update({
      where: { id },
      data: {
        status: "completed",
        endedAt: new Date(),
        findingsCount: counts.findingsCount,
        findingsHigh: counts.findingsHigh,
        findingsMedium: counts.findingsMedium,
        findingsLow: counts.findingsLow,
        urlsCrawled,
        inputsDiscovered,
        // Clear any interrupted/paused state
        interrupted: false,
        errorMsg: null,
      },
    });

    message = supervisorRestarts > 0
      ? `Scan completed successfully (${supervisorRestarts} supervisor restarts). Report and findings are ready.`
      : "Scan completed successfully. Report and findings are ready.";
  } else {
    // Check if the trail was recently updated (within last 60s)
    let trailIsRecent = false;
    if (lastTimestamp) {
      try {
        const trailTime = new Date(lastTimestamp).getTime();
        const now = Date.now();
        const ageSeconds = (now - trailTime) / 1000;
        trailIsRecent = ageSeconds < 60;
      } catch {}
    }

    if (trailIsRecent) {
      // Trail is being actively written — scan is still running
      // (likely supervisor-restarted)
      actualStatus = "running";
      await db.scan.update({
        where: { id },
        data: {
          status: "running",
          urlsCrawled,
          inputsDiscovered,
        },
      });
      message = supervisorRestarts > 0
        ? `Scan is still running (${supervisorRestarts} supervisor restarts so far). Live logs should be updating.`
        : "Scan is still running. Live logs should be updating.";
    } else {
      // Trail is stale — scan is genuinely interrupted
      actualStatus = "interrupted";
      const counts = await readFindingsCounts(id);
      await db.scan.update({
        where: { id },
        data: {
          status: "interrupted",
          findingsCount: counts.findingsCount,
          findingsHigh: counts.findingsHigh,
          findingsMedium: counts.findingsMedium,
          findingsLow: counts.findingsLow,
          urlsCrawled,
          inputsDiscovered,
          interrupted: true,
        },
      });
      message = supervisorRestarts > 0
        ? `Scan was interrupted (${supervisorRestarts} supervisor restarts). Partial findings are available — use Force Complete to generate a report.`
        : "Scan was interrupted. Partial findings are available — use Force Complete to generate a report.";
    }
  }

  return NextResponse.json({
    ok: true,
    status: actualStatus,
    scanComplete,
    supervisorRestarts,
    lastTimestamp,
    message,
  });
}
