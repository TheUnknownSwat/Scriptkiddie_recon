import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { launchScan } from "@/lib/scanner-runner";

/**
 * POST /api/scans/[id]/skip-relogin
 *
 * Resumes a paused scan WITHOUT re-logging in. Creates a new scan row
 * that inherits the original scan's config but sets a flag
 * (pauseReason contains "IGNORE_SESSION_EXPIRY") that tells the
 * scanner-runner to pass --ignore-session-expiry to the scanner.
 *
 * This is for unauthenticated scans where the target redirects
 * everything to /login (which is normal, not a session expiry).
 *
 * The original scan is marked as "interrupted".
 */
export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const original = await db.scan.findUnique({ where: { id } });
  if (!original) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // Create a new scan row with the same config + the ignore flag
  const newScan = await db.scan.create({
    data: {
      targetUrl: original.targetUrl,
      depth: original.depth,
      scopePatterns: original.scopePatterns,
      excludePatterns: original.excludePatterns,
      ignoreRobots: original.ignoreRobots,
      allowExternal: original.allowExternal,
      delayMs: original.delayMs,
      concurrency: original.concurrency,
      loginUrl: original.loginUrl,
      loginUser: original.loginUser,
      headersFileContent: original.headersFileContent,
      payloadsFileContent: original.payloadsFileContent,
      llmAssist: original.llmAssist,
      llmAnalyze: original.llmAnalyze,
      customHeaders: original.customHeaders,
      testAccessControl: original.testAccessControl,
      manualLoginState: original.manualLoginState,
      manualLoginStatePath: original.manualLoginStatePath,
      deepLogic: original.deepLogic,
      status: "pending",
      // This is the key: the scanner-runner checks pauseReason for
      // "IGNORE_SESSION_EXPIRY" and passes --ignore-session-expiry
      pauseReason: "IGNORE_SESSION_EXPIRY — user chose to skip re-login",
    },
  });

  // Mark the original as interrupted
  await db.scan.update({
    where: { id },
    data: {
      pausedForRelogin: false,
      status: "interrupted",
      pauseReason: `Skipped re-login → ${newScan.id}`,
    },
  });

  try {
    await launchScan(newScan.id);
    return NextResponse.json({
      id: newScan.id,
      status: "running",
      resumedFrom: id,
      message: "Scan resumed with session-expiry detection DISABLED. " +
               "The scanner will not pause for re-login.",
    }, { status: 201 });
  } catch (e) {
    return NextResponse.json(
      { error: "Failed to resume", detail: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}
