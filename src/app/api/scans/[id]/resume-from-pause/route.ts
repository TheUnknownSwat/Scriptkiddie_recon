import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { launchScan } from "@/lib/scanner-runner";

/**
 * POST /api/scans/[id]/resume-from-pause
 *
 * Resumes a scan that was paused due to session expiry.
 * The user clicks "Resume Scan" after re-logging in.
 */
export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const original = await db.scan.findUnique({ where: { id } });
  if (!original) return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  if (!original.pausedForRelogin) return NextResponse.json({ error: "Scan is not paused." }, { status: 409 });
  if (!original.manualLoginStatePath) return NextResponse.json({ error: "No state file. Re-login first." }, { status: 400 });

  const newScan = await db.scan.create({
    data: {
      targetUrl: original.targetUrl, depth: original.depth,
      scopePatterns: original.scopePatterns, excludePatterns: original.excludePatterns,
      ignoreRobots: original.ignoreRobots, allowExternal: original.allowExternal,
      delayMs: original.delayMs, concurrency: original.concurrency,
      loginUrl: original.loginUrl, loginUser: original.loginUser,
      headersFileContent: original.headersFileContent, payloadsFileContent: original.payloadsFileContent,
      llmAssist: original.llmAssist, llmAnalyze: original.llmAnalyze,
      customHeaders: original.customHeaders, testAccessControl: original.testAccessControl,
      manualLoginState: true, manualLoginStatePath: original.manualLoginStatePath,
      deepLogic: original.deepLogic, status: "pending",
    },
  });
  await db.scan.update({ where: { id }, data: { pausedForRelogin: false, status: "interrupted", pauseReason: "Resumed → " + newScan.id } });
  try {
    await launchScan(newScan.id);
    return NextResponse.json({ id: newScan.id, status: "running", resumedFrom: id }, { status: 201 });
  } catch (e) {
    return NextResponse.json({ error: "Failed to resume", detail: e instanceof Error ? e.message : String(e) }, { status: 500 });
  }
}
