import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { launchScan } from "@/lib/scanner-runner";
import { readFindingsCounts } from "@/lib/scanner-paths";
import { execSync } from "child_process";
import path from "path";
import fs from "fs/promises";

/**
 * POST /api/scans/[id]/kill-chrome-restart
 *
 * Nuclear option: kills ALL Chrome/Chromium processes, then creates a NEW
 * scan that RESUMES from the last test number (using --skip-tests).
 *
 * Use case: The scan froze at test 410. Click this button to:
 *   1. Kill all Chrome processes (frees memory)
 *   2. Read the trail to find the last completed test number
 *   3. Create a new scan with the same config
 *   4. Pass --skip-tests=<last_test> so the scan resumes at test <last_test+1>
 *
 * Optional body:
 *   { "ignoreSessionExpiry": true }  — also passes --ignore-session-expiry
 */
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const original = await db.scan.findUnique({ where: { id } });
  if (!original) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  let ignoreSessionExpiry = false;
  try {
    const body = await req.json();
    ignoreSessionExpiry = Boolean(body.ignoreSessionExpiry);
  } catch {}

  // --- Step 1: Stop any running scanner subprocess ---
  // We send SIGTERM (graceful) and then WAIT for the subprocess to
  // actually exit before proceeding. Previously we only waited a fixed
  // 2s, which was sometimes too short — the old subprocess would still
  // be holding Chrome/Playwright resources when the new scan tried to
  // launch, causing the new scan to fail silently ("it just ends").
  try {
    const { stopScan, isScanRunning } = await import("@/lib/scanner-runner");
    await stopScan(id);
    // Poll for up to 15s waiting for the subprocess to actually exit.
    for (let i = 0; i < 30; i++) {
      if (!isScanRunning(id)) break;
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  } catch {}
  // Extra safety margin: even after the subprocess exits, Chrome may
  // take a moment to release its resources. Give it 2s.
  await new Promise((resolve) => setTimeout(resolve, 2000));

  // --- Step 2: Kill ALL Chrome/Chromium processes ---
  // Belt-and-braces: even if the subprocess exited gracefully, there
  // may be orphaned Chrome processes (the scanner's pkill watchdog
  // sometimes leaves stragglers). This ensures a clean slate.
  const killCommands = [
    "pkill -9 -f chromium 2>/dev/null; pkill -9 -f chrome 2>/dev/null; pkill -9 -f 'headless' 2>/dev/null; pkill -9 -f chrome-headless-shell 2>/dev/null; pkill -9 -f remote-debugging-pipe 2>/dev/null; echo done",
    "taskkill /F /IM chrome.exe /T 2>nul; taskkill /F /IM chromium.exe /T 2>nul; echo done",
  ];
  for (const cmd of killCommands) {
    try { execSync(cmd, { timeout: 5000, encoding: "utf-8" }); } catch {}
  }

  // --- Step 3: Read the trail to find the last test number ---
  let skipTests = 0;
  try {
    const trailPath = path.join(process.cwd(), "scan-output", id, "execution_trail.jsonl");
    const content = await fs.readFile(trailPath, "utf-8");
    // Find the last "active_progress" or "active_inject" entry that contains
    // a test number like "(410/532 done)" or "test 410"
    let lastTestNum = 0;
    for (const line of content.split("\n")) {
      if (!line.trim()) continue;
      try {
        const entry = JSON.parse(line);
        const result = String(entry.result || "");
        // Match patterns like "(410/532 done)" or "test 410/532"
        const match1 = result.match(/\((\d+)\/\d+\s+done\)/);
        const match2 = result.match(/test\s+(\d+)\/\d+/);
        const match3 = result.match(/(\d+)\/\d+\s+tests/);
        const testNum = match1 ? parseInt(match1[1]) : match2 ? parseInt(match2[1]) : match3 ? parseInt(match3[1]) : 0;
        if (testNum > lastTestNum) lastTestNum = testNum;
      } catch {}
    }
    skipTests = lastTestNum;
  } catch {}

  // --- Step 4: Create a new scan row with the same config ---
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
      pauseReason: [
        ignoreSessionExpiry ? "IGNORE_SESSION_EXPIRY" : "",
        skipTests > 0 ? `SKIP_TESTS=${skipTests}` : "",
        `killed chrome + restart from scan ${id}`,
      ].filter(Boolean).join(" — "),
    },
  });

  await db.scan.update({
    where: { id },
    data: {
      status: "interrupted",
      pausedForRelogin: false,
      pauseReason: `Killed + restarted → ${newScan.id} (resuming at test ${skipTests + 1})`,
    },
  });

  // --- Step 4.5: Copy findings + evidence from the old scan to the new scan ---
  // When the scanner restarts with --skip-tests, it starts with an empty
  // findings list. We need to copy the old scan's findings.json + evidence
  // files so the new scan accumulates on top of the existing findings.
  let oldFindingsCount = 0;
  const oldOutputDir = path.join(process.cwd(), "scan-output", id);
  const newOutputDir = path.join(process.cwd(), "scan-output", newScan.id);

  try {
    // Create the new output directory
    await fs.mkdir(newOutputDir, { recursive: true });
    await fs.mkdir(path.join(newOutputDir, "evidence"), { recursive: true });

    // Copy findings.json (the scanner reads this on startup if it exists)
    const oldFindingsPath = path.join(oldOutputDir, "findings.json");
    try {
      const findingsContent = await fs.readFile(oldFindingsPath, "utf-8");
      const findings = JSON.parse(findingsContent);
      oldFindingsCount = Array.isArray(findings) ? findings.length : 0;
      // Write to the new scan's output dir
      await fs.writeFile(
        path.join(newOutputDir, "findings.json"),
        findingsContent,
        "utf-8",
      );
      console.log(`[kill-chrome-restart] Copied ${oldFindingsCount} findings from ${id} to ${newScan.id}`);
    } catch {
      // No findings.json — that's OK (scan may not have found anything yet)
    }

    // Copy execution_trail.jsonl (so the new scan's trail starts with the old one)
    const oldTrailPath = path.join(oldOutputDir, "execution_trail.jsonl");
    try {
      const trailContent = await fs.readFile(oldTrailPath, "utf-8");
      await fs.writeFile(
        path.join(newOutputDir, "execution_trail.jsonl"),
        trailContent,
        "utf-8",
      );
      console.log(`[kill-chrome-restart] Copied execution trail from ${id} to ${newScan.id}`);
    } catch {
      // No trail — that's OK
    }

    // Copy evidence files (screenshots, raw request/response files)
    const oldEvidenceDir = path.join(oldOutputDir, "evidence");
    try {
      const evidenceFiles = await fs.readdir(oldEvidenceDir);
      for (const file of evidenceFiles) {
        try {
          const src = path.join(oldEvidenceDir, file);
          const dst = path.join(newOutputDir, "evidence", file);
          await fs.copyFile(src, dst);
        } catch {
          // skip individual file errors
        }
      }
      console.log(`[kill-chrome-restart] Copied evidence files from ${id} to ${newScan.id}`);
    } catch {
      // No evidence dir — that's OK
    }

    // Copy other useful files (crawl_map, attack_surface, headers, etc.)
    const filesToCopy = [
      "crawl_map.json",
      "attack_surface.json",
      "headers_raw.json",
      "headers_comparison.json",
      "software_inventory.json",
      "directory_findings.json",
      "interesting_locations.json",
      "scan_state.json",
    ];
    for (const fname of filesToCopy) {
      try {
        const src = path.join(oldOutputDir, fname);
        const dst = path.join(newOutputDir, fname);
        await fs.copyFile(src, dst);
      } catch {
        // file may not exist — skip
      }
    }

    // Copy the manual-login state file (if any) and update the new
    // scan's manualLoginStatePath to point to the NEW scan's copy.
    // Otherwise the new scan's --load-state flag would point at the
    // OLD scan's directory, which works today but breaks if the old
    // scan's output dir is ever cleaned up.
    if (original.manualLoginState && original.manualLoginStatePath) {
      try {
        const oldStateName = path.basename(original.manualLoginStatePath);
        const src = path.join(oldOutputDir, oldStateName);
        const dst = path.join(newOutputDir, oldStateName);
        await fs.copyFile(src, dst);
        await db.scan.update({
          where: { id: newScan.id },
          data: {
            manualLoginStatePath: dst,
          },
        });
        console.log(`[kill-chrome-restart] Copied manual login state → ${dst}`);
      } catch (e) {
        // Non-fatal — the new scan will just run without the saved
        // login state (the user can re-login if needed).
        console.error(`[kill-chrome-restart] Failed to copy manual login state:`, e);
      }
    }

    // Update the new scan's DB row with the old findings count.
    // We derive high/medium/low from the copied findings.json (using the
    // same readFindingsCounts helper the scanner-runner uses) so the
    // badge matches the findings list from the start — no over-counting
    // from `active_match` trail events.
    if (oldFindingsCount > 0) {
      try {
        const counts = await readFindingsCounts(newScan.id);
        await db.scan.update({
          where: { id: newScan.id },
          data: {
            findingsCount: counts.findingsCount,
            findingsHigh: counts.findingsHigh,
            findingsMedium: counts.findingsMedium,
            findingsLow: counts.findingsLow,
          },
        });
      } catch {
        // Fall back to just the count if severity parsing fails.
        await db.scan.update({
          where: { id: newScan.id },
          data: { findingsCount: oldFindingsCount },
        });
      }
    }
  } catch (e) {
    console.error(`[kill-chrome-restart] Failed to copy findings:`, e);
    // Non-fatal — the scan will still start, just without the old findings
  }

  // --- Step 5: Launch the new scan ---
  // The scanner-runner checks pauseReason for SKIP_TESTS=N and passes
  // --skip-tests N to the scanner.
  try {
    await launchScan(newScan.id);
    return NextResponse.json({
      ok: true,
      id: newScan.id,
      killedChrome: true,
      skipTests,
      message: `Killed Chrome. New scan ${newScan.id} resumes at test ${skipTests + 1}.` +
               (ignoreSessionExpiry ? " Session-expiry DISABLED." : ""),
    }, { status: 201 });
  } catch (e) {
    return NextResponse.json({
      ok: false,
      id: newScan.id,
      killedChrome: true,
      error: "Chrome killed but new scan failed to start",
      detail: e instanceof Error ? e.message : String(e),
    }, { status: 500 });
  }
}
