import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { launchScan } from "@/lib/scanner-runner";

/**
 * POST /api/scans
 *
 * Create a new scan record and launch the scanner.py subprocess.
 *
 * Request body (JSON):
 *   targetUrl: string         (required, must start with http:// or https://)
 *   depth?: number            (default 3)
 *   scopePatterns?: string    (comma-separated globs)
 *   excludePatterns?: string  (comma-separated globs)
 *   ignoreRobots?: boolean
 *   allowExternal?: boolean
 *   delayMs?: number          (default 500)
 *   concurrency?: number      (default 1, max 3)
 *   loginUrl?: string
 *   loginUser?: string
 *   loginPassword?: string    (NOT persisted; passed to subprocess via env var)
 *   headersFileContent?: string (contents of whitelist.txt)
 *   payloadsFileContent?: string (contents of payloads.txt)
 *
 * Response: 201 Created with { id, status: 'running' }
 */
export async function POST(req: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON body" },
      { status: 400 },
    );
  }

  const targetUrl = String(body.targetUrl || "").trim();
  if (!targetUrl) {
    return NextResponse.json(
      { error: "targetUrl is required" },
      { status: 400 },
    );
  }
  if (!/^https?:\/\//i.test(targetUrl)) {
    return NextResponse.json(
      { error: "targetUrl must start with http:// or https://" },
      { status: 400 },
    );
  }

  // Validate login: if loginUrl is provided, loginUser + loginPassword
  // are required. (Mirrors the CLI validation in scanner.py.)
  const loginUrl = body.loginUrl ? String(body.loginUrl).trim() : null;
  const loginUser = body.loginUser ? String(body.loginUser).trim() : null;
  const loginPassword = body.loginPassword
    ? String(body.loginPassword)
    : null;
  // A captured session (manualLoginState) is AUTHORITATIVE and does NOT
  // require username/password — it's the only way to auth OAuth/SSO flows
  // (Microsoft, Google, SAML) where the login page redirects to an IdP.
  const hasCapture = Boolean(body.manualLoginState && body.manualLoginStatePath);
  if (loginUrl && !hasCapture && !loginUser) {
    return NextResponse.json(
      { error: "loginUser is required when loginUrl is set (or capture a session via ‘Launch Browser to Login’)" },
      { status: 400 },
    );
  }
  if (loginUrl && !hasCapture && !loginPassword) {
    return NextResponse.json(
      { error: "loginPassword is required when loginUrl is set (or capture a session via ‘Launch Browser to Login’)" },
      { status: 400 },
    );
  }

  // Validate concurrency (1..3, mirrors scanner.py's hard limit).
  let concurrency = Number(body.concurrency) || 1;
  if (concurrency < 1) concurrency = 1;
  if (concurrency > 3) concurrency = 3;

  // Create the DB row first (status='pending'), then launch the subprocess.
  // This ordering ensures the SSE log stream can subscribe before the
  // first log line is written.
  const scan = await db.scan.create({
    data: {
      title: body.title ? String(body.title).trim() : null,
      targetUrl,
      depth: Number(body.depth) || 3,
      scopePatterns: String(body.scopePatterns || "").trim(),
      excludePatterns: String(body.excludePatterns || "").trim(),
      ignoreRobots: Boolean(body.ignoreRobots),
      allowExternal: Boolean(body.allowExternal),
      delayMs: Number(body.delayMs) || 500,
      concurrency,
      loginUrl,
      loginUser,
      // We deliberately do NOT store loginPassword in the DB.
      headersFileContent: body.headersFileContent
        ? String(body.headersFileContent)
        : null,
      payloadsFileContent: body.payloadsFileContent
        ? String(body.payloadsFileContent)
        : null,
      wordlistFileContent: body.wordlistFileContent ? String(body.wordlistFileContent) : null,
      weakCiphersFileContent: body.weakCiphersFileContent ? String(body.weakCiphersFileContent) : null,
      llmAssist: Boolean(body.llmAssist),
      llmInteresting: Boolean(body.llmInteresting),
      llmAnalyze: Boolean(body.llmAnalyze),
      customHeaders: body.customHeaders
        ? String(body.customHeaders)
        : null,
      testAccessControl: Boolean(body.testAccessControl),
      manualLoginState: Boolean(body.manualLoginState),
      manualLoginStatePath: body.manualLoginStatePath
        ? String(body.manualLoginStatePath)
        : null,
      deepLogic: Boolean(body.deepLogic),
      testFileUpload: Boolean(body.testFileUpload),
      uploadBaseFilename: body.uploadBaseFilename
        ? String(body.uploadBaseFilename)
        : null,
      // Build pauseReason from scan mode flags
      pauseReason: [
        body.authenticatedScan === false ? "IGNORE_SESSION_EXPIRY" : "",
        body.crawlOnly ? "CRAWL_ONLY" : "",
        body.crawlLlmUrls ? "CRAWL_LLM_URLS" : "",
        body.skipDirBrute ? "SKIP_DIR_BRUTE" : "",
      ].filter(Boolean).join(" — ") || null,
      status: "pending",
    },
  });

  // If a login password was provided, set it as an env var that the
  // scanner subprocess will inherit. We use process.env so the spawn
  // call in scanner-runner.ts picks it up automatically.
  //
  // SECURITY NOTE: this env var lives in the Next.js server process's
  // memory for the duration of the scan. It is NOT persisted to disk
  // and is NOT logged. After the scan starts, we delete it to minimise
  // the window. For multi-user deployments you'd want a secrets manager.
  if (loginPassword) {
    process.env.WEBRECON_LOGIN_PASSWORD = loginPassword;
  }

  // Launch the scanner subprocess. We do this BEFORE responding so the
  // client can immediately subscribe to the SSE stream and not miss the
  // first log lines.
  try {
    await launchScan(scan.id);
  } catch (e) {
    // If the subprocess fails to spawn (e.g. python3 not installed),
    // mark the scan as failed and return the error.
    await db.scan.update({
      where: { id: scan.id },
      data: {
        status: "failed",
        errorMsg: `Failed to launch scanner: ${e instanceof Error ? e.message : String(e)}`,
        endedAt: new Date(),
      },
    });
    return NextResponse.json(
      {
        error: "Failed to launch scanner. Is python3 installed and on PATH?",
        detail: e instanceof Error ? e.message : String(e),
        scanId: scan.id,
      },
      { status: 500 },
    );
  }

  // Clear the login password env var after the scan starts, to minimise
  // the window during which it's in memory. (The subprocess has already
  // inherited it via the spawn env.)
  if (loginPassword) {
    delete process.env.WEBRECON_LOGIN_PASSWORD;
  }

  return NextResponse.json(
    { id: scan.id, status: "running" },
    { status: 201 },
  );
}

/**
 * GET /api/scans
 *
 * List all scans, most recent first. Returns a summary (no file contents).
 *
 * Query params:
 *   ?status=running  → filter by status
 *   ?limit=50        → max results (default 50, max 200)
 */
export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const status = searchParams.get("status") || undefined;
  const limit = Math.min(
    200,
    Math.max(1, parseInt(searchParams.get("limit") || "50", 10)),
  );

  const scans = await db.scan.findMany({
    where: status ? { status } : undefined,
    orderBy: { createdAt: "desc" },
    take: limit,
    // We never return the headersFileContent / payloadsFileContent in
    // the list view — they can be large and aren't needed for the
    // dashboard. The detail view fetches them separately if needed.
    select: {
      id: true,
      title: true,
      targetUrl: true,
      depth: true,
      scopePatterns: true,
      excludePatterns: true,
      ignoreRobots: true,
      allowExternal: true,
      delayMs: true,
      concurrency: true,
      loginUrl: true,
      loginUser: true,
      loginSucceeded: true,
      llmAssist: true,
      llmInteresting: true,
      llmAnalyze: true,
      customHeaders: true,
      testAccessControl: true,
      manualLoginState: true,
      manualLoginStatePath: true,
      deepLogic: true,
      testFileUpload: true,
      uploadBaseFilename: true,
      wordlistFileContent: true,
      weakCiphersFileContent: true,
      pausedForRelogin: true,
      pauseReason: true,
      status: true,
      exitCode: true,
      errorMsg: true,
      findingsCount: true,
      findingsHigh: true,
      findingsMedium: true,
      findingsLow: true,
      urlsCrawled: true,
      inputsDiscovered: true,
      interrupted: true,
      createdAt: true,
      startedAt: true,
      endedAt: true,
    },
  });

  return NextResponse.json({ scans });
}
