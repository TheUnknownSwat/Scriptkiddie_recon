import { spawn, ChildProcess, execFileSync } from "child_process";
import path from "path";
import { db } from "@/lib/db";
import { BIN_DIR, SCANNER_PATH, effectiveLlmMaxTokens, getLlmTimeoutMs, readFindingsCounts, scanOutputDir, writeScanInputFiles } from "@/lib/scanner-paths";

/**
 * Resolve the Python interpreter that has `playwright` installed.
 *
 * WHY THIS EXISTS:
 * When the Next.js dev server is launched (e.g. via `bun run dev` from a
 * shell whose PATH doesn't include the user's venv), `python3` resolves
 * to the system interpreter — which usually does NOT have `playwright`
 * installed. The scanner subprocess then dies immediately with
 * `[FATAL] playwright is not installed`, the trail file is never written,
 * and the Live View UI shows 0 logs (because the SSE endpoint has nothing
 * to stream).
 *
 * This function probes a list of candidate interpreters and returns the
 * first one that can `import playwright`. The result is cached for the
 * lifetime of the process so we only pay the probe cost once.
 *
 * Candidate order:
 *   1. $WEBRECON_PYTHON env var (explicit override — power users)
 *   2. `python3` on PATH (works if dev shell PATH includes a venv)
 *   3. `python` on PATH (Windows often only has `python`)
 *   4. Common venv locations relative to the project root
 *   5. `python3` again (last resort — will produce the original error)
 */
export function findPythonWithPlaywright(): string {
  // Cache the result so we don't probe on every scan launch.
  if ((findPythonWithPlaywright as unknown as { _cached?: string })._cached) {
    return (findPythonWithPlaywright as unknown as { _cached?: string })._cached!;
  }

  const candidates: string[] = [];

  // 1. Explicit env override
  if (process.env.WEBRECON_PYTHON) {
    candidates.push(process.env.WEBRECON_PYTHON);
  }

  // 2-3. Default interpreters on PATH
  candidates.push("python3", "python");

  // 4. Common venv locations relative to project root (cwd's parent)
  const projectRoot = process.cwd();
  const projectParent = path.dirname(projectRoot);
  const homeDir = process.env.HOME || "/root";
  candidates.push(
    path.join(projectRoot, ".venv", "bin", "python3"),
    path.join(projectRoot, ".venv", "bin", "python"),
    path.join(projectRoot, "venv", "bin", "python3"),
    path.join(projectRoot, "venv", "bin", "python"),
    path.join(projectParent, ".venv", "bin", "python3"),
    path.join(projectParent, ".venv", "bin", "python"),
    path.join(projectParent, "venv", "bin", "python3"),
    // Home-directory venv (very common: ~/.venv)
    path.join(homeDir, ".venv", "bin", "python3"),
    path.join(homeDir, ".venv", "bin", "python"),
    path.join(homeDir, "venv", "bin", "python3"),
    // Common system-wide locations
    "/usr/local/bin/python3",
    "/opt/python3/bin/python3",
  );

  for (const candidate of candidates) {
    try {
      // Probe: can this interpreter import playwright AND import its
      // sync_api submodule (which is what the scanner actually uses)?
      // We avoid playwright.__version__ because that attribute doesn't
      // exist on some versions — instead we use importlib.metadata which
      // always works for installed packages.
      const output = execFileSync(
        candidate,
        [
          "-c",
          "import playwright, importlib.metadata as m; print(m.version('playwright'))",
        ],
        { timeout: 3000, stdio: ["ignore", "pipe", "ignore"], encoding: "utf-8" },
      );
      if (output.trim().length > 0) {
        // Got a version string → playwright is importable. Cache + return.
        (findPythonWithPlaywright as unknown as { _cached?: string })._cached = candidate;
        console.log(
          `[scanner-runner] Using Python interpreter: ${candidate} (playwright ${output.trim()})`,
        );
        return candidate;
      }
    } catch {
      // Interpreter not found, or playwright not installed — try next.
      continue;
    }
  }

  // 5. Nothing worked. If the user opted in to auto-install (via env var
  // WEBRECON_AUTO_INSTALL_PLAYWRIGHT=1), try `pip install playwright` on
  // the first candidate that has pip available, then re-probe. This makes
  // first-run setup easier for users with internet access. Disabled by
  // default — the tool is designed for airgapped use.
  const autoInstall = process.env.WEBRECON_AUTO_INSTALL_PLAYWRIGHT === "1";
  if (autoInstall) {
    for (const candidate of ["python3", "python", ...candidates]) {
      try {
        // First check if pip is available on this interpreter.
        execFileSync(candidate, ["-m", "pip", "--version"], {
          timeout: 5000,
          stdio: ["ignore", "pipe", "ignore"],
          encoding: "utf-8",
        });
      } catch {
        continue; // no pip on this interpreter
      }
      try {
        console.log(
          `[scanner-runner] Auto-installing playwright on ${candidate} (WEBRECON_AUTO_INSTALL_PLAYWRIGHT=1)...`,
        );
        // Install the Python package. ~30s on a fast connection.
        execFileSync(candidate, ["-m", "pip", "install", "playwright"], {
          timeout: 180000,
          stdio: "inherit",
        });
        // Install the Chromium browser binary. ~120s on a fast connection.
        execFileSync(candidate, ["-m", "playwright", "install", "chromium"], {
          timeout: 300000,
          stdio: "inherit",
        });
        // Re-probe: confirm playwright is now importable.
        const output = execFileSync(
          candidate,
          ["-c", "import playwright, importlib.metadata as m; print(m.version('playwright'))"],
          { timeout: 3000, stdio: ["ignore", "pipe", "ignore"], encoding: "utf-8" },
        );
        if (output.trim().length > 0) {
          console.log(
            `[scanner-runner] Auto-install succeeded. Using Python interpreter: ${candidate} (playwright ${output.trim()})`,
          );
          (findPythonWithPlaywright as unknown as { _cached?: string })._cached = candidate;
          return candidate;
        }
      } catch (e) {
        console.warn(
          `[scanner-runner] Auto-install failed on ${candidate}: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
        continue;
      }
    }
  }

  // 6. Final fallback — return `python3` so the user sees the scanner's
  // built-in "playwright is not installed" error with install instructions.
  console.warn(
    "[scanner-runner] No Python interpreter with playwright found. " +
      "Falling back to `python3`. Install playwright with: " +
      "pip install playwright && playwright install chromium" +
      (autoInstall ? "" : " (or set WEBRECON_AUTO_INSTALL_PLAYWRIGHT=1 to auto-install)"),
  );
  (findPythonWithPlaywright as unknown as { _cached?: string })._cached = "python3";
  return "python3";
}

/**
 * In-memory registry of running scanner subprocesses.
 *
 * WHY IN-MEMORY (not DB):
 *  - The PID is only meaningful in this process's table — it can't be
 *    used by a restart of the Next.js server to kill a stale scanner.
 *  - If the Next.js server restarts, any running scanners become orphan
 *    processes; we accept this trade-off because the scanner itself
 *    handles SIGINT/SIGTERM cleanly and writes a partial report.
 *  - For long-running production deployments you'd want a separate
 *    worker process (e.g. BullMQ), but for an airgapped single-user
 *    tool this is overkill.
 */
const runningScans = new Map<string, ChildProcess>();

/**
 * Launch a scanner.py subprocess for the given scan record.
 *
 * The scan record must already exist in the DB (created by the API route
 * before calling this function). We read its fields, build the CLI args,
 * spawn the subprocess, and register it in the in-memory map.
 *
 * On subprocess exit, we update the DB row with the final status, exit
 * code, and finding counts (parsed from the trail file).
 */
export async function launchScan(scanId: string): Promise<void> {
  const scan = await db.scan.findUnique({ where: { id: scanId } });
  if (!scan) {
    throw new Error(`Scan ${scanId} not found`);
  }

  // Mark the scan as running + record the start time.
  await db.scan.update({
    where: { id: scanId },
    data: { status: "running", startedAt: new Date() },
  });

  // Write the per-scan headers/payloads files (if the user provided them).
  const { headersPath, payloadsPath, wordlistPath, weakCiphersPath } = await writeScanInputFiles(
    scanId,
    scan.headersFileContent,
    scan.payloadsFileContent,
    scan.wordlistFileContent,
    scan.weakCiphersFileContent,
  );

  // Build the CLI args. We mirror the scanner.py argument names exactly.
  const outputDir = await scanOutputDir(scanId);

  // Load LLM settings from the DB. These are passed to the scanner
  // subprocess via environment variables (LLM_BASE_URL, LLM_API_KEY,
  // LLM_MODEL) and via the --llm-tokens CLI flag.
  //
  // The scanner.py reads LLM_BASE_URL / LLM_API_KEY / LLM_MODEL from env
  // (or .env file) at startup. By setting them on the subprocess env,
  // each scan inherits the current settings without needing a .env file.
  const settings = await db.setting.findUnique({ where: { id: "default" } });
  const llmMaxTokens = effectiveLlmMaxTokens(settings?.llmMaxTokens);

  const args: string[] = [
    SCANNER_PATH,
    "--url", scan.targetUrl,
    "--output", outputDir,
    "--depth", String(scan.depth),
    "--delay", String(scan.delayMs),
    "--concurrency", String(scan.concurrency),
    "--max-payload-bytes", "2000",
    "--llm-tokens", String(llmMaxTokens),
  ];
  if (scan.scopePatterns) {
    args.push("--scope", scan.scopePatterns);
  }
  if (scan.excludePatterns) {
    args.push("--exclude", scan.excludePatterns);
  }
  if (scan.ignoreRobots) {
    args.push("--ignore-robots");
  }
  if (scan.allowExternal) {
    args.push("--allow-external");
  }
  if (headersPath) {
    args.push("--headers", headersPath);
  }
  if (payloadsPath) {
    args.push("--payloads", payloadsPath);
  }
  if (wordlistPath) {
    args.push("--wordlist", wordlistPath);
  }
  if (weakCiphersPath) {
    args.push("--weak-ciphers", weakCiphersPath);
  }
  // Form-login vs captured-session: a manual-browser capture (--load-state)
  // is AUTHORITATIVE, especially for OAuth/SSO (Microsoft, Google, SAML)
  // where the app's login page redirects to an IdP and a username/password
  // form login can't succeed. When a capture exists, we do NOT also pass
  // --login-url/--login-user (and skip the password env var below) — otherwise
  // the scanner runs form login AFTER loading the capture, it fails, and
  // clobbers login_succeeded → reports UNAUTHENTICATED despite the captured
  // session being loaded.
  const hasCapture = !!(scan.manualLoginState && scan.manualLoginStatePath);
  if (scan.loginUrl && !hasCapture) {
    args.push("--login-url", scan.loginUrl);
  }
  if (scan.loginUser && !hasCapture) {
    args.push("--login-user", scan.loginUser);
  }
  // LLM-assisted scanning: if enabled, the scanner will ask the LLM to
  // analyse crawl results mid-scan and suggest priority inputs + custom
  // payloads. The LLM config (endpoint, API key, model) is passed via
  // env vars below.
  if (scan.llmAssist) {
    args.push("--llm-assist");
  }
  // AI Content Analysis during scan: re-visit every crawled page + 1 LLM
  // call per page (no cap). Off by default — scan-time cost.
  if (scan.llmInteresting) {
    args.push("--llm-interesting");
  }
  // LLM vulnerability analysis: if enabled, after active scanning the
  // LLM reviews findings + raw responses to detect vulns regex missed.
  if (scan.llmAnalyze) {
    args.push("--llm-analyze");
  }
  // Custom HTTP headers: JSON string of key-value pairs sent with every
  // request. Used for CSRF tokens, Authorization headers, etc.
  if (scan.customHeaders) {
    args.push("--custom-headers", scan.customHeaders);
  }
  // Access Control Testing: forced browsing (clear cookies, re-visit URLs).
  if (scan.testAccessControl) {
    args.push("--test-access-control");
  }
  // Manual Browser Login: load a captured session state file.
  if (scan.manualLoginState && scan.manualLoginStatePath) {
    args.push("--load-state", scan.manualLoginStatePath);
  }
  // Deep Logic Testing: business logic flaw detection (experimental).
  if (scan.deepLogic) {
    args.push("--deep-logic");
  }
  // File Upload Testing: probes <input type=file> for unrestricted uploads.
  if (scan.testFileUpload) {
    args.push("--test-file-upload");
    if (scan.uploadBaseFilename) {
      args.push("--upload-base-filename", scan.uploadBaseFilename);
    }
  }
  // Debug: skip first N tests in active scan. Used via the
  // WEBRECON_SKIP_TESTS env var OR via pauseReason containing "SKIP_TESTS=N"
  // (set by the "Kill Chrome & Restart" button to resume from the last test).
  let skipTestsValue = process.env.WEBRECON_SKIP_TESTS || "";
  // Check pauseReason for SKIP_TESTS=N (set by kill-chrome-restart endpoint)
  if (scan.pauseReason) {
    const skipMatch = scan.pauseReason.match(/SKIP_TESTS=(\d+)/);
    if (skipMatch) {
      skipTestsValue = skipMatch[1];
    }
  }
  if (skipTestsValue && /^\d+$/.test(skipTestsValue)) {
    const skipNum = parseInt(skipTestsValue, 10);
    if (skipNum > 0) {
      args.push("--skip-tests", String(skipNum));
      console.log(`[scanner-runner] --skip-tests ${skipNum} (resuming from test ${skipNum + 1})`);
    }
  }
  // Debug: log every test (not just every 10th). Set WEBRECON_VERBOSE_TESTS=1
  if (process.env.WEBRECON_VERBOSE_TESTS === "1") {
    args.push("--verbose-tests");
    console.log(`[scanner-runner] --verbose-tests (from WEBRECON_VERBOSE_TESTS env var)`);
  }
  // Full debug mode: extensive logging for troubleshooting. Set WEBRECON_DEBUG=1
  if (process.env.WEBRECON_DEBUG === "1") {
    args.push("--debug");
    console.log(`[scanner-runner] --debug (full debug logging enabled)`);
  }
  // Disable all watchdogs: per-test 60s pkill, progress 120s pkill, context
  // recycle every 50 tests. Set WEBRECON_DISABLE_WATCHDOG=1 in .env. Used
  // for debugging to determine if a hang is caused by the watchdogs killing
  // Chrome at a bad time or by something else.
  // WARNING: with watchdogs disabled, a truly hung test will freeze the scan
  // forever. Only use this for debugging.
  if (process.env.WEBRECON_DISABLE_WATCHDOG === "1") {
    args.push("--no-watchdog");
    console.log(`[scanner-runner] --no-watchdog (ALL watchdogs DISABLED — debugging only)`);
  }
  // Crawl Only mode — skip active fuzzing. Set via scan.pauseReason
  // containing "CRAWL_ONLY" (set by the UI toggle).
  if (scan.pauseReason && scan.pauseReason.includes("CRAWL_ONLY")) {
    args.push("--crawl-only");
    console.log(`[scanner-runner] --crawl-only (crawl only, no active fuzzing)`);
  }
  // Ignore session expiry: completely disable the session-expiry check.
  // Set via WEBRECON_IGNORE_SESSION_EXPIRY=1 in .env, OR per-scan via
  // the scan row's pauseReason field (set by the "Skip Re-login" button).
  if (process.env.WEBRECON_IGNORE_SESSION_EXPIRY === "1" ||
      (scan.pauseReason && scan.pauseReason.includes("IGNORE_SESSION_EXPIRY"))) {
    args.push("--ignore-session-expiry");
    console.log(`[scanner-runner] --ignore-session-expiry (session-expiry detection disabled)`);
  }
  // Crawl LLM-suggested URLs: if the scan's pauseReason contains
  // CRAWL_LLM_URLS (set by the UI toggle), auto-crawl same-domain URLs
  // suggested by the LLM planner.
  if (scan.pauseReason && scan.pauseReason.includes("CRAWL_LLM_URLS")) {
    args.push("--crawl-llm-urls");
    console.log(`[scanner-runner] --crawl-llm-urls (auto-crawl LLM-suggested URLs)`);
  }
  // Skip directory brute-force: set by the "Crawl Only" preset (without
  // dir busting). The "Crawl + Dir Bust" preset does NOT set this.
  if (scan.pauseReason && scan.pauseReason.includes("SKIP_DIR_BRUTE")) {
    args.push("--skip-dir-brute");
    console.log(`[scanner-runner] --skip-dir-brute (skipping directory brute-force)`);
  }
  // Login password: we don't store it in the DB. The API route that
  // creates the scan row must pass it via the WEBRECON_LOGIN_PASSWORD
  // env var to THIS process at spawn time. We carry it through here.
  // (See createScan route for the env-var plumbing.)

  // Build the subprocess environment. We inherit process.env (which may
  // carry WEBRECON_LOGIN_PASSWORD from the API route) and add the LLM
  // credentials from the DB settings.
  const childEnv: Record<string, string | undefined> = {
    ...process.env,
  };
  if (settings?.llmBaseUrl) {
    childEnv.LLM_BASE_URL = settings.llmBaseUrl;
  }
  if (settings?.llmApiKey) {
    childEnv.LLM_API_KEY = settings.llmApiKey;
  }
  if (settings?.llmModel) {
    childEnv.LLM_MODEL = settings.llmModel;
  }
  // Pass the LLM timeout to the Python scanner (seconds).
  // The TS-side uses WEBRECON_LLM_TIMEOUT_MS (milliseconds), but the
  // Python side uses seconds. We convert here so the user only sets
  // ONE env var in .env.
  const llmTimeoutMs = getLlmTimeoutMs();
  childEnv.WEBRECON_LLM_TIMEOUT_SECONDS = String(Math.floor(llmTimeoutMs / 1000));

  // Spawn the subprocess. We resolve the Python interpreter that actually
  // has playwright installed (see findPythonWithPlaywright above) — this
  // matters when the dev server is launched from a shell whose PATH
  // doesn't include the user's venv.
  // stdio: 'pipe' so we can capture stderr for error reporting.
  const pythonBin = findPythonWithPlaywright();
  // Spawn with detached:true so the scanner + its Chromium child form a
  // separate process group. This lets stopScan() kill the ENTIRE group
  // (Python + Chromium) via process.kill(-pid, "SIGKILL") — otherwise
  // killing just the Python parent leaves Chromium orphaned, consuming
  // memory and holding the target's session open.
  // We do NOT call child.unref() because we want the parent to wait for
  // the child's exit (the 'exit' handler finalizes the scan row).
  const child = spawn(pythonBin, args, {
    cwd: outputDir,
    env: childEnv,
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });

  runningScans.set(scanId, child);

  // --- Optionally launch the external supervisor ---
  // The supervisor (bin/supervisor.py) is a SEPARATE process that
  // monitors heartbeat.json. If the scanner hangs (heartbeat goes
  // stale), the supervisor kills it and restarts with --resume
  // --skip-tests.
  //
  // This is the ULTIMATE freeze recovery — it works even when
  // Playwright's C code blocks the asyncio event loop and all
  // in-process watchdogs are ineffective.
  //
  // Enable by setting WEBRECON_SUPERVISOR=1 in .env. The supervisor
  // threshold is configurable via WEBRECON_SUPERVISOR_THRESHOLD
  // (default: 180s).
  //
  // CRITICAL: The supervisor MUST be launched with `detached: true` +
  // `unref()` so it SURVIVES the scanner's exit. When the supervisor
  // kills a hung scanner, the scanner exits → scanner-runner's exit
  // handler fires. If the supervisor were attached, it would be killed
  // here too — before it can restart the scanner.
  //
  // The supervisor exits on its own when:
  //   - It sees `scan_complete` in the trail (normal completion)
  //   - It exceeds --max-restarts
  //   - The user writes a `supervisor_stop` marker file (Stop button)
  let supervisorChild: ChildProcess | null = null;
  if (process.env.WEBRECON_SUPERVISOR === "1") {
    try {
      const supervisorThreshold = process.env.WEBRECON_SUPERVISOR_THRESHOLD || "180";
      const supervisorArgs = [
        path.join(BIN_DIR, "supervisor.py"),
        outputDir,
        "--threshold", supervisorThreshold,
        "--max-restarts", "20",
      ];
      supervisorChild = spawn(pythonBin, supervisorArgs, {
        cwd: process.cwd(),
        stdio: ["ignore", "pipe", "pipe"],
        detached: true,  // detached — survives scanner exit
      });
      // unref() tells Node.js not to keep the event loop alive for
      // this child. The supervisor runs independently.
      supervisorChild.unref();
      console.log(`[supervisor:${scanId}] Launched supervisor (PID ${supervisorChild.pid}, threshold ${supervisorThreshold}s, DETACHED)`);
      // Log supervisor stderr to the Next.js terminal for debugging.
      // These listeners don't prevent exit because we unref()'d.
      supervisorChild.stderr?.on("data", (chunk: Buffer) => {
        process.stderr.write(`[supervisor:${scanId}] ${chunk}`);
      });
      supervisorChild.stdout?.on("data", (chunk: Buffer) => {
        process.stdout.write(`[supervisor:${scanId}] ${chunk}`);
      });
    } catch (e) {
      console.error(`[supervisor:${scanId}] Failed to launch supervisor:`, e);
    }
  }

  // Collect stderr so we can store an error message on failure.
  let stderrBuffer = "";
  child.stderr?.on("data", (chunk: Buffer) => {
    stderrBuffer += chunk.toString("utf-8");
    // Also echo to the Next.js terminal so the dev sees runtime errors.
    process.stderr.write(`[scanner:${scanId}] ${chunk}`);
  });
  // CRITICAL: Drain stdout too. The scanner writes log output to stdout
  // (via Python's logging module). If stdout is piped but never read, the
  // OS pipe buffer fills up (64KB on Linux, ~4KB on Windows) and the
  // scanner process BLOCKS on the next stdout write. This was the root
  // cause of "scan doesn't auto-complete" — the scanner finished (logged
  // scan_complete + wrote the marker) but hung on the final print()
  // because the pipe was full. The process never exited → finalizeScan
  // never ran → DB stayed "running".
  child.stdout?.on("data", (chunk: Buffer) => {
    process.stdout.write(`[scanner:${scanId}] ${chunk}`);
  });

  // --- Periodic DB update while the scan is running ---
  // The finalizeScan function (on exit) parses the trail for finding counts,
  // but that only runs when the subprocess EXITS. While the scan is running,
  // the DB shows findingsCount=0, which confuses users ("I see findings in
  // the logs but the dashboard says 0").
  //
  // This interval parses the trail every 5s and updates the DB with the
  // current finding counts + URL/input counts. It stops when the subprocess
  // exits (the 'exit' handler clears the interval).
  //
  // PERFORMANCE: we cache the last-seen counts and only write to the DB
  // when they actually change. Without this, Prisma executes a full UPDATE
  // every 5s even when the scan is frozen on a slow payload — producing
  // the wall-of-SQL spam the user sees in their console. With this, the
  // DB stays quiet when nothing has changed.
  let lastFindingsCount = -1;
  let lastUrlsCrawled = -1;
  let lastInputsDiscovered = -1;
  const progressInterval = setInterval(async () => {
    try {
      const fs = await import("fs/promises");

      // --- Check for scan_completed.marker FIRST (before the trail read) ---
      // This ensures completion is detected even if the trail file read
      // fails (locked, too large, etc.). Previously the marker check was
      // AFTER the trail read, and an early return on empty trail skipped it.
      let markerData: any = null;
      try {
        const markerPath = path.join(
          process.cwd(), "scan-output", scanId, "scan_completed.marker",
        );
        const markerContent = await fs.readFile(markerPath, "utf-8");
        markerData = JSON.parse(markerContent);
      } catch {}

      if (markerData) {
        const currentScan = await db.scan.findUnique({ where: { id: scanId } });
        // The scanner writes the marker during graceful shutdown EVEN when
        // interrupted (user Stop) — with interrupted: true. Honor it: a
        // stopped scan must land on "interrupted", not "completed".
        const markerInterrupted = markerData?.interrupted === true;
        const finalStatus = markerInterrupted ? "interrupted" : "completed";
        if (currentScan && currentScan.status !== finalStatus && currentScan.status !== "completed") {
          const counts = await readFindingsCounts(scanId);
          const fc = markerData?.findings_count ?? counts.findingsCount;
          const fh = markerData?.findings_high ?? counts.findingsHigh;
          const fm = markerData?.findings_medium ?? counts.findingsMedium;
          const fl = markerData?.findings_low ?? counts.findingsLow;
          console.log(`[scanner:${scanId}] Auto-detected scan_complete via marker file — marking as ${finalStatus} (findings=${fc})`);
          await db.scan.update({
            where: { id: scanId },
            data: {
              status: finalStatus,
              endedAt: new Date(),
              findingsCount: fc,
              findingsHigh: fh,
              findingsMedium: fm,
              findingsLow: fl,
              interrupted: markerInterrupted,
              errorMsg: null,
            },
          });
        }
        return;
      }

      // --- Read the trail file for progress (urls, inputs, scan_complete) ---
      const trailPath = path.join(
        process.cwd(), "scan-output", scanId, "execution_trail.jsonl",
      );
      const content = await fs.readFile(trailPath, "utf-8").catch(() => "");
      if (!content) return;

      let urlsCrawled = 0;
      let inputsDiscovered = 0;
      let scanCompleteFound = false;

      for (const line of content.split("\n")) {
        if (!line.trim()) continue;
        try {
          const entry = JSON.parse(line);
          if (entry.action === "scan_complete") {
            scanCompleteFound = true;
          }
          else if (entry.action === "crawl_done") {
            const m = String(entry.result || "").match(/visited (\d+) URLs/);
            if (m) urlsCrawled = parseInt(m[1], 10);
          }
          else if (entry.action === "attack_surface_done") {
            const m = String(entry.result || "").match(/total inputs=(\d+)/);
            if (m) inputsDiscovered = parseInt(m[1], 10);
          }
        } catch { /* skip malformed lines */ }
      }

      // --- Auto-complete: detect scan_complete via marker file OR trail ---
      // The scanner writes a `scan_completed.marker` file right after
      // logging scan_complete. This is the SURE-FIRE way to detect
      // completion — it doesn't depend on finalizeScan, exit codes,
      // pause_state, or any other Node.js-side logic.
      //
      // We also check the trail for scan_complete as a fallback.
      //
      // This fixes the "stuck at running" bug that occurs when:
      //   - finalizeScan fails (exception, race condition)
      //   - pause_state.json is stale from a previous run
      //   - The supervisor restarted the scanner (new process untracked)
      //   - The scanner exited with a non-zero code but still completed
      // (Marker file is already checked at the TOP of this interval —
      // this is a fallback that also catches scan_complete in the trail.)
      if (scanCompleteFound) {
        const currentScan = await db.scan.findUnique({ where: { id: scanId } });
        if (currentScan && currentScan.status !== "completed") {
          const counts = await readFindingsCounts(scanId);
          console.log(`[scanner:${scanId}] Auto-detected scan_complete in trail — marking as completed (findings=${counts.findingsCount})`);
          await db.scan.update({
            where: { id: scanId },
            data: {
              status: "completed",
              endedAt: new Date(),
              findingsCount: counts.findingsCount,
              findingsHigh: counts.findingsHigh,
              findingsMedium: counts.findingsMedium,
              findingsLow: counts.findingsLow,
              urlsCrawled,
              inputsDiscovered,
              interrupted: false,
              errorMsg: null,
            },
          });
        }
        return;
      }

      // Derive finding counts from findings.json (the SAME source the
      // findings list UI uses). This was previously counted from
      // `active_match` trail events, which OVER-counts because the
      // scanner emits one event per matched pattern, not per Finding.
      // A single Finding matching 11 patterns would show "11" in the
      // badge but only 1 row in the list — now both show 1.
      const counts = await readFindingsCounts(scanId);
      const findingsCount = counts.findingsCount;
      const findingsHigh = counts.findingsHigh;
      const findingsMedium = counts.findingsMedium;
      const findingsLow = counts.findingsLow;

      // Skip the DB write if nothing changed since the last poll. This is
      // the difference between 1 UPDATE per finding vs. 1 UPDATE per 5s
      // regardless of activity — which matters when a scan takes 10+ min
      // and the user is watching the console.
      if (
        findingsCount === lastFindingsCount &&
        urlsCrawled === lastUrlsCrawled &&
        inputsDiscovered === lastInputsDiscovered
      ) {
        return;
      }
      lastFindingsCount = findingsCount;
      lastUrlsCrawled = urlsCrawled;
      lastInputsDiscovered = inputsDiscovered;

      await db.scan.update({
        where: { id: scanId },
        data: {
          findingsCount,
          findingsHigh,
          findingsMedium,
          findingsLow,
          urlsCrawled,
          inputsDiscovered,
        },
      });
    } catch {
      // ignore — don't let progress updates crash the scan
    }
  }, 5000);

  // On exit, update the DB row with the final status + parse the trail
  // file for finding counts.
  //
  // CRITICAL: Do NOT kill the supervisor here! The supervisor is a
  // detached process that survives scanner exits. When the supervisor
  // kills a hung scanner, THIS exit handler fires — if we killed the
  // supervisor, it would never get to restart the scanner.
  //
  // The supervisor exits on its own when:
  //   - It sees `scan_complete` in the trail (normal completion)
  //   - It exceeds --max-restarts
  //   - The user writes a `supervisor_stop` marker file (Stop button)
  child.on("exit", async (code, signal) => {
    runningScans.delete(scanId);
    console.log(`[scanner:${scanId}] Process exited: code=${code} signal=${signal}`);

    // --- Finalize the scan ---
    try {
      console.log(`[scanner:${scanId}] Calling finalizeScan...`);
      await finalizeScan(scanId, code, signal, stderrBuffer);
      console.log(`[scanner:${scanId}] finalizeScan completed`);

      // Verify the DB was actually updated
      const finalScan = await db.scan.findUnique({ where: { id: scanId } });
      console.log(`[scanner:${scanId}] DB status after finalizeScan: ${finalScan?.status}`);
      if (finalScan?.status === "running") {
        console.log(`[scanner:${scanId}] WARNING: DB still shows 'running' after finalizeScan — checking trail for scan_complete...`);
        // Force-check: if scan_complete is in the trail, manually update the DB
        try {
          const fs = await import("fs/promises");
          const trailContent = await fs.readFile(
            path.join(process.cwd(), "scan-output", scanId, "execution_trail.jsonl"),
            "utf-8"
          );
          if (trailContent.includes('"action":"scan_complete"') ||
              trailContent.includes('"action": "scan_complete"')) {
            // Honor interruption here too — a graceful Stop writes
            // scan_complete with interrupted=true (top-level trail field)
            // and exits 130/SIGTERM; forcing "completed" would mislabel it.
            const wasInterrupted =
              trailContent.includes('"interrupted":true') ||
              trailContent.includes('"interrupted": true') ||
              code === 130 || signal === "SIGTERM" || signal === "SIGINT";
            const forcedStatus = wasInterrupted ? "interrupted" : "completed";
            console.log(`[scanner:${scanId}] Found scan_complete in trail — forcing DB update to '${forcedStatus}'`);
            const counts = await readFindingsCounts(scanId);
            await db.scan.update({
              where: { id: scanId },
              data: {
                status: forcedStatus,
                endedAt: new Date(),
                findingsCount: counts.findingsCount,
                findingsHigh: counts.findingsHigh,
                findingsMedium: counts.findingsMedium,
                findingsLow: counts.findingsLow,
                interrupted: wasInterrupted,
                errorMsg: null,
              },
            });
            console.log(`[scanner:${scanId}] DB forced to '${forcedStatus}'`);
          }
        } catch (e2) {
          console.error(`[scanner:${scanId}] Force-check failed:`, e2);
        }
      }
    } catch (e) {
      console.error(`[scanner:${scanId}] finalizeScan threw exception:`, e);
    }

    // --- Keep the periodic updater alive for 60s after exit ---
    // This ensures scan_complete is detected even if:
    //   1. finalizeScan fails (exception, race condition)
    //   2. The supervisor restarted the scanner (new process not tracked)
    //   3. The scanner exited with a non-zero code but still wrote
    //      scan_complete to the trail
    //
    // The periodic updater self-terminates when:
    //   - It finds scan_complete in the trail → marks as "completed"
    //   - The DB status changes to "completed" or "failed"
    //   - 60 seconds pass (enough time for finalizeScan to complete)
    //   - 30 minutes pass (for supervisor-restarted scans)
    const keepAliveStart = Date.now();
    const isSupervisorEnabled = process.env.WEBRECON_SUPERVISOR === "1";
    const keepAliveTimeout = isSupervisorEnabled ? 30 * 60 * 1000 : 60000; // 30min or 60s
    if (isSupervisorEnabled) {
      console.log(`[scanner:${scanId}] Supervisor enabled — keeping periodic updater alive to detect scan_complete from restarted scanner`);
    }
    const watchdogInterval = setInterval(async () => {
      // Check if timeout has passed
      if (Date.now() - keepAliveStart > keepAliveTimeout) {
        clearInterval(watchdogInterval);
        clearInterval(progressInterval);
        console.log(`[scanner:${scanId}] Keep-alive timeout (${keepAliveTimeout / 1000}s) — stopping periodic updater`);
        return;
      }
      // Check if the scan is now completed/failed/interrupted in the DB
      try {
        const currentScan = await db.scan.findUnique({ where: { id: scanId } });
        if (currentScan && currentScan.status !== "running" && currentScan.status !== "pending") {
          clearInterval(watchdogInterval);
          clearInterval(progressInterval);
          console.log(`[scanner:${scanId}] Scan is now ${currentScan.status} — stopping periodic updater`);
        }
      } catch {}
    }, 5000); // check every 5s
  });

  // If the subprocess fails to spawn (e.g. python3 not found), 'error'
  // fires instead of 'exit'. Handle it the same way.
  child.on("error", async (err) => {
    runningScans.delete(scanId);
    // Note: supervisorChild is intentionally NOT killed here either.
    stderrBuffer += `\n[spawn error] ${err.message}`;
    try {
      await finalizeScan(scanId, -1, null, stderrBuffer);
    } catch (e) {
      console.error(`[scanner:${scanId}] failed to finalize scan:`, e);
    }
  });
}

/**
 * Update the DB row after the scanner subprocess exits.
 *
 * We parse the trail file to extract finding counts and URL counts. If
 * the trail file is missing or malformed, we fall back to zero counts
 * (the report.html may still have been generated, so we don't fail the
 * whole finalization).
 */
async function finalizeScan(
  scanId: string,
  code: number | null,
  signal: NodeJS.Signals | null,
  stderr: string,
): Promise<void> {
  const fs = await import("fs/promises");
  const trailPath = path.join(
    process.cwd(),
    "scan-output",
    scanId,
    "execution_trail.jsonl",
  );

  // Default values — used if we can't parse the trail.
  let findingsCount = 0;
  let findingsHigh = 0;
  let findingsMedium = 0;
  let findingsLow = 0;
  let urlsCrawled = 0;
  let inputsDiscovered = 0;
  let interrupted = false;
  // null = the trail's scan_complete entry has NO top-level `interrupted`
  // field (older scanner / crash truncation) — fall back to exit-code/signal
  // heuristics. true/false = the scanner explicitly declared its state, and
  // that declaration WINS over the heuristics (a scan that logged
  // scan_complete with interrupted=false and then got SIGTERM'd by a
  // watchdog cleaning up a zombie must still count as completed).
  let interruptedDeclared: boolean | null = null;

  try {
    const trailContent = await fs.readFile(trailPath, "utf-8");
    for (const line of trailContent.split("\n")) {
      if (!line.trim()) continue;
      try {
        const entry = JSON.parse(line);
        if (entry.action === "crawl_done") {
          // The result string contains "visited N URLs" — extract N.
          const m = String(entry.result || "").match(/visited (\d+) URLs/);
          if (m) urlsCrawled = parseInt(m[1], 10);
        } else if (entry.action === "attack_surface_done") {
          const m = String(entry.result || "").match(/total inputs=(\d+)/);
          if (m) inputsDiscovered = parseInt(m[1], 10);
        } else if (entry.action === "scan_complete") {
          if (entry.interrupted === true || entry.interrupted === "True") {
            interrupted = true;
            interruptedDeclared = true;
          } else if (entry.interrupted === false || entry.interrupted === "False") {
            interruptedDeclared = false;
          }
        }
      } catch {
        // Skip malformed lines (truncated on crash).
      }
    }
  } catch {
    // Trail file doesn't exist or can't be read — leave counts at zero.
  }


  // Derive finding counts from findings.json (the SAME source the
  // findings list UI uses) — see readFindingsCounts() for the rationale.
  // We do this AFTER parsing the trail so urlsCrawled/inputsDiscovered/
  // interrupted are still populated from the trail (they're not in
  // findings.json).
  const finalCounts = await readFindingsCounts(scanId);
  findingsCount = finalCounts.findingsCount;
  findingsHigh = finalCounts.findingsHigh;
  findingsMedium = finalCounts.findingsMedium;
  findingsLow = finalCounts.findingsLow;

  // Determine final status.
  //  - code === 0           → completed (or interrupted if the trail says so)
  //  - code === 130         → interrupted (SIGINT exit code)
  //  - signal === 'SIGTERM' → interrupted
  //  - anything else        → failed
  let status: string;
  let errorMsg: string | null = null;
  let pausedForRelogin = false;
  let pauseReason: string | null = null;

  // --- Check for scan_complete in the trail FIRST ---
  // This overrides EVERYTHING — pause_state, exit code, signals, etc.
  // If the scanner wrote scan_complete, the scan is DONE.
  let scanCompleteInTrail = false;
  let supervisorRestarted = false;
  try {
    const trailContent2 = await fs.readFile(trailPath, "utf-8");
    if (trailContent2.includes('"action":"scan_complete"') ||
        trailContent2.includes('"action": "scan_complete"')) {
      scanCompleteInTrail = true;
    }
    if (trailContent2.includes('"action":"supervisor_restart"') ||
        trailContent2.includes('"action": "supervisor_restart"')) {
      supervisorRestarted = true;
    }
  } catch {}

  if (scanCompleteInTrail) {
    // The scan ran to its tail (scan_complete logged) — normally
    // "completed" regardless of exit path. BUT if it was INTERRUPTED (user
    // Stop: scanner logs scan_complete with a top-level interrupted=true
    // field during graceful SIGTERM shutdown, exits 130/SIGTERM), it must
    // be "interrupted" — previously the stop path was absorbed here and the
    // Stop button showed "completed".
    // The scanner's EXPLICIT declaration (interrupted field on the
    // scan_complete entry) WINS over exit-code/signal heuristics: a scan
    // that completed and then got SIGTERM'd by watchdog cleanup of a
    // zombie process still counts as completed. Heuristics only apply when
    // the field is absent (older scanner / truncated trail).
    const wasInterrupted =
      interruptedDeclared !== null
        ? interruptedDeclared
        : (code === 130 || signal === "SIGTERM" || signal === "SIGINT");
    if (wasInterrupted) {
      status = "interrupted";
    } else {
      status = "completed";
    }
    pausedForRelogin = false;
    // Delete stale pause_state.json so it doesn't confuse future runs
    try {
      const pauseStatePath2 = path.join(
        process.cwd(), "scan-output", scanId, "pause_state.json",
      );
      await fs.unlink(pauseStatePath2);
    } catch {}
  } else {
    // scan_complete NOT in trail — check if it was paused.
    const pauseStatePath = path.join(
      process.cwd(), "scan-output", scanId, "pause_state.json",
    );
    try {
      const pauseContent = await fs.readFile(pauseStatePath, "utf-8");
      const pauseState = JSON.parse(pauseContent);
      if (pauseState.paused) {
        pausedForRelogin = true;
        pauseReason = pauseState.reason || "Session expired";
        status = "paused";
      }
    } catch {
      // No pause_state.json — normal exit.
    }

    if (!pausedForRelogin) {
      // Check if already force-completed — don't overwrite
      const currentScan = await db.scan.findUnique({ where: { id: scanId } });
      if (currentScan?.status === "completed") return;

      if (supervisorRestarted) {
        status = "running";
        errorMsg = `Scanner was killed by the supervisor and restarted with --resume --skip-tests. The restarted scanner is still running.`;
      } else if (interrupted || code === 130 || signal === "SIGTERM" || signal === "SIGINT") {
        status = "interrupted";
      } else if (code === 0) {
        status = "completed";
      } else {
        status = "failed";
        errorMsg = stderr.trim().slice(-2000) || `Scanner exited with code ${code}`;
      }
    }
  }

  // Clamp the exit code to signed 32-bit: Windows force-terminations
  // surface as 0xFFFFFFFF (4294967295), which Prisma's Int column can't
  // hold — an unclamped value makes every subsequent scan-list query
  // throw (P2023) and the dashboard shows HTTP 500 until the row is
  // repaired by hand.
  const exitCodeSafe = typeof code === "number" && Number.isInteger(code)
    ? Math.max(-2147483648, Math.min(2147483647, code))
    : -1;

  await db.scan.update({
    where: { id: scanId },
    data: {
      status,
      exitCode: exitCodeSafe,
      errorMsg,
      pausedForRelogin,
      pauseReason,
      findingsCount,
      findingsHigh,
      findingsMedium,
      findingsLow,
      urlsCrawled,
      inputsDiscovered,
      interrupted,
      endedAt: new Date(),
    },
  });
}

/**
 * Resume a previously interrupted scan. Creates a new scan DB row with
 * the same config as the original, but spawns the scanner with --resume
 * pointing to the original scan's output directory. The scanner loads
 * scan_state.json and skips completed phases.
 *
 * Returns the new scan ID.
 */
export async function resumeScan(originalScanId: string): Promise<string> {
  const original = await db.scan.findUnique({ where: { id: originalScanId } });
  if (!original) {
    throw new Error(`Original scan ${originalScanId} not found`);
  }

  // Create a new scan row with the same config.
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
      wordlistFileContent: original.wordlistFileContent,
      weakCiphersFileContent: original.weakCiphersFileContent,
      llmAssist: original.llmAssist,
      llmInteresting: original.llmInteresting,
      llmAnalyze: original.llmAnalyze,
      customHeaders: original.customHeaders,
      testAccessControl: original.testAccessControl,
      testFileUpload: original.testFileUpload,
      uploadBaseFilename: original.uploadBaseFilename,
      status: "pending",
    },
  });

  // The output dir for the RESUMED scan is the SAME as the original —
  // this is critical because --resume loads scan_state.json from the
  // output dir. We point the new scan at the original's output dir.
  const originalOutputDir = path.join(
    process.cwd(),
    "scan-output",
    originalScanId,
  );

  // Create a symlink from the new scan's output dir to the original's
  // output dir. This way, the web UI (which reads scan-output/<new_id>/)
  // can find llm_plan.json, findings.json, report.html, etc. without
  // knowing about the indirection.
  //
  // We use a symlink (not a copy) so that files written by the scanner
  // (to the original dir via --output) are immediately visible to the
  // UI (reading from the new dir via the symlink).
  //
  // IMPORTANT: Create the symlink BEFORE calling writeScanInputFiles,
  // because writeScanInputFiles writes to scan-output/<new_id>/ which
  // is now the symlink → files go into the original dir.
  const newOutputDir = path.join(
    process.cwd(),
    "scan-output",
    newScan.id,
  );
  try {
    const fs = await import("fs/promises");
    // Windows: real symlinks need Developer Mode/admin, so use a junction
    // (no elevation required, absolute local paths only — which these are).
    // Without this, resume on Windows leaves the new row with no output dir
    // and its Live View shows no logs (the scanner writes to the original
    // dir via --output, invisible to the new row's file reads).
    const linkType = process.platform === "win32" ? "junction" : "dir";
    // Remove the new output dir if it exists (it might have been
    // created by a previous scan attempt). We replace it with a link.
    try {
      const stat = await fs.lstat(newOutputDir);
      if (stat.isSymbolicLink()) {
        // Already a symlink — leave it (points to original dir).
      } else if (stat.isDirectory()) {
        await fs.rm(newOutputDir, { recursive: true, force: true });
        await fs.symlink(originalOutputDir, newOutputDir, linkType);
      }
    } catch {
      // Doesn't exist — create the link.
      await fs.symlink(originalOutputDir, newOutputDir, linkType);
    }
    console.log(`[scanner-runner] Resume: linked (${linkType}) ${newOutputDir} → ${originalOutputDir}`);
  } catch (e) {
    // If linking still fails, fall back to no link. The scanner will still
    // work (it uses --output originalOutputDir directly), but the UI won't
    // be able to read files from scan-output/<new_id>/.
    console.error(`[scanner-runner] Resume: failed to create link:`, e);
  }

  // Load LLM settings (same as launchScan).
  const settings = await db.setting.findUnique({ where: { id: "default" } });
  const llmMaxTokens = effectiveLlmMaxTokens(settings?.llmMaxTokens);

  // Write the per-scan headers/payloads files. These go into the new
  // scan's dir (which is symlinked to the original dir, so the files
  // are actually written to the original dir and visible from both IDs).
  const { headersPath, payloadsPath, wordlistPath, weakCiphersPath } = await writeScanInputFiles(
    newScan.id,
    newScan.headersFileContent,
    newScan.payloadsFileContent,
    newScan.wordlistFileContent,
    newScan.weakCiphersFileContent,
  );

  // Build CLI args — same as launchScan but with --resume + the original
  // output dir (NOT the new scan's dir).
  const args: string[] = [
    SCANNER_PATH,
    "--url", newScan.targetUrl,
    "--output", originalOutputDir,  // <-- resume uses the ORIGINAL output dir
    "--depth", String(newScan.depth),
    "--delay", String(newScan.delayMs),
    "--concurrency", String(newScan.concurrency),
    "--max-payload-bytes", "2000",
    "--llm-tokens", String(llmMaxTokens),
    "--resume",  // <-- the key flag
  ];
  if (newScan.scopePatterns) args.push("--scope", newScan.scopePatterns);
  if (newScan.excludePatterns) args.push("--exclude", newScan.excludePatterns);
  if (newScan.ignoreRobots) args.push("--ignore-robots");
  if (newScan.allowExternal) args.push("--allow-external");
  if (headersPath) args.push("--headers", headersPath);
  if (payloadsPath) args.push("--payloads", payloadsPath);
  if (wordlistPath) args.push("--wordlist", wordlistPath);
  if (weakCiphersPath) args.push("--weak-ciphers", weakCiphersPath);
  // Capture takes precedence over form-login (OAuth/SSO can't form-login).
  // Also: resume previously did NOT re-push --load-state, losing the captured
  // session on resume — fixed here.
  const hasCaptureResume = !!(newScan.manualLoginState && newScan.manualLoginStatePath);
  if (newScan.loginUrl && !hasCaptureResume) args.push("--login-url", newScan.loginUrl);
  if (newScan.loginUser && !hasCaptureResume) args.push("--login-user", newScan.loginUser);
  if (hasCaptureResume) args.push("--load-state", newScan.manualLoginStatePath!);
  if (newScan.llmAssist) args.push("--llm-assist");
  if (newScan.llmInteresting) args.push("--llm-interesting");
  if (newScan.llmAnalyze) args.push("--llm-analyze");
  if (newScan.customHeaders) args.push("--custom-headers", newScan.customHeaders);
  if (newScan.testAccessControl) args.push("--test-access-control");
  if (newScan.testFileUpload) {
    args.push("--test-file-upload");
    if (newScan.uploadBaseFilename) {
      args.push("--upload-base-filename", newScan.uploadBaseFilename);
    }
  }

  // Build env (same as launchScan).
  const childEnv: Record<string, string | undefined> = { ...process.env };
  if (settings?.llmBaseUrl) childEnv.LLM_BASE_URL = settings.llmBaseUrl;
  if (settings?.llmApiKey) childEnv.LLM_API_KEY = settings.llmApiKey;
  if (settings?.llmModel) childEnv.LLM_MODEL = settings.llmModel;

  // Mark the new scan as running.
  await db.scan.update({
    where: { id: newScan.id },
    data: { status: "running", startedAt: new Date() },
  });

  // Spawn the subprocess. Use the same Python-discovery logic as launchScan
  // so resume also benefits from the venv-aware interpreter lookup + the
  // detached process group (so stopScan can kill Python + Chromium together).
  const pythonBin = findPythonWithPlaywright();
  const child = spawn(pythonBin, args, {
    cwd: originalOutputDir,
    env: childEnv,
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });
  runningScans.set(newScan.id, child);

  let stderrBuffer = "";
  child.stderr?.on("data", (chunk: Buffer) => {
    stderrBuffer += chunk.toString("utf-8");
    process.stderr.write(`[scanner:${newScan.id}] ${chunk}`);
  });
  // Drain stdout (same fix as launchScan — prevents pipe deadlock).
  child.stdout?.on("data", (chunk: Buffer) => {
    process.stdout.write(`[scanner:${newScan.id}] ${chunk}`);
  });

  // Periodic DB update (same as launchScan). Uses the same change-detection
  // cache to avoid spamming Prisma with no-op UPDATEs every 5s.
  let lastFindingsCount = -1;
  let lastUrlsCrawled = -1;
  let lastInputsDiscovered = -1;
  const progressInterval = setInterval(async () => {
    try {
      const trailPath = path.join(
        process.cwd(), "scan-output", originalScanId, "execution_trail.jsonl",
      );
      const fs = await import("fs/promises");
      const content = await fs.readFile(trailPath, "utf-8").catch(() => "");
      if (!content) return;
      let urlsCrawled = 0, inputsDiscovered = 0;
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
        } catch {}
      }
      // Same fix as launchScan: read findings.json (NOT trail events) so
      // the badge matches the findings list. The scanner writes to
      // originalScanId's directory (the resumed scan's output dir).
      const counts = await readFindingsCounts(originalScanId);
      const findingsCount = counts.findingsCount;
      const findingsHigh = counts.findingsHigh;
      const findingsMedium = counts.findingsMedium;
      const findingsLow = counts.findingsLow;
      if (
        findingsCount === lastFindingsCount &&
        urlsCrawled === lastUrlsCrawled &&
        inputsDiscovered === lastInputsDiscovered
      ) {
        return;
      }
      lastFindingsCount = findingsCount;
      lastUrlsCrawled = urlsCrawled;
      lastInputsDiscovered = inputsDiscovered;
      await db.scan.update({
        where: { id: newScan.id },
        data: {
          findingsCount,
          findingsHigh,
          findingsMedium,
          findingsLow,
          urlsCrawled,
          inputsDiscovered,
        },
      });
    } catch {}
  }, 5000);

  child.on("exit", async (code, signal) => {
    clearInterval(progressInterval);
    runningScans.delete(newScan.id);
    try {
      await finalizeScan(newScan.id, code, signal, stderrBuffer);
    } catch (e) {
      console.error(`[scanner:${newScan.id}] failed to finalize:`, e);
    }
  });

  child.on("error", async (err) => {
    runningScans.delete(newScan.id);
    stderrBuffer += `\n[spawn error] ${err.message}`;
    try {
      await finalizeScan(newScan.id, -1, null, stderrBuffer);
    } catch (e) {
      console.error(`[scanner:${newScan.id}] failed to finalize:`, e);
    }
  });

  return newScan.id;
}

/**
 * Kill a running scanner subprocess (graceful SIGTERM first, then SIGKILL
 * after 10s). Used by the "Stop scan" button in the UI.
 *
 * WHY 10s (not 5s): When the scanner is blocked inside a Playwright C call
 * (e.g. page.goto() waiting for a JavaScript alert() dialog to be dismissed),
 * the SIGTERM signal handler runs but the asyncio event loop can't yield
 * control to check `stop_event.is_set()`. The process appears "stuck" until
 * Playwright's internal timeout fires (default 30s) or the OS kills it.
 * Giving 10s allows Playwright's own timeouts to fire on milder hangs; if
 * it's truly stuck, SIGKILL forces immediate termination.
 *
 * WHY kill the process GROUP: The scanner spawns Chromium as a child
 * process. Killing just the Python parent leaves Chromium orphaned and
 * consuming memory. We use process.kill(-pid) to signal the entire process
 * group (set via detached:true at spawn — though we currently don't set
 * that, so this is a no-op fallback). As a belt-and-suspenders measure,
 * we also try `child.kill("SIGKILL")` which Node translates to the
 * platform-appropriate force-kill.
 */
export async function stopScan(scanId: string): Promise<boolean> {
  const child = runningScans.get(scanId);
  if (!child) return false;
  const pid = child.pid;

  // Write a `supervisor_stop` marker file so the detached supervisor
  // knows to exit (it's not killed by the exit handler anymore).
  // The supervisor checks for this file in its poll loop.
  try {
    const fs = await import("fs/promises");
    const stopMarker = path.join(
      process.cwd(), "scan-output", scanId, "supervisor_stop",
    );
    await fs.writeFile(stopMarker, new Date().toISOString(), "utf-8");
  } catch {}

  // SIGTERM triggers the scanner's graceful shutdown handler, which saves
  // partial evidence and renders a partial report.
  try {
    child.kill("SIGTERM");
  } catch {
    // Process may have already exited — ignore.
  }

  // After 10s, if the process hasn't exited, force-kill it.
  // We check `child.exitCode === null` (not `child.killed`) because
  // `child.killed` is true as soon as SIGTERM is SENT, even if the process
  // is still running. `child.exitCode` is null until the process actually
  // exits.
  setTimeout(() => {
    try {
      if (child.exitCode === null && !child.signalCode) {
        // Try to kill the entire process group (Python + Chromium).
        // process.kill(-pid) sends the signal to all processes in the
        // group. This only works if the child was spawned with
        // detached:true (which creates a new process group). As a
        // fallback, we also kill the child directly.
        if (pid) {
          try {
            process.kill(-pid, "SIGKILL");
          } catch {
            // Not in a process group, or already exited — fall through.
          }
        }
        child.kill("SIGKILL");
      }
    } catch {
      // Process already exited — ignore.
    }
  }, 10000);

  return true;
}

/**
 * Check whether a scan is currently running (has a live subprocess).
 */
export function isScanRunning(scanId: string): boolean {
  return runningScans.has(scanId);
}
