import path from "path";
import fs from "fs/promises";

/**
 * Paths and helpers for invoking bin/scanner.py from the Next.js API.
 *
 * The scanner is a standalone Python script copied verbatim into bin/.
 * We spawn it as a subprocess (NOT import it) because:
 *  - It uses asyncio + Playwright, which has its own event loop that
 *    conflicts with Next.js's runtime if imported.
 *  - Subprocess isolation means a scanner crash cannot take down the
 *    web UI — the user can still see partial results + re-launch.
 *  - The scanner writes its output to a per-scan directory, which the
 *    API can stream back to the browser via SSE.
 */

const PROJECT_ROOT = process.cwd();
export const BIN_DIR = path.join(PROJECT_ROOT, "bin");
export const SCANNER_PATH = path.join(BIN_DIR, "scanner.py");
export const DEFAULT_PAYLOADS_PATH = path.join(BIN_DIR, "payloads.txt");
export const DEFAULT_WORDLIST_PATH = path.join(BIN_DIR, "wordlist.txt");
export const DEFAULT_WHITELIST_PATH = path.join(BIN_DIR, "whitelist.txt");
export const DEFAULT_WEAK_CIPHERS_PATH = path.join(BIN_DIR, "weak_ciphers.txt");

// All scan outputs (report.html, execution_trail.jsonl, evidence/*) live
// under this directory. Each scan gets its own subdirectory named by ID.
export const SCAN_OUTPUT_ROOT = path.join(PROJECT_ROOT, "scan-output");

/**
 * Get the absolute path to a scan's output directory.
 * Creates the directory if it doesn't exist (mkdir -p semantics).
 */
export async function scanOutputDir(scanId: string): Promise<string> {
  const dir = path.join(SCAN_OUTPUT_ROOT, scanId);
  await fs.mkdir(dir, { recursive: true });
  return dir;
}

/**
 * Path to a scan's report.html (may not exist yet if scan is still running).
 */
export function reportPath(scanId: string): string {
  return path.join(SCAN_OUTPUT_ROOT, scanId, "report.html");
}

/**
 * Path to a scan's execution_trail.jsonl (the live log file).
 * The scanner appends one JSON object per line as it runs.
 */
export function trailPath(scanId: string): string {
  return path.join(SCAN_OUTPUT_ROOT, scanId, "execution_trail.jsonl");
}

/**
 * Path to a scan's findings.json (the authoritative findings list).
 * Each entry is one Finding object — the same array the /findings API
 * serves and the OWASP coverage panel renders.
 */
export function findingsPath(scanId: string): string {
  return path.join(SCAN_OUTPUT_ROOT, scanId, "findings.json");
}

/**
 * Read findings.json and derive (count, high, medium, low) from it.
 *
 * WHY THIS EXISTS:
 * The scanner logs one `active_match` trail event PER PATTERN MATCH,
 * but a single Finding can carry multiple matched patterns
 * (e.g. `XSS:script_alert_block` + `XSS:exact_payload_reflection`).
 * Counting trail events therefore over-counts findings — a scan with
 * 1 Finding that matched 11 patterns would show "11 findings" in the
 * header badge but only 1 row in the findings list.
 *
 * This helper reads the SAME source the findings list uses
 * (findings.json) so the badge and the list always agree.
 *
 * Returns zeros if the file doesn't exist or is malformed (the
 * scanner writes it incrementally, so it may be empty or partial
 * during a running scan — that's fine, we'll re-read on the next poll).
 */
export async function readFindingsCounts(
  scanId: string,
): Promise<{
  findingsCount: number;
  findingsHigh: number;
  findingsMedium: number;
  findingsLow: number;
}> {
  try {
    const raw = await fs.readFile(findingsPath(scanId), "utf-8");
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) {
      return { findingsCount: 0, findingsHigh: 0, findingsMedium: 0, findingsLow: 0 };
    }
    let high = 0, medium = 0, low = 0;
    for (const f of arr) {
      const sev = String((f as any)?.severity || "").toLowerCase();
      if (sev === "high") high++;
      else if (sev === "medium") medium++;
      else if (sev === "low") low++;
      else if (sev === "info" || sev === "informational") {
        // info findings don't count toward high/medium/low but DO
        // count toward the total.
      }
    }
    return {
      findingsCount: arr.length,
      findingsHigh: high,
      findingsMedium: medium,
      findingsLow: low,
    };
  } catch {
    return { findingsCount: 0, findingsHigh: 0, findingsMedium: 0, findingsLow: 0 };
  }
}

/**
 * Path to a scan's evidence directory (contains per-test .txt files +
 * screenshots).
 */
export function evidenceDir(scanId: string): string {
  return path.join(SCAN_OUTPUT_ROOT, scanId, "evidence");
}

/**
 * Resolve a user-supplied evidence filename to an absolute path inside
 * the scan's evidence directory. Returns null if the path would escape
 * the evidence directory (defence against path traversal).
 */
export function safeEvidencePath(scanId: string, filename: string): string | null {
  const dir = evidenceDir(scanId);
  // path.resolve collapses any ../ sequences and gives us an absolute path.
  const resolved = path.resolve(dir, filename);
  // Verify the resolved path is still inside the evidence dir.
  if (!resolved.startsWith(dir + path.sep) && resolved !== dir) {
    return null;
  }
  return resolved;
}

/**
 * Persist the user-supplied headers/payloads file contents to a temporary
 * file in the scan's output directory, so the scanner can read them via
 * --headers / --payloads. Returns the absolute paths.
 *
 * We write per-scan copies (rather than reusing a shared file) so that:
 *  - Each scan is fully reproducible from its DB row + output dir.
 *  - Concurrent scans with different whitelists don't clobber each other.
 */
export async function writeScanInputFiles(
  scanId: string,
  headersContent: string | null,
  payloadsContent: string | null,
  wordlistContent: string | null = null,
  weakCiphersContent: string | null = null,
): Promise<{
  headersPath: string | null;
  payloadsPath: string | null;
  wordlistPath: string | null;
  weakCiphersPath: string | null;
}> {
  const dir = await scanOutputDir(scanId);
  let headersPath: string | null = null;
  let payloadsPath: string | null = null;
  let wordlistPath: string | null = null;
  let weakCiphersPath: string | null = null;
  if (headersContent) {
    headersPath = path.join(dir, "whitelist.txt");
    await fs.writeFile(headersPath, headersContent, "utf-8");
  }
  if (payloadsContent) {
    payloadsPath = path.join(dir, "payloads.txt");
    await fs.writeFile(payloadsPath, payloadsContent, "utf-8");
  }
  if (wordlistContent) {
    wordlistPath = path.join(dir, "wordlist.txt");
    await fs.writeFile(wordlistPath, wordlistContent, "utf-8");
  }
  if (weakCiphersContent) {
    weakCiphersPath = path.join(dir, "weak_ciphers.txt");
    await fs.writeFile(weakCiphersPath, weakCiphersContent, "utf-8");
  }
  return { headersPath, payloadsPath, wordlistPath, weakCiphersPath };
}

/**
 * Strip reasoning model artifacts from LLM responses.
 *
 * Reasoning models like DeepSeek-R1, o1, etc. wrap their internal
 * reasoning in <think>...</think> tags. If we don't strip these, the
 * reasoning text leaks into the generated payloads/wordlist when the
 * user clicks "Add to payloads".
 *
 * This function removes:
 *   - <think>...</think> blocks (including unclosed ones at the end)
 *   - <reasoning>...</reasoning> blocks (some models use this)
 *   - Leading/trailing whitespace
 *
 * It does NOT strip markdown code fences or comments — those are
 * handled by the caller (each route has its own line-by-line parser).
 */
export function stripThinkTags(text: string): string {
  if (!text) return "";
  // Remove <think>...</think> blocks (non-greedy, multiline).
  // Also handle unclosed <think> tags (reasoning model may not close
  // them if the response was truncated).
  let result = text.replace(/<think>[\s\S]*?<\/think>/gi, "");
  result = result.replace(/<think>[\s\S]*/gi, ""); // unclosed <think>
  // Remove <reasoning>...</reasoning> blocks.
  result = result.replace(/<reasoning>[\s\S]*?<\/reasoning>/gi, "");
  result = result.replace(/<reasoning>[\s\S]*/gi, ""); // unclosed
  return result.trim();
}

/**
 * Parse an LLM response into a list of lines (payloads or wordlist paths).
 *
 * Handles:
 *   - Stripping <think> tags (reasoning models)
 *   - Removing markdown code fences (```...```)
 *   - Removing comment lines (# or //)
 *   - Removing numbered list prefixes (e.g. "1. payload")
 *   - Removing empty lines
 *   - Deduplication (preserving order)
 */
export function parseLlmLineList(rawReply: string): string[] {
  // Strip reasoning tags first.
  const cleaned = stripThinkTags(rawReply);
  return cleaned
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#") && !line.startsWith("//"))
    .filter((line) => !line.startsWith("```"))
    .map((line) => line.replace(/^\d+\.\s*/, ""))
    .filter((line, idx, arr) => arr.indexOf(line) === idx);
}

/**
 * Resolve the effective global LLM max-tokens value.
 *
 * Precedence: WEBRECON_LLM_MAX_TOKENS env var (deploy-level override)
 * > the Settings "Max Tokens per Request" DB value > 4000 default.
 *
 * This is the value the scanner subprocess receives via --llm-tokens and the
 * input that per-call clampGenTokens() ranges are applied to. Note per-call
 * ceilings still apply (each route clamps for its payload size), and the LLM
 * server's own completion cap (e.g. LM Studio's 4096) is the final limit.
 */
export function effectiveLlmMaxTokens(dbValue?: number | null): number {
  const env = process.env.WEBRECON_LLM_MAX_TOKENS;
  if (env) {
    const parsed = parseInt(env, 10);
    if (!isNaN(parsed) && parsed > 0) return parsed;
  }
  if (typeof dbValue === "number" && Number.isFinite(dbValue)) return dbValue;
  return 4000;
}

/**
 * Clamp a per-call generation token budget from the effective max-tokens value.
 *
 * Input is normally effectiveLlmMaxTokens(settings.llmMaxTokens). Each AI
 * generator call (payloads / wordlist / per-endpoint / per-file) is clamped
 * to a small range so one call can't balloon and truncate. The setting
 * therefore affects generation within [lo, hi]; out-of-range values clamp.
 */
export function clampGenTokens(
  setting: number | null | undefined,
  lo = 256,
  hi = 1024,
  fallback = 600,
): number {
  const n = typeof setting === "number" && Number.isFinite(setting) ? setting : fallback;
  return Math.min(hi, Math.max(lo, Math.floor(n)));
}

export interface LlmLineListResult {
  items: string[];
  truncated: boolean; // choices[0].finish_reason === "length"
  httpStatus: number; // 0 when no HTTP response (network/timeout error)
  error?: string; // present when the call failed
}

export interface LlmRawResult {
  ok: boolean;
  status: number; // HTTP status (0 on network/timeout error)
  data: any; // parsed JSON body (null on failure)
  error?: string; // present on failure
}

/**
 * Inter-call courtesy gap (ms) — a small pause after each successful LLM call
 * so we don't hammer the endpoint. Configurable via the
 * WEBRECON_LLM_THROTTLE_MS env var. Default 150ms. Set to 0 to disable.
 *
 * This REPLACES the old hard-coded 500ms-per-finding sleep in the AI
 * confidence evaluator. It is intentionally small so fast/cloud endpoints
 * aren't penalized; rate-limited endpoints are additionally protected by
 * callLlmRaw's 429 Retry-After backoff.
 */
export function getLlmThrottleMs(): number {
  const env = process.env.WEBRECON_LLM_THROTTLE_MS;
  if (env) {
    const parsed = parseInt(env, 10);
    if (!isNaN(parsed) && parsed >= 0) return parsed;
  }
  return 150;
}

/**
 * One LLM POST with adaptive throttling + 429 Retry-After backoff.
 *
 * - On HTTP 429 (Too Many Requests): honor the `Retry-After` header (seconds
 *   or HTTP-date), wait, and retry — up to `maxRetries` times. This is the
 *   correct way to handle rate limits (vs a fixed preemptive sleep).
 * - After a successful call: a small courtesy gap (getLlmThrottleMs) before
 *   returning, so back-to-back calls don't flood the endpoint.
 *
 * Never throws — failures are returned as { ok:false, error }.
 */
export async function callLlmRaw(opts: {
  baseUrl: string;
  apiKey?: string | null;
  model: string;
  messages: Array<{ role: string; content: string }>;
  maxTokens: number;
  temperature?: number;
  maxRetries?: number;
}): Promise<LlmRawResult> {
  const {
    baseUrl,
    apiKey,
    model,
    messages,
    maxTokens,
    temperature = 0.7,
    maxRetries = 3,
  } = opts;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
  };
  const body = JSON.stringify({ model, messages, max_tokens: maxTokens, temperature });

  for (let attempt = 0; ; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), getLlmTimeoutMs());
    try {
      const resp = await fetch(baseUrl, { method: "POST", headers, body, signal: controller.signal });
      clearTimeout(timeout);

      // 429 — honor Retry-After and retry (up to maxRetries).
      if (resp.status === 429 && attempt < maxRetries) {
        const ra = resp.headers.get("retry-after");
        let waitMs = 2000; // default exponential-ish backoff base
        if (ra) {
          const secs = parseFloat(ra);
          if (!isNaN(secs) && secs >= 0) {
            waitMs = Math.min(30000, Math.max(500, Math.round(secs * 1000)));
          } else {
            const dt = Date.parse(ra);
            if (!isNaN(dt)) waitMs = Math.min(30000, Math.max(500, dt - Date.now()));
          }
        } else {
          waitMs = Math.min(30000, 1000 * (attempt + 1) * 2);
        }
        await new Promise((r) => setTimeout(r, waitMs));
        continue;
      }

      if (!resp.ok) {
        const text = await resp.text().catch(() => "");
        return { ok: false, status: resp.status, data: null, error: `LLM returned HTTP ${resp.status}: ${text.slice(0, 300)}` };
      }

      const data = await resp.json();
      // Courtesy gap so back-to-back calls don't flood the endpoint.
      const gap = getLlmThrottleMs();
      if (gap > 0) await new Promise((r) => setTimeout(r, gap));
      return { ok: true, status: resp.status, data };
    } catch (e) {
      clearTimeout(timeout);
      return {
        ok: false,
        status: 0,
        data: null,
        error: `LLM request failed: ${e instanceof Error ? e.message : String(e)}`,
      };
    }
  }
}

/**
 * One LLM "generate a line list" call with truncation detection.
 *
 * Centralizes the fetch, auth header, timeout, finish_reason detection, and
 * parsing (via parseLlmLineList). When the response is truncated
 * (finish_reason === "length") the final parsed line is dropped — it is
 * almost certainly a half-generated item.
 *
 * Built on callLlmRaw, so it inherits the adaptive throttle + 429 backoff.
 * Never throws — failures are returned as { error } so callers can decide.
 */
export async function callLlmLineList(opts: {
  baseUrl: string;
  apiKey?: string | null;
  model: string;
  system: string;
  user: string;
  maxTokens: number;
  temperature?: number;
}): Promise<LlmLineListResult> {
  const { baseUrl, apiKey, model, system, user, maxTokens, temperature } = opts;
  const r = await callLlmRaw({
    baseUrl,
    apiKey,
    model,
    messages: [
      { role: "system", content: system },
      { role: "user", content: user },
    ],
    maxTokens,
    temperature,
  });
  if (!r.ok || r.data == null) {
    return { items: [], truncated: false, httpStatus: r.status, error: r.error };
  }
  const rawReply = r.data?.choices?.[0]?.message?.content || r.data?.choices?.[0]?.text || "";
  const finishReason = String(r.data?.choices?.[0]?.finish_reason || "").toLowerCase();
  const truncated = finishReason === "length";
  let items = parseLlmLineList(rawReply);
  if (truncated && items.length > 0) {
    // The last line is almost certainly incomplete — drop it.
    items = items.slice(0, -1);
  }
  return { items, truncated, httpStatus: r.status };
}

/**
 * Write JSON to a path atomically (temp file + rename) so concurrent readers
 * (e.g. a polling GET) never observe a half-written file.
 */
export async function writeJsonAtomic(filePath: string, value: unknown): Promise<void> {
  const tmp = `${filePath}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(value, null, 2), "utf-8");
  await fs.rename(tmp, filePath);
}


/**
 * Get the LLM request timeout (in milliseconds).
 *
 * Configurable via the WEBRECON_LLM_TIMEOUT_MS env var.
 * Default: 120000 (2 minutes).
 *
 * This is used by all LLM API routes (payload generation, wordlist
 * generation, llm-interesting, explain, ai-confidence, chat, etc.)
 * so you can set ONE value in .env to control all LLM timeouts.
 *
 * Example .env:
 *   WEBRECON_LLM_TIMEOUT_MS=300000   # 5 minutes for slow LLMs
 */
export function getLlmTimeoutMs(): number {
  const env = process.env.WEBRECON_LLM_TIMEOUT_MS;
  if (env) {
    const parsed = parseInt(env, 10);
    if (!isNaN(parsed) && parsed > 0) return parsed;
  }
  return 120000;  // default: 2 minutes
}
