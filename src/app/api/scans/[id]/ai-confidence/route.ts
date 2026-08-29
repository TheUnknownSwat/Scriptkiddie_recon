import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { callLlmRaw, clampGenTokens, effectiveLlmMaxTokens, stripThinkTags, writeJsonAtomic } from "@/lib/scanner-paths";
import fs from "fs/promises";
import path from "path";

/**
 * AI Confidence Evaluation — progressive, batched, resumable (no SSE).
 *
 * POST starts a background job (fire-and-forget) and returns immediately with
 * `{ started, progress }`. The job evaluates findings in BATCHES (~6 per LLM
 * call, ~6× fewer calls than the old one-per-finding loop), writes
 * `ai_confidence.json` atomically after each batch, and updates an in-memory
 * JobState. The browser polls GET every ~1.5s to pick up newly-written
 * results → the "AI agreed?" badges appear one-by-one as each batch lands.
 *
 * Why a background job (not a long blocking POST): the browser/proxy may time
 * out a long request; decoupling the work from the request means it survives
 * disconnects, and re-POSTing resumes from where it stopped (already-evaluated
 * finding_ids are skipped).
 *
 * LLM calls are plain JSON POST (no streaming) — the throttle is adaptive
 * (small courtesy gap via WEBRECON_LLM_THROTTLE_MS + 429 Retry-After backoff),
 * replacing the old hard-coded 500ms-per-finding sleep.
 *
 * Each result: { finding_id, title, confidence "High"|"Medium"|"Low",
 *                reasoning, suggested_test }.
 * Summary: { total, agreed, disagreed, percent }.
 */

interface JobState {
  running: boolean;
  total: number; // total findings to cover
  done: number; // results written so far
  error: string | null;
  startedAt: number;
}

// Module-level job registry. Same in-memory pattern the scan registry uses
// (and the same "doesn't survive a server restart" caveat — a restart just
// means re-POST, which resumes from the on-disk file).
const jobs = new Map<string, JobState>();

const BATCH_SIZE = 6; // findings per LLM call
const AI_CONFIDENCE_FILE = "ai_confidence.json";

interface ConfidenceResult {
  finding_id: string;
  title: string;
  confidence: string;
  reasoning: string;
  suggested_test: string;
}

function computeSummary(results: ConfidenceResult[]) {
  const agreed = results.filter((r) => r.confidence === "High").length;
  const disagreed = results.filter((r) => r.confidence === "Low").length;
  return {
    total: results.length,
    agreed,
    disagreed,
    percent: results.length > 0 ? Math.round((agreed / results.length) * 100) : 0,
  };
}

function jobProgress(job: JobState | undefined) {
  if (!job) return null;
  return { done: job.done, total: job.total, running: job.running, error: job.error };
}

/**
 * Evaluate one batch of findings in a single LLM call. Returns one result per
 * finding (fallbacks on any failure so every finding gets an entry — the run
 * continues instead of aborting on one bad call).
 */
async function evalBatch(
  cfg: { baseUrl: string; apiKey: string | null; model: string; maxTokens: number },
  batch: any[],
): Promise<ConfidenceResult[]> {
  const digests = batch.map((f, idx) => ({
    index: idx,
    finding_id: f.finding_id,
    title: f.title,
    severity: f.severity,
    owasp_category: f.owasp_category,
    url: f.url,
    payload: (f.payload || "").slice(0, 150),
    patterns_matched: f.patterns_matched,
    request_snippet: (f.request_raw || "").slice(0, 250),
    response_snippet: (f.response_raw || "").slice(0, 250),
  }));

  const prompt = `You are a web application security analyst. Evaluate each of these ${batch.length} findings — TRUE positive (real vulnerability) or FALSE positive (benign match)?

FINDINGS (JSON array, in order):
${JSON.stringify(digests, null, 2)}

Return ONLY a JSON ARRAY (no markdown, no explanation), one entry per finding IN ORDER, each:
{"index": <0-based index>, "confidence": "High|Medium|Low", "reasoning": "one short sentence", "suggested_test": "one concrete manual step"}`;

  const r = await callLlmRaw({
    baseUrl: cfg.baseUrl,
    apiKey: cfg.apiKey,
    model: cfg.model,
    messages: [
      { role: "system", content: "You are a security finding evaluator. You output ONLY a JSON array. Be conservative — prefer Medium over High unless the evidence is strong." },
      { role: "user", content: prompt },
    ],
    maxTokens: cfg.maxTokens,
    temperature: 0.2,
  });

  // Parse the JSON array (best-effort) once.
  let arr: any[] = [];
  if (r.ok && r.data != null) {
    const rawReply = r.data?.choices?.[0]?.message?.content || r.data?.choices?.[0]?.text || "";
    const cleaned = stripThinkTags(rawReply);
    const start = cleaned.indexOf("[");
    const end = cleaned.lastIndexOf("]");
    if (start !== -1 && end !== -1 && end > start) {
      try {
        const parsed = JSON.parse(cleaned.substring(start, end + 1));
        if (Array.isArray(parsed)) arr = parsed;
      } catch {
        /* fall through to per-finding fallbacks */
      }
    }
  }

  // Build a result for EVERY finding (fallbacks keep the run going on failure).
  return batch.map((f, idx) => {
    const fid = f.finding_id || `unknown_${idx}`;
    const title = f.title || "Unknown";
    const fallback = (reasoning: string): ConfidenceResult => ({
      finding_id: fid,
      title,
      confidence: "Medium",
      reasoning,
      suggested_test: "",
    });
    if (!r.ok || r.data == null) {
      return fallback(r.error || "LLM did not respond");
    }
    // Match by explicit index field, else by array position.
    const matched = arr.find((a) => a && typeof a.index === "number" && a.index === idx) || arr[idx];
    if (matched && matched.confidence) {
      return {
        finding_id: fid,
        title,
        confidence: String(matched.confidence || "Medium"),
        reasoning: String(matched.reasoning || ""),
        suggested_test: String(matched.suggested_test || ""),
      };
    }
    return fallback("LLM did not return an entry for this finding");
  });
}

/**
 * The background job. Mutates the JobState in the map so GET can report
 * progress. Writes ai_confidence.json atomically after each batch.
 */
async function runJob(
  scanId: string,
  cfg: { baseUrl: string; apiKey: string | null; model: string; maxTokens: number },
  toEvaluate: any[],
  totalFindings: number,
  initialResults: ConfidenceResult[],
  outputPath: string,
) {
  const job = jobs.get(scanId);
  if (!job) return;

  // Accumulator starts from the resumed results.
  const results: ConfidenceResult[] = [...initialResults];

  try {
    for (let i = 0; i < toEvaluate.length; i += BATCH_SIZE) {
      if (!job.running) break; // safety (no external cancel currently, but guarded)
      const batch = toEvaluate.slice(i, i + BATCH_SIZE);
      const batchResults = await evalBatch(cfg, batch);
      results.push(...batchResults);
      const summary = computeSummary(results);
      try {
        await writeJsonAtomic(outputPath, { results, summary, saved_at: new Date().toISOString() });
      } catch {
        /* non-fatal — keep going; next batch will retry the write */
      }
      job.done = results.length;
    }
    // Final write with the complete summary.
    const summary = computeSummary(results);
    try {
      await writeJsonAtomic(outputPath, { results, summary, saved_at: new Date().toISOString() });
    } catch {
      /* non-fatal */
    }
    job.done = results.length;
  } catch (e) {
    job.error = e instanceof Error ? e.message : String(e);
  } finally {
    job.running = false;
  }
}

export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;

  const [scan, settings] = await Promise.all([
    db.scan.findUnique({ where: { id } }),
    db.setting.findUnique({ where: { id: "default" } }),
  ]);
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }
  if (!settings?.llmBaseUrl) {
    return NextResponse.json(
      { error: "AI analysis skipped: LLM endpoint not configured. Set the Endpoint URL in Settings. (API key is optional for local LLM servers like Ollama.)" },
      { status: 400 },
    );
  }

  // Load findings.json from disk.
  const findingsPath = path.join(process.cwd(), "scan-output", id, "findings.json");
  let findings: any[] = [];
  try {
    findings = JSON.parse(await fs.readFile(findingsPath, "utf-8"));
  } catch {
    return NextResponse.json(
      { error: "No findings to evaluate. Run a scan first." },
      { status: 400 },
    );
  }
  if (findings.length === 0) {
    return NextResponse.json({
      results: [],
      summary: { total: 0, agreed: 0, disagreed: 0, percent: 0 },
      progress: { done: 0, total: 0, running: false, error: null },
    });
  }

  // Already running? Don't start a second job.
  const existing = jobs.get(id);
  if (existing?.running) {
    return NextResponse.json({ started: true, alreadyRunning: true, progress: jobProgress(existing) });
  }

  // Resume: read existing ai_confidence.json → skip already-evaluated ids.
  const outputPath = path.join(process.cwd(), "scan-output", id, AI_CONFIDENCE_FILE);
  let savedResults: ConfidenceResult[] = [];
  try {
    const data = JSON.parse(await fs.readFile(outputPath, "utf-8"));
    if (Array.isArray(data.results)) savedResults = data.results;
  } catch {
    /* no existing file — fresh run */
  }
  const doneIds = new Set(savedResults.map((r) => r.finding_id));
  const toEvaluate = findings.filter((f) => f.finding_id && !doneIds.has(f.finding_id));

  const job: JobState = {
    running: true,
    total: findings.length,
    done: savedResults.length,
    error: null,
    startedAt: Date.now(),
  };
  jobs.set(id, job);

  // Resolved LLM config (model default + clamped per-call token budget).
  // Built here so the guard on settings.llmBaseUrl narrows it to string.
  const cfg = {
    baseUrl: settings.llmBaseUrl,
    apiKey: settings.llmApiKey,
    model: settings.llmModel || "gpt-4o-mini",
    maxTokens: clampGenTokens(effectiveLlmMaxTokens(settings.llmMaxTokens), 512, 1536, 900),
  };

  // Fire-and-forget. Mutates `job` (same reference held in the map) as it goes.
  runJob(id, cfg, toEvaluate, findings.length, savedResults, outputPath).catch((e) => {
    job.running = false;
    job.error = e instanceof Error ? e.message : String(e);
  });

  return NextResponse.json({
    started: true,
    alreadyRunning: false,
    nothingToDo: toEvaluate.length === 0, // all already evaluated
    progress: jobProgress(job),
  });
}

/**
 * GET /api/scans/[id]/ai-confidence
 *
 * Returns the saved results + summary (read from ai_confidence.json) AND a
 * `progress` block from the live job (if one is running). The client polls
 * this every ~1.5s to make badges appear progressively.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const filePath = path.join(process.cwd(), "scan-output", id, AI_CONFIDENCE_FILE);
  const job = jobs.get(id);
  const progress = jobProgress(job);

  try {
    const content = await fs.readFile(filePath, "utf-8");
    const data = JSON.parse(content);
    const results: ConfidenceResult[] = Array.isArray(data.results) ? data.results : [];
    // Older saves lacked a summary — recompute so the header badge is correct.
    if (!data.summary) {
      data.summary = computeSummary(results);
    }
    return NextResponse.json({ ...data, progress });
  } catch {
    return NextResponse.json(
      { results: [], summary: null, progress, error: "AI confidence evaluation not found" },
      { status: 404 },
    );
  }
}
