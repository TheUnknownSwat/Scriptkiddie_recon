import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { clampGenTokens, effectiveLlmMaxTokens, getLlmTimeoutMs, stripThinkTags } from "@/lib/scanner-paths";
import { fetchTargetText, parseCustomHeaders } from "@/lib/target-fetch";
import fs from "fs/promises";
import path from "path";

/**
 * POST /api/scans/[id]/javascripts/analyze-ai
 *
 * Fetches each collected JS file and sends its source to the LLM ONE FILE
 * AT A TIME (never concatenated — that overflowed small-context models),
 * asking it to flag dangerous / suspicious code: eval/Function of dynamic
 * data, innerHTML/document.write of user input, postMessage handlers,
 * hardcoded secrets/keys, hidden debug/console commands, prototype
 * pollution sinks, open redirects in JS, etc.
 *
 * This directly addresses the "planted JS vuln the scanner didn't notice"
 * case — the JS files are now visible AND analyzed.
 *
 * Results: { findings: [{js_url, severity, category, snippet, explanation}],
 *            js_analyzed, llm_error? }
 * Also saved to javascripts_ai_results.json so they reload without re-clicking.
 */

interface LlmSettings {
  llmBaseUrl: string | null;
  llmApiKey: string | null;
  llmModel: string | null;
}
interface JsEntry {
  url: string;
  found_on?: string[];
  external?: boolean;
  filename?: string;
  local_source?: string;
}

const SUSPICIOUS_PROMPT = (url: string, code: string) =>
  `You are a web application security reviewer. Review this ONE JavaScript file's source and flag any DANGEROUS or SUSPICIOUS code that could be a security vulnerability or a backdoor. Specifically look for:
- eval() / new Function() / setTimeout/setInterval with string args built from dynamic data (XSS / code injection sinks)
- innerHTML / outerHTML / document.write / insertAdjacentHTML with user/dynamic data (DOM XSS)
- postMessage handlers without origin checks
- hardcoded secrets, API keys, tokens, passwords, private keys
- hidden debug / backdoor commands (e.g. console commands triggered by specific input, keyboard sequences, or query params)
- prototype pollution sinks (Object.assign, deep-merge of user data)
- open redirect or SSRF in client-side fetch URLs
- dangerous use of document.cookie, localStorage with sensitive data
- disabled / weakened security controls (commented-out auth checks, etc.)

For EACH issue found, output a JSON array of objects: {"severity":"High|Medium|Low","category":"short label","snippet":"the exact code line(s)","explanation":"why it's dangerous"}. If the file is clean, return [].

JavaScript file URL: ${url}
Source code:
${code}

Respond with ONLY the JSON array, no markdown fences, no preamble.`;

function parseJsonArray(rawReply: string): Array<Record<string, unknown>> {
  const cleaned = stripThinkTags(rawReply).trim();
  let text = cleaned;
  if (text.startsWith("```")) {
    const lines = text.split("\n");
    if (lines[0].startsWith("```")) lines.shift();
    if (lines.length > 0 && lines[lines.length - 1].trim() === "```") lines.pop();
    text = lines.join("\n");
  }
  const start = text.indexOf("[");
  if (start === -1) return [];
  const end = text.lastIndexOf("]");
  if (end > start) {
    try {
      const parsed = JSON.parse(text.substring(start, end + 1));
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return repairTruncatedArray(text, start);
    }
  }
  // No closing "]" — the response was TRUNCATED (reasoning models burn the
  // completion budget on <think>). Salvage the complete elements.
  return repairTruncatedArray(text, start);
}

/** Salvage complete elements from a truncated JSON array: cut at the last
 *  top-level "}", drop a dangling partial object/comma, close the array. */
function repairTruncatedArray(text: string, start: number): Array<Record<string, unknown>> {
  let body = text.substring(start);
  const lastClose = body.lastIndexOf("}");
  if (lastClose === -1) return [];
  body = body.substring(0, lastClose + 1).replace(/,\s*$/, "") + "]";
  try {
    const parsed = JSON.parse(body);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
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
  if (!scan) return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  if (!settings?.llmBaseUrl) {
    return NextResponse.json(
      { error: "LLM endpoint not configured. Set the Endpoint URL in Settings. (API key is optional for local LLM servers like Ollama.)" },
      { status: 400 },
    );
  }

  // Load the collected JS list.
  const jsPath = path.join(process.cwd(), "scan-output", id, "javascripts.json");
  let jsFiles: JsEntry[] = [];
  try {
    jsFiles = JSON.parse(await fs.readFile(jsPath, "utf-8"));
    if (!Array.isArray(jsFiles)) jsFiles = [];
  } catch {
    return NextResponse.json(
      { error: "No javascripts.json — run a scan first (the crawl phase collects JS files)." },
      { status: 400 },
    );
  }

  // Analyze ALL JS files — same-origin AND external/CDN. External scripts
  // (saved to js_source/ by the sitemap sweep) can carry supply-chain risk
  // (compromised/tampered CDN files, malicious third-party code), so they're
  // included in the security pass, not just the version inventory.
  // NO cap: results are written to disk after EVERY file (the UI polls +
  // shows N/M progress) and a re-run skips already-analyzed files, so a large
  // file list is just time — not lost work.
  const toAnalyze = jsFiles;
  if (toAnalyze.length === 0) {
    return NextResponse.json({
      findings: [],
      js_analyzed: 0,
      llm_error: "No JS files collected — run a scan first.",
    });
  }
  const sameOrigin = jsFiles.filter((j) => !j.external);

  // --- Resume: keep findings + skip files already analyzed in a previous
  // (possibly interrupted) run. ---
  const resultPath = path.join(
    process.cwd(), "scan-output", id, "javascripts_ai_results.json",
  );
  const findings: Array<Record<string, unknown>> = [];
  const doneUrls = new Set<string>();
  let llmErrorNote: string | null = null;
  try {
    const saved = JSON.parse(await fs.readFile(resultPath, "utf-8"));
    if (Array.isArray(saved.findings)) findings.push(...saved.findings);
    if (Array.isArray(saved.done)) {
      for (const u of saved.done) doneUrls.add(String(u));
    }
    if (typeof saved.llm_error === "string") llmErrorNote = saved.llm_error;
  } catch {
    // No saved results — fresh run.
  }

  const perFileErrors: string[] = [];
  let analyzed = 0;

  // Incremental persist: write after EVERY file so the UI can poll progress
  // and an interrupted run resumes where it stopped.
  const persist = async (running: boolean, analyzedCount: number, errorNote: string | null) => {
    const result = {
      findings,
      js_analyzed: analyzedCount,
      js_total: jsFiles.length,
      same_origin: sameOrigin.length,
      done: Array.from(doneUrls),
      progress: { done: doneUrls.size, total: toAnalyze.length, running },
      llm_error: errorNote,
      saved_at: new Date().toISOString(),
    };
    try {
      await fs.writeFile(resultPath, JSON.stringify(result, null, 2), "utf-8");
    } catch {
      /* non-fatal — results still returned in the response */
    }
    return result;
  };

  // Parse the scan's custom headers once (CSRF tokens / Authorization / auth
  // cookies) so protected static JS resources can be retrieved. The target
  // fetch below accepts self-signed certs (pentest targets commonly use them)
  // — the global Node fetch does NOT, which is why this uses fetchTargetText.
  const targetHeaders = parseCustomHeaders(scan.customHeaders);

  for (const js of toAnalyze) {
    if (doneUrls.has(js.url)) continue; // resume: already analyzed
    // Prefer the JS source saved DURING the scan (by the authenticated
    // browser context — carries the session cookies). Re-fetching from Node
    // now would lack the cookies and 403 on auth-required JS. Only fall back
    // to the target-fetch (self-signed certs + custom headers) if no saved
    // copy exists.
    let code = "";
    const localPath = js.local_source
      ? path.join(process.cwd(), "scan-output", id, js.local_source)
      : null;
    if (localPath) {
      try {
        code = await fs.readFile(localPath, "utf-8");
      } catch {
        code = "";  // saved copy missing — fall through to fetch
      }
    }
    if (!code) {
      try {
        const r = await fetchTargetText(js.url, { headers: targetHeaders, timeoutMs: 15000 });
        if (!r.ok) {
          perFileErrors.push(`${js.url}: ${r.status ? `HTTP ${r.status}` : r.text}`);
          // NOT added to doneUrls: a failed fetch is often transient (no
          // saved source yet, auth redirect). Marking it done permanently
          // blanked the feature after one bad run — leave it retryable so
          // the next click re-attempts it.
          await persist(true, analyzed, llmErrorNote);
          continue;
        }
        code = r.text;
      } catch (e) {
        perFileErrors.push(`${js.url}: ${e instanceof Error ? e.message : String(e)}`);
        // Same as above — retry on the next click, don't poison the resume set.
        await persist(true, analyzed, llmErrorNote);
        continue;
      }
    }
    if (!code || code.length < 20) {
      doneUrls.add(js.url); // trivial file — counts as handled
      await persist(true, analyzed, llmErrorNote);
      continue;
    }
    analyzed++;

    // One LLM call per file (small request — fits any context window).
    try {
      const controller = new AbortController();
      const to = setTimeout(() => controller.abort(), getLlmTimeoutMs());
      const llmResp = await fetch(settings.llmBaseUrl!, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(settings.llmApiKey ? { Authorization: `Bearer ${settings.llmApiKey}` } : {}),
        },
        body: JSON.stringify({
          model: settings.llmModel || "gpt-4o-mini",
          messages: [
            { role: "system", content: "You are a web security reviewer. You output only JSON arrays." },
            { role: "user", content: SUSPICIOUS_PROMPT(js.url, code.slice(0, 4000)) },
          ],
          // Reasoning models burn much of the completion budget on <think> —
          // 1024 truncated the JSON array mid-stream. Honor the Settings
          // value, clamped to a sane per-file range (default 2048).
          max_tokens: clampGenTokens(effectiveLlmMaxTokens(settings.llmMaxTokens), 1024, 4096, 2048),
          temperature: 0.1,
        }),
        signal: controller.signal,
      });
      clearTimeout(to);
      if (!llmResp.ok) {
        const t = await llmResp.text().catch(() => "");
        perFileErrors.push(`${js.url}: LLM HTTP ${llmResp.status} ${t.slice(0, 100)}`);
        continue;
      }
      const data = await llmResp.json();
      const rawReply =
        data?.choices?.[0]?.message?.content || data?.choices?.[0]?.text || "";
      for (const issue of parseJsonArray(rawReply)) {
        findings.push({
          js_url: js.url,
          filename: js.filename || js.url,
          severity: String(issue.severity || "Medium"),
          category: String(issue.category || "Suspicious JS"),
          snippet: String(issue.snippet || "").slice(0, 500),
          explanation: String(issue.explanation || ""),
        });
      }
    } catch (e) {
      perFileErrors.push(`${js.url}: ${e instanceof Error ? e.message : String(e)}`);
    }
    // Mark done + incremental write after every file (resume + live UI).
    doneUrls.add(js.url);
    await persist(true, analyzed, llmErrorNote);
  }

  const finalError = perFileErrors.length
    ? `${perFileErrors.length} file(s) had errors. First: ${perFileErrors[0]}`
    : null;
  const result = await persist(false, analyzed, finalError);
  return NextResponse.json(result);
}

/** GET: return saved AI results so they reload without re-clicking. */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  try {
    const content = await fs.readFile(
      path.join(process.cwd(), "scan-output", id, "javascripts_ai_results.json"),
      "utf-8",
    );
    return NextResponse.json(JSON.parse(content));
  } catch {
    return NextResponse.json(
      { error: "No saved JS analysis. Click 'Analyze JS with AI' to generate." },
      { status: 404 },
    );
  }
}
