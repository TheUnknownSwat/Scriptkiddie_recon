import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { clampGenTokens, effectiveLlmMaxTokens, getLlmTimeoutMs, stripThinkTags } from "@/lib/scanner-paths";
import { fetchTargetText, parseCustomHeaders } from "@/lib/target-fetch";
import fs from "fs/promises";
import path from "path";

/**
 * POST /api/scans/[id]/stylesheets/analyze-ai
 *
 * CSS twin of the JavaScripts AI pass: sends each collected stylesheet to
 * the LLM ONE FILE AT A TIME and asks it to flag security-relevant content
 * that regex scanning can't reason about:
 *  - exfil beacons (url() pointing at telemetry/collector endpoints)
 *  - secrets in comments (API keys, internal hostnames, credentials)
 *  - CSS-exfiltration selectors (input[name=password][value^=a] + url())
 *  - @import chains to unexpected hosts, data: URIs, font-src oddities
 *  - overlay/phishing styling (position:fixed full-page overlays)
 *
 * Progressive + resumable (results written to disk after EVERY file, the
 * UI polls N/M progress, a re-run skips done files). Failed fetches are
 * NOT marked done — they retry on the next click.
 *
 * Results saved to stylesheets_ai_results.json so they reload on reopen.
 */

interface LlmSettings {
  llmBaseUrl: string | null;
  llmApiKey: string | null;
  llmModel: string | null;
}
interface CssEntry {
  url: string;
  found_on?: string[];
  external?: boolean;
  filename?: string;
  local_source?: string;
}

const SUSPICIOUS_CSS_PROMPT = (url: string, code: string) =>
  `You are a web application security reviewer. Review this ONE stylesheet's source and flag any DANGEROUS or SUSPICIOUS content that could be a security issue or backdoor. Specifically look for:
- exfiltration beacons: url() references pointing at telemetry/collect/track endpoints, especially ones that fire on element states
- CSS-exfiltration selectors: attribute selectors like input[name="password"][value^="a"] combined with url() — used to steal form values character-by-character
- secrets in comments: API keys (sk-/AKIA/...), internal hostnames/IPs, credentials, tokens, TODO notes about security
- @import or src references to unexpected/external hosts (data exfil or supply-chain channels)
- data: URIs embedding unusual payloads
- overlay/phishing styling: full-page position:fixed overlays that mimic login screens
- references to hidden/internal endpoints (paths or header names leaked in comments)

For EACH issue found, output a JSON array of objects: {"severity":"High|Medium|Low","category":"short label","snippet":"the exact code line(s)","explanation":"why it's dangerous"}. If the file is clean, return [].

Stylesheet URL: ${url}
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

  // Load the collected stylesheet list.
  const cssPath = path.join(process.cwd(), "scan-output", id, "stylesheets.json");
  let cssFiles: CssEntry[] = [];
  try {
    cssFiles = JSON.parse(await fs.readFile(cssPath, "utf-8"));
    if (!Array.isArray(cssFiles)) cssFiles = [];
  } catch {
    return NextResponse.json(
      { error: "No stylesheets.json — run a scan first (the sitemap sweep collects CSS files)." },
      { status: 400 },
    );
  }

  // Analyze ALL stylesheets — same-origin AND external/CDN (a compromised
  // CDN stylesheet is a supply-chain risk). NO cap: results persist after
  // every file and a re-run resumes.
  const toAnalyze = cssFiles;
  if (toAnalyze.length === 0) {
    return NextResponse.json({
      findings: [],
      css_analyzed: 0,
      llm_error: "No CSS files collected — run a scan first.",
    });
  }
  const sameOrigin = cssFiles.filter((c) => !c.external);

  // --- Resume: keep findings + skip files already analyzed in a previous
  // (possibly interrupted) run. ---
  const resultPath = path.join(
    process.cwd(), "scan-output", id, "stylesheets_ai_results.json",
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

  const persist = async (running: boolean, analyzedCount: number, errorNote: string | null) => {
    const result = {
      findings,
      css_analyzed: analyzedCount,
      css_total: cssFiles.length,
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

  const targetHeaders = parseCustomHeaders(scan.customHeaders);

  for (const css of toAnalyze) {
    if (doneUrls.has(css.url)) continue; // resume: already analyzed
    // Prefer the copy saved DURING the scan (authenticated browser context).
    let code = "";
    const localPath = css.local_source
      ? path.join(process.cwd(), "scan-output", id, css.local_source)
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
        const r = await fetchTargetText(css.url, { headers: targetHeaders, timeoutMs: 15000 });
        if (!r.ok) {
          // NOT added to doneUrls: failed fetches are often transient —
          // they retry on the next click instead of being permanently
          // skipped (which blanked the JS pass after one bad run).
          perFileErrors.push(`${css.url}: ${r.status ? `HTTP ${r.status}` : r.text}`);
          await persist(true, analyzed, llmErrorNote);
          continue;
        }
        code = r.text;
      } catch (e) {
        perFileErrors.push(`${css.url}: ${e instanceof Error ? e.message : String(e)}`);
        await persist(true, analyzed, llmErrorNote);
        continue;
      }
    }
    if (!code || code.length < 20) {
      doneUrls.add(css.url); // trivial file — counts as handled
      await persist(true, analyzed, llmErrorNote);
      continue;
    }
    analyzed++;

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
            { role: "user", content: SUSPICIOUS_CSS_PROMPT(css.url, code.slice(0, 4000)) },
          ],
          max_tokens: clampGenTokens(effectiveLlmMaxTokens(settings.llmMaxTokens), 1024, 4096, 2048),
          temperature: 0.1,
        }),
        signal: controller.signal,
      });
      clearTimeout(to);
      if (!llmResp.ok) {
        const t = await llmResp.text().catch(() => "");
        perFileErrors.push(`${css.url}: LLM HTTP ${llmResp.status} ${t.slice(0, 100)}`);
        continue;
      }
      const data = await llmResp.json();
      const rawReply =
        data?.choices?.[0]?.message?.content || data?.choices?.[0]?.text || "";
      for (const issue of parseJsonArray(rawReply)) {
        findings.push({
          css_url: css.url,
          filename: css.filename || css.url,
          severity: String(issue.severity || "Medium"),
          category: String(issue.category || "Suspicious CSS"),
          snippet: String(issue.snippet || "").slice(0, 500),
          explanation: String(issue.explanation || ""),
        });
      }
    } catch (e) {
      perFileErrors.push(`${css.url}: ${e instanceof Error ? e.message : String(e)}`);
    }
    doneUrls.add(css.url);
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
      path.join(process.cwd(), "scan-output", id, "stylesheets_ai_results.json"),
      "utf-8",
    );
    return NextResponse.json(JSON.parse(content));
  } catch {
    return NextResponse.json(
      { error: "No saved CSS analysis. Click 'Analyze CSS with AI' to generate." },
      { status: 404 },
    );
  }
}
