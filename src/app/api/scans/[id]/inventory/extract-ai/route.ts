import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { clampGenTokens, effectiveLlmMaxTokens, getLlmTimeoutMs, stripThinkTags } from "@/lib/scanner-paths";
import fs from "fs/promises";
import path from "path";

// ============================================================================
// Per-source LLM helpers
// ============================================================================
// The original implementation concatenated EVERY crawled source into one
// giant prompt, which overflowed small-context models (HTTP 400 "request
// exceeds context size"). These helpers send ONE source at a time — each
// request stays small regardless of how many pages were crawled, exactly
// like the AI-confidence flow processes findings one-by-one.

interface LlmSettings {
  llmBaseUrl: string | null;
  llmApiKey: string | null;
  llmModel: string | null;
  llmMaxTokens: number | null;
}
interface LlmProductItem {
  product: string;
  version: string;
  source: string;
  source_url?: string;
  category: string;
  evidence: string;
  advisory: string;
}

/** Parse a JSON array of {product,version,source_file} out of an LLM reply.
 *  Tolerates markdown fences, <think> tags, and truncated JSON. Returns [] on
 *  any failure (caller treats empty as "LLM found nothing in this source"). */
function parseLlmProductArray(rawReply: string): Array<Record<string, unknown>> {
  const cleaned = stripThinkTags(rawReply).trim();
  let text = cleaned;
  if (text.startsWith("```")) {
    const lines = text.split("\n");
    if (lines[0].startsWith("```")) lines.shift();
    if (lines.length > 0 && lines[lines.length - 1].trim() === "```") lines.pop();
    text = lines.join("\n");
  }
  const start = text.indexOf("[");
  const end = text.lastIndexOf("]");
  let jsonStr = "";
  if (start !== -1 && end !== -1 && end > start) {
    jsonStr = text.substring(start, end + 1);
  } else if (start !== -1) {
    // Truncated array — repair by closing it.
    let truncated = text.substring(start);
    truncated = truncated.replace(/,\s*"[^"]*"[^,}]*$/, "");
    truncated = truncated.replace(/,\s*$/, "");
    truncated = truncated.replace(/,\s*\{[^}]*$/, "");
    truncated = truncated.replace(/\{[^}]*$/, "");
    truncated += "]";
    jsonStr = truncated;
  }
  if (!jsonStr) return [];
  try {
    const parsed = JSON.parse(jsonStr);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/** Send ONE source file to the LLM and return the products it identifies.
 *  Never throws — returns {items: [], error} on any failure so the caller can
 *  continue with the next source. Per-source content is capped to keep every
 *  request well under any reasonable context window. */
async function extractProductsFromSource(
  settings: LlmSettings,
  sourceUrl: string,
  content: string,
): Promise<{ items: LlmProductItem[]; error?: string }> {
  // Cap per source (≈1000–1500 tokens) so even a 4k-context model is fine.
  const cappedContent = content.slice(0, 4000);
  const prompt = `You are a software fingerprinting assistant. Review this ONE source file and list every software library, framework, or server technology you find, including the exact version number if present (even if hidden in a minified JS header or a CSS comment).

Format the output as a JSON array of objects with 'product', 'version', and 'source_file'. If the version is not found, use "unknown". If you find nothing, return [].

Example: [{"product": "jQuery", "version": "3.6.0", "source_file": "${sourceUrl}"}]

SOURCE URL: ${sourceUrl}
SOURCE CODE:
${cappedContent}

Respond with ONLY the JSON array, no markdown fences, no preamble.`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), getLlmTimeoutMs());
  try {
    const resp = await fetch(settings.llmBaseUrl!, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(settings.llmApiKey ? { Authorization: `Bearer ${settings.llmApiKey}` } : {}),
      },
      body: JSON.stringify({
        model: settings.llmModel || "gpt-4o-mini",
        messages: [
          {
            role: "system",
            content:
              "You are a software fingerprinting assistant. You output only JSON arrays.",
          },
          { role: "user", content: prompt },
        ],
        max_tokens: clampGenTokens(effectiveLlmMaxTokens(settings.llmMaxTokens), 1024, 4096, 2048),
        temperature: 0.1,
      }),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      return { items: [], error: `HTTP ${resp.status}: ${text.slice(0, 150)}` };
    }
    const data = await resp.json();
    const rawReply =
      data?.choices?.[0]?.message?.content || data?.choices?.[0]?.text || "";
    const parsed = parseLlmProductArray(rawReply);
    const advisory = (p: string, v: string) =>
      `Detected ${p} ${v}. Please manually verify this version against the NVD / vendor CVE database for known vulnerabilities and end-of-life status.`;
    const items: LlmProductItem[] = parsed
      .filter((it) => it && (it as Record<string, unknown>).product)
      .map((it) => {
        const r = it as Record<string, unknown>;
        const product = String(r.product);
        const version = String(r.version || "unknown");
        const sf = String(r.source_file || sourceUrl);
        return {
          product,
          version,
          source: `LLM (source: ${sf})`,
          source_url: sf,
          category: "LLM Detected",
          evidence: `LLM identified: ${product} ${version}`,
          advisory: advisory(product, version),
        };
      });
    return { items };
  } catch (e) {
    clearTimeout(timeout);
    return {
      items: [],
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

/**
 * POST /api/scans/[id]/inventory/extract-ai
 *
 * LLM-Assisted Deep Version Extraction.
 *
 * Sends the collected raw HTML/JS/CSS source files (already saved to disk
 * during the scan — no new network requests) to the configured LLM with a
 * prompt asking it to extract every software library, framework, or server
 * technology + version number.
 *
 * The LLM's response (a JSON array of {product, version, source_file}) is
 * merged with the regex-extracted inventory (from software_inventory.json),
 * deduplicating by product name.
 *
 * If the LLM fails or is unreachable, returns the regex-only results without
 * error (graceful degradation).
 */
export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;

  // Load scan + settings.
  const [scan, settings] = await Promise.all([
    db.scan.findUnique({ where: { id } }),
    db.setting.findUnique({ where: { id: "default" } }),
  ]);
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }
  if (!settings?.llmBaseUrl) {
    return NextResponse.json(
      { error: "LLM endpoint not configured. Set the Endpoint URL in Settings. (API key is optional for local LLM servers like Ollama.)" },
      { status: 400 },
    );
  }

  // --- 1. Load the existing regex-extracted inventory ---
  const inventoryPath = path.join(
    process.cwd(), "scan-output", id, "software_inventory.json",
  );
  let regexItems: Array<{
    product: string;
    version: string;
    category: string;
    source: string;
    evidence: string;
    advisory: string;
  }> = [];
  try {
    const content = await fs.readFile(inventoryPath, "utf-8");
    const data = JSON.parse(content);
    regexItems = data.items || [];
  } catch {
    // No inventory file — that's OK, we'll just return LLM results.
  }

  // --- 2. Load the raw sources (all saved on disk during the scan) ---
  // a) page_sources.json (dict url→HTML; includes dir-brute pages when the
  //    re-crawl appended them). b) The authenticated-captured JS sources from
  //    js_source/ (via javascripts.json local_source) — version fingerprints
  //    often live in JS headers. Fallback: headers_raw.json.
  const sources: Array<{ url: string; content: string }> = [];
  const seenSourceUrls = new Set<string>();
  const addSource = (url: string, content: string) => {
    if (!url || seenSourceUrls.has(url)) return;
    if (typeof content !== "string" || content.length <= 50) return;
    seenSourceUrls.add(url);
    sources.push({ url, content: content.slice(0, 5000) });
  };

  try {
    const pageSourcesPath = path.join(
      process.cwd(), "scan-output", id, "page_sources.json",
    );
    const content = await fs.readFile(pageSourcesPath, "utf-8");
    const pageSources = JSON.parse(content);
    for (const [url, html] of Object.entries(pageSources)) {
      addSource(url, html as string);
    }
  } catch {
    // No page_sources.json — fall back to headers_raw.json below.
  }

  // Saved JS sources (authenticated-captured during the scan).
  try {
    const jsPath = path.join(
      process.cwd(), "scan-output", id, "javascripts.json",
    );
    const jsFiles: Array<{ url?: string; external?: boolean; local_source?: string }> =
      JSON.parse(await fs.readFile(jsPath, "utf-8"));
    for (const jf of jsFiles) {
      if (!jf || jf.external || !jf.local_source || !jf.url) continue;
      try {
        const jsContent = await fs.readFile(
          path.join(process.cwd(), "scan-output", id, jf.local_source),
          "utf-8",
        );
        addSource(jf.url, jsContent);
      } catch {
        // Saved copy missing — skip.
      }
    }
  } catch {
    // No javascripts.json — skip.
  }

  // Fallback (older scans without page_sources.json).
  if (sources.length === 0) {
    try {
      const headersRawPath = path.join(
        process.cwd(), "scan-output", id, "headers_raw.json",
      );
      const content = await fs.readFile(headersRawPath, "utf-8");
      const entries = JSON.parse(content);
      for (const entry of entries) {
        addSource(entry.url, entry.body);
      }
    } catch {
      // No headers_raw.json either — sources stays empty.
    }
  }

  if (sources.length === 0) {
    return NextResponse.json(
      { error: "No source files found to analyze. The scan may not have captured any HTML." },
      { status: 400 },
    );
  }

  // --- 3. Call the LLM, ONE source at a time (progressive + resumable) ---
  // NO source cap: results are written to disk after EVERY source (the UI
  // polls + shows N/M progress) and a re-run skips already-done sources, so
  // a large source list is just time — not lost work. A failure on one
  // source doesn't abort the rest.
  const outputPath = path.join(
    process.cwd(), "scan-output", id, "inventory_ai_results.json",
  );
  let llmItems: Array<{
    product: string;
    version: string;
    source: string;
    category: string;
    evidence: string;
    advisory: string;
  }> = [];
  const doneUrls = new Set<string>();
  let llmError: string | null = null;
  try {
    const saved = JSON.parse(await fs.readFile(outputPath, "utf-8"));
    if (Array.isArray(saved.llm_items)) llmItems = saved.llm_items;
    if (Array.isArray(saved.done)) {
      for (const u of saved.done) doneUrls.add(String(u));
    }
    if (typeof saved.llm_error === "string") llmError = saved.llm_error;
  } catch {
    // No saved results — fresh run.
  }

  const pending = sources.filter((s) => !doneUrls.has(s.url));
  const total = sources.length;
  const perSourceErrors: string[] = [];

  // Merge + persist helper — rebuilds the merged view (regex + LLM, deduped
  // by product+version) and writes the file atomically-enough for polling.
  const persist = async (running: boolean) => {
    const merged = mergeItems(regexItems, llmItems);
    try {
      await fs.writeFile(
        outputPath,
        JSON.stringify({
          items: regexItems,
          llm_items: llmItems,
          merged,
          done: Array.from(doneUrls),
          progress: { done: doneUrls.size, total, running },
          llm_error: llmError,
          source: "regex+llm",
          saved_at: new Date().toISOString(),
        }, null, 2),
        "utf-8",
      );
    } catch {
      // Non-fatal — results still returned in the response.
    }
    return merged;
  };

  for (const s of pending) {
    const { items, error } = await extractProductsFromSource(
      settings as unknown as LlmSettings,
      s.url,
      s.content,
    );
    if (items.length) llmItems.push(...items);
    if (error) perSourceErrors.push(`${s.url}: ${error}`);
    doneUrls.add(s.url);
    await persist(true);
  }

  // If the LLM found nothing AND every source errored, degrade gracefully to
  // regex-only (preserving the old behaviour). If only SOME sources failed,
  // we keep whatever the LLM did find and surface the errors as a note.
  if (llmItems.length === 0 && perSourceErrors.length > 0) {
    const firstErr = perSourceErrors[0];
    const moreNote = perSourceErrors.length > 1
      ? ` (+${perSourceErrors.length - 1} more)`
      : "";
    llmError = `LLM extraction failed for all sources. First error: ${firstErr}${moreNote}`;
    const merged = await persist(false);
    return NextResponse.json({
      items: regexItems,
      llm_items: [],
      merged,
      done: Array.from(doneUrls),
      progress: { done: doneUrls.size, total, running: false },
      llm_error: llmError,
      source: "regex_only",
    });
  }

  const merged = await persist(false);
  return NextResponse.json({
    items: regexItems,
    llm_items: llmItems,
    merged,
    done: Array.from(doneUrls),
    progress: { done: doneUrls.size, total, running: false },
    llm_error: null,
    source: "regex+llm",
  });
}

/** Merge regex + LLM items, dedup by product+version (lowercase). Same
 *  product+version from different URLs merges into one row listing all
 *  source URLs; different versions are kept as separate rows. */
function mergeItems(
  regexItems: Array<{
    product: string; version: string; category: string;
    source: string; evidence: string; advisory: string;
  }>,
  llmItems: Array<Record<string, any>>,
) {
  const merged: Array<Record<string, any>> = [...regexItems];
  const seenKeys = new Map<string, number>();
  for (let i = 0; i < regexItems.length; i++) {
    const key = `${regexItems[i].product.toLowerCase()}|${regexItems[i].version.toLowerCase()}`;
    seenKeys.set(key, i);
  }
  for (const llmItem of llmItems) {
    const key = `${String(llmItem.product).toLowerCase()}|${String(llmItem.version).toLowerCase()}`;
    const existingIdx = seenKeys.get(key);
    if (existingIdx !== undefined) {
      const existing = merged[existingIdx];
      const existingSources = existing.source_urls || [existing.source];
      const newUrl = llmItem.source_url || "";
      if (newUrl && !existingSources.includes(newUrl)) {
        existingSources.push(newUrl);
      }
      existing.source_urls = existingSources;
      existing.source = `${existingSources.length} source(s)`;
    } else {
      seenKeys.set(key, merged.length);
      llmItem.source_urls = llmItem.source_url ? [llmItem.source_url] : [];
      merged.push(llmItem);
    }
  }
  return merged;
}

/**
 * GET /api/scans/[id]/inventory/extract-ai
 *
 * Returns saved AI inventory results (if they exist) so the UI can
 * reload them without re-clicking "Extract Versions with AI".
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const outputPath = path.join(
    process.cwd(), "scan-output", id, "inventory_ai_results.json",
  );
  try {
    const content = await fs.readFile(outputPath, "utf-8");
    return NextResponse.json(JSON.parse(content));
  } catch {
    return NextResponse.json(
      { error: "No saved AI inventory results. Click 'Extract Versions with AI' to generate." },
      { status: 404 },
    );
  }
}
