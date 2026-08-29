import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { clampGenTokens, effectiveLlmMaxTokens, getLlmTimeoutMs, stripThinkTags } from "@/lib/scanner-paths";
import fs from "fs/promises";
import path from "path";

/**
 * POST /api/scans/[id]/llm-interesting
 *
 * LLM-Driven Interesting Content Analysis.
 *
 * After the scan finishes, collects raw HTML + inline JS from every
 * crawled URL (already saved to disk during the scan) and sends it
 * to the LLM. The LLM identifies:
 *   - Hardcoded credentials / API keys
 *   - Hidden API endpoints / fetch/XHR calls
 *   - Developer comments (TODO, FIXME, DEBUG, SECURITY)
 *   - Potential logic flaws
 *   - Anything else a pentester should check
 *
 * Returns a JSON array of {title, reason, suggested_test, url}.
 *
 * Truncates page content to the configured token limit (default 4000
 * tokens ≈ 16000 chars per URL).
 *
 * If the LLM is unreachable, returns an error — the UI shows
 * "LLM analysis skipped: LLM not configured."
 */
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
      { error: "LLM analysis skipped: LLM endpoint not configured. Set the Endpoint URL in Settings. (API key is optional for local LLM servers like Ollama.)" },
      { status: 400 },
    );
  }

  // Load crawl_map.json to get the list of URLs.
  const crawlMapPath = path.join(
    process.cwd(), "scan-output", id, "crawl_map.json",
  );
  let urls: string[] = [];
  try {
    const content = await fs.readFile(crawlMapPath, "utf-8");
    const crawlMap = JSON.parse(content);
    urls = crawlMap
      .filter((c: any) => c.in_scope)
      .slice(0, 20) // cap at 20 URLs to avoid too many LLM calls
      .map((c: any) => c.url);
  } catch {
    return NextResponse.json(
      { error: "Crawl map not found. Run a scan first." },
      { status: 400 },
    );
  }

  if (urls.length === 0) {
    return NextResponse.json({ findings: [], message: "No URLs to analyze." });
  }

  // Load page_sources.json — this is the primary source of HTML bodies.
  // The scanner captures raw HTML for each in-scope URL during attack
  // surface mapping and saves it to this file.
  const pageSourcesPath = path.join(
    process.cwd(), "scan-output", id, "page_sources.json",
  );
  let pageBodies: Record<string, string> = {};
  try {
    const content = await fs.readFile(pageSourcesPath, "utf-8");
    pageBodies = JSON.parse(content);
  } catch {
    // page_sources.json doesn't exist — fall back to headers_raw.json
  }

  // Also try headers_raw.json as a fallback (older scans may not have
  // page_sources.json).
  if (Object.keys(pageBodies).length === 0) {
    const headersRawPath = path.join(
      process.cwd(), "scan-output", id, "headers_raw.json",
    );
    try {
      const content = await fs.readFile(headersRawPath, "utf-8");
      const entries = JSON.parse(content);
      for (const entry of entries) {
        if (entry.url && entry.body) {
          pageBodies[entry.url] = entry.body;
        }
      }
    } catch {
      // No bodies available — we'll send URLs only.
    }
  }

  const maxTokens = settings.llmMaxTokens || 4000;
  const charBudget = maxTokens * 4; // rough estimate: 4 chars per token
  const allFindings: Array<{
    title: string;
    reason: string;
    suggested_test: string;
    url: string;
  }> = [];

  // Process each URL. We batch up to 3 URLs per LLM call to save API calls.
  const batchSize = 3;
  for (let i = 0; i < urls.length; i += batchSize) {
    const batch = urls.slice(i, i + batchSize);

    // Build the content for this batch.
    let contentBlocks = "";
    for (const url of batch) {
      let body = pageBodies[url] || "";
      if (!body) {
        // Try to fetch the page content from the evidence files.
        // The scanner saves raw HTML in headers_raw.json.
        contentBlocks += `\n=== URL: ${url} ===\n(no HTML body available)\n`;
        continue;
      }
      // Truncate to stay within token budget per URL.
      const perUrlBudget = Math.floor(charBudget / batch.length);
      if (body.length > perUrlBudget) {
        body = body.slice(0, perUrlBudget) + "\n...[truncated]";
      }
      contentBlocks += `\n=== URL: ${url} ===\n${body}\n`;
    }

    if (!contentBlocks.trim()) continue;

    const prompt = `You are a web security analyst. Review the following page source (HTML + inline JS) and identify anything that looks interesting for a pentester. This includes:

1. Hardcoded credentials or API keys.
2. Hidden API endpoints or fetch/XHR calls that aren't linked in the HTML.
3. Developer comments (TODO, FIXME, DEBUG, SECURITY).
4. Potential logic flaws based on the structure.
5. Anything else a pentester should manually check.

For each finding, provide a short title, a 1-sentence explanation of why it's interesting, and a suggested test. Output the response as JSON:

[{"title": "...", "reason": "...", "suggested_test": "...", "url": "..."}]

Use the URL from the "=== URL:" header to fill the "url" field. If no interesting content is found, return an empty array [].

PAGE SOURCES:
${contentBlocks}

Respond with ONLY the JSON array. No markdown, no preamble.`;

    const llmPayload = {
      model: settings.llmModel || "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content: "You are a web security analyst. You output ONLY JSON arrays.",
        },
        { role: "user", content: prompt },
      ],
      max_tokens: clampGenTokens(effectiveLlmMaxTokens(settings.llmMaxTokens), 1024, 4096, 2048),
      temperature: 0.2,
    };

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), getLlmTimeoutMs());
      const resp = await fetch(settings.llmBaseUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(settings.llmApiKey ? { Authorization: `Bearer ${settings.llmApiKey}` } : {}),
        },
        body: JSON.stringify(llmPayload),
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (!resp.ok) continue; // skip this batch on error

      const data = await resp.json();
      const rawReply =
        data?.choices?.[0]?.message?.content ||
        data?.choices?.[0]?.text ||
        "";

      // Strip <think> tags from reasoning models (DeepSeek-R1, o1, etc.)
      // before parsing JSON. Without this, the JSON parser fails because
      // the <think> block isn't valid JSON.
      const cleanedReply = stripThinkTags(rawReply);

      // Parse JSON array from response.
      let text = cleanedReply.trim();
      if (text.startsWith("```")) {
        const lines = text.split("\n");
        if (lines[0].startsWith("```")) lines.shift();
        if (lines.length > 0 && lines[lines.length - 1].trim() === "```") lines.pop();
        text = lines.join("\n");
      }
      const start = text.indexOf("[");
      const end = text.lastIndexOf("]");
      if (start !== -1 && end !== -1 && end > start) {
        const parsed = JSON.parse(text.substring(start, end + 1));
        if (Array.isArray(parsed)) {
          for (const item of parsed) {
            if (item.title) {
              allFindings.push({
                title: String(item.title),
                reason: String(item.reason || ""),
                suggested_test: String(item.suggested_test || ""),
                url: String(item.url || batch[0] || ""),
              });
            }
          }
        }
      }
    } catch {
      // Skip this batch on error — continue with the next.
    }
  }

  // Save to disk.
  const outputPath = path.join(
    process.cwd(), "scan-output", id, "llm_interesting_findings.json",
  );
  await fs.writeFile(
    outputPath,
    JSON.stringify({ findings: allFindings }, null, 2),
    "utf-8",
  );

  return NextResponse.json({ findings: allFindings });
}

/**
 * GET /api/scans/[id]/llm-interesting
 *
 * Returns saved LLM interesting findings (if they exist).
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const filePath = path.join(
    process.cwd(), "scan-output", id, "llm_interesting_findings.json",
  );
  try {
    const content = await fs.readFile(filePath, "utf-8");
    return NextResponse.json(JSON.parse(content));
  } catch {
    return NextResponse.json(
      { findings: [], error: "LLM interesting findings not found" },
      { status: 404 },
    );
  }
}
