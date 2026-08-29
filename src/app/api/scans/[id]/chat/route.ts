import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import fs from "fs/promises";
import path from "path";
import { effectiveLlmMaxTokens, findingsPath, getLlmTimeoutMs, stripThinkTags, trailPath } from "@/lib/scanner-paths";

/**
 * POST /api/scans/[id]/chat
 *
 * AI Assistant chat endpoint. The pentester sends a question about the
 * scan findings; the LLM receives the scan context (findings, headers,
 * SSL info) plus the question, and replies with analysis/suggestions.
 *
 * The LLM NEVER makes scanning decisions — it only advises. The pentester
 * remains in control of all actions.
 *
 * Request body (JSON):
 *   message: string         (the pentester's question)
 *   history?: Array<{role, content}>  (previous chat messages for context)
 *
 * Response: 200 with { reply: string } or 400/500 on error.
 */
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;

  // Load the scan + settings.
  const [scan, settings] = await Promise.all([
    db.scan.findUnique({ where: { id } }),
    db.setting.findUnique({ where: { id: "default" } }),
  ]);
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }
  if (!settings?.llmBaseUrl) {
    return NextResponse.json(
      {
        error:
          "LLM endpoint not configured. Set the Endpoint URL in Settings. (API key is optional for local LLM servers like Ollama.)",
      },
      { status: 400 },
    );
  }

  // Parse the request body.
  let body: { message?: string; history?: Array<{ role: string; content: string }> };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }
  const userMessage = String(body.message || "").trim();
  if (!userMessage) {
    return NextResponse.json({ error: "message is required" }, { status: 400 });
  }

  // Build the scan context (findings + headers + SSL info from the trail).
  // We read the execution_trail.jsonl and extract key events to give the
  // LLM a structured picture of what the scan found.
  const scanContext = await buildScanContext(id, scan.targetUrl);

  // Build the chat messages for the LLM.
  // System prompt: sets the LLM's role as a security assistant.
  // We explicitly tell it NOT to make decisions — only advise.
  const systemPrompt = `You are a web security assistant for a pentester. The pentester has run an automated scan and is asking you questions about the results.

IMPORTANT RULES:
1. You are an ADVISOR only. You cannot run tools, cannot modify the scan, cannot make decisions. You can only ANALYZE and SUGGEST.
2. All findings from the scanner are UNVERIFIED. Always remind the pentester that manual verification is required.
3. Be concise and technical. The pentester is an expert — don't over-explain basics.
4. If the pentester asks you to suggest payloads, provide them as a JSON array of strings when appropriate.
5. If you don't know something, say so. Do not fabricate findings or responses.
6. Never claim a finding is confirmed. Always use language like "potential", "likely", "requires manual verification".

SCAN CONTEXT:
${scanContext}`;

  const messages: Array<{ role: string; content: string }> = [
    { role: "system", content: systemPrompt },
    // Include chat history (previous Q&A) for multi-turn conversation.
    ...(body.history || []).filter(
      (m) => m.role === "user" || m.role === "assistant",
    ),
    { role: "user", content: userMessage },
  ];

  // Call the LLM endpoint (OpenAI-compatible chat completions).
  const llmPayload = {
    model: settings.llmModel || "gpt-4o-mini",
    messages,
    max_tokens: Math.min(2048, effectiveLlmMaxTokens(settings.llmMaxTokens)),
    temperature: 0.3, // low temperature for factual analysis
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

    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      return NextResponse.json(
        {
          error: `LLM endpoint returned HTTP ${resp.status}: ${text.slice(0, 300)}`,
        },
        { status: 502 },
      );
    }

    const data = await resp.json();
    const rawReply =
      data?.choices?.[0]?.message?.content ||
      data?.choices?.[0]?.text ||
      "(LLM returned an empty response)";

    // Strip <think> tags from reasoning models (DeepSeek-R1, o1, etc.)
    const reply = stripThinkTags(rawReply);

    return NextResponse.json({ reply });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return NextResponse.json(
      { error: `LLM request failed: ${msg}` },
      { status: 502 },
    );
  }
}

/**
 * Build a text summary of the scan's findings for the LLM context.
 *
 * We read from MULTIPLE sources to give the LLM a complete picture:
 *   1. DB scan row (summary stats: status, finding counts, URLs crawled)
 *   2. findings.json (full finding details: title, severity, URL, payload,
 *      patterns_matched, request/response snippets)
 *   3. headers_comparison.json (missing headers + mismatches)
 *   4. llm_analysis.json (LLM vulnerability analysis results, if available)
 *   5. interesting_locations.json (interesting URLs + source code findings)
 *   6. execution_trail.jsonl (passive findings: cookies, SSL, mixed content)
 *
 * We truncate the context to fit within the LLM's token budget (rough
 * estimate: 4 chars per token, cap at ~12000 chars = ~3000 tokens).
 */
async function buildScanContext(scanId: string, targetUrl: string): Promise<string> {
  const outputDir = path.join(process.cwd(), "scan-output", scanId);
  const lines: string[] = [
    `Target: ${targetUrl}`,
    `Scan ID: ${scanId}`,
  ];

  // --- 1. DB scan summary ---
  const scan = await db.scan.findUnique({ where: { id: scanId } });
  if (scan) {
    if (scan.title) lines.push(`Title: ${scan.title}`);
    lines.push(`Status: ${scan.status}`);
    lines.push(`Findings: ${scan.findingsCount} total (${scan.findingsHigh} High, ${scan.findingsMedium} Medium, ${scan.findingsLow} Low)`);
    lines.push(`URLs Crawled: ${scan.urlsCrawled}`);
    lines.push(`Inputs Discovered: ${scan.inputsDiscovered}`);
    if (scan.interrupted) lines.push("Scan was interrupted (partial data).");
    if (scan.loginUrl) lines.push(`Login URL: ${scan.loginUrl} (user: ${scan.loginUser})`);
  }

  // --- 2. findings.json (full finding details) ---
  try {
    const content = await fs.readFile(findingsPath(scanId), "utf-8");
    const findings = JSON.parse(content);
    if (Array.isArray(findings) && findings.length > 0) {
      lines.push(`\n--- DETAILED FINDINGS (${findings.length} total) ---`);
      // Include all findings (truncate each to save token budget)
      for (const f of findings) {
        const patterns = f.patterns_matched ? f.patterns_matched.join(", ") : "";
        lines.push(
          `  [${f.severity || "?"}] ${f.title || "Untitled"} | ${f.owasp_category || "?"} | url=${f.url || ""} | input=${f.payload ? f.payload.slice(0, 80) : ""} | patterns=${patterns}`,
        );
      }
    }
  } catch {
    // No findings.json yet
  }

  // --- 3. headers_comparison.json (missing + mismatched headers) ---
  try {
    const headersPath = path.join(outputDir, "headers_comparison.json");
    const content = await fs.readFile(headersPath, "utf-8");
    const headers = JSON.parse(content);
    if (Array.isArray(headers) && headers.length > 0) {
      // Missing headers (in whitelist but not in response)
      const inRef = headers.filter((h: any) => h.in_reference);
      const missing = inRef.filter((h: any) => !h.value);
      const mismatches = inRef.filter((h: any) => h.value && !h.value_matches_expected);
      if (missing.length > 0 || mismatches.length > 0) {
        lines.push("\n--- SECURITY HEADERS ---");
        if (missing.length > 0) {
          lines.push("Missing headers:");
          for (const h of missing.slice(0, 15)) {
            lines.push(`  - ${h.name} (expected: ${h.expected_value || "any"})`);
          }
        }
        if (mismatches.length > 0) {
          lines.push("Value mismatches:");
          for (const h of mismatches.slice(0, 10)) {
            lines.push(`  - ${h.name}: got "${(h.value || "").slice(0, 60)}" expected "${h.expected_value}"`);
          }
        }
      }
    }
  } catch {
    // No headers file
  }

  // --- 4. llm_analysis.json (LLM vulnerability analysis) ---
  try {
    const analysisPath = path.join(outputDir, "llm_analysis.json");
    const content = await fs.readFile(analysisPath, "utf-8");
    const analysis = JSON.parse(content);
    if (analysis && !analysis.llm_error) {
      lines.push("\n--- LLM VULNERABILITY ANALYSIS ---");
      if (analysis.summary) {
        lines.push(`Summary: ${analysis.summary.slice(0, 500)}`);
      }
      if (analysis.llm_detected_vulns && analysis.llm_detected_vulns.length > 0) {
        lines.push("LLM-detected vulnerabilities:");
        for (const v of analysis.llm_detected_vulns.slice(0, 10)) {
          lines.push(`  - [${v.severity || "?"}] ${v.title} (${v.owasp_category || "?"}) — ${v.reasoning || ""}`.slice(0, 200));
        }
      }
      if (analysis.false_positive_candidates && analysis.false_positive_candidates.length > 0) {
        lines.push(`False positive candidates: ${analysis.false_positive_candidates.length}`);
      }
    }
  } catch {
    // No LLM analysis file
  }

  // --- 5. interesting_locations.json ---
  try {
    const ilPath = path.join(outputDir, "interesting_locations.json");
    const content = await fs.readFile(ilPath, "utf-8");
    const il = JSON.parse(content);
    if (il) {
      const urlFindings = il.url_findings || [];
      const paramFindings = il.param_findings || [];
      const headerFindings = il.header_findings || [];
      if (urlFindings.length > 0 || paramFindings.length > 0 || headerFindings.length > 0) {
        lines.push("\n--- INTERESTING LOCATIONS ---");
        if (urlFindings.length > 0) {
          lines.push(`Interesting URLs (${urlFindings.length}):`);
          for (const u of urlFindings.slice(0, 10)) {
            lines.push(`  - ${u.url || u.path || "?"} — ${u.reason || u.category || ""}`.slice(0, 150));
          }
        }
        if (paramFindings.length > 0) {
          lines.push(`Interesting parameters (${paramFindings.length}):`);
          for (const p of paramFindings.slice(0, 10)) {
            lines.push(`  - ${p.name || "?"} on ${p.url || "?"} — ${p.reason || ""}`.slice(0, 150));
          }
        }
      }
    }
  } catch {
    // No interesting locations file
  }

  // --- 6. Trail (passive findings: cookies, SSL, mixed content) ---
  try {
    const trailContent = await fs.readFile(trailPath(scanId), "utf-8");
    const entries = trailContent
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean);

    // Extract missing headers from trail (passive scan)
    const missingHeaders = entries
      .filter((e: any) => e.action === "passive_missing_header")
      .map((e: any) => e.result);
    if (missingHeaders.length > 0) {
      // Only add if not already covered by headers_comparison.json
      if (!lines.some(l => l.includes("Missing headers:"))) {
        lines.push("\n--- MISSING SECURITY HEADERS ---");
        for (const h of missingHeaders) lines.push(`  - ${h}`);
      }
    }

    // Extract SSL issues
    const sslEntry = entries.find((e: any) => e.action === "ssl_inspect" && e.result);
    if (sslEntry) {
      lines.push("\n--- SSL/TLS INSPECTION ---");
      lines.push(`  ${sslEntry.result}`);
    }

    // Extract cookie issues
    const cookieIssues = entries.filter((e: any) => e.action === "passive_cookie_issue");
    if (cookieIssues.length > 0) {
      lines.push("\n--- COOKIE ISSUES ---");
      for (const c of cookieIssues.slice(0, 10)) {
        lines.push(`  ${c.result}`);
      }
    }

    // Extract directory brute-force findings
    const dirFindings = entries.filter((e: any) => e.action === "directory_bruteforce_done");
    if (dirFindings.length > 0) {
      lines.push(`\n--- DIRECTORY BRUTE-FORCE ---`);
      lines.push(`  ${dirFindings[dirFindings.length - 1].result}`);
    }
  } catch {
    // No trail file
  }

  // Truncate to ~12000 chars to stay within token budget
  let result = lines.join("\n");
  if (result.length > 12000) {
    result = result.slice(0, 11700) + "\n...[truncated — see full scan output for more details]";
  }
  return result;
}
