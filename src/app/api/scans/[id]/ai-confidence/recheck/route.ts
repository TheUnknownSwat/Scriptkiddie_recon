import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { getLlmTimeoutMs, stripThinkTags } from "@/lib/scanner-paths";
import fs from "fs/promises";
import path from "path";

/**
 * POST /api/scans/[id]/ai-confidence/recheck
 *
 * Re-checks a SINGLE finding with the LLM. Used when the initial AI
 * confidence check failed for one finding (e.g. LLM timeout) but
 * succeeded for others.
 *
 * Body: { finding_id: string }
 *
 * Returns: { result: { finding_id, confidence, reasoning, suggested_test } }
 */
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const [scan, settings] = await Promise.all([
    db.scan.findUnique({ where: { id } }),
    db.setting.findUnique({ where: { id: "default" } }),
  ]);
  if (!scan) return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  if (!settings?.llmBaseUrl) {
    return NextResponse.json({ error: "LLM endpoint not configured. Set the Endpoint URL in Settings. (API key is optional for local LLM servers like Ollama.)" }, { status: 400 });
  }

  let body: { finding_id?: string };
  try { body = await req.json(); } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  const findingId = body.finding_id;
  if (!findingId) {
    return NextResponse.json({ error: "finding_id is required" }, { status: 400 });
  }

  // Load the finding from findings.json
  const findingsPath = path.join(process.cwd(), "scan-output", id, "findings.json");
  let findings: any[] = [];
  try {
    findings = JSON.parse(await fs.readFile(findingsPath, "utf-8"));
  } catch {
    return NextResponse.json({ error: "findings.json not found" }, { status: 400 });
  }

  const finding = findings.find(f => f.finding_id === findingId);
  if (!finding) {
    return NextResponse.json({ error: `Finding ${findingId} not found` }, { status: 404 });
  }

  // Build single-finding prompt
  const findingDigest = {
    finding_id: finding.finding_id,
    title: finding.title,
    severity: finding.severity,
    owasp_category: finding.owasp_category,
    url: finding.url,
    payload: (finding.payload || "").slice(0, 200),
    patterns_matched: finding.patterns_matched,
    request_snippet: (finding.request_raw || "").slice(0, 300),
    response_snippet: (finding.response_raw || "").slice(0, 300),
  };

  const prompt = `You are a web application security analyst. Evaluate this SINGLE finding — is it a TRUE positive (real vulnerability) or FALSE positive (benign match)?

FINDING:
${JSON.stringify(findingDigest, null, 2)}

Return ONLY this JSON (no markdown, no explanation):
{"confidence": "High|Medium|Low", "reasoning": "1-2 sentences", "suggested_test": "one concrete manual step"}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), getLlmTimeoutMs());
    const resp = await fetch(settings.llmBaseUrl, {
      method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(settings.llmApiKey ? { Authorization: `Bearer ${settings.llmApiKey}` } : {}),
        },
      body: JSON.stringify({
        model: settings.llmModel || "gpt-4o-mini",
        messages: [
          { role: "system", content: "You are a security finding evaluator. You output ONLY JSON." },
          { role: "user", content: prompt },
        ],
        max_tokens: 512,
        temperature: 0.2,
      }),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!resp.ok) {
      return NextResponse.json({ error: `LLM HTTP ${resp.status}` }, { status: 502 });
    }

    const data = await resp.json();
    const rawReply = data?.choices?.[0]?.message?.content || data?.choices?.[0]?.text || "";
    const cleaned = stripThinkTags(rawReply);

    // Parse JSON
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");
    if (start !== -1 && end !== -1 && end > start) {
      try {
        const parsed = JSON.parse(cleaned.substring(start, end + 1));
        const result = {
          finding_id: findingId,
          confidence: String(parsed.confidence || "Medium"),
          reasoning: String(parsed.reasoning || ""),
          suggested_test: String(parsed.suggested_test || ""),
        };

        // Update the saved ai_confidence.json with the new result
        const aiConfPath = path.join(process.cwd(), "scan-output", id, "ai_confidence.json");
        try {
          const existing = JSON.parse(await fs.readFile(aiConfPath, "utf-8"));
          if (existing.results) {
            const idx = existing.results.findIndex((r: any) => r.finding_id === findingId);
            if (idx !== -1) {
              existing.results[idx] = { ...existing.results[idx], ...result };
            } else {
              existing.results.push(result);
            }
            await fs.writeFile(aiConfPath, JSON.stringify(existing, null, 2), "utf-8");
          }
        } catch {
          // No existing file — just return the result
        }

        return NextResponse.json({ result });
      } catch {
        return NextResponse.json({ error: "LLM returned invalid JSON" }, { status: 502 });
      }
    }

    return NextResponse.json({ error: "LLM did not return JSON" }, { status: 502 });
  } catch (e) {
    return NextResponse.json({ error: `LLM failed: ${e instanceof Error ? e.message : String(e)}` }, { status: 502 });
  }
}
