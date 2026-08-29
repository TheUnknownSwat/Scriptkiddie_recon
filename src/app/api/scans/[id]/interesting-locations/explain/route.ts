import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { getLlmTimeoutMs } from "@/lib/scanner-paths";

/**
 * POST /api/scans/[id]/interesting-locations/explain
 *
 * Asks the LLM to explain a specific interesting location item. The
 * pentester clicks "Explain with AI" on a flagged URL/parameter/header,
 * and the LLM explains:
 *   - What the vulnerability class is
 *   - Why this specific item is interesting
 *   - How to test it manually
 *   - Example payloads to try
 *
 * The LLM receives the item details + scan context, returns a text
 * explanation. The LLM NEVER executes anything — it only advises.
 *
 * Request body (JSON):
 *   type: "url" | "param" | "header"
 *   item: the interesting location object (url, category, description, etc.)
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
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }
  if (!settings?.llmBaseUrl) {
    return NextResponse.json(
      { error: "LLM endpoint not configured. Set the Endpoint URL in Settings. (API key is optional for local LLM servers like Ollama.)" },
      { status: 400 },
    );
  }

  let body: { type?: string; item?: Record<string, unknown> };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const itemType = body.type || "unknown";
  const item = body.item || {};

  // Build the prompt for the LLM.
  const itemJson = JSON.stringify(item, null, 2);
  const prompt = `You are a web penetration testing instructor. A scanner has flagged the following item as "interesting" — a potential target for manual testing. Explain to the pentester WHY it's interesting and HOW to test it.

ITEM TYPE: ${itemType}
ITEM DETAILS:
${itemJson}

TARGET URL: ${scan.targetUrl}

Provide a concise explanation (3-5 short paragraphs) covering:
1. What vulnerability class this item belongs to (e.g. IDOR, open redirect, XSS, SSRF, path traversal).
2. Why this specific item was flagged (what about the URL/param/header looks interesting).
3. How to test it manually (step-by-step, with example payloads).
4. What to look for in the response to confirm a vulnerability.
5. Any caveats or false positive indicators to watch for.

Be specific and technical. The pentester is an expert. Use example payloads where appropriate. Do NOT use markdown headers — just plain text paragraphs.`;

  // Call the LLM.
  const llmPayload = {
    model: settings.llmModel || "gpt-4o-mini",
    messages: [
      {
        role: "system",
        content:
          "You are a web security instructor. Provide concise, actionable explanations for pentesters. Never claim a finding is confirmed — always use 'potential', 'likely', 'requires verification'.",
      },
      { role: "user", content: prompt },
    ],
    max_tokens: 1024,
    temperature: 0.3,
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
        { error: `LLM returned HTTP ${resp.status}: ${text.slice(0, 300)}` },
        { status: 502 },
      );
    }

    const data = await resp.json();
    const reply =
      data?.choices?.[0]?.message?.content ||
      data?.choices?.[0]?.text ||
      "(LLM returned an empty response)";

    return NextResponse.json({ explanation: reply });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return NextResponse.json(
      { error: `LLM request failed: ${msg}` },
      { status: 502 },
    );
  }
}
