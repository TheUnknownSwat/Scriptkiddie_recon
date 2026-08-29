import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { callLlmLineList, clampGenTokens, effectiveLlmMaxTokens, parseLlmLineList } from "@/lib/scanner-paths";

/**
 * POST /api/payloads/generate
 *
 * AI Payload Generator — HYBRID strategy.
 *
 * Phase 1: ONE tuned call (compact context, ≤ ~10 payloads). Fast.
 * Phase 2 (per-endpoint fallback): runs ONLY if Phase 1 was truncated or
 *   returned too few payloads. Loops over up to MAX_ENDPOINTS discovered
 *   form endpoints, one SMALL call per endpoint asking for a few payloads
 *   tailored to that endpoint's fields, then merges + dedupes. Each call
 *   stays well under the token cap so nothing truncates.
 *
 * This fixes the old single-call generator, which asked for 15-30 long
 * polyglot payloads in one shot, overflowed the LLM's token cap, got
 * `finish_reason: length`, parsed to ~0 lines, and returned a silent empty
 * result. The per-call budget is now clamped (see clampGenTokens) so the
 * Settings "Max Tokens" field actually controls it, and truncation is
 * detected per call.
 *
 * The LLM NEVER injects payloads — it returns a text list the user reviews.
 *
 * Response: { payloads, category, count, truncated, endpoints_analyzed, phase, note? }
 */

const PAYLOAD_SYSTEM =
  "You are a penetration testing payload generator. You output ONLY raw payloads, one per line. No comments, no markdown, no explanations.";

// Cap on the per-endpoint fallback loop. Each call against a slow local LLM
// can take ~1-2 min, so this bounds total runtime (~6 calls max in phase 2).
const MAX_ENDPOINTS = 6;

const CATEGORY_DESCRIPTIONS: Record<string, string> = {
  all: "all vulnerability types (XSS, SQLi, Path Traversal, Command Injection, Open Redirect, SSTI)",
  xss: "Cross-Site Scripting (XSS) — include WAF-bypass variants, context-specific payloads (HTML, attribute, JS, URL), and a couple of polyglots",
  sqli: "SQL Injection — UNION-based, error-based, blind/time-based; cover MySQL/PostgreSQL/MSSQL/SQLite",
  path_traversal: "Path Traversal / LFI — Linux + Windows paths, encoding bypasses, known sensitive files",
  cmdi: "Command Injection — semicolon, pipe, backtick, command substitution; Linux + Windows",
  open_redirect: "Open Redirect — protocol-relative URLs, JavaScript URIs, validator bypasses",
  ssti: "Server-Side Template Injection — Jinja2, Twig, FreeMarker, Velocity, Thymeleaf variants",
};

const SAFETY_CONSTRAINT =
  "CONSTRAINT: ONLY safe, non-destructive payloads — no DROP/DELETE/UPDATE/INSERT, no DoS (no infinite loops / fork bombs / large SLEEP), no destructive OS commands (rm -rf, shutdown), no real external domains (use example.com / evil.com).";

export async function POST(req: NextRequest) {
  let body: { scanId?: string; category?: string; currentPayloads?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const settings = await db.setting.findUnique({ where: { id: "default" } });
  if (!settings?.llmBaseUrl) {
    return NextResponse.json(
      { error: "LLM endpoint not configured. Set the Endpoint URL in Settings. (API key is optional for local LLM servers like Ollama.)" },
      { status: 400 },
    );
  }

  const category = body.category || "all";
  const categoryText = CATEGORY_DESCRIPTIONS[category] || CATEGORY_DESCRIPTIONS.all;
  const currentPayloads = body.currentPayloads || "";
  const genTokens = clampGenTokens(effectiveLlmMaxTokens(settings.llmMaxTokens));
  const model = settings.llmModel || "gpt-4o-mini";
  const baseUrl = settings.llmBaseUrl;
  const apiKey = settings.llmApiKey;

  // --- Build compact context from the scan ---
  // tech stack + input NAMES/types (grouped by endpoint for phase 2). We send
  // far less than the old route (no 40 full input records, no 40 crawl URLs) —
  // just enough for the LLM to tailor payloads without bloating the prompt.
  let techContext = "Unknown technology stack.";
  const endpointInputs: Array<{ url: string; method: string; fields: string[] }> = [];
  let inputsBlurb = "";
  if (body.scanId) {
    const fs = await import("fs/promises");
    const path = await import("path");
    const scanDir = path.join(process.cwd(), "scan-output", body.scanId);
    try {
      const inventory = JSON.parse(
        await fs.readFile(path.join(scanDir, "software_inventory.json"), "utf-8"),
      );
      const items = inventory.items || [];
      if (items.length > 0) {
        techContext =
          "Detected technology:\n" +
          items
            .slice(0, 15)
            .map((i: any) => `${i.product} ${i.version || ""} (${i.category || "?"})`.trim())
            .join("\n");
      }
    } catch {
      /* no inventory — leave generic */
    }
    try {
      const surface = JSON.parse(
        await fs.readFile(path.join(scanDir, "attack_surface.json"), "utf-8"),
      );
      if (Array.isArray(surface)) {
        const named = surface.filter((s: any) => s && s.name);
        // Group by endpoint (method + url) for the per-endpoint fallback.
        const byEndpoint = new Map<string, { url: string; method: string; fields: string[] }>();
        for (const s of named) {
          const key = `${s.method || "?"} ${s.url || "?"}`;
          let ep = byEndpoint.get(key);
          if (!ep) {
            ep = { url: s.url || "?", method: s.method || "?", fields: [] };
            byEndpoint.set(key, ep);
          }
          ep.fields.push(`${s.name}(${s.input_type || "?"})`);
        }
        // Rank endpoints by field count (rich endpoints first) for the fallback.
        endpointInputs.push(
          ...Array.from(byEndpoint.values()).sort((a, b) => b.fields.length - a.fields.length),
        );
        // Compact input blurb for the phase-1 prompt (names + types only).
        const flat = named.slice(0, 20).map((s: any) => `${s.name}(${s.input_type || "?"})`);
        if (flat.length > 0) {
          inputsBlurb =
            "\nDiscovered inputs (name(type)) — tailor payloads to these: " + flat.join(", ");
        }
      }
    } catch {
      /* no attack_surface — skip */
    }
  }

  // Seed the dedup set with the user's current payloads so nothing duplicates.
  const seen = new Set(parseLlmLineList(currentPayloads));
  const payloads: string[] = [];
  const addUnique = (items: string[]) => {
    for (const p of items) {
      if (!seen.has(p)) {
        seen.add(p);
        payloads.push(p);
      }
    }
  };

  // --- Phase 1: one tuned call (fewer payloads, compact context) ---
  const phase1Prompt = `Generate ${categoryText}.

${SAFETY_CONSTRAINT}

Target context:
${techContext}${inputsBlurb}

Generate 8-10 NEW payloads (do NOT duplicate existing ones). Prioritise: payloads tailored to the discovered inputs above; tech-stack-specific variants; WAF-bypass / encoding variants; context-specific (HTML body / attribute / JS string / URL param).

Output: ONE payload per line. Raw only — no comments, no numbering, no markdown, no text before or after.`;

  const phase1 = await callLlmLineList({
    baseUrl,
    apiKey,
    model,
    system: PAYLOAD_SYSTEM,
    user: phase1Prompt,
    maxTokens: genTokens,
  });
  addUnique(phase1.items);

  let truncated = phase1.truncated;
  let endpointsAnalyzed = 0;
  let phase: "single" | "hybrid" = "single";

  // Hard network/HTTP error on phase 1 with no context to fall back to.
  if (phase1.error && endpointInputs.length === 0) {
    return NextResponse.json({ error: phase1.error }, { status: 502 });
  }

  // --- Phase 2: per-endpoint fallback ONLY if truncated or too few results ---
  const tooFew = payloads.length < 5;
  if ((truncated || tooFew) && endpointInputs.length > 0) {
    phase = "hybrid";
    const endpoints = endpointInputs.slice(0, MAX_ENDPOINTS);
    for (const ep of endpoints) {
      const recent = payloads.slice(-15).join("  |  ") || "(none yet)";
      const epPrompt = `Target ONE endpoint on the application.
Endpoint: ${ep.method} ${ep.url}
Form fields on this endpoint: ${ep.fields.join(", ")}
Target tech: ${techContext}

Generate 3-5 ${categoryText} payloads tailored to THESE specific fields (e.g. a field named redirect/url/next → open-redirect; a search/name/title field → reflected XSS; an id/userid param → SQLi; a JSON-body field → JSON-structured). Do NOT duplicate these already-generated payloads: ${recent}

${SAFETY_CONSTRAINT}

Output: ONE payload per line. Raw only — no comments, no numbering, no markdown.`;
      const r = await callLlmLineList({
        baseUrl,
        apiKey,
        model,
        system: PAYLOAD_SYSTEM,
        user: epPrompt,
        maxTokens: genTokens,
      });
      endpointsAnalyzed++;
      addUnique(r.items);
      if (r.truncated) truncated = true;
    }
  }

  // --- Build a user-facing note ---
  const noteParts: string[] = [];
  if (phase === "hybrid") {
    noteParts.push(
      `hybrid mode: first call ${truncated ? "was truncated" : "returned few results"}, so analyzed ${endpointsAnalyzed} endpoint(s) and merged`,
    );
  } else if (truncated) {
    noteParts.push("response was truncated at the token limit — results may be partial");
  }
  if (payloads.length === 0) {
    noteParts.push(
      "No payloads generated — the model returned no usable lines (usually a truncation/parse issue). Try a narrower category or raise the Max Tokens setting.",
    );
  }
  const note = noteParts.length > 0 ? noteParts.join(" · ") : null;

  return NextResponse.json({
    payloads,
    category,
    count: payloads.length,
    truncated,
    endpoints_analyzed: endpointsAnalyzed,
    phase,
    note,
  });
}
