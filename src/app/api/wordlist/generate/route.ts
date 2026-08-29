import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { callLlmLineList, clampGenTokens, effectiveLlmMaxTokens } from "@/lib/scanner-paths";
import fs from "fs/promises";
import path from "path";

/**
 * POST /api/wordlist/generate
 *
 * AI Wordlist Generator.
 *
 * Sends the detected technology stack (from a selected scan's software
 * inventory) + the current wordlist to the LLM. The LLM generates
 * additional directory/file paths tailored to the target's tech stack.
 *
 * The user reviews the generated paths, then copies the ones they want
 * into the Settings → Default Wordlist textarea.
 *
 * Request body (JSON):
 *   scanId?: string — if provided, sends the scan's software inventory
 *   currentWordlist?: string — the current wordlist (to avoid duplicates)
 */
export async function POST(req: NextRequest) {
  let body: { scanId?: string; currentWordlist?: string };
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

  const currentWordlist = body.currentWordlist || "";

  // --- Build context from the scan ---
  // TECH STACK (software_inventory.json) + the ACTUAL app structure
  // discovered during the crawl (crawl_map.json URL paths +
  // interesting_locations.json flagged endpoints). Without the crawl data
  // the LLM only knows "this is nginx" and emits a generic wordlist; with
  // it, the LLM can derive app-specific paths (e.g. seeing /api/guestbook
  // → suggest /api/, /api/v1/, /guestbook.bak, /api/guestbook.old).
  let techContext = "Unknown technology stack.";
  let crawlContext = "";
  if (body.scanId) {
    const scanDir = path.join(process.cwd(), "scan-output", body.scanId);
    // Tech stack (versions).
    try {
      const inventory = JSON.parse(
        await fs.readFile(path.join(scanDir, "software_inventory.json"), "utf-8"),
      );
      const items = inventory.items || [];
      if (items.length > 0) {
        techContext = `Detected technology:\n` +
          items.map((i: any) => `${i.product} ${i.version} (${i.category})`).join("\n");
      }
    } catch {
      // No inventory — leave techContext generic.
    }
    // Crawl results → the app's real URL structure.
    try {
      const crawlMap = JSON.parse(
        await fs.readFile(path.join(scanDir, "crawl_map.json"), "utf-8"),
      );
      if (Array.isArray(crawlMap)) {
        // Reduce URLs to path stems (strip query) and dedupe. Cap to keep
        // the prompt within the token budget.
        const stems = new Set<string>();
        for (const c of crawlMap) {
          if (!c || typeof c.url !== "string") continue;
          try {
            const u = new URL(c.url);
            stems.add(u.pathname);
          } catch {
            /* skip malformed */
          }
          if (stems.size >= 60) break;
        }
        if (stems.size > 0) {
          crawlContext += `\nDiscovered URL paths (the app's real structure — derive NEW paths from these, e.g. parent dirs, .bak/.old/.zip variants, versioned siblings):\n  ` +
            Array.from(stems).join("\n  ");
        }
      }
    } catch {
      // No crawl_map — skip.
    }
    // Interesting locations → flagged admin/API/config endpoints.
    try {
      const il = JSON.parse(
        await fs.readFile(path.join(scanDir, "interesting_locations.json"), "utf-8"),
      );
      const hints: string[] = [];
      for (const key of ["url_findings", "param_findings", "header_findings"]) {
        for (const f of (il[key] || [])) {
          if (f && f.where) hints.push(String(f.where));
          if (hints.length >= 20) break;
        }
      }
      if (hints.length > 0) {
        crawlContext += `\nHeuristically interesting endpoints/params:\n  ` + hints.join("\n  ");
      }
    } catch {
      // No interesting_locations — skip.
    }
  }

  const prompt = `You are an expert penetration tester planning directory brute-forcing. Generate a list of directory and file paths to probe on a web server.

Context about the target:
${techContext}${crawlContext}

Current wordlist already in use (DO NOT duplicate these):
${currentWordlist || "(none)"}

Generate 20-40 NEW paths that are NOT in the current list. Focus on:
1. PATHS DERIVED FROM THE DISCOVERED URL STRUCTURE (if provided above): parent directories of known paths, versioned siblings (/v1/, /v2/), backup variants of known files (.bak, .old, .swp, .zip, .sql, ~), index files in known dirs.
2. Paths specific to the detected technology stack (e.g. WordPress → /wp-content/uploads/, Tomcat → /manager/text, Django → /admin/auth/).
3. Common config/backup paths (.env, config.php.bak, web.config.old, dump.sql).
4. API documentation paths (/swagger, /api-docs, /openapi.json, /graphql).
5. Version control and CI/CD paths (.git/config, .svn, .hg, .gitlab-ci.yml, Jenkinsfile).
6. Cloud/metadata paths (/_aws/, /.well-known/).
7. Framework-specific debug/actuator paths (/actuator, /debug, /__debug__).

CRITICAL CONSTRAINT: Generate ONLY safe, non-destructive paths. These are READ-ONLY probes — do not include paths that would trigger destructive actions (no /admin/delete, /api/drop, etc.).

Output format: ONE path per line. Do NOT include comments, explanations, or markdown. Just the raw paths, one per line. Do NOT number them. Do NOT add any text before or after the list.

Example output:
wp-content/uploads/
wp-content/plugins/
.env.bak
config.old
api/swagger.json
.well-known/security.txt`;

  // Use the shared helper so this route honors the Settings "Max Tokens"
  // field (clamped per-call) and detects truncation, matching the payloads
  // generator. max_tokens is no longer hardcoded to 2048.
  const result = await callLlmLineList({
    baseUrl: settings.llmBaseUrl,
    apiKey: settings.llmApiKey,
    model: settings.llmModel || "gpt-4o-mini",
    system:
      "You are a penetration testing wordlist generator. You output ONLY raw paths, one per line. No comments, no markdown, no explanations.",
    user: prompt,
    maxTokens: clampGenTokens(effectiveLlmMaxTokens(settings.llmMaxTokens)),
  });

  if (result.error) {
    return NextResponse.json({ error: result.error }, { status: 502 });
  }

  let note: string | null = null;
  if (result.truncated) {
    note = "response was truncated at the token limit — some paths may be cut off";
  } else if (result.items.length === 0) {
    note = "No paths generated — the model returned no usable lines. Try again or raise the Max Tokens setting.";
  }

  return NextResponse.json({
    paths: result.items,
    count: result.items.length,
    truncated: result.truncated,
    note,
  });
}
