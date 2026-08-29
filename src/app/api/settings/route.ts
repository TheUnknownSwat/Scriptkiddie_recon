import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import fs from "fs/promises";
import path from "path";
import { DEFAULT_WHITELIST_PATH, DEFAULT_PAYLOADS_PATH, DEFAULT_WORDLIST_PATH, DEFAULT_WEAK_CIPHERS_PATH } from "@/lib/scanner-paths";

/**
 * GET /api/settings
 *
 * Returns the singleton settings row. If it doesn't exist yet (first run),
 * we create it with defaults — including pre-filling the whitelist/payloads
 * from the bin/ files so the user has a sensible starting point.
 *
 * The API key is returned MASKED (****) for security — the frontend never
 * needs to display the actual key, only indicate whether one is set.
 */
export async function GET() {
  let settings = await db.setting.findUnique({ where: { id: "default" } });
  if (!settings) {
    // First run: pre-fill defaults from the bin/ files.
    let defaultWhitelist = "";
    let defaultPayloads = "";
    let defaultWordlist = "";
    let defaultWeakCiphers = "";
    try {
      defaultWhitelist = await fs.readFile(DEFAULT_WHITELIST_PATH, "utf-8");
    } catch {
      // bin/whitelist.txt missing — leave empty.
    }
    try {
      defaultPayloads = await fs.readFile(DEFAULT_PAYLOADS_PATH, "utf-8");
    } catch {
      // bin/payloads.txt missing — leave empty.
    }
    try {
      defaultWordlist = await fs.readFile(DEFAULT_WORDLIST_PATH, "utf-8");
    } catch {
      // bin/wordlist.txt missing — leave empty.
    }
    try {
      defaultWeakCiphers = await fs.readFile(DEFAULT_WEAK_CIPHERS_PATH, "utf-8");
    } catch {
      // bin/weak_ciphers.txt missing — leave empty.
    }
    settings = await db.setting.create({
      data: {
        id: "default",
        defaultWhitelist,
        defaultPayloads,
        defaultWordlist,
        defaultWeakCiphers,
      },
    });
  }

  // Mask the API key for the response. We return a boolean indicating
  // whether a key is set, so the UI can show "API key: set" vs "not set".
  return NextResponse.json({
    settings: {
      llmBaseUrl: settings.llmBaseUrl || "",
      llmApiKeySet: Boolean(settings.llmApiKey),
      llmApiKeyMasked: settings.llmApiKey ? "••••••••" : "",
      llmModel: settings.llmModel,
      llmMaxTokens: settings.llmMaxTokens,
      defaultWhitelist: settings.defaultWhitelist || "",
      defaultPayloads: settings.defaultPayloads || "",
      defaultWordlist: settings.defaultWordlist || "",
      defaultWeakCiphers: settings.defaultWeakCiphers || "",
      updatedAt: settings.updatedAt,
    },
  });
}

/**
 * PUT /api/settings
 *
 * Update the singleton settings row. The API key is handled specially:
 * if the client sends llmApiKey = "" (empty), we KEEP the existing key
 * (so the user doesn't accidentally clear it by submitting the form
 * without filling in the key field). To explicitly clear the key, the
 * client sends llmApiKey = null.
 *
 * Request body (JSON):
 *   llmBaseUrl?: string
 *   llmApiKey?: string | null  ("" = keep, null = clear, "sk-..." = set)
 *   llmModel?: string
 *   llmMaxTokens?: number
 *   defaultWhitelist?: string
 *   defaultPayloads?: string
 */
export async function PUT(req: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  // Build the update data, handling the API key special case.
  const update: Record<string, unknown> = {};
  if (body.llmBaseUrl !== undefined) {
    // Handle null explicitly (clears the field). Handle non-strings by
    // converting to string. Trim and treat empty as null.
    // CRITICAL: String(null) returns the literal string "null" — we must
    // check for null FIRST to avoid saving the string "null" as the URL.
    if (body.llmBaseUrl === null) {
      update.llmBaseUrl = null;
    } else {
      const url = String(body.llmBaseUrl).trim();
      update.llmBaseUrl = url || null;
    }
  }
  if (body.llmApiKey !== undefined) {
    if (body.llmApiKey === null) {
      update.llmApiKey = null; // explicitly clear
    } else if (body.llmApiKey === "") {
      // empty string = keep existing — don't include in update
    } else {
      update.llmApiKey = String(body.llmApiKey);
    }
  }
  if (body.llmModel !== undefined) {
    if (body.llmModel === null) {
      update.llmModel = "gpt-4o-mini"; // reset to default
    } else {
      update.llmModel = String(body.llmModel).trim() || "gpt-4o-mini";
    }
  }
  if (body.llmMaxTokens !== undefined) {
    const tokens = Number(body.llmMaxTokens);
    if (tokens < 256 || tokens > 128000) {
      return NextResponse.json(
        { error: "llmMaxTokens must be between 256 and 128000" },
        { status: 400 },
      );
    }
    update.llmMaxTokens = tokens;
  }
  if (body.defaultWhitelist !== undefined) {
    update.defaultWhitelist = String(body.defaultWhitelist) || null;
  }
  if (body.defaultPayloads !== undefined) {
    update.defaultPayloads = String(body.defaultPayloads) || null;
  }
  if (body.defaultWordlist !== undefined) {
    update.defaultWordlist = String(body.defaultWordlist) || null;
  }
  if (body.defaultWeakCiphers !== undefined) {
    update.defaultWeakCiphers = String(body.defaultWeakCiphers) || null;
  }

  // Upsert (create if doesn't exist, update if it does).
  const settings = await db.setting.upsert({
    where: { id: "default" },
    create: { id: "default", ...update },
    update,
  });

  // If the wordlist was updated, also write it to bin/wordlist.txt so the
  // scanner picks it up on the next scan. The scanner reads the wordlist
  // directly from bin/wordlist.txt (no CLI flag for it).
  if (body.defaultWordlist !== undefined && settings.defaultWordlist) {
    try {
      await fs.writeFile(DEFAULT_WORDLIST_PATH, settings.defaultWordlist, "utf-8");
    } catch {
      // If the write fails (e.g. permissions), the scanner will use
      // whatever bin/wordlist.txt already has. Not fatal.
    }
  }

  // Same edit-in-place flow for the weak-cipher policy: the scanner reads
  // bin/weak_ciphers.txt directly at import time (no CLI flag), so saving
  // here writes the edited content back to disk for the next scan.
  if (body.defaultWeakCiphers !== undefined && settings.defaultWeakCiphers) {
    try {
      await fs.writeFile(DEFAULT_WEAK_CIPHERS_PATH, settings.defaultWeakCiphers, "utf-8");
    } catch {
      // Non-fatal — the scanner falls back to the existing on-disk policy.
    }
  }

  return NextResponse.json({
    ok: true,
    settings: {
      llmBaseUrl: settings.llmBaseUrl || "",
      llmApiKeySet: Boolean(settings.llmApiKey),
      llmApiKeyMasked: settings.llmApiKey ? "••••••••" : "",
      llmModel: settings.llmModel,
      llmMaxTokens: settings.llmMaxTokens,
      defaultWhitelist: settings.defaultWhitelist || "",
      defaultPayloads: settings.defaultPayloads || "",
      defaultWordlist: settings.defaultWordlist || "",
      defaultWeakCiphers: settings.defaultWeakCiphers || "",
      updatedAt: settings.updatedAt,
    },
  });
}
