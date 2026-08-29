import { get as httpsGet, type RequestOptions } from "node:https";
import { get as httpGet } from "node:http";

/**
 * Fetch a TARGET url's body as text — i.e. a URL on the site being scanned,
 * NOT the LLM endpoint.
 *
 * Why this exists instead of the global `fetch`:
 *   The Python scanner accepts self-signed / private-CA certs (it's a pentest
 *   tool scanning lab + internal targets). Node's global fetch (undici) does
 *   NOT — it rejects self-signed certs with a generic `TypeError: fetch failed`,
 *   which broke server-side target fetches like "Analyze JS with AI" against
 *   HTTPS targets with self-signed certs. This helper uses node:https directly
 *   with `rejectUnauthorized: false` so server-side target fetches match the
 *   scanner's behaviour.
 *
 * Also forwards the scan's custom headers (CSRF tokens, Authorization, cookies)
 * so protected/behind-auth static resources can be retrieved.
 *
 * Only use this for TARGET URLs. Never use it for the LLM endpoint, which must
 * keep normal TLS verification.
 */

export interface TargetFetchResult {
  ok: boolean;
  status: number; // 0 when the request never got an HTTP response (TLS / conn / timeout error)
  text: string; // body when ok; otherwise a short error message
}

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

function singleGet(
  url: string,
  headers: Record<string, string>,
  timeoutMs: number,
  maxBytes: number,
): Promise<TargetFetchResult> {
  const isHttps = url.startsWith("https://");
  const options: RequestOptions = {
    headers,
    // Pentest targets commonly use self-signed / private-CA certs.
    rejectUnauthorized: false,
  };
  return new Promise((resolve) => {
    let done = false;
    const finish = (r: TargetFetchResult) => {
      if (done) return;
      done = true;
      resolve(r);
    };
    let req: ReturnType<typeof httpsGet> | undefined;
    try {
      req = (isHttps ? httpsGet : httpGet)(url, options, (res) => {
        // Surface redirects to the caller (which follows them via Location).
        if (REDIRECT_CODES.has(res.statusCode ?? 0)) {
          const loc = res.headers.location;
          try { (req as any)?.destroy(); } catch { /* noop */ }
          try { res.destroy(); } catch { /* noop */ }
          finish({ ok: false, status: res.statusCode ?? 0, text: loc ?? "" });
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        let oversize = false;
        res.on("data", (c: Buffer) => {
          if (oversize) return;
          size += c.length;
          if (size > maxBytes) {
            oversize = true;
            finish({ ok: false, status: res.statusCode ?? 0, text: `response exceeded ${maxBytes} bytes` });
            return;
          }
          chunks.push(c);
        });
        res.on("end", () => {
          const status = res.statusCode ?? 0;
          finish({
            ok: status >= 200 && status < 300,
            status,
            text: Buffer.concat(chunks).toString("utf-8"),
          });
        });
        res.on("error", (e) =>
          finish({ ok: false, status: 0, text: e instanceof Error ? e.message : String(e) }),
        );
      });
      req.setTimeout(timeoutMs, () =>
        finish({ ok: false, status: 0, text: `timeout after ${timeoutMs}ms` }),
      );
      req.on("error", (e) =>
        finish({ ok: false, status: 0, text: e instanceof Error ? e.message : String(e) }),
      );
    } catch (e) {
      finish({ ok: false, status: 0, text: e instanceof Error ? e.message : String(e) });
    }
  });
}

export async function fetchTargetText(
  url: string,
  opts: {
    headers?: Record<string, string>;
    timeoutMs?: number;
    maxBytes?: number;
  } = {},
): Promise<TargetFetchResult> {
  const headers = opts.headers ?? {};
  const timeoutMs = opts.timeoutMs ?? 15000;
  const maxBytes = opts.maxBytes ?? 2_000_000;
  let current = url;
  for (let hop = 0; hop < 5; hop++) {
    const r = await singleGet(current, headers, timeoutMs, maxBytes);
    if (REDIRECT_CODES.has(r.status)) {
      // r.text holds the Location header — resolve relative to current URL.
      try {
        current = new URL(r.text, current).toString();
        continue;
      } catch {
        return { ok: false, status: r.status, text: `redirect with unparseable Location: ${r.text}` };
      }
    }
    return r;
  }
  return { ok: false, status: 0, text: "too many redirects" };
}

/**
 * Parse a scan's `customHeaders` JSON string into a header record.
 * Returns {} on missing/invalid input (never throws).
 */
export function parseCustomHeaders(raw: string | null | undefined): Record<string, string> {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === "string" || typeof v === "number") out[k] = String(v);
      }
      return out;
    }
  } catch {
    /* ignore — malformed customHeaders shouldn't break the fetch */
  }
  return {};
}
