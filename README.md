# Scriptkiddie_recon
Offline web security scanner with AI-assisted analysis via local LLM or cloud models


# ScriptKiddie-Recon

**An offline, AI-assisted web security scanner for pentesters.**

The tool crawls a target website, captures headers, inspects SSL/TLS (certificate
chain + cipher-suite enumeration), runs passive checks (security headers, cookies,
error-message / sensitive-info leakage, JavaScript & CSS inventory), and actively
fuzzes every input it finds — **XSS, SQLi, Path Traversal, Command Injection, Open
Redirect, SSTI, SSRF, XXE, CSS Injection, and File Upload (extension bypass, MIME
spoofing, polyglot)**. It also tests for Broken Access Control, analyses captured
**JWTs** (weak claims + `alg=none` bypass), tests `<input type=file>` endpoints for
unrestricted/dangerous uploads, brute-forces common directories, and (optionally)
runs business-logic tests. Every finding ships
with raw HTTP request/response pairs, screenshots, and step-by-step execution
trails. A self-contained HTML report is generated at the end — no external
dependencies, no cloud, works fully airgapped.

**All findings are UNVERIFIED.** The tool automates evidence collection, not
verdicts. A qualified engineer must manually confirm every finding before
remediation.

---

## Authorisation

Only run this tool against targets you are explicitly authorised to test, and
disclose what it sends — see [Exactly What This Tool Sends to the Target](#exactly-what-this-tool-sends-to-the-target)
(and the per-scan `payload_manifest.json`). Active checks
(XSS/SQLi/Path Traversal/CMDi/File Upload) send crafted payloads — file-upload
probes upload real (benign, marker-string) files to the target, and even with
rate limiting, all active checks are detectable and may trigger WAF rules,
account lockouts, or incident-response processes. **Obtain written authorisation
first.**

## Quick Start (3 commands)

After completing the [Installation](#installation) steps below, start the app with:

```bash
bun run db:push    # one-time: creates the SQLite database + tables
bun run dev        # starts the Next.js dev server on http://localhost:3000
```

Then open **http://localhost:3000** in your browser.

That's it. The `bun run dev` command is all you need for day-to-day use —
it starts the web UI, auto-detects your Python interpreter (with Playwright),
and manages scan subprocesses. The database persists between restarts.

> **Windows users:** replace `bun` with `npm` (or install bun from bun.sh).
> All commands work identically.

---

## Table of Contents

1. [What the Tool Does (Scanner Phases)](#what-the-tool-does)
2. [Where the LLM Comes Into Play](#where-the-llm-comes-into-play)
3. [Where to Change Settings](#where-to-change-settings)
4. [Installation](#installation)
5. [Quick Start: Scan the Demo Site](#quick-start)
6. [CLI Examples](#cli-examples)
7. [Web UI Reference (Every Tab Explained)](#web-ui-reference)
8. [File Structure](#file-structure)
9. [Supervisor (Freeze Auto-Recovery)](#supervisor-freeze-auto-recovery)
10. [Troubleshooting](#troubleshooting)
11. [Out of Scope (What This Tool Does NOT Do)](#out-of-scope-what-this-tool-does-not-do)
12. [Exactly What This Tool Sends to the Target](#exactly-what-this-tool-sends-to-the-target)
13. [Authorisation](#authorisation)

---

## What the Tool Does

The scanner runs in 8 phases. Each phase builds on the previous one. You can
stop the scan at any time (red Stop button or Ctrl+C) — a partial report is
always generated.

### Phase 1: Authentication (optional)

Establishes a session so the scanner can access authenticated areas of the
target. Three methods, all optional, all coexist:

| Method | When to use | How to configure |
|--------|-------------|-----------------|
| **Form login** | Simple username/password login page | New Scan → Login URL + Username + Password |
| **Manual browser login** | CAPTCHA, 2FA, SSO, complex multi-step auth | Live View → "Launch Browser to Login" button → log in manually in a visible Chromium window → click "Capture Session & Continue" |
| **Custom HTTP headers** | CSRF tokens, Bearer tokens, API keys | New Scan → Custom HTTP Headers (JSON) |

If none of these are used, the scanner runs unauthenticated. The web GUI itself
has no login — `http://localhost:3000` is open to anyone on localhost.

#### Session Expiry & Re-login

During active fuzzing, the scanner checks every response for session expiry:

- **HTTP 401** (Unauthorized) → session expired
- **HTTP 302** redirect to a login page → session expired
- **HTTP 200** with login page keywords in the HTML body → session expired

**Important**: The login keyword check only applies to HTML responses
(`Content-Type: text/html`). JS, CSS, and JSON responses are NOT checked,
to avoid false positives on SPAs that have route names like `/login`.

When session expiry is detected:

1. **Scanner pauses** — sets `stop_event`, saves `pause_state.json` to disk
   with the reason, timestamp, and session duration
2. **Browser state cleared** — all cookies are cleared from the Playwright
   context to prevent the old expired session from persisting
3. **Dashboard shows** status: "Paused (Awaiting Re-login)" (orange badge)
4. **Live View shows** a yellow/orange banner with two buttons:
   - **"Launch Browser to Re-login"** — opens a visible Chromium window
     for manual re-login (handles CAPTCHA, 2FA, SSO)
   - **"Resume Scan"** — only appears after the user has re-logged in
     and captured the new session. Creates a new scan with `--resume`
     + `--load-state` pointing to the new session state.
5. **No auto-cancel** — the scan remains paused indefinitely until the
   user clicks "Resume Scan". There is no 10-minute timeout.

**Known limitation (unfixed — read before trusting a resumed scan):** the
re-login gate is cosmetic. The only server-side check on "Resume Scan" is that
a capture file exists — it does NOT verify the capture is newer than the
pause, and the scanner treats any saved cookie file as a live authenticated
session without probing it (the pause clears the in-browser cookies, not the
on-disk `manual_login_state.json`). So you can click Resume without
re-logging in and the scan starts labeled "authenticated". If the session
truly expired, the mid-scan expiry detector usually re-pauses on the first
protected page (401 / login redirect) — but on targets that don't clearly
signal logged-out state, or after "Skip Re-login & Continue" (which disables
the detector), the scan can run to completion "authenticated" while actually
testing logged-out pages. Safe habit: always re-login + capture before
resuming a paused scan, and treat authenticated coverage on a resumed scan
with suspicion if the session was old.

The session duration (time from scan start to expiry) is logged so the
pentester knows the timeout window for the target application.

### Phase 2: Reconnaissance & Crawling

Maps the attack surface by crawling the target with a real Chromium browser
(Playwright).

- **BFS crawler** — follows `<a href>`, `<form action>`, inline JS
  `fetch()`/`window.location` calls, AND **HTML comments** (extracts URLs
  from `<!-- ... -->` — catches commented-out links, debug endpoints, and
  hidden paths that standard crawlers miss)
- **Configurable depth** — default 3 (how many links deep to follow)
- **Scope enforcement** at 4 layers:
  1. Domain restriction (stays on target's registrable domain unless
     `--allow-external`)
  2. `--scope` patterns (only crawl URLs matching these globs)
  3. `--exclude` patterns (never fuzz URLs matching these globs)
  4. `robots.txt` (respects Disallow rules unless `--ignore-robots`)
- **Rate limiting** — `--delay` (default 500ms) with ±10% jitter to avoid
  WAF fingerprinting. `--concurrency` (default 1, max 3).
- Saves `crawl_map.json` with all discovered URLs and scope decisions.

### Phase 3: Passive Analysis (no payloads sent)

Inspects what the application already returns. No extra requests beyond the
initial crawl.

| Analysis | What it checks | Output file |
|----------|---------------|-------------|
| **Header Capture** | Captures ALL response headers (including redirects). Cross-references against your whitelist policy. Three tables: A (all headers + match status), B (anomalies — not in whitelist), C (policy violations — in whitelist but wrong value). | `headers_raw.json`, `headers_comparison.json` |
| **SSL/TLS Inspection** | Certificate expiry, self-signed, hostname mismatch, **weak public-key size** (RSA/DSA < 2048, ECC < 256), **weak signature algorithm** (SHA-1 / MD5 signatures). Enumerates cipher suites testssl-style — ~25 TLS 1.2 ciphers plus the TLS 1.3 suites (when the Python build supports `set_ciphersuites`); shows which the server accepts/rejects and flags weak ones with the reason from the policy. Decodes the full certificate chain (every cert — leaf, intermediates, root — with key algorithm + bit size + signature algorithm, not just the leaf). Probes TLS 1.0/1.1/1.2/1.3 protocol support. The weak-cipher/protocol policy is editable in `bin/weak_ciphers.txt` — add a newly-disclosed cipher CVE by appending one line, no code change. | `ssl_record.json`, `cert_chain.pem` |
| **Source Code Analysis** | Regex scan of raw HTML/JS for: developer comments (TODO/FIXME/DEBUG/SECRET), hardcoded API keys (sk-/AKIA/40+ char base64), email addresses, internal IP addresses (10.x/172.16-31.x/192.168.x), hidden form defaults (value="admin"). | `interesting_locations.json` |
| **Input Surface Mapping** | Catalogs all `<form>`, `<input>`, `<textarea>`, `<select>`, `fetch()` calls. Flags hidden inputs as privilege escalation risks. | `interesting_locations.json` |
| **Interesting Locations** | Heuristic flags for admin panels, API endpoints, IDOR candidates, redirect params, command injection params, SSRF candidates, sensitive headers. Each item has 5 sections: Why / Where / Evidence / Suggested Test / AI Insight. | `interesting_locations.json` |
| **Software Inventory** | Passive fingerprinting from HTTP headers (Server, X-Powered-By), HTML meta tags (`<meta name="generator">`), HTML comments, JS file URLs (`/jquery-3.6.0.min.js`), CSS file URLs (`/bootstrap-5.3.0.min.css`). The same product+version+category is combined into ONE row even when matched by multiple patterns (e.g. Bootstrap matched as both a JS file and a CSS file collapses to a single row with all sources + URLs merged). Groups by category (Web Server, CMS, JS Framework, CSS Framework, Backend). Does NOT query CVE databases — outputs a static advisory to manually check NVD. | `software_inventory.json` |
| **Directory Brute-Force** | Tries 70 common paths (admin, .git/config, .env, wp-admin, graphql, swagger.json, etc.) from `bin/wordlist.txt` — **prefix-aware**: fuzzes the root **and** each discovered path prefix (so if the crawl found `/v1` and `/v2`, it also tries `/v1/admin`, `/v2/admin`, etc.; capped at ~12 prefixes). **Discovered 200-status pages are re-crawled**: their forms/inputs are added to the attack surface (active fuzzes them) and their in-scope links are added to the crawl map (passive scans them) — so content reachable only via a dir-brute path is detected. If the LLM is configured, it reorders the wordlist based on detected technology. Flags 200/301/401/403 responses. | `directory_findings.json` |
| **Passive OWASP Checks** | Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options); insecure cookies (each cookie shows explicit Secure / HttpOnly / SameSite attributes — Strict/Lax/None/unset); error messages in pages (stack traces, SQL errors, file-path disclosure, debug output); sensitive information (API keys, internal IPs, emails, credit-card/SSN patterns, JWTs, private keys); mixed content (HTTP resources on HTTPS page). A full-page screenshot is captured when error messages or sensitive info are found, so the engineer can see the context. | `passive_findings.json`, `evidence/passive_*.png` |
| **CSS Secret Scan** | Fetches each same-origin `<link rel="stylesheet">` and runs the sensitive-info regexes (emails, internal IPs, API keys, JWTs, private keys, DB URLs) over the CSS source — catches secrets/internal hostnames leaked in CSS comments or `url()` references. External/CDN stylesheets are skipped. | (added to `passive_findings.json` sensitive_info) |
| **Sitemap Source Sweep** | After the sitemap is final (crawl + dir-brute + LLM discovery), visits every in-scope sitemap URL not already captured — **on the authenticated browser session** — and saves its HTML (+ iframes) to `page_sources.json`. Collects `<script src>` files: same-origin fetched authenticated, **external/CDN scripts fetched via plain GET (cap ~50)** so version fingerprints in CDN paths reach the AI extraction. The regex software inventory is **rebuilt** over the full page set. Honest limit: covers 100% of the sitemap (= what the scan *discovered*); pages behind unexecuted JS / modal-only / 401-403 dir-brute paths are not in the sitemap. CDN fetches are read-only GETs to public script hosts — recorded in the payload manifest under `third_party_fetches`. | `page_sources.json`, `javascripts.json`, `js_source/`, `software_inventory.json` |
| **JWT Collection** | Harvests `eyJ…` tokens from cookies + page HTML + Authorization headers during the passive pass and writes them to `jwt_tokens.json` for the post-scan JWT-analysis phase. | `jwt_tokens.json` |
| **JavaScripts** | Collects every `<script src>` from the crawled pages into a dedicated list (absolute-ized, deduped, marked same-origin vs external/CDN, with the pages each was found on) — so JS files are VISIBLE (a planted JS vuln otherwise hides completely). Shown in the JavaScripts tab; same-origin files can be analyzed with the AI. | `javascripts.json` |

### Phase 4: Active Fuzzing (sends payloads)

Injects payloads from `bin/payloads.txt` into every discovered input (URL
parameters, form fields, fetch body parameters). The payload list is NOT
hardcoded in the source — it lives entirely in `bin/payloads.txt` and can be
edited via Settings → Default Payloads.

**Payload types (47 by default):**

| Type | Count | Example payloads | Detection method |
|------|-------|-----------------|-----------------|
| XSS | 15 | `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>` | Regex for `<script>...alert(...)...</script>`, `onX=alert(`, `javascript:alert(`, exact payload reflection |
| SQLi | 5 | `' OR '1'='1`, `admin'--`, `1' AND SLEEP(5)--` | Regex for MySQL/PostgreSQL/MSSQL/Oracle/SQLite error messages |
| Path Traversal | 4 | `../../../../etc/passwd`, `..\..\windows\win.ini` | Regex for `root:x:0:0:` (passwd), `[fonts]` (win.ini), unencoded `../../` |
| Command Injection | 4 | `; whoami`, `\| id`, `$({whoami})` | Regex for `uid=\d+(` (id output), `PING \d+` (ping output), `$({whoami})` not reflected |
| Open Redirect | 2 | `https://evil.com`, `//evil.com` | Checks Location header for `evil.com` |
| SSTI | 4 | `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%=7*7%>` | Checks for `49` in response (but not in payload — confirms template evaluation) |
| SSRF | 8 | `http://169.254.169.254/latest/meta-data/`, `file:///etc/passwd`, `dict://localhost/` | Reflection/metadata: cloud-metadata content (ami-/instance-id/credentials) or leaked internal-fetch errors (Connection refused, getaddrinfo). *Blind SSRF (silent fetch) is not detected — needs an out-of-band listener.* |
| XXE | 6 | `<?xml ...><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>` | XML payloads are POSTed raw with `Content-Type: application/xml` (not form-encoded). Matches passwd/win.ini contents or echoed DOCTYPE/ENTITY. |
| CSS Injection | — | (any reflected payload) | Detects when an injected payload lands inside a `<style>…</style>` block or a `style="…"` attribute — the CSS-injection context that enables data exfiltration / UI deception. Flagged Medium. |

**For every single test:**
- Raw HTTP request (method + URL + headers + body) saved to `evidence/*.txt`
- Raw HTTP response (status + headers + body) saved to same file
- Rendered DOM (post-injection) saved to same file
- Screenshot taken at the moment of detection (for findings)
- Execution trail (Steps to Reproduce) logged: `[Step 1] Navigated to...`,
  `[Step 2] Filled input...`, `[Step 3] Submitted...`, `[Step 4] Pattern matched...`
- `findings.json` updated INCREMENTALLY (after each finding, not at the end)

**Payload safety:**
- `--max-payload-bytes` (default 2000) truncates oversized payloads
- Rate limiting with ±10% jitter between every request
- Max concurrency 3 (hard cap — Playwright contexts are memory-heavy)

**Progress bar:** The UI shows real-time progress: "Testing input 15/42, payload
3/20 — 45/840 tests (5%) — ETA 10m 0s"

### Phase 5: Deep Logic Testing (optional, experimental)

Disabled by default. Only runs when `--deep-logic` is set or the user clicks
"Run Deep Logic Scan" in the Live View (after the initial scan finishes).

- **Happy path walkthrough**: Navigates to each URL with numeric parameters,
  captures the baseline response
- **State mutation**: Re-runs with -1, 0, 999999999, 0.01, -0.01
- **Anomaly detection**: Compares mutated response to baseline — flags
  negative numeric values (e.g. negative total price), success indicators
  after invalid input, or responses too similar to baseline (input not
  validated)

Saves `deep_logic_findings.json` with request sequences + screenshots.

### Phase 6: Broken Access Control Testing (optional)

Disabled by default. Only runs when `--test-access-control` is set.

- Clears ALL cookies from the browser context (removing session tokens)
- Re-visits each in-scope URL without authentication
- Flags URLs that return 200 + non-login content as potential BAC (A01)
- If login was performed, severity is High (the URL was supposed to require auth)
- If no login was performed, severity is Info (public page — but worth noting)

### Phase 6.5: JWT Analysis (always runs)

Reads the JWTs collected during the passive pass (`jwt_tokens.json`) and runs two
offline checks (A07:2025 Authentication Failures):

- **Weak/missing claims (passive, always):** decodes each token and flags missing
  `exp` (High — token never expires), missing `sub` (Low), `exp` > 1 year out
  (Medium), or an `alg=none` token the server actually issued (High).
- **`alg=none` bypass (only if the scan is authenticated):** forges the header to
  `alg=none` with an empty signature and replays a protected request carrying the
  forged token where the original was. The replay code supports both a cookie
  placement and an `Authorization: Bearer` placement, but tokens are only ever
  harvested from the browser cookie jar and the rendered page HTML (see
  [Detection limits](#detection-limits)), so in practice the cookie path is what
  fires. If the server accepts the forged token (HTTP 200), flags High.

Findings flow into the OWASP tab under A07. Writes `jwt_analysis.json`. NB: the
200-check has no baseline comparison, so a public page that returns 200
unconditionally can yield a false-positive High — confirm manually.

### Phase 6.6: File Upload Testing (optional)

Tests every discovered `<input type="file">` for unrestricted/dangerous upload
flaws (A05:2025 Injection). Off by default — enable via the **Test File Uploads**
toggle (New Scan) or `--test-file-upload`. Skips automatically if no file inputs
are in the attack surface.

- **Browser-driven.** Uses Playwright `set_input_files()` + a real form submit,
  so it reuses the logged-in session, CSRF tokens, and hidden fields (no raw
  multipart bypassing the form).
- **Probes (~10):**
  - **Extension bypass** — `.php`, `.phtml`, `.php5`, double-extension `.php.jpg`,
    null-byte `.php%00.jpg`.
  - **MIME spoofing** — a `.php` file declared as `image/jpeg`.
  - **Magic-byte polyglot** — `GIF89a` + PHP, to defeat `getimagesize()` checks.
  - **Stored XSS** — SVG with `onload`, and an `.html` file with `<script>`.
  - **Benign baseline** — a plain `.txt` (control: if only this is accepted,
    validation works; if the dangerous ones also pass, that's the vuln).
- **Per-scan base filename.** The scanner generates `<base>.php`, `<base>.phtml`,
  `<base>.svg`, etc. from a configurable base name (default `webrecon_upload`,
  via the New Scan field or `--upload-base-filename`). Pick something unique so
  you can grep for it server-side.
- **Detection (UNVERIFIED).** Records the HTTP status, whether the filename was
  reflected in the response, and extracts the **landing URL** where the uploaded
  file can be reached (from the response body, `Location` header, or JSON
  `url`/`path`/`location`/`file`/`link`/`src` fields; plus best-effort candidate
  paths under `/uploads/`, `/files/`, `/media/` when nothing is reflected). It
  does NOT fetch the landing URL or execute the file — see [Out of Scope](#out-of-scope-what-this-tool-does-not-do).
- **Findings.** An accepted dangerous upload (e.g. `.php` webshell, SVG XSS) →
  High/Medium finding under **A05:2025 Injection** in the OWASP tab, with raw
  request/response + screenshot. The full table of every attempt (accepted AND
  rejected) + landing URLs goes to the dedicated **Uploads tab** for manual
  verification — click a landing URL to confirm the file is actually served.

All probe content carries a harmless marker (`WR-UPLOAD-OK`) so uploaded files
are never actually malicious and are easy to find/clean up.

### Phase 7: Evidence Aggregation

- **Screenshots**: Full-page screenshot before fuzzing (shown in Headers tab) +
  after fuzzing. Per-finding screenshots at the exact moment of detection.
- **Raw HTTP traffic**: Every request/response saved as individual `.txt` files
  with UUID + timestamp filenames in `evidence/`
- **Execution trail**: `execution_trail.jsonl` — JSON Lines log of every action
  the scanner took. Used to generate "Steps to Reproduce" in the report.
- **Scan state**: `scan_state.json` saved after each phase for resume support.
  If the scan is interrupted, `--resume` skips completed phases.

### Phase 8: Reporting

Generates a self-contained HTML report (`report.html`):
- Single file, no external CDNs, all screenshots base64-encoded
- JSON data blocks are sanitized (`</script>` → `<\/script>`) to prevent
  self-XSS from reflected payloads
- Served via a strict Content-Security-Policy (`connect-src 'none'` — blocks
  all network connections from the report)

**Report tabs:** Executive Summary, Header Analysis (Table A/B/C), Attack
Surface, SSL/TLS & Crypto, OWASP Top 10 2025 (nested per finding), Raw Evidence
Vault.

---

## Where the LLM Comes Into Play

**The scanner works 100% offline without any LLM.** The LLM is purely optional
and enhances specific features. If the LLM endpoint is unreachable, every LLM
feature degrades gracefully (fallback text, empty results, disabled buttons).

**API key is optional.** Local LLM servers (Ollama, LM Studio, llama.cpp, vLLM,
GPT4All) typically don't use authentication — just set the Endpoint URL and
leave the API Key blank. The `Authorization` header is only sent when a key is
provided. For OpenAI/Anthropic, enter the key as usual.

**All AI features auto-run in the background.** You don't need to visit any
specific tab — every panel stays mounted (via `forceMount`), so their
auto-triggers fire when data arrives on disk, regardless of which tab you're
viewing. Start a scan with the LLM configured, walk away, come back —
everything's done. Results persist to JSON files on disk and reload on reopen.

### LLM features timeline

```
Phase 1 (Auth)     — NO LLM
Phase 2 (Crawl)    — NO LLM
Phase 3 (Passive)  — LLM reorders directory brute-force wordlist using the
                       DISCOVERED crawl paths + tech stack (if configured)
Phase 6.45         — AI Content Analysis (--llm-interesting, off by default):
                       after the crawl + dir-brute re-crawl, re-visits EVERY
                       in-scope page (authenticated, NO page cap) and asks the
                       LLM per page for interesting content (creds, hidden
                       endpoints, dev comments, logic flaws). Findings stream
                       to llm_interesting_findings.json (resumable). Same-site
                       paths the LLM extracts from content (comments/JS/text)
                       are PROBED afterwards (≤20, same-host GETs) — hits land
                       in directory_findings.json as base "(llm-discovered)"
                       and are recorded in the payload manifest.
Phase 4 (Fuzzing)  — LLM Planner runs BEFORE fuzzing (--llm-assist):
                       reads crawl URLs + inputs, suggests priority inputs +
                       custom tech-stack payloads + additional URLs to crawl
                     LLM Analyzer runs AFTER fuzzing (--llm-analyze):
                       detects vulns regex missed, classifies OWASP categories,
                       flags false positives, suggests follow-up tests
Phase 6.5 (JWT)    — NO LLM (offline decode + alg=none forge/replay)
Phase 6.6 (Upload) — NO LLM (browser-driven probes + landing-URL extraction)
Phase 7 (Evidence) — NO LLM
Phase 8 (Report)   — LLM generates Executive Summary text (falls back to
                       deterministic rule-based summary if LLM unavailable)
Post-scan (UI)     — "Explain with AI" button on every Interesting Location
                     "Run AI Content Analysis" button in Interesting tab — for
                       scans WITHOUT --llm-interesting: capped fallback (first
                       20 saved pages); with --llm-interesting the scan-time
                       results load automatically and the button is a re-run
                     "AI Confidence Evaluation" auto-runs on OWASP findings
                       (LLM rates each finding High/Medium/Low confidence)
                     "Extract Versions with AI" button in Software Inventory
                       (per-source — one file per LLM call, can't overflow context)
                     "Analyze JS with AI" button in the JavaScripts tab — fetches
                       each same-origin JS file and flags dangerous code (eval/
                       Function sinks, innerHTML/document.write of dynamic data,
                       postMessage without origin checks, hardcoded secrets,
                       hidden debug/backdoor console commands, prototype pollution).
                       Per-file (one LLM call per JS, capped at 25).
                     "Analyze CSS with AI" button in the CSS tab — the same
                       per-file pass for stylesheets: exfil beacons in url(),
                       secrets in comments, CSS-exfil selectors, unexpected
                       @import hosts (auto-runs after completion, resumable).
                     "AI Payload Generator" + "AI Wordlist Generator" in Settings —
                       generate tailored payloads/paths from the scan's ACTUAL
                       crawl results (discovered URLs + inputs + tech stack), not
                       just the version list.
                     "AI Assistant" chat tab (ask LLM about findings)
```

### What the LLM NEVER does

- Execute HTTP requests itself
- Escape the scan scope
- Disable rate limiting
- Skip evidence collection
- Confirm findings as true positives
- Modify raw evidence (requests, responses, screenshots)
- Make any decision about whether a finding is real

### Configuring the LLM

**Settings tab → LLM Configuration:**

| Field | What to enter |
|-------|--------------|
| LLM Endpoint URL | OpenAI-compatible chat-completions URL (e.g. `https://api.openai.com/v1/chat/completions`, or local Ollama `http://localhost:11434/v1/chat/completions`) |
| API Key | Bearer token for the endpoint |
| Model | Model name (e.g. `gpt-4o-mini`, `llama3`, `claude-3-haiku`) |
| Max Tokens | Token budget per request (default 4000, caps context window) |

Click **Test Connection** to verify the endpoint is reachable and the API key
is valid.

---

## Where to Change Settings

### Settings tab (web UI)

| Setting | What it controls | Where it's stored |
|---------|-----------------|-------------------|
| **LLM Endpoint URL** | The chat-completions endpoint | DB (Setting table) |
| **LLM API Key** | Bearer token (masked in UI, never returned by API) | DB |
| **LLM Model** | Model name | DB |
| **LLM Max Tokens** | Token budget per LLM request. **Env override: `WEBRECON_LLM_MAX_TOKENS`** (env > DB > default 4000) — applies to the scanner subprocess (`--llm-tokens`, Python-side cap 32768) and every web LLM route (each still clamps per-call, e.g. JS-file analysis 1024–4096; the LLM server's own completion cap is the final limit) | DB + env |
| **Default Whitelist** | Header policy (which headers to expect + expected values) | DB + `bin/whitelist.txt` |
| **Default Payloads** | Fuzzing payloads (one per line, `#` = comment) | DB + `bin/payloads.txt` |
| **Default Wordlist** | Directory brute-force paths (one per line, `#` = comment) | DB + `bin/wordlist.txt` |

### Files you can edit directly

| File | What it controls | Format |
|------|-----------------|--------|
| `bin/payloads.txt` | ALL fuzzing payloads (NO hardcoded fallback in source) | One per line, `#` = comment |
| `bin/wordlist.txt` | Directory brute-force wordlist (NO hardcoded fallback) | One path per line, `#` = comment |
| `bin/whitelist.txt` | Header policy (reference list) | `Header-Name` or `Header-Name: expected-value` or `Header: v1\|v2` |
| `bin/weak_ciphers.txt` | Weak-cipher / weak-TLS-protocol policy used by the SSL/TLS inspection (both the negotiated check and the cipher-suite enumeration). Add a new cipher CVE by appending one line — no code change. A hardcoded seed is used only if the file is missing. | `PATTERN \| REASON \| SEVERITY` per line; `@TLS PROTOCOL \| REASON \| SEVERITY` for protocol versions; `#` = comment. See the file header for full docs. |
| `.env` | `DATABASE_URL` for SQLite | `DATABASE_URL=file:../db/webrecon.db` (relative — works on Linux + Windows) |

### Per-scan overrides (New Scan form)

Every setting can be overridden per-scan in the New Scan form:
- Target URL + crawl depth
- Scope/exclude patterns
- Rate limiting (delay + concurrency)
- Login (form login, manual browser, custom headers)
- LLM toggles (llm-assist, llm-interesting, llm-analyze)
- Access control testing
- Deep logic testing
- File upload testing (+ base filename for probes)
- Whitelist + payloads + wordlist + weak-ciphers (pre-filled from Settings, editable per-scan; inner-tabbed so the page stays compact)

### CLI flags (all mirror the web UI)

```
--url              Target URL (required)
--output           Output directory (default: ./scan_report)
--depth            Crawl depth (default: 3)
--delay            Delay between requests in ms (default: 500)
--concurrency      Parallel contexts (default: 1, max: 3)
--scope            Comma-separated allow globs
--exclude          Comma-separated deny globs
--allow-external   Follow external links (DANGEROUS)
--ignore-robots    Ignore robots.txt
--headers          Path to whitelist file
--payloads         Path to payloads file (default: bin/payloads.txt)
--wordlist         Path to wordlist file (default: bin/wordlist.txt). Per-scan override.
--weak-ciphers     Path to weak-cipher policy (default: bin/weak_ciphers.txt). Per-scan override.
--login-url        Login page URL
--login-user       Username
--login-password   Password (or WEBRECON_LOGIN_PASSWORD env var)
--login-user-field Username input field name (default: username)
--login-pass-field Password input field name (default: password)
--custom-headers   JSON object of headers to send with every request
--load-state       Path to Playwright storageState JSON (manual login)
--test-access-control  Test Broken Access Control (clear cookies, re-visit)
--deep-logic       EXPERIMENTAL: business logic testing
--test-file-upload Test <input type=file> for unrestricted/dangerous uploads (A05).
                    Browser-driven: extension bypass, MIME spoof, polyglot, XSS.
--upload-base-filename  Base filename for upload probes (default: webrecon_upload).
                    Scanner appends .php/.phtml/.svg/etc.
--llm-assist       LLM pre-scan planning
--llm-interesting  AI Content Analysis during scan: re-visit every crawled page
                    (incl. dir-brute finds) + 1 LLM call per page. No page cap. Off by default.
--llm-analyze      LLM post-scan vulnerability analysis
--llm-tokens       LLM token budget (default: 4000)
--max-payload-bytes  Payload size cap (default: 2000)
--resume           Resume interrupted scan from scan_state.json
--report-only      Regenerate report.html from on-disk JSON (no browser/network/LLM).
                    Used by the web UI's force-complete so a force-completed scan
                    gets the FULL styled report instead of a minimal table.
--browser-headless / --no-browser-headless  Toggle headless mode
```

---

## Installation

### Prerequisites

| Tool | Why | Version |
|------|-----|---------|
| **Node.js** or **bun** | Runs the Next.js web app | 18+ / latest |
| **Python** | Runs `scanner.py` | 3.10+ |
| **Chromium** | Playwright's headless browser | Latest |

### Kali Linux

```bash
# 1. Unzip
unzip webrecon-webapp.zip
cd webrecon-webapp

# 2. Install Node.js (if not already installed)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# 3. Install bun (recommended — faster than npm)
curl -fsSL https://bun.sh/install | bash
source ~/.bashrc

# 4. Install Node.js dependencies
bun install

# 5. Install Python dependencies into a venv named .venv
#    (The dev server auto-detects .venv/bin/python3 — no manual PATH setup needed.)
sudo apt-get install -y python3-pip python3-venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt   # installs playwright + cryptography + python-dotenv

# 6. Install Chromium for Playwright
playwright install chromium
sudo playwright install-deps chromium   # installs OS libs Chromium needs

# 7. Set up the database
cp .env.example .env          # creates .env with DATABASE_URL=file:../db/webrecon.db
bun run db:push               # creates db/webrecon.db + tables (runs prisma db push)

# 8. Start the web app
bun run dev

# 9. Open http://localhost:3000
```

> **No venv? No problem.** If you skip step 5 and just install playwright
> system-wide (`pip install playwright`), the dev server's
> `findPythonWithPlaywright()` helper will discover it automatically. It
> probes `python3`, `python`, `<project>/.venv/bin/python3`,
> `$HOME/.venv/bin/python3`, and several other common locations.
>
> **Airgapped install?** Pre-install playwright + Chromium on a machine
> with internet, then copy the entire `.venv/` directory + the
> `~/.cache/ms-playwright/` directory to the airgapped machine.

### Windows

```powershell
# 1. Unzip
Expand-Archive webrecon-webapp.zip
cd webrecon-webapp

# 2. Install Node.js from https://nodejs.org (LTS)
winget install OpenJS.NodeJS.LTS

# 3. Install Python from https://python.org (3.10+)
winget install Python.Python.3.12

# 4. Install Node.js dependencies
npm install

# 5. Install Python dependencies into a venv named .venv
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# 6. Install Chromium
playwright install chromium

# 7. Set up the database
copy .env.example .env
npm run db:push

# 8. Start the web app
npm run dev

# 9. Open http://localhost:3000
```

> **Windows DATABASE_URL**: The `.env.example` file uses a RELATIVE path
> (`file:../db/webrecon.db`) so it works on Windows without modification.
> Do NOT change it to an absolute Unix path like `file:/home/.../db/custom.db`
> — on Windows the leading `/` resolves to the current drive root (e.g.
> `Z:\home\...`) and Prisma will throw a confusing `Z:/` error.
>
> **Why `../db/` and not `./db/`?** Prisma resolves relative DB paths from
> the directory containing `prisma/schema.prisma` (i.e. the `prisma/`
> folder), NOT from `process.cwd()`. So `file:./db/webrecon.db` would
> create `prisma/db/webrecon.db` — which is NOT where the app expects it.
> Using `file:../db/webrecon.db` puts the DB at `<project-root>/db/webrecon.db`.

### Optional: Manual Login Service (CAPTCHA / 2FA / SSO)

The "Launch Browser to Login" feature opens a real Chromium window so you
can log in manually (handles CAPTCHA, 2FA, SSO, non-standard flows). It
requires a separate mini-service running on port 3001:

```bash
# In a separate terminal:
cd mini-services/manual-login-service
bun install
bun run dev
```

You can now use "Launch Browser to Login" from either:
- **New Scan form** — log in BEFORE the scan starts (the captured session
  is passed to the scanner via `--load-state`)
- **Live View** (when a scan pauses due to session expiry) — log in to
  refresh the session, then click "Resume Scan"

### Auto-Install Playwright (Optional)

If you don't want to set up a venv manually, you can let the dev server
auto-install playwright on first scan. Set this in your `.env`:

```
WEBRECON_AUTO_INSTALL_PLAYWRIGHT=1
```

When enabled, the scanner-runner will run `pip install playwright &&
playwright install chromium` on the first scan if no interpreter has it.
Requires internet access on first run. Disabled by default for airgapped
use.

---

## Quick Start

### Scan the built-in demo site

The app includes a deliberately vulnerable test site at `/api/demo/` covering
**every scanner feature**. All vulnerabilities are simulated (no real command
execution, fetching, or filesystem access) and the upload store is in-memory —
safe to run anywhere.

| Endpoint | Feature it lights up |
|---|---|
| `/api/demo/search?q=` | Reflected XSS |
| `/api/demo/login` | SQL injection (error + bypass) + form login + weak-JWT cookie |
| `/api/demo/user?id=` | IDOR + sensitive data (SSNs) |
| `/api/demo/file?name=` | Path traversal |
| `/api/demo/ping?host=` | Command injection (simulated `id`/`whoami`/ping output) |
| `/api/demo/redirect?url=` | Open redirect |
| `/api/demo/render?tpl=` | SSTI (`{{7*7}}` → 49) |
| `/api/demo/fetch?url=` | SSRF (simulated cloud-metadata + internal-host error leaks) |
| `/api/demo/xml` | XXE (raw `application/xml` POST) |
| `/api/demo/theme?color=` | CSS injection (reflected into `<style>`) |
| `/api/demo/upload` | Unrestricted file upload (form + landing URL) |
| `/api/demo/token` | Weak JWT — no `exp` claim, in page + cookie |
| `/api/demo/admin` | Broken access control + unverified JWT (`alg=none` replay target) |
| `/api/demo/profile` | Rich form surface (select/textarea/checkbox/radio/hidden `value=admin`) |
| `/api/demo/docs` | Crawl-depth chain (landing → docs → leaf pages) |
| `/api/demo/static/analytics.js` | Vulnerable JS — eval sink, innerHTML of dynamic data, postMessage without origin check, hardcoded `sk-` key, hidden debug command (JavaScripts tab + Analyze JS with AI) |
| `/api/demo/static/jquery-3.6.0.min.js` | Software inventory fingerprint (jQuery 3.6.0) |
| `/api/demo/.git/config`, `.env`, `swagger.json`, `debug`, `actuator` | Directory brute-force finds (secrets in `.env`/`debug`) |
| `/api/demo/phpmyadmin` (403), `graphql` (401), `wp-admin` (302) | Dir-brute status-code variety |
| Landing page HTML comments | Dev secrets, hardcoded API key, internal IP `192.168.1.50`, hidden `/api/demo/debug` mention — feeds source analysis, Interesting tab, and LLM-discovered paths |
| Every response | Missing security headers, insecure cookies, `Server`/`X-Powered-By` banners |

### Steps

1. Open `http://localhost:3000`
2. Click **New Scan** tab
3. Click the blue **"Fill demo target"** button — configures the full-feature
   demo scan (target, depth 3, delay 100ms, LLM toggles, file-upload testing
   with base filename `demodemo`). Login is left blank on purpose — see below.
4. Click **Launch Scan**
5. Watch the **Logs** tab stream in real-time

### Demo walkthrough (tab by tab)

When the scan completes:

1. **OWASP** — the headline tab. A03 Injection (XSS/SQLi/CMDi/SSTI/XXE),
   A01 Broken Access Control (admin page), A05 file uploads, A07 JWT
   (missing `exp`, `alg=none` bypass). Expand any finding → severity badge,
   AI confidence badge, Steps to Reproduce, screenshot, raw HTTP pair.
2. **Security Checks** — error messages, sensitive info (the `.env`/debug
   secrets), insecure cookies (red Secure/HttpOnly/SameSite pills), mixed
   content — with page screenshots at detection time.
3. **Headers** — Table A (all headers), B (anomalies), C (policy violations:
   missing HSTS/CSP/X-Frame-Options).
4. **Sitemap** — the full crawl map including the docs chain and
   `html_comment`-sourced discoveries, with source badges.
5. **Dir Brute** — `.git/config`, `.env`, `swagger.json`, `actuator` (200s),
   `phpmyadmin` (403), `graphql` (401); rows with `base: (llm-discovered)`
   are paths the AI extracted from page comments (e.g. `/api/demo/debug`).
6. **JavaScripts** — lists `analytics.js` + `jquery-3.6.0.min.js`;
   "Analyze JS with AI" (auto-runs) flags the eval sink, the
   `innerHTML = location.hash` DOM-XSS sink, the unchecked postMessage
   handler, and the hardcoded API key in `analytics.js`.
7. **Inventory** — fingerprints jQuery 3.6.0 + VulnTest-CMS 2.1.7 (meta
   generator) + the fake server banners; "Extract Versions with AI"
   auto-runs.
8. **Uploads** — every probe attempt; accepted probes have clickable landing
   URLs (`/api/demo/uploads/demodemo.php` etc.) you can open live.
9. **Manifest** — the exact payload/wordlist/probe inventory for the audit
   story (nothing sent to third parties).
10. **Report** — the self-contained HTML report; open in a new tab for the
    executive-summary view.

**Authenticated demo (browser-login popup):** before launching, click
**Launch Browser to Login** in the Live View of a stopped/finished scan (or
use it pre-scan), log in as `admin / admin123` in the popup, then
**Capture Session & Continue** — the scan runs authenticated, the weak JWT
lands in the cookie jar (A07 findings), and re-running with **Broken Access
Control testing** enabled flags `/api/demo/admin` High (admin content served
with no session).

> The upload store is in-memory — uploaded demo files disappear when the dev
> server restarts (landing URLs will 404 until re-uploaded).

### Stop + resume

- Click the red **Stop Scan** button at any time → scanner saves all evidence +
  generates a partial report with "INTERRUPTED" banner
- Click **Resume Scan** → creates a new scan that loads `scan_state.json` and
  skips completed phases

**Known limitation (unfixed): every resume/continue creates a NEW scan row —
where your data lives depends on which button you clicked.**
- **Resume Scan** (interrupted/failed scan): the new row is symlinked to the
  ORIGINAL scan's output directory, so everything collected so far (crawl
  map, page sources, saved JS, findings, report) carries over, and
  `--resume` skips phases already completed.
- **Continue after a re-login pause** (and **Skip Re-login**): NOT a resume.
  It launches a brand-new scan in a NEW, EMPTY output directory with the
  captured session (`--load-state`) but NO `--resume` — it restarts from
  Phase 1. Nothing carries over: the crawl map, `page_sources.json`, saved
  JS, dir-brute results and AI findings collected by the original scan stay
  with the ORIGINAL row. Until the continued scan re-completes its own crawl
  and sitemap sweep, its Sitemap / Inventory / JavaScripts / Interesting
  tabs are empty and the AI extraction features have no sources to read.
  Open the ORIGINAL scan row for the accumulated data; treat the continued
  row as a fresh scan.

---

## CLI Examples

### Basic scan
```bash
python bin/scanner.py --url https://target.example.com --output ./scan_report
```

### With login + custom headers + access control testing
```bash
python bin/scanner.py \
    --url https://app.example.com \
    --login-url https://app.example.com/login \
    --login-user alice \
    --login-password 'P@ssw0rd!' \
    --custom-headers '{"X-CSRF-Token":"abc123"}' \
    --test-access-control \
    --output ./scan_report
```

### With manual browser login (state file)
```bash
# First, capture a session via the web UI's "Launch Browser to Login" button.
# Then run the scanner with --load-state:
python bin/scanner.py \
    --url https://app.example.com \
    --load-state ./scan_output/manual_login_state.json \
    --output ./scan_report
```

### With deep logic + LLM features
```bash
python bin/scanner.py \
    --url https://shop.example.com \
    --deep-logic \
    --llm-assist \
    --llm-analyze \
    --output ./scan_report
```

### With file-upload testing
```bash
python bin/scanner.py \
    --url https://app.example.com \
    --login-url https://app.example.com/login \
    --login-user admin --login-password 'pass' \
    --test-file-upload --upload-base-filename mytest \
    --output ./scan_report
```
Tests every `<input type=file>` with extension-bypass / MIME-spoof / polyglot /
XSS probes; only fires on pages that actually have a file input. Landing URLs
for accepted uploads appear in the **Uploads** tab — click to verify manually.

### Resume an interrupted scan
```bash
python bin/scanner.py \
    --url https://target.example.com \
    --output ./scan_report \
    --resume
```

---

## Web UI Reference

### Dashboard tab
- List of all past + running scans (auto-refreshes every 5s)
- Status badges (pending/running/completed/failed/interrupted)
- Finding counts by severity, URLs crawled, inputs discovered, duration
- Click any scan to open the Live View

### New Scan tab
- Form mirroring all CLI flags
- "Fill demo target" quick-start button
- Login section (form login, custom headers)
- LLM toggles (llm-assist, llm-interesting, llm-analyze)
- Access control + deep logic toggles
- **File upload testing** toggle (+ base-filename field for the probes)
- Whitelist + payloads + wordlist + weak-ciphers (inner-tabbed textareas, pre-filled from Settings, editable per-scan)

### Live View tab (shown when a scan is selected)

| Sub-tab | What it shows |
|---------|--------------|
| **Logs** | Real-time SSE stream of `execution_trail.jsonl`, colour-coded |
| **Headers** | Table A (all headers + whitelist comparison), Table B (anomalies), Table C (policy violations) + landing page screenshot |
| **SSL/TLS** | Certificate details (subject, issuer, validity); decoded certificate chain (leaf + intermediates + root, each with subject/issuer/validity/CA flag/**key algorithm + bit size**/**signature algorithm**, with weak-key / weak-signature certs flagged red); Security Issues list covers expiry, self-signed, hostname mismatch, **weak key size** (RSA/DSA <2048, ECC <256), **weak signature algorithm** (SHA-1/MD5), weak protocol, weak cipher. Supported cipher suites table (testssl-style — every probed cipher shown as Accepted/Rejected with Strong/Weak + reason; weak-and-accepted rows highlighted red); protocol-support badges (TLS 1.0–1.3, SSLv2/v3); negotiated cipher/protocol; raw PEM chain. Weak-cipher policy is editable in `bin/weak_ciphers.txt`. |
| **Security Checks** | Four internal sub-tabs: **Error Messages** (stack traces, SQL errors, file-path disclosure, debug output + a page screenshot taken at detection time); **Sensitive Info** (API keys, internal IPs, emails, credit-card/SSN patterns, JWTs, private keys + the same page screenshot); **Cookies** (insecure cookies shown with explicit Secure / HttpOnly / SameSite pills — green/red — plus session-cookie configuration issues); **Mixed Content** (HTTP resources loaded on an HTTPS page). |
| **OWASP** | Interactive A01–A10 categories. Findings from every active check — XSS, SQLi, Path Traversal, Command Injection, Open Redirect, SSTI, **SSRF, XXE, CSS Injection** — plus **JWT** weaknesses (A07) and accepted **dangerous file uploads** (A05). Click to expand → severity badge, AI confidence badge (High/Medium/Low), Steps to Reproduce (numbered list), screenshot, collapsible raw HTTP request/response. Filter: Show All / Show AI Agreed Only. CSV export. "Mark Verified" / "Mark False Positive" buttons. |
| **Interesting** | URL-grouped sub-tabs. Each URL shows findings with 5 sections: Why interesting / Where found / Evidence Snapshot / Suggested Test / AI Insight ("Explain with AI" button). Plus "AI Interesting Findings" section (LLM content analysis). **Best coverage: enable "AI Content Analysis during scan" (--llm-interesting)** — the scan re-visits every discovered page (incl. dir-brute finds, no cap, authenticated) and the results load here automatically. The button is a capped fallback re-run (first 20 saved pages) for scans without the toggle. |
| **Sitemap** | The full crawl map (`crawl_map.json`), grouped into collapsible path sections (`/api/`, `/admin/`, root pages…) — every URL with depth, source badge (`a_href` / `form_action` / `js_extract` / `html_comment` / `directory_bruteforce` / `llm_discovered`), clickable, out-of-scope flagged. The raw "what the app actually contains" view (vs the Dir Brute tab, which shows wordlist probe results). |
| **Attack Surface** | Every discovered input (name, type, location, method, clickable URL) that active fuzzing targeted — including dir-brute re-crawl additions. (The crawled-URL list lives in the Sitemap tab.) |
| **Manifest** | The payload manifest in the UI: summary chips (payload/wordlist counts, upload probes, JWT forge, auth flags) + collapsible sections for the exact fuzzing payload list (incl. LLM-appended ones; Copy All), the directory wordlist with `llm_discovered_additions` (path/status/found-via), file-upload probes, and Auth & JWT — including the harvested JWT tokens (masked, per-token copy for manual testing). Written near scan end; empty state until then. |
| **Inventory** | Software fingerprinting results grouped by category (Web Server, CMS, JS Framework, etc.), with **All / Internal / External-CDN filter buttons** — external rows carry a CDN badge (product fingerprinted from an external script host, e.g. jQuery via jsdelivr). The same product+version is combined into a single row even when detected via multiple sources (JS file + CSS file), with all sources + URLs merged into one row's "Found On" column. "Extract Versions with AI": **progressive + resumable** — analyzes every saved source (full-sitemap page HTML + saved JS incl. external/CDN scripts, no 25-source cap), streams results to disk per source (button shows `N/M sources`), auto-triggers once the scan completes, and a re-run resumes where it stopped. |
| **JavaScripts** | Every `<script src>` discovered during the scan (same-origin vs external/CDN, with the pages each was found on; **All / Same-origin / External-CDN filter buttons**). "Analyze JS with AI": **auto-runs after the scan completes** (so the sitemap sweep's JS — including scripts only referenced on dir-brute/late pages — is all on disk), analyzes **every file, same-origin AND external/CDN** (supply-chain risk: compromised/tampered CDN files), progressive + resumable (button shows `N/M files`, findings stream in; re-click resumes). Flags dangerous code (eval/Function sinks, innerHTML of dynamic data, postMessage without origin checks, hardcoded secrets, hidden debug/backdoor console commands); findings from external scripts carry an **External/CDN badge**. Catches vulns planted in JS that regex + page-HTML analysis miss. Failed fetches are retried on the next click (not silently dropped); interrupted scans don't auto-trigger it — use the manual button. |
| **CSS** | Every `<link rel=stylesheet>` discovered during the scan (same-origin vs external/CDN, with the pages each was found on; origin filter buttons). Contents are saved to `css_source/` by the sitemap sweep (same-origin authenticated, external via plain GET — recorded in the payload manifest). "Analyze CSS with AI": auto-runs after completion, per-file, progressive + resumable — flags what the regex secret scan can't reason about: exfil beacons (`url()` firing on element states), secrets in comments, CSS-exfiltration selectors (`input[name=password][value^=a]` + `url()`), unexpected `@import` hosts, and overlay/phishing styling. |
| **Dir Brute** | Directory brute-force results — paths that returned 200/301/401/403, with page titles + clickable links. **Prefix-aware**: each row records the `base` it was found under (root or a discovered prefix like `/v1`), so `/v1/admin` and `/admin` are distinguishable. Rows with `base: (llm-discovered)` are paths the AI Content Analysis extracted from page content (comments/JS/text) — probed and recorded like any other. |
| **Deep Logic** | Business logic findings (if `--deep-logic` enabled). Shows baseline vs mutated response comparison + anomaly description + Steps to Reproduce |
| **Uploads** | File-upload probe table (if `--test-file-upload` enabled). One row per probe attempt (accepted AND rejected): result badge, filename, declared MIME, HTTP status, filename-reflected flag, and a **clickable landing URL** (where the uploaded file can be reached) so you can manually confirm it's served. Candidate URLs (under `/uploads/`, `/files/`, etc.) are shown with a "candidate" badge when no concrete landing URL was reflected. Accepted dangerous uploads also appear in the OWASP tab as A05 findings. |
| **LLM Plan** | LLM's pre-scan suggestions (if `--llm-assist` enabled): priority inputs, custom payloads, additional URLs, reasoning |
| **Report** | Self-contained HTML report in an iframe + "Open in New Tab" + "Download" buttons |
| **Evidence** | File browser of raw `.txt` request/response pairs + screenshots. Each file opens in a new tab. |
| **LLM Analysis** | LLM's post-scan analysis (if `--llm-analyze` enabled): LLM-detected vulnerabilities, OWASP classifications, false positive candidates, follow-up tests, overall summary |
| **AI Assistant** | Chat with the LLM about the scan findings. Suggested questions included. LLM receives scan context (findings, headers, SSL) + your question. |

### Live View header buttons

| Button | When it appears | What it does |
|--------|----------------|-------------|
| **Stop Scan** (red) | While scan is running | Sends SIGTERM → scanner saves evidence + generates partial report |
| **Resume Scan** | When scan is interrupted/failed | Creates new scan with `--resume` → skips completed phases |
| **Resume from Pause** | When scan is paused (session expired) | Creates a NEW scan with `--load-state` using the re-captured session — fresh output dir, restarts from Phase 1 (see [Stop + resume](#stop--resume) limitation) |
| **Launch Browser to Login** | When scan is NOT running | Opens a visible Chromium window for manual login (CAPTCHA/2FA/SSO) → "Capture Session & Continue" saves cookies |
| **Run Deep Logic Scan** (purple) | When scan is completed/interrupted | Creates new scan with `--deep-logic` enabled |
| **Dark mode toggle** (sun/moon) | Always | Toggles light/dark theme (follows OS preference by default) |

### Settings tab

Four sub-tabs:

**1. LLM Configuration**
- Endpoint URL, API Key (masked), Model, Max Tokens
- Test Connection button
- Save Settings button

**2. Whitelist**
- Header policy textarea (which headers to expect + expected values)
- Save Settings button

**3. Payloads**
- Fuzzing payloads textarea (pre-filled from `bin/payloads.txt`)
- **AI Payload Generator** — generates new payloads tailored to the target's tech stack:
  - Category dropdown (All / XSS / SQLi / Path Traversal / CMDi / Open Redirect / SSTI)
  - Scan dropdown (select a completed scan for tech context — shows `targetUrl - date`)
  - "Generate Payloads with AI" button → LLM returns 15-30 payloads
  - Preview box with "Copy All" + "Add to Payloads" buttons
  - Prompt includes a safety constraint: "Generate ONLY safe, non-destructive payloads"
- Save Settings button

**4. Wordlist**
- Directory brute-force wordlist textarea (pre-filled from `bin/wordlist.txt`)
- **AI Wordlist Generator** — generates new paths tailored to the target's tech stack:
  - Scan dropdown (select a completed scan for tech context)
  - "Generate Wordlist with AI" button → LLM returns 20-40 paths
  - Preview box with "Copy All" + "Add to List" buttons
  - Prompt includes a safety constraint: "Generate ONLY safe, non-destructive paths"
- Save Settings button

---

## File Structure

```
webrecon-webapp/
├── bin/
│   ├── scanner.py          # The Python scanner engine (~12500 lines)
│   ├── payloads.txt        # ALL fuzzing payloads (NO hardcoded fallback)
│   ├── wordlist.txt        # Directory brute-force wordlist (NO hardcoded fallback)
│   ├── whitelist.txt       # Default header policy
│   └── weak_ciphers.txt    # Editable weak-cipher / weak-TLS-protocol policy (SSL/TLS tab)
├── prisma/
│   └── schema.prisma       # Database schema (Scan + Setting models)
├── src/
│   ├── app/
│   │   ├── page.tsx        # Single-page app (4 tabs)
│   │   ├── layout.tsx      # Theme provider + metadata
│   │   ├── api/
│   │   │   ├── demo/       # Built-in vulnerable test site
│   │   │   ├── scans/      # Scan CRUD + SSE + report + chat + LLM
│   │   │   └── settings/   # LLM config + test connection
│   │   └── ...
│   ├── components/
│   │   ├── scan-list.tsx       # Dashboard
│   │   ├── new-scan-form.tsx   # New scan form
│   │   ├── scan-detail.tsx     # Live view (12 sub-tabs)
│   │   ├── settings-panel.tsx  # Settings tab
│   │   ├── theme-provider.tsx  # Dark mode
│   │   └── theme-toggle.tsx    # Dark mode button
│   └── lib/
│       ├── db.ts               # Prisma client
│       ├── scanner-paths.ts    # Path helpers
│       ├── scanner-runner.ts   # Subprocess manager
│       └── types.ts            # Shared TypeScript types
├── mini-services/
│   └── manual-login-service/  # Playwright headed browser service (port 3001)
├── .env.example            # DATABASE_URL template
├── package.json
└── README.md               # This file
```

---

## Supervisor (Freeze Auto-Recovery)

The scanner has an **external supervisor** (`bin/supervisor.py`) that monitors
the scan and automatically restarts it if it freezes. This is the ultimate
freeze recovery mechanism — it works even when Playwright's C code blocks the
asyncio event loop and all in-process watchdogs are ineffective.

### How it works

1. The scanner writes `heartbeat.json` continuously — once per active-fuzzing
   test **and** via a background heartbeat keeper (every 30s) that keeps the
   heartbeat fresh during ANY slow phase (LLM analysis over 150 findings, LLM
   planner/summary, source-code analysis). Without the keeper, those phases
   used to starve the heartbeat and the supervisor would kill+restart the scan
   in an infinite loop. The keeper is an asyncio task, so it still starves on a
   REAL Playwright freeze (event loop blocked) → the supervisor kills correctly.
2. The supervisor (a separate OS process) polls this file every 10 seconds
3. If the heartbeat goes stale (>180s), the supervisor:
   - Kills the scanner PID (SIGTERM, then SIGKILL after 5s)
   - Kills any orphaned Chrome processes
   - Restarts the scanner with `--resume --skip-tests <last_test>`
4. The scan resumes from where it left off, with all previous findings preserved

### Enabling the supervisor

Add to `.env`:
```
WEBRECON_SUPERVISOR=1
WEBRECON_SUPERVISOR_THRESHOLD=180
```

When `WEBRECON_SUPERVISOR=1` is set, the web app automatically launches the
supervisor alongside every scan. You'll see `[supervisor:<scan_id>]` messages
in the dev server console.

### Running the supervisor manually

If you want to monitor a scan without auto-restarting (dry-run mode):
```bash
python3 bin/supervisor.py scan-output/<scan_id> --no-restart --verbose
```

### Disabling in-process watchdogs (for debugging)

The scanner has 3 in-process watchdogs (per-test 60s, progress 120s, context
recycle every 20 tests). To disable them and rely solely on the supervisor:
```
WEBRECON_DISABLE_WATCHDOG=1
```

### What happens when the supervisor restarts a scan

1. The old scan is marked as "interrupted" (not "failed") so the UI's rescan
   button works
2. The new scanner loads `scan_state.json` (skips crawl/headers/SSL/passive) +
   `findings.json` (preserves old findings)
3. Active scan resumes from test N+1
4. The trail shows a `supervisor_restart` event
5. The whole recovery takes ~10 seconds

---

## Troubleshooting

### Playwright not found on Kali Linux

```bash
playwright install chromium
sudo playwright install-deps chromium
```

### Python venv issues

```bash
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### Database errors

```bash
bun run db:push   # Recreate the database
```

### Manual login browser doesn't open

Requires a display server (X11 on Linux). On a headless server:
```bash
cd mini-services/manual-login-service
xvfb-run bun run dev
```

### Scan takes too long

- Reduce `--depth` to 1 or 2
- Increase `--delay` (slower but gentler)
- Use `--scope` to limit crawled URLs
- Use `--exclude` to skip slow/destructive endpoints
- Use `--resume` to continue an interrupted scan

### LLM features not working

1. Go to **Settings** tab
2. Enter LLM endpoint URL + API key
3. Click **Test Connection**
4. Click **Save**

The scanner works fully offline without an LLM.

### `alert(1)` popup when viewing the report

This was a self-XSS bug in the report (fixed). If you still see it, re-run the
scan — old reports generated before the fix still contain the vulnerable HTML.

### "Analyze JS with AI" shows no findings

Check `scan-output/<id>/javascripts_ai_results.json` first:

- **`js_analyzed: 0` with all URLs in `done`** — the run was "poisoned": every
  file failed to fetch (usually because the analysis fired before the JS
  sources were saved) and got permanently marked done. **Fixed in the current
  version** — failed fetches are no longer marked done and retry on the next
  click. Scans analyzed with an OLDER version may still carry the poisoned
  `done` list: delete `javascripts_ai_results.json` once and click Analyze
  again.
- **`llm_error`** — the first failure reason (auth-required JS with no saved
  source, fetch timeout, LLM HTTP error). Same-origin JS is normally read from
  the copy saved during the scan (`js_source/`); the live re-fetch fallback
  carries no session cookies and can fail on authenticated targets.
- **Interrupted scans do NOT auto-run the analysis** — a stopped scan never
  ran the sitemap sweep, so its JS sources are incomplete. The manual button
  still works; expect better results from a scan that ran to completion.

Known coverage limit: only the FIRST 4000 characters of each JS file are sent
to the LLM — a vuln deeper in a large file is not seen by this pass.

---

## Roadmap

Nice-to-haves if time permits — none affect current functionality (see
[Out of Scope](#out-of-scope-what-this-tool-does-not-do) for details):

- Session-liveness validation on resume (don't trust stale login captures)
- Data carry-over for the re-login "Continue" path (currently restarts fresh)
- Plain Resume for username/password scans (the password is never stored)
- v2: rework of the resume/state machinery

---

## Out of Scope (What This Tool Does NOT Do)

Setting honest expectations — these are deliberate limits, not bugs:

### Detection limits
- **Blind SSRF.** SSRF detection is reflection/metadata-only (cloud-metadata
  content or leaked fetch errors). If the server fetches your injected URL
  silently and returns nothing useful, it is NOT flagged. Catching that needs
  an out-of-band listener (not implemented).
- **JWT secret cracking & algorithm confusion.** JWT analysis covers weak/missing
  claims + the `alg=none` bypass only. It does NOT brute-force HS256 secrets or
  test RS256→HS256 confusion.
- **JWT collection scope.** Tokens are harvested from the browser cookie jar and
  the rendered page HTML only. Outbound `Authorization: Bearer` request headers
  are NOT inspected (the collector runs in the passive pass and has no access to
  request headers), so header-carried tokens are never collected — which means
  the `Authorization`-header replay branch in the `alg=none` test is effectively
  unused; only cookie-carried tokens get replayed.
- **`alg=none` replay has no baseline.** The bypass test flags ANY HTTP 200
  response to the forged token. There is no "is this URL actually protected?"
  pre-check, so a token found on a public page that returns 200 unconditionally
  can be reported as a High bypass it isn't. Treat `alg=none` High findings as
  "needs manual confirmation", not a confirmed exploit.
- **Body-sourced JWT replay quirk.** A token harvested from page HTML
  (`source: body`) is replayed by planting it as a cookie literally named
  `token`. If the server reads its session from a differently-named cookie (or
  from an `Authorization` header), the replay never reaches the auth check and
  the test is inconclusive for that token (silently reported as "not
  vulnerable").
- **DOM-based XSS via taint tracking.** XSS detection is regex/reflection-based
  (does the payload execute in HTML/JS context?). It does NOT do source→sink
  dataflow analysis, so DOM XSS that only fires via `innerHTML = location.hash`
  style sinks without reflection is missed.
- **CSRF token auto-extraction.** Authenticated fuzzing requires you to supply
  tokens via custom headers / manual login. The scanner does not auto-extract
  and re-inject CSRF tokens per request.
- **Full JS static analysis.** The "Analyze JS with AI" pass is LLM-based
  heuristic flagging, not a rigorous taint analyser (no Semgrep/CodeQL-style
  dataflow).
- **No vulnerability confirmation.** Every finding is UNVERIFIED — the tool
  collects evidence, a human confirms. It never exploits or auto-verifies.
- **No upload exploit confirmation.** File-upload testing records that the server
  *accepted* a dangerous file and where it *appears* to be reachable, but it does
  NOT fetch the landing URL or execute the file to confirm RCE/code-exec. Open the
  landing URL in the Uploads tab and verify manually.
- **Blind-upload detection is weak.** If the server accepts the file but returns
  no reflected filename and no discoverable landing URL, the probe is marked
  rejected/unclear and will NOT produce a finding — even though the upload may
  have succeeded silently. Endpoints that respond with an opaque 200 and no path
  are under-reported.
- **Content-level validation not bypassed.** The MIME/extension/polyglot tricks
  bypass *declaration-level* checks (filename + Content-Type). Validation that
  inspects actual CONTENT — antivirus scanning, deep magic-byte allowlisting,
  server-side re-encoding — is not bypassed by these probes.
- **JS AI analysis reads only the first 4000 chars per file.** The per-file
  LLM prompt is capped at 4000 characters of source, so dangerous code deeper
  in a large (e.g. minified bundle) file is not seen by the "Analyze JS with
  AI" pass.

### Scope of testing
- **Web applications only.** Browser-based (Playwright/Chromium). Not for mobile
  binaries, thick clients, or pure network-service scanning. It does fuzz API
  endpoints it discovers, but it's not a dedicated API-fuzzing tool.
- **No DoS / load / stress testing.** Payloads are deliberately non-destructive
  and rate-limited. The tool will not stress-test capacity.
- **Not stealthy.** A modern WAF can fingerprint it within ~20 requests. This is
  an evidence-collection tool for authorised assessments, not an evasion tool.
- **No live CVE/database lookups.** Software inventory outputs a static
  "manually verify against NVD" advisory. No external queries (airgap design).
- **No external reporting integrations.** No SARIF/SIEM/defect-tracker export
  (findings export is CSV; the report is self-contained HTML).

### Operational
- **Single-user, localhost.** The web UI has no authentication and binds
  localhost. Not for multi-user or internet-exposed deployments.
- **SPA / client-side-routing limits.** The crawler follows `<a>`/`<<form>`/inline
  fetches it finds. Heavy single-page apps with dynamic JS routing may
  under-crawl (no deep JS-execution crawl beyond the initial render).
- **Complex auth flows.** Form login + manual-browser capture cover most cases.
  Multi-step OAuth/SAML flows aren't automated (use manual login capture).
- **Running scans don't survive a server restart.** The scan registry is
  in-memory; restarting the Next.js dev server orphans any running scanner
  (it completes on its own, but the UI loses the live link). Re-resume to
  reconnect.
- **Resumed scans don't validate the saved session (known bug, accepted).**
  Both resume paths (interrupted-scan "Resume Scan" and the pause-flow
  "Resume") reuse the on-disk login capture without checking that it's newer
  than the pause or still alive. A resumed scan can report "authenticated"
  while testing logged-out pages if the session expired during the gap. The
  mid-scan expiry detector catches most cases (re-pauses on 401/login
  redirects), but "Skip Re-login" disables it. Related quirk: plain Resume
  of a scan that used form username/password login fails at startup (the
  password is never stored, and the scanner rejects `--login-url` without
  one) — re-create the scan or switch to manual browser login.
- **Re-login "Continue" restarts the scan from scratch (known bug, accepted).**
  All resume paths create a NEW scan row. Plain "Resume Scan" (interrupted)
  shares the original's output directory via a symlink and skips completed
  phases, but the pause-flow "Resume" / "Skip Re-login" launch a fresh scan
  in a new, empty output directory without `--resume` — the crawl, page
  sources, saved JS and AI results collected by the original are NOT carried
  over. Data-heavy tabs (Sitemap, Inventory, JavaScripts, AI extractions) on
  the continued row remain empty until that scan rediscovers everything
  itself; use the original scan row for the accumulated results.

---

## Exactly What This Tool Sends to the Target

Transparency for the pentester — you're signing off on what hits the target, so
here's the complete inventory. **Everything goes to exactly two places: the scan
target (the URL you entered) and the LLM endpoint you configured. Nothing is sent
to any third party — no telemetry, no analytics, no phone-home, no CDNs.**

### 1. Fuzzing payloads — `bin/payloads.txt` (editable; you control these)
Injected into **every discovered input** (form fields, URL params, fetch bodies), so
the target receives `payload × every input`. Default set (~49 lines): XSS (15),
SQLi (5), Path Traversal (4), Command Injection (5 — incl. an echo-canary
`|| echo wrcanda7ry`), Open Redirect (2), SSTI (4), SSRF (8 — internal/metadata
URLs), XXE (6 — sent as `application/xml` POSTs). Edit the file to add/remove.

### 2. Directory brute-force wordlist — `bin/wordlist.txt` (editable)
~70 paths (admin, .git/config, .env, wp-admin, api/v1, swagger, actuator,
phpmyadmin…) each GET-requested against the root **and** every discovered path
prefix (prefix-aware). Edit the file to change the set.

### 3. Hardcoded in the code (not in the editable files)
- **File-upload probes** (`FILE_UPLOAD_PROBES` in `scanner.py`) — 10 synthetic
  files uploaded to any `<input type=file>`, **only if you enable "Test File
  Uploads"**. Contents are benign markers (`<?php echo 'WR-UPLOAD-OK'; ?>`,
  `alert(1)` SVG/HTML, etc.) — **not** real webshells. If the server accepts one,
  that file is actually written to the target (clean up via the `WR-UPLOAD-OK` marker).
- **JWT `alg=none` forge** — only if the scan is authenticated **and** JWT tokens
  were found. Re-signs the target's own token with `alg=none` + empty signature and
  replays it at the target. Nothing foreign.
- **CMDi echo-canary token** (`CMDI_ECHO_CANARY = "wrcanda7ry"` in the code, paired
  with the payload line in `payloads.txt`) — a marker the scanner looks for in the
  target's response.

### 4. Other target traffic (non-payload)
Crawler GETs every in-scope link/form + `robots.txt` + same-origin CSS; the sitemap sweep additionally does read-only GETs to public external/CDN script + stylesheet hosts referenced by the target's pages (recorded in the manifest under `third_party_fetches`); TLS certificate + cipher-suite probes (handshakes only, no payload data); your login credentials + custom headers (only what you typed).

### Per-scan audit record: the Manifest tab
Every scan writes `scan-output/<id>/payload_manifest.json` recording **exactly**
what was sent: the full payload list (incl. any LLM-appended payloads), the
wordlist (incl. LLM-discovered path probes), the file-upload probes fired,
whether the JWT forge ran, and auth flags. View it in the web UI's **Manifest
tab** (masked JWT tokens with copy, collapsible sections); the HTML report's
**Scope of Engagement** table also points to it. Use it for your client report /
scope proof. The file stays on disk — it is not sent anywhere.

### The one configurable egress: the LLM endpoint
The opt-in AI features (planner, analyzer, JS analysis, AI confidence, chat) send
scan context (findings, JS source, crawled content) to the LLM endpoint you set in
Settings. **If it's localhost** (LM Studio `http://localhost:1234`, Ollama
`http://localhost:11434`) → nothing leaves your PC except traffic to the target. If
you ever point it at a **cloud** LLM, that scan data goes to that provider — the
only "data leaves" channel, fully under your control.

---

## Author & Contributors

- @TheUnknownSwat(https://github.com/TheUnknownSwat) — pentester and builder of ScriptKiddie-Recon.
- @Seymis(https://github.com/Seymis) — contributor.

Contributions welcome — open an issue or pull request. See the repo's
Contributors tab for the full list.

---

## Authorisation

Only run this tool against targets you are explicitly authorised to test, and
disclose what it sends — see [Exactly What This Tool Sends to the Target](#exactly-what-this-tool-sends-to-the-target)
(and the per-scan `payload_manifest.json`). Active checks
(XSS/SQLi/Path Traversal/CMDi/File Upload) send crafted payloads — file-upload
probes upload real (benign, marker-string) files to the target, and even with
rate limiting, all active checks are detectable and may trigger WAF rules,
account lockouts, or incident-response processes. **Obtain written authorisation
first.**
