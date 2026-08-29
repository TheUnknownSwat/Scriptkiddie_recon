# Quick Start

## Quick Start (3 commands)

After completing the [Installation](#installation) steps below, start the app with:

```bash
bun run db:push    # one-time: creates the SQLite database + tables
bun run dev        # starts the Next.js dev server on http://localhost:3000
```

Then open **http://localhost:3000** in your browser.

### Scan the built-in demo site



The app includes a deliberately vulnerable test site at `/api/demo/` covering

\*\*every scanner feature\*\*. All vulnerabilities are simulated (no real command

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

| `/api/demo/render?tpl=` | SSTI (`{{7\*7}}` → 49) |

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



\### Steps



1\. Open `http://localhost:3000`

2\. Click \*\*New Scan\*\* tab

3\. Click the blue \*\*"Fill demo target"\*\* button — configures the full-feature

&#x20;  demo scan (target, depth 3, delay 100ms, LLM toggles, file-upload testing

&#x20;  with base filename `demodemo`). Login is left blank on purpose — see below.

4\. Click \*\*Launch Scan\*\*

5\. Watch the \*\*Logs\*\* tab stream in real-time



\## CLI Examples



\### Basic scan

```bash

python bin/scanner.py --url https://target.example.com --output ./scan\_report

```



\### With login + custom headers + access control testing

```bash

python bin/scanner.py \\

&#x20;   --url https://app.example.com \\

&#x20;   --login-url https://app.example.com/login \\

&#x20;   --login-user alice \\

&#x20;   --login-password 'P@ssw0rd!' \\

&#x20;   --custom-headers '{"X-CSRF-Token":"abc123"}' \\

&#x20;   --test-access-control \\

&#x20;   --output ./scan\_report

```



\### With manual browser login (state file)

```bash

\# First, capture a session via the web UI's "Launch Browser to Login" button.

\# Then run the scanner with --load-state:

python bin/scanner.py \\

&#x20;   --url https://app.example.com \\

&#x20;   --load-state ./scan\_output/manual\_login\_state.json \\

&#x20;   --output ./scan\_report

```



\### With deep logic + LLM features

```bash

python bin/scanner.py \\

&#x20;   --url https://shop.example.com \\

&#x20;   --deep-logic \\

&#x20;   --llm-assist \\

&#x20;   --llm-analyze \\

&#x20;   --output ./scan\_report

```



\### With file-upload testing

```bash

python bin/scanner.py \\

&#x20;   --url https://app.example.com \\

&#x20;   --login-url https://app.example.com/login \\

&#x20;   --login-user admin --login-password 'pass' \\

&#x20;   --test-file-upload --upload-base-filename mytest \\

&#x20;   --output ./scan\_report

```

Tests every `<input type=file>` with extension-bypass / MIME-spoof / polyglot /

XSS probes; only fires on pages that actually have a file input. Landing URLs

for accepted uploads appear in the \*\*Uploads\*\* tab — click to verify manually.



\### Resume an interrupted scan

```bash

python bin/scanner.py \\

&#x20;   --url https://target.example.com \\

&#x20;   --output ./scan\_report \\

&#x20;   --resume

```



\---



\### CLI flags (all mirror the web UI)



```

\--url              Target URL (required)

\--output           Output directory (default: ./scan\_report)

\--depth            Crawl depth (default: 3)

\--delay            Delay between requests in ms (default: 500)

\--concurrency      Parallel contexts (default: 1, max: 3)

\--scope            Comma-separated allow globs

\--exclude          Comma-separated deny globs

\--allow-external   Follow external links (DANGEROUS)

\--ignore-robots    Ignore robots.txt

\--headers          Path to whitelist file

\--payloads         Path to payloads file (default: bin/payloads.txt)

\--wordlist         Path to wordlist file (default: bin/wordlist.txt). Per-scan override.

\--weak-ciphers     Path to weak-cipher policy (default: bin/weak\_ciphers.txt). Per-scan override.

\--login-url        Login page URL

\--login-user       Username

\--login-password   Password (or WEBRECON\_LOGIN\_PASSWORD env var)

\--login-user-field Username input field name (default: username)

\--login-pass-field Password input field name (default: password)

\--custom-headers   JSON object of headers to send with every request

\--load-state       Path to Playwright storageState JSON (manual login)

\--test-access-control  Test Broken Access Control (clear cookies, re-visit)

\--deep-logic       EXPERIMENTAL: business logic testing

\--test-file-upload Test <input type=file> for unrestricted/dangerous uploads (A05).

&#x20;                   Browser-driven: extension bypass, MIME spoof, polyglot, XSS.

\--upload-base-filename  Base filename for upload probes (default: webrecon\_upload).

&#x20;                   Scanner appends .php/.phtml/.svg/etc.

\--llm-assist       LLM pre-scan planning

\--llm-interesting  AI Content Analysis during scan: re-visit every crawled page

&#x20;                   (incl. dir-brute finds) + 1 LLM call per page. No page cap. Off by default.

\--llm-analyze      LLM post-scan vulnerability analysis

\--llm-tokens       LLM token budget (default: 4000)

\--max-payload-bytes  Payload size cap (default: 2000)

\--resume           Resume interrupted scan from scan\_state.json

\--report-only      Regenerate report.html from on-disk JSON (no browser/network/LLM).

&#x20;                   Used by the web UI's force-complete so a force-completed scan

&#x20;                   gets the FULL styled report instead of a minimal table.

\--browser-headless / --no-browser-headless  Toggle headless mode

```



\---



\## Web UI Reference



\### Dashboard tab

\- List of all past + running scans (auto-refreshes every 5s)

\- Status badges (pending/running/completed/failed/interrupted)

\- Finding counts by severity, URLs crawled, inputs discovered, duration

\- Click any scan to open the Live View



\### New Scan tab

\- Form mirroring all CLI flags

\- "Fill demo target" quick-start button

\- Login section (form login, custom headers)

\- LLM toggles (llm-assist, llm-interesting, llm-analyze)

\- Access control + deep logic toggles

\- \*\*File upload testing\*\* toggle (+ base-filename field for the probes)

\- Whitelist + payloads + wordlist + weak-ciphers (inner-tabbed textareas, pre-filled from Settings, editable per-scan)



\## Troubleshooting



\### Playwright not found on Kali Linux



```bash

playwright install chromium

sudo playwright install-deps chromium

```



\### Python venv issues



```bash

source venv/bin/activate  # Linux/Mac

venv\\Scripts\\activate     # Windows

```



\### Database errors



```bash

bun run db:push   # Recreate the database

```



\### Manual login browser doesn't open



Requires a display server (X11 on Linux). On a headless server:

```bash

cd mini-services/manual-login-service

xvfb-run bun run dev

```



\### Scan takes too long



\- Reduce `--depth` to 1 or 2

\- Increase `--delay` (slower but gentler)

\- Use `--scope` to limit crawled URLs

\- Use `--exclude` to skip slow/destructive endpoints

\- Use `--resume` to continue an interrupted scan



\### LLM features not working



1\. Go to \*\*Settings\*\* tab

2\. Enter LLM endpoint URL + API key

3\. Click \*\*Test Connection\*\*

4\. Click \*\*Save\*\*



The scanner works fully offline without an LLM.



\### `alert(1)` popup when viewing the report



This was a self-XSS bug in the report (fixed). If you still see it, re-run the

scan — old reports generated before the fix still contain the vulnerable HTML.



\### "Analyze JS with AI" shows no findings



Check `scan-output/<id>/javascripts\_ai\_results.json` first:



\- \*\*`js\_analyzed: 0` with all URLs in `done`\*\* — the run was "poisoned": every

&#x20; file failed to fetch (usually because the analysis fired before the JS

&#x20; sources were saved) and got permanently marked done. \*\*Fixed in the current

&#x20; version\*\* — failed fetches are no longer marked done and retry on the next

&#x20; click. Scans analyzed with an OLDER version may still carry the poisoned

&#x20; `done` list: delete `javascripts\_ai\_results.json` once and click Analyze

&#x20; again.

\- \*\*`llm\_error`\*\* — the first failure reason (auth-required JS with no saved

&#x20; source, fetch timeout, LLM HTTP error). Same-origin JS is normally read from

&#x20; the copy saved during the scan (`js\_source/`); the live re-fetch fallback

&#x20; carries no session cookies and can fail on authenticated targets.

\- \*\*Interrupted scans do NOT auto-run the analysis\*\* — a stopped scan never

&#x20; ran the sitemap sweep, so its JS sources are incomplete. The manual button

&#x20; still works; expect better results from a scan that ran to completion.



Known coverage limit: only the FIRST 4000 characters of each JS file are sent

to the LLM — a vuln deeper in a large file is not seen by this pass.



\---



