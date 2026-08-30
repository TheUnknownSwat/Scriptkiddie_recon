# Scriptkiddie_recon
Offline web security scanner with AI-assisted analysis via local LLM or cloud models

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


## 📚 Documentation

| File | What it covers |
|------|----------------|
| [Quick Start](./quick-start.md) | Get a scan running in 3 commands — including the built-in demo target. |
| [Installation](./installation.md) | Step-by-step setup for Kali Linux, Windows, and airgapped environments. |
| [Tool Details](./tool-details.md) | Full scanner architecture, 8 phases, LLM integration, CLI flags, Web UI reference, troubleshooting, and out-of-scope limits. |
| [Contributors](./contributors.md) | People who helped build this tool. |

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

1. [Installation](#installation)
2. [Quick Start: Scan the Demo Site](#quick-start)
3. [CLI Examples](#cli-examples)



## Roadmap

Nice-to-haves if time permits — none affect current functionality (see
[Out of Scope](#out-of-scope-what-this-tool-does-not-do) for details):

- Session-liveness validation on resume (don't trust stale login captures)
- Data carry-over for the re-login "Continue" path (currently restarts fresh)
- Plain Resume for username/password scans (the password is never stored)
- v2: rework of the resume/state machinery

---

