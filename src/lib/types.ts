/**
 * Shared types for the ScriptKiddie-Recon UI.
 *
 * These mirror the Scan model in prisma/schema.prisma and the JSON shapes
 * returned by the API routes. Keeping them in one place avoids drift
 * between the API and the client.
 */

export interface ScanSummary {
  id: string;
  title: string | null;
  targetUrl: string;
  depth: number;
  scopePatterns: string;
  excludePatterns: string;
  ignoreRobots: boolean;
  allowExternal: boolean;
  delayMs: number;
  concurrency: number;
  loginUrl: string | null;
  loginUser: string | null;
  loginSucceeded: boolean | null;
  llmAssist: boolean;
  llmInteresting: boolean;
  llmAnalyze: boolean;
  customHeaders: string | null;
  testAccessControl: boolean;
  manualLoginState: boolean;
  manualLoginStatePath: string | null;
  deepLogic: boolean;
  testFileUpload: boolean;
  uploadBaseFilename: string | null;
  wordlistFileContent: string | null;
  weakCiphersFileContent: string | null;
  pausedForRelogin: boolean;
  pauseReason: string | null;
  status: "pending" | "running" | "completed" | "failed" | "interrupted" | "paused";
  exitCode: number | null;
  errorMsg: string | null;
  findingsCount: number;
  findingsHigh: number;
  findingsMedium: number;
  findingsLow: number;
  urlsCrawled: number;
  inputsDiscovered: number;
  interrupted: boolean;
  createdAt: string;
  startedAt: string | null;
  endedAt: string | null;
}

export interface EvidenceFile {
  name: string;
  sizeBytes: number;
  modified: string;
}

// ---------------------------------------------------------------------------
// SSL/TLS inspection record (mirrors SSLRecord in bin/scanner.py).
// Served by GET /api/scans/[id]/ssl from ssl_record.json. All the NEW
// testssl-style fields (supported_ciphers, cert_chain_details, supports_*)
// are optional so scans made before they existed still type-check.
// ---------------------------------------------------------------------------

export interface SSLCipherProbe {
  cipher: string;
  protocol: string;
  accepted: boolean;
  strength: "weak" | "strong";
  reason: string;
  severity: string;
  detail?: string;
}

export interface SSLCertDetails {
  position: number;
  role: string; // "leaf" | "intermediate" | "root"
  subject?: string;
  issuer?: string;
  not_before?: string;
  not_after?: string;
  is_ca?: boolean;
  is_self_signed?: boolean;
  signature_algorithm?: string;
  parse_error?: string;
}

export interface SSLRecord {
  hostname: string;
  port: number;
  issuer: string;
  subject: string;
  not_before: string;
  not_after: string;
  days_until_expiry: number | null;
  is_expired: boolean;
  is_self_signed: boolean;
  is_untrusted_root: boolean;
  hostname_mismatch: boolean;
  negotiated_cipher: string;
  negotiated_protocol: string;
  weak_ciphers_detected: string[];
  weak_protocols_detected: string[];
  pem_chain: string;
  // NEW (testssl-style enumeration + decoded chain). Optional for old scans.
  supported_ciphers?: SSLCipherProbe[];
  cert_chain_details?: SSLCertDetails[];
  supports_tls_1_0?: boolean;
  supports_tls_1_1?: boolean;
  supports_tls_1_2?: boolean;
  supports_tls_1_3?: boolean;
  supports_sslv2?: boolean;
  supports_sslv3?: boolean;
}

// ---------------------------------------------------------------------------
// Passive findings (mirrors PassiveFindings in bin/scanner.py).
// Served by GET /api/scans/[id]/passive from passive_findings.json.
// ---------------------------------------------------------------------------

export interface InsecureCookie {
  name: string;
  domain: string;
  path: string;
  issues: string[];
  // NEW explicit attribute fields (UI pills). Optional for old scans.
  secure?: boolean;
  http_only?: boolean;
  same_site?: string; // "Strict" | "Lax" | "None" | "unset"
  expires?: number;
}

export interface PassiveFindingEntry {
  category?: string;
  severity?: string;
  snippet?: string;
  value?: string;
  owasp?: string;
  url?: string;
  [key: string]: unknown;
}

export interface PassiveFindings {
  missing_security_headers: string[];
  insecure_cookies: InsecureCookie[];
  mixed_content: PassiveFindingEntry[];
  other: PassiveFindingEntry[];
  error_messages: PassiveFindingEntry[];
  session_cookie_config: PassiveFindingEntry[];
  sensitive_info: PassiveFindingEntry[];
  // NEW: filename of a full-page screenshot captured when error_messages or
  // sensitive_info were found (served via /api/scans/[id]/evidence/<name>).
  // Optional for old scans.
  screenshot_path?: string | null;
}

/**
 * A single finding from findings.json. The scanner writes one of these
 * for every active check that produces a positive match. All findings
 * are UNVERIFIED — the human analyst must confirm them.
 *
 * Fields mirror what bin/scanner.py emits in `_write_finding()`.
 */
export interface ScanFinding {
  finding_id: string;
  owasp_category?: string;
  title: string;
  severity: "High" | "Medium" | "Low" | "Info";
  url: string;
  payload?: string;
  patterns_matched?: string[];
  request_raw?: string;
  response_raw?: string;
  execution_trail?: string[];
  screenshot_path?: string;
  has_screenshot?: boolean;
  unverified?: boolean;
  /** Extra fields the scanner may attach (varies by check type). */
  [key: string]: unknown;
}

export interface ScanDetailResponse {
  scan: ScanSummary & { isRunning: boolean };
  evidenceFiles: EvidenceFile[];
}

/**
 * A single entry in the scanner's execution_trail.jsonl. Each line is a
 * JSON object with at least `ts`, `action`, and `result` fields, plus
 * arbitrary extra fields depending on the action.
 */
export interface TrailEntry {
  ts: string;
  action: string;
  result?: string;
  [key: string]: unknown;
}

/**
 * The payload of the SSE 'done' event, sent when the scanner subprocess exits.
 */
export interface ScanDoneEvent {
  status: ScanSummary["status"];
  findingsCount: number;
  findingsHigh: number;
  interrupted: boolean;
}
