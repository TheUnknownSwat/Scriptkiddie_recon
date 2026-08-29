"use client";

import { useState, useEffect } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
} from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Loader2, ShieldAlert, Rocket, DownloadCloud, KeyRound, ExternalLink, CheckCircle2, Bot } from "lucide-react";

interface NewScanFormProps {
  onScanCreated: (scanId: string) => void;
}

/**
 * Form for launching a new scan. Mirrors all the CLI flags of scanner.py.
 *
 * On mount, we fetch the default whitelist + payloads from /api/settings
 * and pre-fill the textareas. The user can still override them per-scan.
 */
export function NewScanForm({ onScanCreated }: NewScanFormProps) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // --- Form state ---
  const [title, setTitle] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [depth, setDepth] = useState(3);
  const [scopePatterns, setScopePatterns] = useState("");
  const [excludePatterns, setExcludePatterns] = useState("");
  const [ignoreRobots, setIgnoreRobots] = useState(false);
  const [allowExternal, setAllowExternal] = useState(false);
  const [delayMs, setDelayMs] = useState(500);
  const [concurrency, setConcurrency] = useState(1);

  // Login (optional) — two modes:
  //   1. Automated form-login (loginUrl + user + password)
  //   2. Manual browser login (user clicks "Launch Browser", logs in
  //      manually — including CAPTCHA/2FA/SSO — then captures the session)
  const [loginUrl, setLoginUrl] = useState("");
  const [loginUser, setLoginUser] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginUserField, setLoginUserField] = useState("username");
  const [loginPassField, setLoginPassField] = useState("password");
  // Manual browser login state. After capture, this holds the path to the
  // Playwright storageState JSON file the scanner will load via --load-state.
  const [manualLoginStatePath, setManualLoginStatePath] = useState<string | null>(null);
  const [manualLoginLaunching, setManualLoginLaunching] = useState(false);
  const [manualLoginError, setManualLoginError] = useState<string | null>(null);
  const [manualLoginCaptured, setManualLoginCaptured] = useState(false);

  // Reference files (contents, not paths) — pre-filled from settings.
  const [headersFileContent, setHeadersFileContent] = useState("");
  const [payloadsFileContent, setPayloadsFileContent] = useState("");
  const [wordlistFileContent, setWordlistFileContent] = useState("");
  const [weakCiphersFileContent, setWeakCiphersFileContent] = useState("");
  const [defaultsLoaded, setDefaultsLoaded] = useState(false);
  const [refTab, setRefTab] = useState<"whitelist" | "payloads" | "wordlist" | "weak-ciphers">("whitelist");

  // LLM-assisted scanning (optional): the LLM analyses crawl results
  // mid-scan and suggests priority inputs + custom payloads.
  const [llmAssist, setLlmAssist] = useState(false);

  // AI Content Analysis during scan (optional): after the crawl (+ dir-brute
  // re-crawl), re-visit EVERY in-scope page and LLM-analyze it for
  // interesting content. 1 LLM call per page — off by default.
  const [llmInteresting, setLlmInteresting] = useState(false);

  // LLM vulnerability analysis (optional): after active scanning, the
  // LLM reviews findings to detect vulns regex missed + classify OWASP.
  const [llmAnalyze, setLlmAnalyze] = useState(false);

  // Custom HTTP headers (optional): JSON key-value pairs sent with every
  // request. Use for CSRF tokens, Authorization headers, etc.
  const [customHeaders, setCustomHeaders] = useState("");

  // Access Control Testing (optional): forced browsing — clear cookies,
  // re-visit URLs, flag accessible-without-auth as A01 BAC.
  const [testAccessControl, setTestAccessControl] = useState(false);

  // Deep Logic Testing (optional): business-logic flaw detection.
  const [deepLogic, setDeepLogic] = useState(false);

  // File Upload Testing (optional): exercises <input type=file> with
  // extension-bypass / MIME-spoof / polyglot / XSS probes (A05). Accepted
  // dangerous uploads surface as findings; landing URLs go to the Uploads tab.
  const [testFileUpload, setTestFileUpload] = useState(false);
  // Base filename for upload probes — scanner appends .php/.phtml/.svg/etc.
  // Pick something unique so you can grep for it server-side.
  const [uploadBaseFilename, setUploadBaseFilename] = useState("");

  // Crawl Only mode — skip active fuzzing entirely. Just crawl + headers +
  // SSL + attack surface + directory brute. Use to plan your scan.
  const [crawlOnly, setCrawlOnly] = useState(false);
  const [crawlLlmUrls, setCrawlLlmUrls] = useState(false);
  const [skipDirBrute, setSkipDirBrute] = useState(false);

  // Authenticated scan toggle. When CHECKED, the scanner will use the
  // login credentials/session and enable session-expiry detection.
  // When UNCHECKED, the scanner passes --ignore-session-expiry (the
  // scanner will NEVER pause for re-login, even if it sees a 401 or
  // redirect to /login — which is normal for unauthenticated visitors).
  // Default: checked if loginUrl is set, unchecked otherwise.
  const [authenticatedScan, setAuthenticatedScan] = useState(false);

  // --- Manual browser login handlers ---
  // The flow is:
  //   1. User clicks "Launch Browser to Login" — we POST to
  //      /api/manual-login/launch (which starts the manual-login mini-service
  //      on port 3001 with a headed Chromium window pointing at loginUrl).
  //   2. User logs in manually in the popup browser (handles CAPTCHA, 2FA,
  //      SSO, etc.).
  //   3. User clicks "Capture Session" — the mini-service saves the
  //      Playwright storageState (cookies + localStorage) to a JSON file
  //      and returns the path. We store it in manualLoginStatePath.
  //   4. When the user submits the scan, we pass manualLoginStatePath +
  //      manualLoginState=true in the POST body. The API route stores it
  //      on the Scan row; the scanner-runner passes it to scanner.py via
  //      --load-state.
  const handleLaunchManualLogin = async () => {
    if (!loginUrl.trim()) {
      setManualLoginError("Enter a Login URL first — the browser needs to know where to navigate.");
      return;
    }
    setManualLoginLaunching(true);
    setManualLoginError(null);
    setManualLoginCaptured(false);
    try {
      const resp = await fetch("/api/manual-login/launch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ loginUrl: loginUrl.trim() }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `HTTP ${resp.status}`);
      }
      // The mini-service is now opening a browser window. Tell the user
      // to log in manually, then click "Capture Session".
      setManualLoginCaptured(false);
    } catch (e) {
      setManualLoginError(e instanceof Error ? e.message : String(e));
    } finally {
      setManualLoginLaunching(false);
    }
  };

  const handleCaptureManualLogin = async () => {
    setManualLoginLaunching(true);
    setManualLoginError(null);
    try {
      const resp = await fetch("/api/manual-login/capture", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `HTTP ${resp.status}`);
      }
      setManualLoginStatePath(data.statePath);
      setManualLoginCaptured(true);
    } catch (e) {
      setManualLoginError(e instanceof Error ? e.message : String(e));
    } finally {
      setManualLoginLaunching(false);
    }
  };

  // Load default whitelist + payloads from settings on mount.
  useEffect(() => {
    fetch("/api/settings")
      .then((r) => r.json())
      .then((data) => {
        if (data.settings?.defaultWhitelist) {
          setHeadersFileContent(data.settings.defaultWhitelist);
        }
        if (data.settings?.defaultPayloads) {
          setPayloadsFileContent(data.settings.defaultPayloads);
        }
        if (data.settings?.defaultWordlist) {
          setWordlistFileContent(data.settings.defaultWordlist);
        }
        if (data.settings?.defaultWeakCiphers) {
          setWeakCiphersFileContent(data.settings.defaultWeakCiphers);
        }
        setDefaultsLoaded(true);
      })
      .catch(() => setDefaultsLoaded(true));
  }, []);

  const handleUseDefaults = () => {
    // Re-fetch from settings (in case they were updated in another tab).
    fetch("/api/settings")
      .then((r) => r.json())
      .then((data) => {
        setHeadersFileContent(data.settings?.defaultWhitelist || "");
        setPayloadsFileContent(data.settings?.defaultPayloads || "");
        setWordlistFileContent(data.settings?.defaultWordlist || "");
        setWeakCiphersFileContent(data.settings?.defaultWeakCiphers || "");
      });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!targetUrl.trim()) {
      setError("Target URL is required");
      return;
    }
    if (!/^https?:\/\//i.test(targetUrl.trim())) {
      setError("Target URL must start with http:// or https://");
      return;
    }

    // Login validation mirrors the API.
    // A captured session (manual-browser login) is AUTHORITATIVE and does
    // NOT require a username/password — this is the only way to auth
    // OAuth/SSO flows (Microsoft, Google, SAML) where the login page
    // redirects to an IdP and a form login can't succeed.
    if (loginUrl.trim() && !manualLoginCaptured && !loginUser.trim()) {
      setError("Login user is required when login URL is set (or use ‘Launch Browser to Login’ to capture a session instead)");
      return;
    }
    if (loginUrl.trim() && !manualLoginCaptured && !loginPassword) {
      setError("Login password is required when login URL is set (or use ‘Launch Browser to Login’ to capture a session instead)");
      return;
    }

    setSubmitting(true);
    try {
      const resp = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: title.trim() || null,
          targetUrl: targetUrl.trim(),
          depth,
          scopePatterns: scopePatterns.trim(),
          excludePatterns: excludePatterns.trim(),
          ignoreRobots,
          allowExternal,
          delayMs,
          concurrency,
          loginUrl: loginUrl.trim() || null,
          loginUser: loginUser.trim() || null,
          loginPassword: loginPassword || null,
          loginUserField: loginUserField.trim() || "username",
          loginPassField: loginPassField.trim() || "password",
          // Manual browser login state (from "Launch Browser to Login" button).
          // If captured, the scanner loads this Playwright storageState file
          // via --load-state so it scans as the authenticated user.
          manualLoginState: manualLoginCaptured && manualLoginStatePath ? true : false,
          manualLoginStatePath: manualLoginCaptured ? manualLoginStatePath : null,
          headersFileContent: headersFileContent.trim() || null,
          payloadsFileContent: payloadsFileContent.trim() || null,
          wordlistFileContent: wordlistFileContent.trim() || null,
          weakCiphersFileContent: weakCiphersFileContent.trim() || null,
          llmAssist,
          llmInteresting,
          llmAnalyze,
          customHeaders: customHeaders.trim() || null,
          testAccessControl,
          deepLogic,
          testFileUpload,
          uploadBaseFilename: uploadBaseFilename.trim() || null,
          // When NOT an authenticated scan, the scanner-runner will pass
          // --ignore-session-expiry (disables session-expiry detection).
          // This prevents false pauses on unauthenticated scans where the
          // target redirects everything to /login.
          authenticatedScan,
          crawlOnly,
          crawlLlmUrls,
          skipDirBrute,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `HTTP ${resp.status}`);
      }
      onScanCreated(data.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6 max-w-3xl">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">New Scan</h2>
        <p className="text-sm text-muted-foreground">
          Configure and launch a new web security assessment. All findings
          will be UNVERIFIED — manual confirmation required.
        </p>
      </div>

      {/* Quick-start: scan the built-in vulnerable demo site */}
      <Alert>
        <Rocket className="h-4 w-4" />
        <AlertTitle>Try the built-in vulnerable test site</AlertTitle>
        <AlertDescription className="flex items-center justify-between">
          <span>
            Click "Fill demo target" to configure a full-feature scan of the
            deliberately vulnerable test site (XSS, SQLi, CMDi, SSRF, XXE,
            SSTI, uploads, JWT, vulnerable JS, dir-brute targets + more).
            Login is left blank so you can demo the manual browser login
            (admin / admin123) separately.
          </span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="ml-4 shrink-0"
            onClick={() => {
              setTargetUrl("http://localhost:3000/api/demo");
              setDepth(3);
              setDelayMs(100);
              setLlmAssist(true);
              setLlmInteresting(true);
              setLlmAnalyze(true);
              setTestFileUpload(true);
              setUploadBaseFilename("demodemo");
              // Login fields deliberately left empty — the browser-login
              // popup (Launch Browser to Login) is part of the demo.
            }}
          >
            Fill demo target
          </Button>
        </AlertDescription>
      </Alert>

      {error && (
        <Alert variant="destructive">
          <ShieldAlert className="h-4 w-4" />
          <AlertTitle>Validation error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Target */}
      <Card>
        <CardHeader>
          <CardTitle>Target</CardTitle>
          <CardDescription>
            The URL to scan. Must include the scheme (http:// or https://).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="title">Scan Title (optional)</Label>
            <Input
              id="title"
              placeholder="e.g. Production web app — Q1 pentest"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="font-medium"
            />
            <p className="text-xs text-muted-foreground">
              A friendly name to identify this scan in the dashboard. If left
              blank, the target URL is shown.
            </p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="targetUrl">Target URL *</Label>
            <Input
              id="targetUrl"
              placeholder="https://target.example.com"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              required
              className="font-mono"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="depth">Crawl Depth</Label>
            <Input
              id="depth"
              type="number"
              min={0}
              max={10}
              value={depth}
              onChange={(e) => setDepth(parseInt(e.target.value) || 3)}
            />
            <p className="text-xs text-muted-foreground">
              How many links deep to crawl (default: 3). Higher = slower but
              more coverage.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Scan Mode — between Target and Scope */}
      <Card>
        <CardHeader>
          <CardTitle>Scan Mode</CardTitle>
          <CardDescription>
            Choose what the scanner should do. Presets configure the options
            below automatically — you can still fine-tune individual toggles.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Preset buttons */}
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" size="sm"
              onClick={() => {
                setCrawlOnly(false); setTestAccessControl(false);
                setCrawlLlmUrls(false); setDeepLogic(false); setSkipDirBrute(false);
              }}
              className="border-blue-300 text-blue-700 dark:border-blue-700 dark:text-blue-300"
            >
              Normal (Active Scan)
            </Button>
            <Button type="button" variant="outline" size="sm"
              onClick={() => {
                setCrawlOnly(true); setTestAccessControl(false);
                setCrawlLlmUrls(false); setDeepLogic(false); setSkipDirBrute(true);
              }}
              className="border-green-300 text-green-700 dark:border-green-700 dark:text-green-300"
            >
              Crawl Only
            </Button>
            <Button type="button" variant="outline" size="sm"
              onClick={() => {
                setCrawlOnly(true); setTestAccessControl(false);
                setCrawlLlmUrls(false); setDeepLogic(false); setSkipDirBrute(false);
              }}
              className="border-green-300 text-green-700 dark:border-green-700 dark:text-green-300"
            >
              Crawl + Dir Bust
            </Button>
            <Button type="button" variant="outline" size="sm"
              onClick={() => {
                setCrawlOnly(false); setTestAccessControl(true);
                setCrawlLlmUrls(false); setDeepLogic(false); setSkipDirBrute(false);
              }}
              className="border-orange-300 text-orange-700 dark:border-orange-700 dark:text-orange-300"
            >
              Test BAC
            </Button>
            <Button type="button" variant="outline" size="sm"
              onClick={() => {
                setCrawlOnly(false); setTestAccessControl(false);
                setCrawlLlmUrls(true); setDeepLogic(false); setSkipDirBrute(false);
              }}
              className="border-purple-300 text-purple-700 dark:border-purple-700 dark:text-purple-300"
            >
              LLM Crawl URLs
            </Button>
            <Button type="button" variant="outline" size="sm"
              onClick={() => {
                setCrawlOnly(false); setTestAccessControl(false);
                setCrawlLlmUrls(false); setDeepLogic(true); setSkipDirBrute(false);
              }}
              className="border-pink-300 text-pink-700 dark:border-pink-700 dark:text-pink-300"
            >
              Deep Logic
            </Button>
          </div>

          {/* Individual toggles */}
          <div className="space-y-2 pt-2 border-t">
            <div className="flex items-center justify-between rounded-lg border-2 p-3"
              style={{borderColor: crawlOnly ? "rgb(34 197 94)" : "rgb(229 231 235)"}}>
              <div className="space-y-0.5">
                <Label htmlFor="crawlOnly" className="text-sm font-medium">Crawl Only Mode</Label>
                <p className="text-xs text-muted-foreground">
                  {crawlOnly ? "Skips active fuzzing. Crawls + headers + SSL + attack surface." : "Crawl + headers + SSL + attack surface — NO payload injection."}
                </p>
              </div>
              <Switch id="crawlOnly" checked={crawlOnly} onCheckedChange={setCrawlOnly} />
            </div>
            <div className="flex items-center justify-between rounded-lg border-2 p-3"
              style={{borderColor: skipDirBrute ? "rgb(100 116 139)" : "rgb(229 231 235)"}}>
              <div className="space-y-0.5">
                <Label htmlFor="skipDirBrute" className="text-sm font-medium">Skip Directory Brute-force</Label>
                <p className="text-xs text-muted-foreground">
                  {skipDirBrute ? "Skips directory brute-force (faster recon)." : "Skip trying 70+ common directory paths. Faster but less coverage."}
                </p>
              </div>
              <Switch id="skipDirBrute" checked={skipDirBrute} onCheckedChange={setSkipDirBrute} />
            </div>
            <div className="flex items-center justify-between rounded-lg border-2 p-3"
              style={{borderColor: testAccessControl ? "rgb(249 115 22)" : "rgb(229 231 235)"}}>
              <div className="space-y-0.5">
                <Label htmlFor="testAccessControl" className="text-sm font-medium">Test Broken Access Control (A01)</Label>
                <p className="text-xs text-muted-foreground">
                  {testAccessControl ? "Clears cookies + re-visits URLs to find BAC." : "Forced browsing — clear cookies, re-visit in-scope URLs, flag accessible-without-auth."}
                </p>
              </div>
              <Switch id="testAccessControl" checked={testAccessControl} onCheckedChange={setTestAccessControl} />
            </div>
            <div className="flex items-center justify-between rounded-lg border-2 p-3"
              style={{borderColor: crawlLlmUrls ? "rgb(168 85 247)" : "rgb(229 231 235)"}}>
              <div className="space-y-0.5">
                <Label htmlFor="crawlLlmUrls" className="text-sm font-medium">Auto-crawl LLM-suggested URLs</Label>
                <p className="text-xs text-muted-foreground">
                  {crawlLlmUrls ? "Crawls same-domain URLs suggested by LLM planner." : "Auto-crawl LLM-suggested URLs on same domain. Off by default (scope safety)."}
                </p>
              </div>
              <Switch id="crawlLlmUrls" checked={crawlLlmUrls} onCheckedChange={setCrawlLlmUrls} />
            </div>
            <div className="flex items-center justify-between rounded-lg border-2 p-3"
              style={{borderColor: deepLogic ? "rgb(236 72 153)" : "rgb(229 231 235)"}}>
              <div className="space-y-0.5">
                <Label htmlFor="deepLogic" className="text-sm font-medium">Deep Logic Scan (A06)</Label>
                <p className="text-xs text-muted-foreground">
                  {deepLogic ? "Mutates numeric params to detect business logic flaws." : "EXPERIMENTAL: mutates numeric params (negative, zero, extreme). SLOW."}
                </p>
              </div>
              <Switch id="deepLogic" checked={deepLogic} onCheckedChange={setDeepLogic} />
            </div>
            <div className="flex items-center justify-between rounded-lg border-2 p-3"
              style={{borderColor: testFileUpload ? "rgb(217 119 6)" : "rgb(229 231 235)"}}>
              <div className="space-y-0.5">
                <Label htmlFor="testFileUpload" className="text-sm font-medium">Test File Uploads (A05)</Label>
                <p className="text-xs text-muted-foreground">
                  {testFileUpload
                    ? "Uploads probe files (.php/.phtml/.svg/etc) to <input type=file> fields. Landing URLs shown in the Uploads tab."
                    : "Extension-bypass / MIME-spoof / polyglot / XSS probes against file inputs. Off by default."}
                </p>
              </div>
              <Switch id="testFileUpload" checked={testFileUpload} onCheckedChange={setTestFileUpload} />
            </div>
            {testFileUpload && (
              <div className="space-y-1 rounded-lg border-2 border-dashed p-3"
                style={{borderColor: "rgb(217 119 6)"}}>
                <Label htmlFor="uploadBaseFilename">Base filename for upload probes</Label>
                <Input
                  id="uploadBaseFilename"
                  placeholder="webrecon_upload"
                  value={uploadBaseFilename}
                  onChange={(e) => setUploadBaseFilename(e.target.value)}
                  className="font-mono"
                />
                <p className="text-xs text-muted-foreground">
                  Scanner generates <code>&lt;base&gt;.php</code>, <code>.phtml</code>,
                  <code> .svg</code>, etc. Pick something unique so you can grep for it server-side.
                  Leave blank to use the default (<code>webrecon_upload</code>).
                </p>
              </div>
            )}

            {/* --- LLM toggles (moved here from the separate LLM card) --- */}
            <div className="pt-2 border-t">
              <p className="text-xs font-medium text-muted-foreground mb-2">
                <Bot className="inline w-3 h-3 mr-1" />LLM-Assisted Scanning (optional)
              </p>
            </div>
            <div className="flex items-center justify-between rounded-lg border-2 p-3"
              style={{borderColor: llmAssist ? "rgb(168 85 247)" : "rgb(229 231 235)"}}>
              <div className="space-y-0.5">
                <Label htmlFor="llmAssist" className="text-sm font-medium">LLM-assisted planning (--llm-assist)</Label>
                <p className="text-xs text-muted-foreground">
                  {llmAssist ? "After crawling, the LLM suggests priority inputs + custom payloads tailored to the app." : "After crawling, the LLM suggests priority inputs + custom payloads. Shown in the LLM Plan tab."}
                </p>
              </div>
              <Switch id="llmAssist" checked={llmAssist} onCheckedChange={setLlmAssist} />
            </div>
            <div className="flex items-center justify-between rounded-lg border-2 p-3"
              style={{borderColor: llmInteresting ? "rgb(168 85 247)" : "rgb(229 231 235)"}}>
              <div className="space-y-0.5">
                <Label htmlFor="llmInteresting" className="text-sm font-medium">AI Content Analysis during scan (--llm-interesting)</Label>
                <p className="text-xs text-muted-foreground">
                  {llmInteresting
                    ? "Re-visits EVERY crawled page (incl. dir-brute finds) with your session and LLM-analyzes each for creds/hidden endpoints/comments. No page cap — 1 LLM call per page."
                    : "After the crawl, re-visit every discovered page and ask the LLM what's interesting. No 20-page cap. Slow (1 LLM call per page) — off by default."}
                </p>
              </div>
              <Switch id="llmInteresting" checked={llmInteresting} onCheckedChange={setLlmInteresting} />
            </div>
            <div className="flex items-center justify-between rounded-lg border-2 p-3"
              style={{borderColor: llmAnalyze ? "rgb(168 85 247)" : "rgb(229 231 235)"}}>
              <div className="space-y-0.5">
                <Label htmlFor="llmAnalyze" className="text-sm font-medium">LLM vulnerability analysis (--llm-analyze)</Label>
                <p className="text-xs text-muted-foreground">
                  {llmAnalyze ? "After active scanning, the LLM reviews findings to classify OWASP + detect false positives." : "After scanning, the LLM classifies findings, flags false positives, and suggests follow-up tests. Shown in the LLM Analysis tab."}
                </p>
              </div>
              <Switch id="llmAnalyze" checked={llmAnalyze} onCheckedChange={setLlmAnalyze} />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Scope */}
      <Card>
        <CardHeader>
          <CardTitle>Scope</CardTitle>
          <CardDescription>
            Restrict the scan to specific URL patterns. Leave blank to scan
            the entire target domain.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="scope">Scope Patterns</Label>
            <Input
              id="scope"
              placeholder="/app/*,/api/v1/*"
              value={scopePatterns}
              onChange={(e) => setScopePatterns(e.target.value)}
              className="font-mono"
            />
            <p className="text-xs text-muted-foreground">
              Comma-separated globs. Only matching URLs are crawled/fuzzed.
            </p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="exclude">Exclude Patterns</Label>
            <Input
              id="exclude"
              placeholder="*/logout,*/delete,*.pdf"
              value={excludePatterns}
              onChange={(e) => setExcludePatterns(e.target.value)}
              className="font-mono"
            />
            <p className="text-xs text-muted-foreground">
              Comma-separated globs. Matching URLs are NEVER fuzzed (use for
              destructive endpoints).
            </p>
          </div>
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label htmlFor="ignoreRobots">Ignore robots.txt</Label>
              <p className="text-xs text-muted-foreground">
                Skip robots.txt Disallow rules. Off by default (respected).
              </p>
            </div>
            <Switch
              id="ignoreRobots"
              checked={ignoreRobots}
              onCheckedChange={setIgnoreRobots}
            />
          </div>
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label htmlFor="allowExternal">Allow External Links</Label>
              <p className="text-xs text-muted-foreground">
                Follow links to other domains. DANGEROUS — only use with
                explicit authorisation.
              </p>
            </div>
            <Switch
              id="allowExternal"
              checked={allowExternal}
              onCheckedChange={setAllowExternal}
            />
          </div>
        </CardContent>
      </Card>

      {/* Rate Limiting */}
      <Card>
        <CardHeader>
          <CardTitle>Rate Limiting</CardTitle>
          <CardDescription>
            Control request speed to avoid overwhelming the target or
            triggering WAF rules. A ±10% jitter is auto-applied.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label htmlFor="delayMs">Delay (ms)</Label>
            <Input
              id="delayMs"
              type="number"
              min={0}
              max={60000}
              value={delayMs}
              onChange={(e) => setDelayMs(parseInt(e.target.value) || 500)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="concurrency">Concurrency</Label>
            <Select
              value={String(concurrency)}
              onValueChange={(v) => setConcurrency(parseInt(v))}
            >
              <SelectTrigger id="concurrency">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1">1 (sequential — safest)</SelectItem>
                <SelectItem value="2">2 (parallel)</SelectItem>
                <SelectItem value="3">3 (max — aggressive)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Login (optional) */}
      <Card>
        <CardHeader>
          <CardTitle>
            Login (Optional){" "}
            <Badge variant="secondary" className="ml-2">
              authenticated scan
            </Badge>
          </CardTitle>
          <CardDescription>
            Log in before scanning to assess the authenticated attack
            surface. Password is masked in logs and NOT persisted to disk.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Authenticated scan toggle — CRITICAL for unauthenticated scans */}
          <div className="flex items-center justify-between rounded-lg border-2 p-3"
               style={{borderColor: authenticatedScan ? "rgb(59 130 246)" : "rgb(229 231 235)"}}>
            <div className="space-y-0.5">
              <Label htmlFor="authenticatedScan" className="text-sm font-medium">
                Authenticated Scan
              </Label>
              <p className="text-xs text-muted-foreground">
                {authenticatedScan
                  ? "Session-expiry detection is ENABLED. The scanner will pause if it detects a login redirect (401/302→/login). Use this when you provided login credentials."
                  : "Session-expiry detection is DISABLED. The scanner will NEVER pause for re-login — even if the target redirects to /login. Use this for unauthenticated scans."}
              </p>
            </div>
            <Switch
              id="authenticatedScan"
              checked={authenticatedScan}
              onCheckedChange={setAuthenticatedScan}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="loginUrl">Login URL</Label>
            <Input
              id="loginUrl"
              placeholder="https://app.example.com/login"
              value={loginUrl}
              onChange={(e) => setLoginUrl(e.target.value)}
              className="font-mono"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="loginUser">Username</Label>
              <Input
                id="loginUser"
                placeholder="alice"
                value={loginUser}
                onChange={(e) => setLoginUser(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="loginPassword">Password</Label>
              <Input
                id="loginPassword"
                type="password"
                placeholder="••••••••"
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="loginUserField">Username Field Name</Label>
              <Input
                id="loginUserField"
                placeholder="username"
                value={loginUserField}
                onChange={(e) => setLoginUserField(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Common alternatives: user, email, login
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="loginPassField">Password Field Name</Label>
              <Input
                id="loginPassField"
                placeholder="password"
                value={loginPassField}
                onChange={(e) => setLoginPassField(e.target.value)}
              />
            </div>
          </div>

          {/* --- Manual Browser Login --- */}
          {/* Divider */}
          <div className="relative py-2">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-card px-2 text-muted-foreground">
                or — manual browser login (CAPTCHA / 2FA / SSO)
              </span>
            </div>
          </div>
          <div className="space-y-3">
            <p className="text-xs text-muted-foreground">
              Use this for sites where automated form-login fails — CAPTCHA,
              2FA, SSO, or non-standard login flows. A real Chromium window
              opens at the Login URL above; you log in manually; then click
              <strong> Capture Session</strong> to save cookies + localStorage.
              The scan will run as your authenticated session.
            </p>
            <div className="flex flex-wrap gap-2 items-center">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={handleLaunchManualLogin}
                disabled={manualLoginLaunching || !loginUrl.trim()}
              >
                {manualLoginLaunching ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <KeyRound className="w-4 h-4 mr-2" />
                )}
                Launch Browser to Login
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={handleCaptureManualLogin}
                disabled={manualLoginLaunching}
              >
                Capture Session
              </Button>
              {manualLoginCaptured && (
                <Badge variant="secondary" className="bg-green-50 text-green-700 dark:bg-green-950 dark:text-green-300">
                  <CheckCircle2 className="w-3 h-3 mr-1" />
                  Session captured — scan will run authenticated
                </Badge>
              )}
            </div>
            {manualLoginError && (
              <Alert variant="destructive">
                <AlertDescription className="text-xs">{manualLoginError}</AlertDescription>
              </Alert>
            )}
            {manualLoginStatePath && (
              <p className="text-xs text-muted-foreground font-mono break-all">
                State file: {manualLoginStatePath}
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Reference Files */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>Reference Files</span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleUseDefaults}
              disabled={!defaultsLoaded}
            >
              <DownloadCloud className="w-4 h-4 mr-2" />
              Load from Settings
            </Button>
          </CardTitle>
          <CardDescription>
            Whitelist (header policy), payloads, wordlist (directory
            brute-force), and weak-cipher policy. Pre-filled from Settings;
            override here for this scan only. If left blank, the scanner uses
            the built-in defaults.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Inner tabs keep all four reference files in one compact block
              (forceMount so switching tabs never loses textarea state). */}
          <Tabs value={refTab} onValueChange={(v) => setRefTab(v as typeof refTab)}>
            <TabsList className="flex flex-wrap h-auto justify-start gap-1">
              <TabsTrigger value="whitelist">Whitelist</TabsTrigger>
              <TabsTrigger value="payloads">Payloads</TabsTrigger>
              <TabsTrigger value="wordlist">Wordlist</TabsTrigger>
              <TabsTrigger value="weak-ciphers">Weak Ciphers</TabsTrigger>
            </TabsList>

            <TabsContent forceMount value="whitelist" className={refTab === "whitelist" ? "mt-3 space-y-2" : "hidden"}>
              <Label htmlFor="headers">Whitelist (headers policy)</Label>
              <Textarea
                id="headers"
                placeholder={
                  "Strict-Transport-Security: max-age=31536000\nX-Content-Type-Options: nosniff\nX-Frame-Options: DENY|SAMEORIGIN"
                }
                value={headersFileContent}
                onChange={(e) => setHeadersFileContent(e.target.value)}
                className="font-mono text-xs min-h-[160px]"
              />
              <p className="text-xs text-muted-foreground">
                Format: <code>Header-Name</code> (presence-only) or{" "}
                <code>Header-Name: expected-value</code> (policy) or{" "}
                <code>Header-Name: v1|v2</code> (alternatives).
              </p>
            </TabsContent>

            <TabsContent forceMount value="payloads" className={refTab === "payloads" ? "mt-3 space-y-2" : "hidden"}>
              <Label htmlFor="payloads">Payloads</Label>
              <Textarea
                id="payloads"
                placeholder={"<script>alert(1)</script>\n' OR '1'='1"}
                value={payloadsFileContent}
                onChange={(e) => setPayloadsFileContent(e.target.value)}
                className="font-mono text-xs min-h-[160px]"
              />
              <p className="text-xs text-muted-foreground">
                One payload per line. Lines starting with # are comments.
              </p>
            </TabsContent>

            <TabsContent forceMount value="wordlist" className={refTab === "wordlist" ? "mt-3 space-y-2" : "hidden"}>
              <Label htmlFor="wordlist">Wordlist (directory brute-force)</Label>
              <Textarea
                id="wordlist"
                placeholder={"admin\n.git/config\n.env\nwp-login.php"}
                value={wordlistFileContent}
                onChange={(e) => setWordlistFileContent(e.target.value)}
                className="font-mono text-xs min-h-[160px]"
              />
              <p className="text-xs text-muted-foreground">
                One path per line. Fuzzed against the root <strong>and</strong> each
                discovered path prefix (e.g. <code>/v1/&lt;entry&gt;</code>). Lines
                starting with # are comments.
              </p>
            </TabsContent>

            <TabsContent forceMount value="weak-ciphers" className={refTab === "weak-ciphers" ? "mt-3 space-y-2" : "hidden"}>
              <Label htmlFor="weak-ciphers">Weak Cipher &amp; TLS Protocol Policy</Label>
              <Textarea
                id="weak-ciphers"
                placeholder={"TLSv1.0 | * | medium\nNULL | * | high\nTLSv1.1 | * | medium"}
                value={weakCiphersFileContent}
                onChange={(e) => setWeakCiphersFileContent(e.target.value)}
                className="font-mono text-xs min-h-[160px]"
              />
              <p className="text-xs text-muted-foreground">
                Format: <code>kind | pattern | severity</code> (kind = TLS version or
                cipher). Applied to this scan only.
              </p>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Custom HTTP Headers */}
      <Card>
        <CardHeader>
          <CardTitle>Custom HTTP Headers (Optional)</CardTitle>
          <CardDescription>
            JSON object of headers sent with EVERY request during the scan.
            Use for CSRF tokens, Authorization headers, custom auth cookies
            that the login flow doesn't capture, internal API keys, etc.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            value={customHeaders}
            onChange={(e) => setCustomHeaders(e.target.value)}
            placeholder={'{\n  "X-CSRF-Token": "abc123",\n  "Authorization": "Bearer eyJ...",\n  "X-Client": "pentest"\n}'}
            className="font-mono text-xs min-h-[120px]"
          />
          <p className="text-xs text-muted-foreground">
            Must be valid JSON. Keys are header names, values are header
            values. Applied via Playwright's <code>set_extra_http_headers()</code>.
          </p>
        </CardContent>
      </Card>

      {/* Submit */}
      <div className="flex items-center gap-3">
        <Button type="submit" disabled={submitting} size="lg">
          {submitting ? (
            <>
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              Launching...
            </>
          ) : (
            <>
              <Rocket className="w-4 h-4 mr-2" />
              Launch Scan
            </>
          )}
        </Button>
        <p className="text-xs text-muted-foreground">
          By launching, you confirm you have written authorisation to test
          the target.
        </p>
      </div>
    </form>
  );
}
