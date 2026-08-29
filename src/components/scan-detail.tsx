"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
} from "@/components/ui/tabs";
import {
  ArrowLeft,
  Square,
  ExternalLink,
  Download,
  FileText,
  Activity,
  FileWarning,
  AlertCircle,
  Camera,
  FileCode,
  Bot,
  Send,
  Loader2,
  ShieldCheck,
  Crosshair,
  Network,
  Target,
  Copy,
  KeyRound,
  FileSearch,
  Server,
  RefreshCw,
  Globe,
  CheckCircle2,
  FlaskConical,
  XCircle,
  Wand2,
  SkipForward,
  Skull,
  Lock,
  ShieldAlert,
  Upload,
  Palette,
} from "lucide-react";
import type {
  ScanDetailResponse,
  ScanSummary,
  TrailEntry,
  ScanDoneEvent,
  ScanFinding,
} from "@/lib/types";

interface ScanDetailProps {
  scanId: string;
  onBack: () => void;
  /** Navigate to a different scan's detail view (used by Kill Chrome & Restart). */
  onNavigateToScan?: (scanId: string) => void;
}

/**
 * Live view for a single scan.
 *
 * Five sub-tabs:
 *   1. Logs      — real-time streaming of execution_trail.jsonl via SSE.
 *   2. OWASP     — OWASP Top 10 (2025) coverage panel showing which
 *                  categories have checks and their status.
 *   3. Report    — iframe showing the generated report.html (when ready).
 *   4. Evidence  — file browser of the evidence/ directory.
 *   5. AI Chat   — chat with the LLM about the scan findings.
 */
export function ScanDetail({ scanId, onBack, onNavigateToScan }: ScanDetailProps) {
  const [detail, setDetail] = useState<ScanDetailResponse | null>(null);
  const [logs, setLogs] = useState<TrailEntry[]>([]);
  const [done, setDone] = useState<ScanDoneEvent | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<
    "logs" | "headers" | "ssl" | "security-checks" | "owasp" | "interesting" | "sitemap" | "inventory" | "javascripts" | "css" | "directory" | "deep-logic" | "uploads" | "manifest" | "attack-surface" | "llm-plan" | "report" | "evidence" | "llm-analysis" | "chat"
  >("logs");
  const logEndRef = useRef<HTMLDivElement>(null);
  // Ref on the ScrollArea root so we can scroll its internal Viewport
  // directly (NOT via scrollIntoView, which also scrolls the whole page).
  const logScrollRef = useRef<HTMLDivElement>(null);
  // Tracks whether the user is parked at the bottom of the log box. We only
  // auto-follow new output when they are — scrolling up to read old logs
  // should not get yanked back down (standard terminal behaviour).
  const logPinnedRef = useRef(true);

  const fetchDetail = useCallback(async () => {
    try {
      const resp = await fetch(`/api/scans/${scanId}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data: ScanDetailResponse = await resp.json();
      setDetail(data);
      return data;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return null;
    }
  }, [scanId]);

  useEffect(() => {
    fetchDetail();
    const interval = setInterval(() => {
      fetchDetail().then((d) => {
        // Keep polling while the scan is running, pending, OR paused.
        // Paused scans need continued polling so the UI detects when the
        // user has completed manual re-login and clicked "Resume Scan"
        // (which flips the status back to running on a NEW scan row).
        // Without this, the Live View freezes on the "paused" banner and
        // never refreshes to show the resumed scan's progress.
        if (
          d &&
          d.scan.status !== "running" &&
          d.scan.status !== "pending" &&
          d.scan.status !== "paused"
        ) {
          clearInterval(interval);
        }
      });
    }, 3000);
    return () => clearInterval(interval);
  }, [fetchDetail]);

  // Subscribe to SSE log stream on mount.
  // Auto-reconnects if the connection drops (browser throttling, network
  // hiccup, dev server restart). Without this, logs freeze at some number
  // and don't update until the user manually refreshes.
  useEffect(() => {
    setLogs([]);
    setDone(null);
    let es: EventSource | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let lastLogTime = Date.now();
    let isClosed = false;

    const connect = () => {
      if (isClosed) return;
      es = new EventSource(`/api/scans/${scanId}/logs`);

      es.addEventListener("log", (e) => {
        lastLogTime = Date.now();
        try {
          const entry: TrailEntry = JSON.parse((e as MessageEvent).data);
          setLogs((prev) => [...prev, entry]);
        } catch {
          // ignore malformed
        }
      });

      es.addEventListener("done", (e) => {
        try {
          const doneEvent: ScanDoneEvent = JSON.parse((e as MessageEvent).data);
          setDone(doneEvent);
          fetchDetail();
        } catch {
          // ignore
        }
        es?.close();
        isClosed = true;
      });

      es.onerror = () => {
        // Connection dropped — close and try to reconnect after 3s
        es?.close();
        if (!isClosed) {
          reconnectTimer = setTimeout(connect, 3000);
        }
      };
    };

    connect();

    // Heartbeat: if no log received for 15s, reconnect
    // (catches silent connection drops where onerror doesn't fire)
    const heartbeat = setInterval(() => {
      if (isClosed) {
        clearInterval(heartbeat);
        return;
      }
      if (Date.now() - lastLogTime > 15000) {
        // No logs for 15s — connection might be dead. Force reconnect.
        es?.close();
        connect();
        lastLogTime = Date.now();
      }
    }, 2000);

    return () => {
      isClosed = true;
      es?.close();
      if (reconnectTimer) clearTimeout(reconnectTimer);
      clearInterval(heartbeat);
    };
  }, [scanId]);

  // Track whether the user is at the bottom of the log box (so we only
  // auto-follow when they haven't scrolled up to read something).
  useEffect(() => {
    const viewport = logScrollRef.current?.querySelector(
      '[data-slot="scroll-area-viewport"]',
    ) as HTMLElement | null;
    if (!viewport) return;
    const onScroll = () => {
      const distanceFromBottom =
        viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight;
      logPinnedRef.current = distanceFromBottom < 60;
    };
    viewport.addEventListener("scroll", onScroll, { passive: true });
    return () => viewport.removeEventListener("scroll", onScroll);
  }, []);

  // Auto-follow new log output. We scroll ONLY the log box's own Viewport
  // (NOT the document). The previous code used scrollIntoView(), which per
  // the CSSOM View spec scrolls EVERY scrollable ancestor including <body> —
  // that's what pinned the whole page to the bottom on every new line.
  useEffect(() => {
    const viewport = logScrollRef.current?.querySelector(
      '[data-slot="scroll-area-viewport"]',
    ) as HTMLElement | null;
    if (viewport && logPinnedRef.current) {
      viewport.scrollTo({ top: viewport.scrollHeight });
    }
  }, [logs]);

  const handleStop = async () => {
    if (!confirm("Stop this scan? Partial evidence will be saved.")) return;
    try {
      await fetch(`/api/scans/${scanId}/stop`, { method: "POST" });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const [forceCompleting, setForceCompleting] = useState(false);
  const handleForceComplete = async () => {
    if (!confirm(
      "Force-complete this scan?\n\n" +
      "This stops the scan immediately and marks it as 'completed' " +
      "(not 'interrupted'). Whatever findings were collected so far " +
      "will be saved and the report will be available.\n\n" +
      "Use this when the scan is stuck or taking too long and you " +
      "want to keep the partial results."
    )) return;
    setForceCompleting(true);
    setError(null);
    try {
      const resp = await fetch(`/api/scans/${scanId}/force-complete`, { method: "POST" });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
      // Refresh the scan detail to show the completed status
      await fetchDetail();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setForceCompleting(false);
    }
  };

  const [resuming, setResuming] = useState(false);
  const handleResume = async () => {
    if (!confirm("Resume this scan from where it stopped? Completed phases will be skipped.")) return;
    setResuming(true);
    setError(null);
    try {
      const resp = await fetch(`/api/scans/${scanId}/resume`, { method: "POST" });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
      // The API returns a NEW scan ID — navigate directly to it
      // instead of bouncing back to the dashboard.
      if (data.id && onNavigateToScan) {
        onNavigateToScan(data.id);
      } else {
        onBack();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setResuming(false);
    }
  };

  // --- Manual Browser Login state ---
  const [manualLoginActive, setManualLoginActive] = useState(false);
  const [manualLoginLaunching, setManualLoginLaunching] = useState(false);
  const [manualLoginCaptured, setManualLoginCaptured] = useState(false);
  const [manualLoginCapturing, setManualLoginCapturing] = useState(false);

  // Poll the manual-login service for status while a browser is open.
  useEffect(() => {
    if (!manualLoginActive) return;
    const interval = setInterval(async () => {
      try {
        const resp = await fetch(`/api/scans/${scanId}/manual-login/status`);
        const data = await resp.json();
        if (!data.active) {
          setManualLoginActive(false);
        }
      } catch {
        // ignore — the service might be unreachable
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [manualLoginActive, scanId]);

  const handleLaunchBrowser = async () => {
    const loginUrl = scan?.loginUrl || scan?.targetUrl || "";
    if (!loginUrl) {
      setError("No target URL to navigate to");
      return;
    }
    setManualLoginLaunching(true);
    setError(null);
    try {
      const resp = await fetch(`/api/scans/${scanId}/manual-login/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ loginUrl }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
      setManualLoginActive(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setManualLoginLaunching(false);
    }
  };

  const handleCaptureSession = async () => {
    setManualLoginCapturing(true);
    setError(null);
    try {
      const resp = await fetch(`/api/scans/${scanId}/manual-login/capture`, {
        method: "POST",
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
      setManualLoginActive(false);
      setManualLoginCaptured(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setManualLoginCapturing(false);
    }
  };

  const handleCancelManualLogin = async () => {
    try {
      await fetch(`/api/scans/${scanId}/manual-login/cancel`, { method: "POST" });
    } catch {
      // ignore
    }
    setManualLoginActive(false);
  };

  // --- Deep Logic Scan state ---
  const [deepLogicRunning, setDeepLogicRunning] = useState(false);
  const handleRunDeepLogic = async () => {
    if (!confirm(
      "Run Deep Logic scan? This is EXPERIMENTAL and SLOW — it will " +
      "mutate numeric parameters (negative, zero, extreme values) to " +
      "detect business logic flaws. A new scan will be launched with " +
      "the same configuration + deep logic enabled."
    )) return;
    setDeepLogicRunning(true);
    setError(null);
    try {
      const resp = await fetch(`/api/scans/${scanId}/run-deep-logic`, {
        method: "POST",
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
      // Navigate to the new scan.
      onBack();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setDeepLogicRunning(false);
    }
  };

  const scan = detail?.scan;
  const isRunning = scan?.status === "running" || scan?.status === "pending";
  const isPaused = scan?.pausedForRelogin || scan?.status === "paused";

  // --- Resume from pause (session expiry) ---
  const [resumingFromPause, setResumingFromPause] = useState(false);
  const handleResumeFromPause = async () => {
    if (!confirm("Resume scan with the new session? The scanner will load the captured cookies and continue.")) return;
    setResumingFromPause(true);
    setError(null);
    try {
      const resp = await fetch(`/api/scans/${scanId}/resume-from-pause`, { method: "POST" });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
      // The resume-from-pause endpoint creates a NEW scan row (the original
      // is marked interrupted). Tell the user the new scan ID so they can
      // find it on the dashboard.
      alert(`Scan resumed as new scan ${data.id}. You'll be taken back to the dashboard — click the new scan to watch its progress.`);
      onBack();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setResumingFromPause(false);
    }
  };

  // --- Skip Re-login & Continue (ignores session expiry entirely) ---
  const [skippingRelogin, setSkippingRelogin] = useState(false);
  const handleSkipRelogin = async () => {
    if (!confirm(
      "Skip re-login and continue?\n\n" +
      "This creates a new scan with session-expiry detection DISABLED.\n" +
      "The scanner will NOT pause for re-login, even if it sees a 401\n" +
      "or redirect to /login.\n\n" +
      "Use this for unauthenticated scans where the target redirects\n" +
      "everything to /login (which is normal, not a session expiry)."
    )) return;
    setSkippingRelogin(true);
    setError(null);
    try {
      const resp = await fetch(`/api/scans/${scanId}/skip-relogin`, { method: "POST" });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
      alert(`Scan resumed (session-expiry disabled) as new scan ${data.id}. Going back to dashboard.`);
      onBack();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSkippingRelogin(false);
    }
  };

  // --- Sync Status (reconcile DB with on-disk state after supervisor restart) ---
  const [syncingStatus, setSyncingStatus] = useState(false);
  const handleSyncStatus = async () => {
    setSyncingStatus(true);
    setError(null);
    try {
      const resp = await fetch(`/api/scans/${scanId}/sync-status`, {
        method: "POST",
      });
      const data = await resp.json();
      if (!data.ok) throw new Error(data.error || `HTTP ${resp.status}`);
      // Refresh the scan detail to show updated status
      await fetchDetail();
      alert(data.message || `Status: ${data.status}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSyncingStatus(false);
    }
  };

  // --- Kill All Chrome & Restart (nuclear option for frozen scans) ---
  const [killingChrome, setKillingChrome] = useState(false);
  const handleKillChromeRestart = async () => {
    if (!confirm(
      "Kill ALL Chrome processes and restart the scan?\n\n" +
      "This will:\n" +
      "  1. Force-kill ALL Chrome/Chromium processes (frees memory)\n" +
      "  2. Stop the current scan\n" +
      "  3. Start a fresh scan with the same config\n\n" +
      "Use this when the scan has been frozen for a long time and the\n" +
      "Stop button doesn't work."
    )) return;
    const ignoreExpiry = confirm(
      "Also disable session-expiry detection in the new scan?\n\n" +
      "Click OK to disable (recommended for unauthenticated scans).\n" +
      "Click Cancel to keep session-expiry detection enabled."
    );
    setKillingChrome(true);
    setError(null);
    try {
      const resp = await fetch(`/api/scans/${scanId}/kill-chrome-restart`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ignoreSessionExpiry: ignoreExpiry }),
      });
      const data = await resp.json();
      if (!resp.ok && !data.killedChrome) throw new Error(data.error || `HTTP ${resp.status}`);
      // If the new scan started successfully, navigate directly to its
      // live view instead of bouncing back to the dashboard. This makes
      // it obvious the scan is continuing (the user previously saw
      // "it just ends" because the old scan's view went stale and the
      // new scan was hidden in the dashboard list).
      if (data.ok && data.id && onNavigateToScan) {
        onNavigateToScan(data.id);
      } else {
        alert(
          `Chrome processes killed. New scan started: ${data.id}\n` +
          (ignoreExpiry ? "Session-expiry detection is DISABLED." : "")
        );
        onBack();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setKillingChrome(false);
    }
  };

  const statusColor = scan
    ? {
        pending: "bg-muted text-muted-foreground",
        running:
          "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
        completed:
          "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
        failed: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
        interrupted:
          "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
        paused:
          "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200",
      }[scan.status]
    : "";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <Button
            variant="ghost"
            size="sm"
            onClick={onBack}
            className="mb-2 -ml-2"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Dashboard
          </Button>
          {scan && (
            <>
              <div className="flex items-center gap-2 mb-1">
                <Badge variant="outline" className={statusColor}>
                  {scan.status}
                </Badge>
                {scan.interrupted && (
                  <Badge variant="outline" className="bg-yellow-50">
                    interrupted
                  </Badge>
                )}
                {scan.loginUrl && (
                  <Badge variant="outline">
                    auth:{" "}
                    {scan.loginSucceeded === true
                      ? "yes"
                      : scan.loginSucceeded === false
                        ? "failed"
                        : "?"}
                  </Badge>
                )}
                {scan.llmAssist && (
                  <Badge variant="outline" className="bg-purple-50 dark:bg-purple-950">
                    <Bot className="w-3 h-3 mr-1" />
                    LLM-assisted
                  </Badge>
                )}
              </div>
              <h2 className="text-xl font-bold font-mono break-all">
                {scan.targetUrl}
              </h2>
              <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-sm text-muted-foreground">
                <span>Findings: {scan.findingsCount}</span>
                {scan.findingsHigh > 0 && (
                  <span className="text-red-600 font-medium">
                    High: {scan.findingsHigh}
                  </span>
                )}
                <span>URLs: {scan.urlsCrawled}</span>
                <span>Inputs: {scan.inputsDiscovered}</span>
                {scan.startedAt && (
                  <span>
                    Started: {new Date(scan.startedAt).toLocaleTimeString()}
                  </span>
                )}
                {scan.endedAt && (
                  <span>
                    Ended: {new Date(scan.endedAt).toLocaleTimeString()}
                  </span>
                )}
              </div>
            </>
          )}
        </div>
        {isRunning && (
          <>
            <Button variant="destructive" size="sm" onClick={handleStop}>
              <Square className="w-4 h-4 mr-2" />
              Stop Scan
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleForceComplete}
              disabled={forceCompleting}
              className="border-orange-400 text-orange-700 dark:border-orange-700 dark:text-orange-400"
            >
              {forceCompleting ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <CheckCircle2 className="w-4 h-4 mr-2" />}
              Force Complete
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleKillChromeRestart}
              disabled={killingChrome}
              className="border-red-400 text-red-700 dark:border-red-700 dark:text-red-400"
              title="Kill ALL Chrome processes and restart the scan from scratch"
            >
              {killingChrome ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Skull className="w-4 h-4 mr-2" />}
              Kill Chrome & Restart
            </Button>
          </>
        )}
        {/* Force Complete also shows on interrupted/failed/paused —
            useful when the scan glitched into a bad state but you want
            to generate a report from whatever findings were collected. */}
        {!isRunning && scan && (scan.status === "interrupted" || scan.status === "failed" || scan.status === "paused") && (
          <Button
            variant="outline"
            size="sm"
            onClick={handleForceComplete}
            disabled={forceCompleting}
            className="border-orange-400 text-orange-700 dark:border-orange-700 dark:text-orange-400"
            title="Generate a report from the partial findings collected so far"
          >
            {forceCompleting ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <CheckCircle2 className="w-4 h-4 mr-2" />}
            Force Complete
          </Button>
        )}
        {!isRunning && scan && (scan.status === "interrupted" || scan.status === "failed") && (
          <Button
            variant="default"
            size="sm"
            onClick={handleResume}
            disabled={resuming}
          >
            {resuming ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <RefreshCw className="w-4 h-4 mr-2" />
            )}
            {resuming ? "Resuming..." : "Resume Scan"}
          </Button>
        )}
        {/* Sync Status button — use after a supervisor restart to check
            if the scan actually completed (the supervisor-restarted
            scanner is invisible to the web app, so the DB may show
            "interrupted" even after the scan finished). */}
        {scan && (scan.status === "interrupted" || scan.status === "failed" || scan.status === "paused") && (
          <Button
            variant="outline"
            size="sm"
            onClick={handleSyncStatus}
            disabled={syncingStatus}
            title="Check if the scan actually completed (use after a supervisor restart)"
          >
            {syncingStatus ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <RefreshCw className="w-4 h-4 mr-2" />}
            Sync Status
          </Button>
        )}

        {/* Manual Browser Login buttons */}
        {!manualLoginActive && !manualLoginCaptured && (
          <Button
            variant="outline"
            size="sm"
            onClick={handleLaunchBrowser}
            disabled={manualLoginLaunching || isRunning}
            title={isRunning ? "Stop the scan before launching manual login" : "Open a visible browser to log in manually (handles CAPTCHA, 2FA, SSO)"}
          >
            {manualLoginLaunching ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Globe className="w-4 h-4 mr-2" />
            )}
            {manualLoginLaunching ? "Launching..." : "Launch Browser to Login"}
          </Button>
        )}
        {manualLoginActive && (
          <>
            <Button
              variant="default"
              size="sm"
              onClick={handleCaptureSession}
              disabled={manualLoginCapturing}
            >
              {manualLoginCapturing ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <CheckCircle2 className="w-4 h-4 mr-2" />
              )}
              {manualLoginCapturing ? "Capturing..." : "Capture Session & Continue"}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleCancelManualLogin}
            >
              Cancel
            </Button>
          </>
        )}
        {manualLoginCaptured && (
          <Badge variant="outline" className="bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300">
            <CheckCircle2 className="w-3 h-3 mr-1" />
            Session captured
          </Badge>
        )}

        {/* Run Deep Logic Scan button (disabled by default, enabled after scan completes) */}
        {!isRunning && scan && (scan.status === "completed" || scan.status === "interrupted") && !scan.deepLogic && (
          <Button
            variant="outline"
            size="sm"
            onClick={handleRunDeepLogic}
            disabled={deepLogicRunning}
            className="border-purple-300 dark:border-purple-700 text-purple-700 dark:text-purple-300"
            title="EXPERIMENTAL: Run business logic testing (happy-path mutation). Slow — disabled by default."
          >
            {deepLogicRunning ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <FlaskConical className="w-4 h-4 mr-2" />
            )}
            {deepLogicRunning ? "Starting..." : "Run Deep Logic Scan"}
          </Button>
        )}
        {scan?.deepLogic && (
          <Badge variant="outline" className="bg-purple-50 dark:bg-purple-950 text-purple-700 dark:text-purple-300">
            <FlaskConical className="w-3 h-3 mr-1" />
            Deep Logic
          </Badge>
        )}
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {done && done.status === "failed" && (
        <Alert variant="destructive">
          <FileWarning className="h-4 w-4" />
          <AlertTitle>Scan failed</AlertTitle>
          <AlertDescription>
            The scanner subprocess exited with an error. Check the logs tab
            for details. Common causes: target unreachable, python3/playwright
            not installed, or invalid scope patterns.
          </AlertDescription>
        </Alert>
      )}

      {done && done.interrupted && (
        <Alert>
          <FileWarning className="h-4 w-4" />
          <AlertTitle>Scan was interrupted</AlertTitle>
          <AlertDescription>
            Partial evidence was saved and a partial report was generated.
            Re-run the scan for full coverage.
          </AlertDescription>
        </Alert>
      )}

      {/* Session expiry banner — shows when scan is paused for re-login */}
      {isPaused && scan && (
        <Alert className="border-orange-300 dark:border-orange-700 bg-orange-50 dark:bg-orange-950/30">
          <AlertCircle className="h-4 w-4 text-orange-600" />
          <AlertTitle className="text-orange-700 dark:text-orange-300">
            Session Expired — Scan Paused
          </AlertTitle>
          <AlertDescription className="space-y-3">
            <p>
              The scanner detected a session expiry ({scan.pauseReason || "authentication required"}).
              The browser's cookies have been cleared. You must re-login to continue.
            </p>
            <div className="flex gap-2 flex-wrap">
              <Button
                variant="outline"
                size="sm"
                onClick={handleLaunchBrowser}
                disabled={manualLoginLaunching}
                className="border-orange-300 dark:border-orange-700 text-orange-700 dark:text-orange-300"
              >
                {manualLoginLaunching ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Globe className="w-4 h-4 mr-2" />}
                {manualLoginLaunching ? "Launching..." : "Launch Browser to Re-login"}
              </Button>
              {manualLoginCaptured && (
                <Button
                  variant="default"
                  size="sm"
                  onClick={handleResumeFromPause}
                  disabled={resumingFromPause}
                >
                  {resumingFromPause ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <RefreshCw className="w-4 h-4 mr-2" />}
                  {resumingFromPause ? "Resuming..." : "Resume Scan"}
                </Button>
              )}
              <Button
                variant="outline"
                size="sm"
                onClick={handleForceComplete}
                disabled={forceCompleting}
                className="border-orange-400 text-orange-700 dark:border-orange-700 dark:text-orange-400"
              >
                {forceCompleting ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <CheckCircle2 className="w-4 h-4 mr-2" />}
                Force Complete (skip re-login)
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={handleSkipRelogin}
                disabled={skippingRelogin}
                className="border-blue-400 text-blue-700 dark:border-blue-700 dark:text-blue-400"
              >
                {skippingRelogin ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <SkipForward className="w-4 h-4 mr-2" />}
                Skip Re-login & Continue
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={handleKillChromeRestart}
                disabled={killingChrome}
                className="border-red-400 text-red-700 dark:border-red-700 dark:text-red-400"
              >
                {killingChrome ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Skull className="w-4 h-4 mr-2" />}
                Kill Chrome & Restart
              </Button>
            </div>
            {!manualLoginCaptured && !manualLoginActive && (
              <p className="text-xs text-muted-foreground">
                Click "Launch Browser to Re-login" to open a browser, log in manually,
                then capture the new session. After capturing, click "Resume Scan".
              </p>
            )}
            {manualLoginActive && (
              <p className="text-xs text-orange-600 dark:text-orange-400">
                Browser is open. Log in manually, then click "Capture Session & Continue".
              </p>
            )}
            <p className="text-xs text-muted-foreground">
              The scan will remain paused until you resume. No auto-cancel.
            </p>
          </AlertDescription>
        </Alert>
      )}

      {/* LLM Plan Approval banner — shows when scanner is waiting for plan approval */}
      <LLMPlanApprovalBanner scanId={scanId} isRunning={isRunning} />

      {/* Progress bar (parsed from active_progress log entries) */}
      {isRunning && (
        <ProgressIndicator logs={logs} />
      )}

      {/* Sub-tabs */}
      <Tabs
        value={activeSubTab}
        onValueChange={(v) =>
          setActiveSubTab(v as "logs" | "headers" | "ssl" | "owasp" | "interesting" | "sitemap" | "inventory" | "javascripts" | "directory" | "deep-logic" | "uploads" | "manifest" | "attack-surface" | "llm-plan" | "report" | "evidence" | "llm-analysis" | "chat")
        }
      >
        <TabsList className="flex w-full flex-wrap h-auto justify-start gap-1">
          <TabsTrigger value="logs">
            <Activity className="w-4 h-4 mr-2" />
            Logs ({logs.length})
          </TabsTrigger>
          <TabsTrigger value="headers">
            <FileText className="w-4 h-4 mr-2" />
            Headers
          </TabsTrigger>
          <TabsTrigger value="ssl">
            <Lock className="w-4 h-4 mr-2" />
            SSL/TLS
          </TabsTrigger>
          <TabsTrigger value="security-checks">
            <ShieldAlert className="w-4 h-4 mr-2" />
            Security Checks
          </TabsTrigger>
          <TabsTrigger value="owasp">
            <ShieldCheck className="w-4 h-4 mr-2" />
            OWASP
          </TabsTrigger>
          <TabsTrigger value="interesting">
            <Crosshair className="w-4 h-4 mr-2" />
            Interesting
          </TabsTrigger>
          <TabsTrigger value="sitemap">
            <Network className="w-4 h-4 mr-2" />
            Sitemap
          </TabsTrigger>
          <TabsTrigger value="attack-surface">
            <Target className="w-4 h-4 mr-2" />
            Attack Surface
          </TabsTrigger>
          <TabsTrigger value="manifest">
            <FileText className="w-4 h-4 mr-2" />
            Manifest
          </TabsTrigger>
          <TabsTrigger value="inventory">
            <Server className="w-4 h-4 mr-2" />
            Inventory
          </TabsTrigger>
          <TabsTrigger value="javascripts">
            <FileCode className="w-4 h-4 mr-2" />
            JavaScripts
          </TabsTrigger>
          <TabsTrigger value="css">
            <Palette className="w-4 h-4 mr-2" />
            CSS
          </TabsTrigger>
          <TabsTrigger value="directory">
            <FileSearch className="w-4 h-4 mr-2" />
            Dir Brute
          </TabsTrigger>
          {scan?.deepLogic && (
            <TabsTrigger value="deep-logic">
              <FlaskConical className="w-4 h-4 mr-2" />
              Deep Logic
            </TabsTrigger>
          )}
          {scan?.testFileUpload && (
            <TabsTrigger value="uploads">
              <Upload className="w-4 h-4 mr-2" />
              Uploads
            </TabsTrigger>
          )}
          {scan?.llmAssist && (
            <TabsTrigger value="llm-plan">
              <Bot className="w-4 h-4 mr-2" />
              LLM Plan
            </TabsTrigger>
          )}
          <TabsTrigger value="report">
            <FileText className="w-4 h-4 mr-2" />
            Report
          </TabsTrigger>
          <TabsTrigger value="evidence">
            <FileText className="w-4 h-4 mr-2" />
            Evidence ({detail?.evidenceFiles.length || 0})
          </TabsTrigger>
          {scan?.llmAnalyze && (
            <TabsTrigger value="llm-analysis">
              <Bot className="w-4 h-4 mr-2" />
              LLM Analysis
            </TabsTrigger>
          )}
          <TabsTrigger value="chat">
            <Bot className="w-4 h-4 mr-2" />
            AI Assistant
          </TabsTrigger>
        </TabsList>

        {/* Logs tab */}
        <TabsContent forceMount value="logs" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="w-5 h-5" />
                Live Execution Trail
              </CardTitle>
              <CardDescription>
                Real-time stream from execution_trail.jsonl. Each line is one
                action taken by the scanner.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea ref={logScrollRef} className="h-[600px] w-full rounded border bg-black text-green-400 font-mono text-xs">
                <div className="p-3 space-y-0.5">
                  {logs.length === 0 && (
                    <p className="text-muted-foreground italic">
                      Waiting for log output...
                    </p>
                  )}
                  {logs.map((entry, i) => (
                    <LogLine key={i} entry={entry} />
                  ))}
                  <div ref={logEndRef} />
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Headers tab — Table A/B/C comparison */}
        <TabsContent forceMount value="headers" className="mt-4">
          <HeadersPanel scanId={scanId} isRunning={isRunning} />
        </TabsContent>

        {/* SSL/TLS tab */}
        <TabsContent forceMount value="ssl" className="mt-4">
          <SSLPanel scanId={scanId} isRunning={isRunning} />
        </TabsContent>

        {/* Security Checks tab */}
        <TabsContent forceMount value="security-checks" className="mt-4">
          <SecurityChecksPanel scanId={scanId} isRunning={isRunning} />
        </TabsContent>

        {/* OWASP tab */}
        <TabsContent forceMount value="owasp" className="mt-4">
          <OwaspCoveragePanel scan={scan} logs={logs} scanId={scanId} />
        </TabsContent>

        {/* Interesting Locations tab */}
        <TabsContent forceMount value="interesting" className="mt-4">
          <InterestingLocationsPanel scanId={scanId} isRunning={isRunning} />
        </TabsContent>

        {/* Sitemap tab — the full crawl map, tree-grouped */}
        <TabsContent forceMount value="sitemap" className="mt-4">
          <SitemapPanel scanId={scanId} isRunning={isRunning} />
        </TabsContent>

        {/* Attack Surface tab — every discovered input */}
        <TabsContent forceMount value="attack-surface" className="mt-4">
          <AttackSurfacePanel scanId={scanId} isRunning={isRunning} />
        </TabsContent>

        {/* Payload Manifest tab — exactly what was sent to the target */}
        <TabsContent forceMount value="manifest" className="mt-4">
          <PayloadManifestPanel scanId={scanId} isRunning={isRunning} />
        </TabsContent>

        {/* Software Inventory tab */}
        <TabsContent forceMount value="inventory" className="mt-4">
          <InventoryPanel scanId={scanId} isRunning={isRunning} targetUrl={scan?.targetUrl} />
        </TabsContent>

        {/* JavaScripts tab */}
        <TabsContent forceMount value="javascripts" className="mt-4">
          <JavaScriptsPanel scanId={scanId} isRunning={isRunning} targetUrl={scan?.targetUrl} scanStatus={scan?.status} />
        </TabsContent>

        {/* CSS (stylesheets) tab */}
        <TabsContent forceMount value="css" className="mt-4">
          <StylesheetsPanel scanId={scanId} isRunning={isRunning} targetUrl={scan?.targetUrl} scanStatus={scan?.status} />
        </TabsContent>

        {/* Directory Brute-force tab */}
        <TabsContent forceMount value="directory" className="mt-4">
          <DirectoryPanel scanId={scanId} isRunning={isRunning} />
        </TabsContent>

        {/* Deep Logic tab (only shown when deepLogic was enabled) */}
        {scan?.deepLogic && (
          <TabsContent forceMount value="deep-logic" className="mt-4">
            <DeepLogicPanel scanId={scanId} isRunning={isRunning} />
          </TabsContent>
        )}

        {/* Uploads tab (only shown when testFileUpload was enabled) */}
        {scan?.testFileUpload && (
          <TabsContent forceMount value="uploads" className="mt-4">
            <UploadsPanel scanId={scanId} isRunning={isRunning} />
          </TabsContent>
        )}

        {/* LLM Plan tab (only shown when llmAssist was enabled) */}
        {scan?.llmAssist && (
          <TabsContent forceMount value="llm-plan" className="mt-4">
            <LLMPlanPanel scanId={scanId} isRunning={isRunning} />
          </TabsContent>
        )}

        {/* Report tab */}
        <TabsContent forceMount value="report" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="w-5 h-5" />
                HTML Report
              </CardTitle>
              <CardDescription>
                Self-contained report with all findings, screenshots, and raw
                evidence. Generated at the end of the scan.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {isRunning ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Activity className="w-12 h-12 mx-auto mb-3 animate-pulse" />
                  <p>Scan is running. Report will be available when it completes.</p>
                </div>
              ) : scan?.status === "completed" || scan?.status === "interrupted" ? (
                <div className="space-y-3">
                  <div className="flex gap-2">
                    <Button asChild size="sm">
                      <a
                        href={`/api/scans/${scanId}/report`}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        <ExternalLink className="w-4 h-4 mr-2" />
                        Open in New Tab
                      </a>
                    </Button>
                    <Button asChild variant="outline" size="sm">
                      <a href={`/api/scans/${scanId}/report?download=1`}>
                        <Download className="w-4 h-4 mr-2" />
                        Download
                      </a>
                    </Button>
                  </div>
                  <iframe
                    src={`/api/scans/${scanId}/report`}
                    className="w-full h-[800px] border rounded bg-white"
                    title="Scan Report"
                  />
                </div>
              ) : scan?.status === "failed" ? (
                <div className="text-center py-12 text-muted-foreground">
                  <FileWarning className="w-12 h-12 mx-auto mb-3" />
                  <p>Scan failed — no report was generated.</p>
                </div>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Evidence tab */}
        <TabsContent forceMount value="evidence" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="w-5 h-5" />
                Raw Evidence Vault
              </CardTitle>
              <CardDescription>
                Per-test raw HTTP request/response pairs and screenshots.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {!detail || detail.evidenceFiles.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <FileText className="w-12 h-12 mx-auto mb-3" />
                  <p>
                    {isRunning
                      ? "No evidence files yet. They appear as the scanner runs active checks."
                      : "No evidence files were generated (no active checks ran)."}
                  </p>
                </div>
              ) : (
                <EvidenceFileList scanId={scanId} files={detail.evidenceFiles} />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* LLM Analysis tab (only shown when llmAnalyze was enabled) */}
        {scan?.llmAnalyze && (
          <TabsContent forceMount value="llm-analysis" className="mt-4">
            <LLMAnalysisPanel scanId={scanId} isRunning={isRunning} />
          </TabsContent>
        )}

        {/* AI Chat tab */}
        <TabsContent forceMount value="chat" className="mt-4">
          <AIChatPanel scanId={scanId} scanStatus={scan?.status} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ===========================================================================
// PROGRESS INDICATOR (parsed from SSE logs)
// ===========================================================================

/**
 * Parses `active_progress` log entries from the SSE stream to display
 * a real-time progress bar with ETA.
 *
 * The scanner logs entries like:
 *   action: "active_progress"
 *   result: "input 15/42 payload 3/20 (45/840 done) ETA 600s"
 */
function ProgressIndicator({ logs }: { logs: TrailEntry[] }) {
  // Find the latest active_progress entry.
  const progressEntry = [...logs]
    .reverse()
    .find((l) => l.action === "active_progress");

  if (!progressEntry) {
    return (
      <div className="rounded-lg border p-3 bg-muted/30 text-sm text-muted-foreground">
        <Loader2 className="w-4 h-4 inline mr-2 animate-spin" />
        Scan in progress... (progress updates appear when active fuzzing starts)
      </div>
    );
  }

  // Parse the result string: "input 15/42 payload 3/20 (45/840 done) ETA 600s"
  const result = String(progressEntry.result || "");
  const inputMatch = result.match(/input (\d+)\/(\d+)/);
  const payloadMatch = result.match(/payload (\d+)\/(\d+)/);
  const doneMatch = result.match(/\((\d+)\/(\d+) done\)/);
  const etaMatch = result.match(/ETA (\d+)s/);

  const currentInput = inputMatch ? parseInt(inputMatch[1]) : 0;
  const totalInputs = inputMatch ? parseInt(inputMatch[2]) : 0;
  const currentPayload = payloadMatch ? parseInt(payloadMatch[1]) : 0;
  const totalPayloads = payloadMatch ? parseInt(payloadMatch[2]) : 0;
  const testsDone = doneMatch ? parseInt(doneMatch[1]) : 0;
  const totalTests = doneMatch ? parseInt(doneMatch[2]) : 0;
  const etaSeconds = etaMatch ? parseInt(etaMatch[1]) : 0;
  const percent = totalTests > 0 ? Math.round((testsDone / totalTests) * 100) : 0;

  // Format ETA.
  const etaStr = etaSeconds > 60
    ? `${Math.floor(etaSeconds / 60)}m ${etaSeconds % 60}s`
    : `${etaSeconds}s`;

  return (
    <div className="rounded-lg border p-3 bg-muted/30 space-y-2">
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium">
          Active Fuzzing: input {currentInput}/{totalInputs}, payload {currentPayload}/{totalPayloads}
        </span>
        <span className="text-muted-foreground text-xs">
          {testsDone}/{totalTests} tests ({percent}%) — ETA {etaStr}
        </span>
      </div>
      <div className="w-full bg-muted rounded-full h-2.5 overflow-hidden">
        <div
          className="bg-primary h-full rounded-full transition-all duration-500"
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
}

// ===========================================================================
// SOFTWARE INVENTORY PANEL
// ===========================================================================

/**
 * Displays the passive software fingerprinting results.
 * Shows detected products grouped by category, with version, source,
 * and a static advisory to check NVD/vendor CVE database.
 */
function InventoryPanel({
  scanId,
  isRunning,
  targetUrl,
}: {
  scanId: string;
  isRunning: boolean;
  targetUrl?: string | null;
}) {
  const [data, setData] = useState<{
    items: Array<{
      product: string;
      version: string;
      category: string;
      source: string;
      evidence: string;
      advisory: string;
    }>;
    summary: Record<string, number>;
  } | null>(null);
  const [loading, setLoading] = useState(true);

  // LLM extraction state.
  const [extracting, setExtracting] = useState(false);
  const [llmItems, setLlmItems] = useState<any[]>([]);
  const [llmError, setLlmError] = useState<string | null>(null);
  const [llmApplied, setLlmApplied] = useState(false);
  const [savedAiResults, setSavedAiResults] = useState<any[] | null>(null);
  const [savedChecked, setSavedChecked] = useState(false);
  const [aiProgress, setAiProgress] = useState<{ done: number; total: number } | null>(null);
  const [invView, setInvView] = useState<"all" | "internal" | "external">("all");
  const autoTriggered = useRef(false);

  useEffect(() => {
    let cancelled = false;
    async function fetchInventory() {
      try {
        const resp = await fetch(`/api/scans/${scanId}/inventory`);
        if (resp.status === 404) {
          if (!cancelled) {
            setData(null);
            setLoading(isRunning);
          }
          return;
        }
        const json = await resp.json();
        if (!cancelled) {
          setData(json);
          setLoading(false);
        }
      } catch {
        if (!cancelled) setLoading(false);
      }
    }
    fetchInventory();

    // --- Auto-load saved AI results (so they persist across page loads) ---
    async function fetchSavedAiResults() {
      try {
        const resp = await fetch(`/api/scans/${scanId}/inventory/extract-ai`);
        if (resp.ok) {
          const json = await resp.json();
          if (!cancelled && json.merged) {
            setSavedAiResults(json.merged);
            setLlmItems(json.llm_items || []);
            setLlmApplied(true);
            if (json.llm_error) setLlmError(json.llm_error);
          }
        }
      } catch {
        // No saved results — that's OK
      }
      if (!cancelled) setSavedChecked(true);
    }
    fetchSavedAiResults();

    const interval = setInterval(() => {
      if (data || !isRunning) {
        clearInterval(interval);
        return;
      }
      fetchInventory();
    }, 2000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [scanId, isRunning]);

  // --- Poll while extracting: the route writes results to disk after EVERY
  //     source, so partial results + an N/M progress counter stream in. ---
  useEffect(() => {
    if (!extracting) return;
    let stopped = false;
    const interval = setInterval(async () => {
      try {
        const resp = await fetch(`/api/scans/${scanId}/inventory/extract-ai`);
        if (!resp.ok || stopped) return;
        const json = await resp.json();
        if (json.merged) {
          setSavedAiResults(json.merged);
          setLlmItems(json.llm_items || []);
          setLlmApplied(true);
        }
        if (json.progress) {
          setAiProgress({ done: json.progress.done ?? 0, total: json.progress.total ?? 0 });
        }
      } catch {
        // partial file mid-write — next tick.
      }
    }, 2000);
    return () => { stopped = true; clearInterval(interval); };
  }, [extracting, scanId]);

  // --- Auto-trigger AI extraction when the scan COMPLETES and no saved
  //     results exist. Previously this fired mid-scan as soon as inventory
  //     data arrived — before dir-brute pages + saved JS sources were even
  //     on disk, so the extraction analyzed incomplete data. Only fires
  //     once per scanId (guarded by autoTriggered ref). ---
  const maybeAutoExtract = useCallback(() => {
    if (autoTriggered.current) return;
    // Blocking gates (any true → skip). Logged for diagnosability.
    const gates = {
      isRunning,
      noData: !data?.items?.length,
      notCheckedYet: !savedChecked,
      hasSaved: Boolean(savedAiResults),
      llmApplied,
      extracting,
    };
    const blocking = Object.entries(gates).filter(([, v]) => v).map(([k]) => k);
    if (blocking.length > 0) {
      console.debug("[inventory] auto-extract skipped:", blocking.join(", "));
      return;
    }
    console.debug("[inventory] auto-extract firing");
    autoTriggered.current = true;
    handleExtractAI();
  }, [isRunning, data, savedChecked, savedAiResults, llmApplied, extracting]);

  useEffect(() => {
    maybeAutoExtract();
  }, [maybeAutoExtract]);

  // Belt-and-braces: when the scan flips to completed, re-check shortly
  // after — data / savedChecked can settle a tick later than isRunning,
  // and the single effect pass above would silently no-op forever.
  useEffect(() => {
    if (isRunning || autoTriggered.current) return;
    const t = setTimeout(() => maybeAutoExtract(), 2000);
    return () => clearTimeout(t);
  }, [isRunning, maybeAutoExtract]);

  // --- LLM extraction handler ---
  const handleExtractAI = async () => {
    setExtracting(true);
    setLlmError(null);
    setAiProgress({ done: 0, total: 0 });
    try {
      const resp = await fetch(`/api/scans/${scanId}/inventory/extract-ai`, {
        method: "POST",
      });
      const json = await resp.json();
      if (!resp.ok) throw new Error(json.error || `HTTP ${resp.status}`);
      if (json.llm_error) {
        setLlmError(json.llm_error);
      }
      if (json.merged) {
        // Use the merged results from the API (already deduped by product+version)
        setSavedAiResults(json.merged);
        setLlmItems(json.llm_items || []);
        setLlmApplied(true);
      } else if (json.llm_items && json.llm_items.length > 0) {
        setLlmItems(json.llm_items);
        setLlmApplied(true);
      } else if (!json.llm_error) {
        setLlmError("LLM did not find any additional products.");
      }
    } catch (e) {
      setLlmError(e instanceof Error ? e.message : String(e));
    } finally {
      setExtracting(false);
      setAiProgress(null);
    }
  };

  // Use saved AI results if available (already merged server-side),
  // otherwise merge client-side.
  const allItems = data?.items || [];
  const mergedItems = savedAiResults
    ? savedAiResults
    : llmApplied
      ? [...allItems, ...llmItems.filter(
          (li: any) => !allItems.some((ri: any) =>
            ri.product.toLowerCase() === li.product.toLowerCase() &&
            ri.version.toLowerCase() === li.version.toLowerCase())
        )]
      : allItems;

  if (loading) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            Fingerprinting software...
          </p>
        </CardContent>
      </Card>
    );
  }

  if (!data || !data.items || data.items.length === 0) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Server className="w-8 h-8 mx-auto text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            No software fingerprints detected via regex. Try the "Extract
            Versions with AI" button below — the LLM can find versions
            hidden in minified JS or CSS comments.
          </p>
          <Button
            variant="outline"
            size="sm"
            onClick={handleExtractAI}
            disabled={extracting}
            className="mt-4"
          >
            {extracting ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Bot className="w-4 h-4 mr-2" />
            )}
            {extracting
              ? `Extracting ${aiProgress && aiProgress.total > 0 ? `${aiProgress.done}/${aiProgress.total} sources` : ""}...`
              : "Extract Versions with AI"}
          </Button>
          {extracting && aiProgress && aiProgress.total > 0 && (
            <p className="text-xs text-muted-foreground mt-2 tabular-nums">
              Analyzing source {aiProgress.done} of {aiProgress.total}… (results stream in below)
            </p>
          )}
          {llmError && (
            <p className="text-xs text-destructive mt-2">{llmError}</p>
          )}
          {llmApplied && llmItems.length > 0 && (
            <div className="mt-4 text-left">
              <p className="text-sm font-medium mb-2">
                LLM-Detected Products ({llmItems.length}):
              </p>
              <div className="overflow-x-auto">
                <table className="w-full text-xs border-collapse">
                  <thead>
                    <tr className="bg-muted">
                      <th className="border p-2 text-left">Product</th>
                      <th className="border p-2 text-left">Version</th>
                      <th className="border p-2 text-left">Source</th>
                      <th className="border p-2 text-left">Advisory</th>
                    </tr>
                  </thead>
                  <tbody>
                    {llmItems.map((item: any, i: number) => (
                      <tr key={i}>
                        <td className="border p-2 font-mono font-medium">{item.product}</td>
                        <td className="border p-2 font-mono">{item.version}</td>
                        <td className="border p-2 text-xs text-purple-600 dark:text-purple-400">{item.source}</td>
                        <td className="border p-2 text-xs text-orange-600 dark:text-orange-400">{item.advisory}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    );
  }

  // Group merged items by category, filtered by the internal/external view.
  // An item is EXTERNAL if any of its source URLs (regex source_urls or LLM
  // source_url) points at a host other than the scan's target — i.e. the
  // product was fingerprinted from an external/CDN script.
  const targetHost = (() => {
    try {
      return targetUrl ? new URL(targetUrl).hostname.toLowerCase() : "";
    } catch {
      return "";
    }
  })();
  const isExternalItem = (item: any): boolean => {
    if (!targetHost) return false;
    const urls: string[] = [
      ...(Array.isArray(item?.source_urls) ? item.source_urls : []),
      ...(typeof item?.source_url === "string" ? [item.source_url] : []),
    ];
    return urls.some((u) => {
      try {
        return new URL(u).hostname.toLowerCase() !== targetHost;
      } catch {
        return false;
      }
    });
  };
  const externalCount = mergedItems.filter(isExternalItem).length;
  const filteredItems =
    invView === "all" ? mergedItems
      : invView === "external" ? mergedItems.filter(isExternalItem)
        : mergedItems.filter((it: any) => !isExternalItem(it));
  const categories: Record<string, typeof mergedItems> = {};
  for (const item of filteredItems) {
    if (!categories[item.category]) categories[item.category] = [];
    categories[item.category].push(item);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Server className="w-5 h-5" />
          Software Inventory & Advisory
        </CardTitle>
        <CardDescription>
          {mergedItems.length} products detected ({allItems.length} regex + {llmApplied ? llmItems.length : 0} LLM)
          across {Object.keys(categories).length} categories
          {externalCount > 0 && ` · ${externalCount} from external/CDN sources`}.
          This is NOT a CVE scanner — manually verify each version against NVD / vendor CVE database.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Button variant={invView === "all" ? "default" : "outline"} size="sm"
                  onClick={() => setInvView("all")}>
            All ({mergedItems.length})
          </Button>
          <Button variant={invView === "internal" ? "default" : "outline"} size="sm"
                  onClick={() => setInvView("internal")}>
            Internal ({mergedItems.length - externalCount})
          </Button>
          <Button variant={invView === "external" ? "default" : "outline"} size="sm"
                  onClick={() => setInvView("external")}>
            External/CDN ({externalCount})
          </Button>
        </div>
        <Alert>
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>
            <strong>Advisory:</strong> For every detected item, manually verify the
            version against the NVD (https://nvd.nist.gov) or the vendor's CVE
            database for known vulnerabilities and end-of-life status.
          </AlertDescription>
        </Alert>

        {/* Extract Versions with AI button — available even during fuzzing,
            since the crawl data (page_sources.json, software_inventory.json)
            is already on disk before fuzzing starts. */}
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={handleExtractAI}
            disabled={extracting}
            className="border-purple-300 dark:border-purple-700 text-purple-700 dark:text-purple-300"
          >
            {extracting ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Bot className="w-4 h-4 mr-2" />
            )}
            {extracting
              ? `Extracting ${aiProgress && aiProgress.total > 0 ? `${aiProgress.done}/${aiProgress.total} sources` : ""}...`
              : "Extract Versions with AI"}
          </Button>
          {llmApplied && (
            <Badge variant="outline" className="bg-purple-50 dark:bg-purple-950 text-purple-700 dark:text-purple-300">
                <Bot className="w-3 h-3 mr-1" />
                LLM: +{llmItems.length} products
              </Badge>
            )}
            {llmError && (
              <span className="text-xs text-destructive">{llmError}</span>
            )}
        </div>

        {Object.entries(categories).sort().map(([category, items]) => (
          <div key={category}>
            <h4 className="font-medium mb-2 flex items-center gap-2">
              <Badge variant="outline" className={
                category === "LLM Detected"
                  ? "bg-purple-50 dark:bg-purple-950"
                  : ""
              }>
                {category}
              </Badge>
              <span className="text-xs text-muted-foreground">({items.length})</span>
            </h4>
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="bg-muted">
                    <th className="border p-2 text-left">Product</th>
                    <th className="border p-2 text-left">Version</th>
                    <th className="border p-2 text-left">Source</th>
                    <th className="border p-2 text-left">Found On</th>
                    <th className="border p-2 text-left">Advisory</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item: any, i: number) => (
                    <tr key={i} className="hover:bg-accent/50">
                      <td className="border p-2 font-mono font-medium">
                        {item.product}
                        {isExternalItem(item) && (
                          <Badge variant="outline" className="ml-2 text-[10px] bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300">
                            CDN
                          </Badge>
                        )}
                      </td>
                      <td className="border p-2 font-mono">{item.version}</td>
                      <td className="border p-2 text-muted-foreground text-xs">
                        {item.source}
                      </td>
                      <td className="border p-2 text-xs text-muted-foreground">
                        {(item.source_urls && item.source_urls.length > 0) ? (
                          <details>
                            <summary className="cursor-pointer hover:text-foreground">
                              {item.source_urls.length} URL(s)
                            </summary>
                            <div className="mt-1 space-y-0.5">
                              {item.source_urls.map((url: string, j: number) => (
                                <div key={j} className="font-mono break-all">
                                  <a href={url} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                                    {url.replace(/^https?:\/\/[^/]+/, "") || url}
                                  </a>
                                </div>
                              ))}
                            </div>
                          </details>
                        ) : (item as any).source_url ? (
                          <a href={(item as any).source_url} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline font-mono break-all">
                            {(item as any).source_url.replace(/^https?:\/\/[^/]+/, "") || (item as any).source_url}
                          </a>
                        ) : "—"}
                      </td>
                      <td className="border p-2 text-xs text-orange-600 dark:text-orange-400">
                        {item.advisory}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

// ===========================================================================
// JAVASCRIPTS PANEL
// ===========================================================================

/**
 * Lists every <script src> the scanner found while crawling (so JS files are
 * VISIBLE — a planted JS vuln otherwise hides completely). Includes an
 * "Analyze JS with AI" button that fetches each same-origin JS file and asks
 * the LLM to flag dangerous code (eval sinks, innerHTML of dynamic data,
 * hardcoded secrets, hidden debug/backdoor commands, etc.).
 */
function JavaScriptsPanel({
  scanId,
  isRunning,
  targetUrl,
  scanStatus,
}: {
  scanId: string;
  isRunning: boolean;
  targetUrl?: string | null;
  scanStatus?: string | null;
}) {
  const [items, setItems] = useState<Array<{
    url: string;
    filename?: string;
    external?: boolean;
    found_on?: string[];
  }>>([]);
  const [loading, setLoading] = useState(true);

  const [analyzing, setAnalyzing] = useState(false);
  const [aiResults, setAiResults] = useState<any[] | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiMeta, setAiMeta] = useState<string>("");
  const [aiProgress, setAiProgress] = useState<{ done: number; total: number } | null>(null);
  const [savedChecked, setSavedChecked] = useState(false);
  const autoTriggered = useRef(false);
  const [jsOriginView, setJsOriginView] = useState<"all" | "same" | "external">("all");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const resp = await fetch(`/api/scans/${scanId}/javascripts`);
        if (resp.status === 404) {
          if (!cancelled) { setItems([]); setLoading(isRunning); }
          return;
        }
        const json = await resp.json();
        if (!cancelled) { setItems(Array.isArray(json) ? json : (json.items || [])); setLoading(false); }
      } catch {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    // Auto-load saved AI results.
    fetch(`/api/scans/${scanId}/javascripts/analyze-ai`)
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => { if (!cancelled && j && Array.isArray(j.findings)) {
        setAiResults(j.findings);
        setAiMeta(`Analyzed ${j.js_analyzed}/${j.same_origin ?? j.js_total ?? 0} same-origin files`);
      }})
      .catch(() => {})
      .finally(() => { if (!cancelled) setSavedChecked(true); });
    const interval = setInterval(() => {
      if (items.length || !isRunning) { clearInterval(interval); return; }
      load();
    }, 2000);
    return () => { cancelled = true; clearInterval(interval); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, isRunning]);

  // --- Auto-trigger JS AI analysis when the scan COMPLETES and no saved
  //     results exist. Previously this fired MID-SCAN as soon as the JS list
  //     arrived — before the sitemap sweep collected the rest of the JS
  //     (incl. what only appears on dir-brute/late pages), so the vulnerable
  //     late-found JS was never analyzed. Waiting for completion guarantees
  //     javascripts.json + js_source/ are final.
  //     "Completed" means COMPLETED — not interrupted/failed. A stopped scan
  //     never ran the sitemap sweep, so its JS sources aren't saved and an
  //     auto-analysis would burn fetches that (before the retry fix) got
  //     permanently marked done, blanking the feature. The manual button
  //     stays available for interrupted scans. ---
  const maybeAutoAnalyze = useCallback(() => {
    if (autoTriggered.current) return;
    const blocking = {
      isRunning,
      notCompleted: scanStatus !== undefined && scanStatus !== null && scanStatus !== "completed",
      noData: !items.length,
      notCheckedYet: !savedChecked,
      hasSaved: Boolean(aiResults),
      analyzing,
    };
    const blocked = Object.entries(blocking).filter(([, v]) => v).map(([k]) => k);
    if (blocked.length > 0) {
      console.debug("[js-analyze] auto-trigger skipped:", blocked.join(", "));
      return;
    }
    console.debug("[js-analyze] auto-trigger firing");
    autoTriggered.current = true;
    analyze();
  }, [isRunning, scanStatus, items, savedChecked, aiResults, analyzing]);

  useEffect(() => {
    maybeAutoAnalyze();
  }, [maybeAutoAnalyze]);

  // Belt-and-braces: re-check 2s after the scan flips to completed so a
  // late-settling gate can't permanently block the trigger.
  useEffect(() => {
    if (isRunning || autoTriggered.current) return;
    const t = setTimeout(() => maybeAutoAnalyze(), 2000);
    return () => clearTimeout(t);
  }, [isRunning, maybeAutoAnalyze]);

  // --- Poll while analyzing: the route writes results to disk after EVERY
  //     file, so partial results + an N/M progress counter stream in. ---
  useEffect(() => {
    if (!analyzing) return;
    let stopped = false;
    const interval = setInterval(async () => {
      try {
        const resp = await fetch(`/api/scans/${scanId}/javascripts/analyze-ai`);
        if (!resp.ok || stopped) return;
        const json = await resp.json();
        if (Array.isArray(json.findings)) setAiResults(json.findings);
        if (json.progress) setAiProgress({ done: json.progress.done ?? 0, total: json.progress.total ?? 0 });
      } catch {
        // partial file mid-write — next tick.
      }
    }, 2000);
    return () => { stopped = true; clearInterval(interval); };
  }, [analyzing, scanId]);

  const analyze = async () => {
    setAnalyzing(true); setAiError(null); setAiProgress({ done: 0, total: 0 });
    try {
      const resp = await fetch(`/api/scans/${scanId}/javascripts/analyze-ai`, { method: "POST" });
      const json = await resp.json();
      if (!resp.ok) throw new Error(json.error || `HTTP ${resp.status}`);
      setAiResults(Array.isArray(json.findings) ? json.findings : []);
      setAiMeta(`Analyzed ${json.js_analyzed}/${json.js_total ?? 0} files${json.llm_error ? " · " + json.llm_error : ""}`);
      if (json.llm_error && (!json.findings || json.findings.length === 0)) setAiError(json.llm_error);
    } catch (e) {
      setAiError(e instanceof Error ? e.message : String(e));
    } finally {
      setAnalyzing(false);
      setAiProgress(null);
    }
  };

  // External-script detection for badges: a finding is external if its
  // js_url host differs from the scan's target host.
  const jsTargetHost = (() => {
    try {
      return targetUrl ? new URL(targetUrl).hostname.toLowerCase() : "";
    } catch {
      return "";
    }
  })();
  const isExternalJs = (f: any): boolean => {
    if (!jsTargetHost || !f?.js_url) return false;
    try {
      return new URL(f.js_url).hostname.toLowerCase() !== jsTargetHost;
    } catch {
      return false;
    }
  };

  const sevColor: Record<string, string> = {
    high: "bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300",
    medium: "bg-yellow-50 dark:bg-yellow-950 text-yellow-700 dark:text-yellow-300",
    low: "bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300",
  };

  if (loading) {
    return (
      <Card><CardContent className="p-12 text-center">
        <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
        <p className="text-sm text-muted-foreground">Collecting JavaScript files...</p>
      </CardContent></Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileCode className="w-5 h-5" />
          JavaScript Files
        </CardTitle>
        <CardDescription>
          {items.length} script(s) discovered during crawl.{" "}
          {items.filter((i) => !i.external).length} same-origin,{" "}
          {items.filter((i) => i.external).length} external/CDN.
          Same-origin files can be analyzed for dangerous code.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Analyze JS with AI — auto-runs once the scan COMPLETES (so the
            sitemap sweep's JS additions are all on disk); the button is a
            manual re-run/resume. */}
        <div className="flex items-center gap-3 flex-wrap">
          <Button variant="outline" size="sm" onClick={analyze} disabled={analyzing || items.length === 0}
                  className="border-purple-300 dark:border-purple-700 text-purple-700 dark:text-purple-300">
            {analyzing ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Bot className="w-4 h-4 mr-2" />}
            {analyzing
              ? `Analyzing ${aiProgress && aiProgress.total > 0 ? `${aiProgress.done}/${aiProgress.total} files` : ""}...`
              : "Analyze JS with AI"}
          </Button>
          {analyzing && aiProgress && aiProgress.total > 0 && (
            <span className="text-xs text-muted-foreground tabular-nums">
              File {aiProgress.done} of {aiProgress.total}… (findings stream in below)
            </span>
          )}
          {aiMeta && <span className="text-xs text-muted-foreground">{aiMeta}</span>}
          {aiError && <span className="text-xs text-destructive">{aiError}</span>}
        </div>

        {items.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No <code>&lt;script src&gt;</code> tags found in the crawled pages.
            (The crawl phase must run first.)
          </p>
        ) : (
          <>
          <div className="flex gap-2">
            <Button variant={jsOriginView === "all" ? "default" : "outline"} size="sm"
                    onClick={() => setJsOriginView("all")}>
              All ({items.length})
            </Button>
            <Button variant={jsOriginView === "same" ? "default" : "outline"} size="sm"
                    onClick={() => setJsOriginView("same")}>
              Same-origin ({items.filter((j) => !j.external).length})
            </Button>
            <Button variant={jsOriginView === "external" ? "default" : "outline"} size="sm"
                    onClick={() => setJsOriginView("external")}>
              External/CDN ({items.filter((j) => j.external).length})
            </Button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs border-collapse">
              <thead>
                <tr className="bg-muted">
                  <th className="border p-2 text-left">File</th>
                  <th className="border p-2 text-left">Origin</th>
                  <th className="border p-2 text-left">Found on</th>
                </tr>
              </thead>
              <tbody>
                {items
                  .filter((j) => jsOriginView === "all" || (jsOriginView === "external" ? j.external : !j.external))
                  .map((j, i) => (
                  <tr key={i} className="hover:bg-muted/50 align-top">
                    <td className="border p-2">
                      <a href={j.url} target="_blank" rel="noopener noreferrer"
                         className="text-blue-600 hover:underline font-mono break-all">
                        {j.filename || j.url}
                      </a>
                    </td>
                    <td className="border p-2">
                      <Badge variant="outline" className={j.external
                        ? "bg-yellow-50 dark:bg-yellow-950 text-yellow-700 dark:text-yellow-300"
                        : "bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300"}>
                        {j.external ? "External/CDN" : "Same-origin"}
                      </Badge>
                    </td>
                    <td className="border p-2 text-muted-foreground">
                      {(j.found_on || []).length} page(s)
                      {(j.found_on || []).length > 0 && (
                        <details><summary className="cursor-pointer hover:text-foreground">list</summary>
                          <div className="mt-1 space-y-0.5">
                            {(j.found_on || []).map((u, k) => (
                              <div key={k} className="font-mono break-all">{u}</div>
                            ))}
                          </div>
                        </details>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          </>
        )}

        {aiResults && aiResults.length > 0 && (
          <div>
            <h4 className="font-medium mb-2 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-red-500" />
              AI Flagged Dangerous Code ({aiResults.length})
            </h4>
            <div className="space-y-2">
              {aiResults.map((f: any, i: number) => (
                <div key={i} className="rounded-lg border p-3">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <Badge variant="outline" className={sevColor[String(f.severity || "").toLowerCase()] || ""}>
                      {f.severity || "?"}
                    </Badge>
                    <Badge variant="outline" className="text-xs">{f.category || "Suspicious JS"}</Badge>
                    {isExternalJs(f) && (
                      <Badge variant="outline" className="text-xs bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300">
                        External/CDN
                      </Badge>
                    )}
                    <span className="text-xs font-mono text-muted-foreground break-all">{f.filename || f.js_url}</span>
                  </div>
                  {f.snippet && (
                    <pre className="text-xs font-mono bg-muted/50 rounded p-2 overflow-x-auto mb-1">{f.snippet}</pre>
                  )}
                  {f.explanation && <p className="text-xs text-muted-foreground">{f.explanation}</p>}
                </div>
              ))}
            </div>
          </div>
        )}
        {aiResults && aiResults.length === 0 && aiMeta && !aiError && (
          <p className="text-xs text-muted-foreground">AI analysis complete — no dangerous code flagged in the analyzed files.</p>
        )}
      </CardContent>
    </Card>
  );
}

// ===========================================================================
// STYLESHEETS PANEL (CSS twin of the JavaScripts panel)
// ===========================================================================

/**
 * Lists every <link rel=stylesheet> the sitemap sweep collected (so CSS files
 * are VISIBLE), with an "Analyze CSS with AI" button that asks the LLM to
 * flag security-relevant content regex scanning can't reason about: exfil
 * beacons in url(), secrets in comments, CSS-exfiltration selectors,
 * unexpected @import hosts, and overlay/phishing styling.
 */
function StylesheetsPanel({
  scanId,
  isRunning,
  targetUrl,
  scanStatus,
}: {
  scanId: string;
  isRunning: boolean;
  targetUrl?: string | null;
  scanStatus?: string | null;
}) {
  const [items, setItems] = useState<Array<{
    url: string;
    filename?: string;
    external?: boolean;
    found_on?: string[];
  }>>([]);
  const [loading, setLoading] = useState(true);

  const [analyzing, setAnalyzing] = useState(false);
  const [aiResults, setAiResults] = useState<any[] | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiMeta, setAiMeta] = useState<string>("");
  const [aiProgress, setAiProgress] = useState<{ done: number; total: number } | null>(null);
  const [savedChecked, setSavedChecked] = useState(false);
  const autoTriggered = useRef(false);
  const [cssOriginView, setCssOriginView] = useState<"all" | "same" | "external">("all");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const resp = await fetch(`/api/scans/${scanId}/stylesheets`);
        if (resp.status === 404) {
          if (!cancelled) { setItems([]); setLoading(isRunning); }
          return;
        }
        const json = await resp.json();
        if (!cancelled) setItems(Array.isArray(json) ? json : (json.items || []));
      } catch {
        // ignore — the sweep may not have written the file yet
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    // Auto-load saved AI results.
    fetch(`/api/scans/${scanId}/stylesheets/analyze-ai`)
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => { if (!cancelled && j && Array.isArray(j.findings)) {
        setAiResults(j.findings);
        setAiMeta(`Analyzed ${j.css_analyzed}/${j.css_total ?? 0} files`);
      }})
      .catch(() => {})
      .finally(() => { if (!cancelled) setSavedChecked(true); });
    const interval = setInterval(() => {
      if (items.length || !isRunning) { clearInterval(interval); return; }
      load();
    }, 2000);
    return () => { cancelled = true; clearInterval(interval); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, isRunning]);

  // --- Auto-trigger CSS AI analysis when the scan COMPLETES (mirrors the
  //     JS panel: interrupted scans never ran the full sweep, so their CSS
  //     sources are incomplete — manual button only for those). ---
  const maybeAutoAnalyze = useCallback(() => {
    if (autoTriggered.current) return;
    const blocking = {
      isRunning,
      notCompleted: scanStatus !== undefined && scanStatus !== null && scanStatus !== "completed",
      noData: !items.length,
      notCheckedYet: !savedChecked,
      hasSaved: Boolean(aiResults),
      analyzing,
    };
    const blocked = Object.entries(blocking).filter(([, v]) => v).map(([k]) => k);
    if (blocked.length > 0) {
      console.debug("[css-analyze] auto-trigger skipped:", blocked.join(", "));
      return;
    }
    console.debug("[css-analyze] auto-trigger firing");
    autoTriggered.current = true;
    analyze();
  }, [isRunning, scanStatus, items, savedChecked, aiResults, analyzing]);

  useEffect(() => {
    maybeAutoAnalyze();
  }, [maybeAutoAnalyze]);

  // Belt-and-braces: re-check 2s after the scan flips to completed.
  useEffect(() => {
    if (isRunning || autoTriggered.current) return;
    const t = setTimeout(() => maybeAutoAnalyze(), 2000);
    return () => clearTimeout(t);
  }, [isRunning, maybeAutoAnalyze]);

  // --- Poll while analyzing: results persist after EVERY file. ---
  useEffect(() => {
    if (!analyzing) return;
    let stopped = false;
    const interval = setInterval(async () => {
      try {
        const resp = await fetch(`/api/scans/${scanId}/stylesheets/analyze-ai`);
        if (!resp.ok || stopped) return;
        const json = await resp.json();
        if (Array.isArray(json.findings)) setAiResults(json.findings);
        if (json.progress) setAiProgress({ done: json.progress.done ?? 0, total: json.progress.total ?? 0 });
      } catch {
        // partial file mid-write — next tick.
      }
    }, 2000);
    return () => { stopped = true; clearInterval(interval); };
  }, [analyzing, scanId]);

  const analyze = async () => {
    setAnalyzing(true); setAiError(null); setAiProgress({ done: 0, total: 0 });
    try {
      const resp = await fetch(`/api/scans/${scanId}/stylesheets/analyze-ai`, { method: "POST" });
      const json = await resp.json();
      if (!resp.ok) throw new Error(json.error || `HTTP ${resp.status}`);
      setAiResults(Array.isArray(json.findings) ? json.findings : []);
      setAiMeta(`Analyzed ${json.css_analyzed}/${json.css_total ?? 0} files${json.llm_error ? " · " + json.llm_error : ""}`);
      if (json.llm_error && (!json.findings || json.findings.length === 0)) setAiError(json.llm_error);
    } catch (e) {
      setAiError(e instanceof Error ? e.message : String(e));
    } finally {
      setAnalyzing(false);
      setAiProgress(null);
    }
  };

  // External-stylesheet detection for badges.
  const cssTargetHost = (() => {
    try {
      return targetUrl ? new URL(targetUrl).hostname.toLowerCase() : "";
    } catch {
      return "";
    }
  })();
  const isExternalCss = (f: any): boolean => {
    if (!cssTargetHost || !f?.css_url) return false;
    try {
      return new URL(f.css_url).hostname.toLowerCase() !== cssTargetHost;
    } catch {
      return false;
    }
  };

  const sevColor: Record<string, string> = {
    high: "bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300",
    medium: "bg-yellow-50 dark:bg-yellow-950 text-yellow-700 dark:text-yellow-300",
    low: "bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300",
  };

  if (loading) {
    return (
      <Card><CardContent className="p-12 text-center">
        <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
        <p className="text-sm text-muted-foreground">Collecting stylesheets...</p>
      </CardContent></Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Palette className="w-5 h-5" />
          Stylesheets
        </CardTitle>
        <CardDescription>
          {items.length} stylesheet(s) collected.{" "}
          {items.filter((i) => !i.external).length} same-origin,{" "}
          {items.filter((i) => i.external).length} external/CDN.
          The AI pass flags exfil beacons, secrets in comments, exfil selectors
          and unexpected imports — beyond what the regex secret scan catches.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-3 flex-wrap">
          <Button variant="outline" size="sm" onClick={analyze} disabled={analyzing || items.length === 0}
                  className="border-purple-300 dark:border-purple-700 text-purple-700 dark:text-purple-300">
            {analyzing ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Bot className="w-4 h-4 mr-2" />}
            {analyzing
              ? `Analyzing ${aiProgress && aiProgress.total > 0 ? `${aiProgress.done}/${aiProgress.total} files` : ""}...`
              : "Analyze CSS with AI"}
          </Button>
          {analyzing && aiProgress && aiProgress.total > 0 && (
            <span className="text-xs text-muted-foreground tabular-nums">
              File {aiProgress.done} of {aiProgress.total}… (findings stream in below)
            </span>
          )}
          {aiMeta && <span className="text-xs text-muted-foreground">{aiMeta}</span>}
          {aiError && <span className="text-xs text-destructive">{aiError}</span>}
        </div>

        {items.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No <code>&lt;link rel=&quot;stylesheet&quot;&gt;</code> tags found in the sitemap pages.
            (The sitemap sweep runs near the end of the scan.)
          </p>
        ) : (
          <>
          <div className="flex gap-2">
            <Button variant={cssOriginView === "all" ? "default" : "outline"} size="sm"
                    onClick={() => setCssOriginView("all")}>
              All ({items.length})
            </Button>
            <Button variant={cssOriginView === "same" ? "default" : "outline"} size="sm"
                    onClick={() => setCssOriginView("same")}>
              Same-origin ({items.filter((c) => !c.external).length})
            </Button>
            <Button variant={cssOriginView === "external" ? "default" : "outline"} size="sm"
                    onClick={() => setCssOriginView("external")}>
              External/CDN ({items.filter((c) => c.external).length})
            </Button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs border-collapse">
              <thead>
                <tr className="bg-muted">
                  <th className="border p-2 text-left">File</th>
                  <th className="border p-2 text-left">Origin</th>
                  <th className="border p-2 text-left">Found on</th>
                </tr>
              </thead>
              <tbody>
                {items
                  .filter((c) => cssOriginView === "all" || (cssOriginView === "external" ? c.external : !c.external))
                  .map((c, i) => (
                  <tr key={i} className="hover:bg-muted/50 align-top">
                    <td className="border p-2">
                      <a href={c.url} target="_blank" rel="noopener noreferrer"
                         className="text-blue-600 hover:underline font-mono break-all">
                        {c.filename || c.url}
                      </a>
                    </td>
                    <td className="border p-2">
                      <Badge variant="outline" className={c.external
                        ? "bg-yellow-50 dark:bg-yellow-950 text-yellow-700 dark:text-yellow-300"
                        : "bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300"}>
                        {c.external ? "External/CDN" : "Same-origin"}
                      </Badge>
                    </td>
                    <td className="border p-2 text-muted-foreground">
                      {(c.found_on || []).length} page(s)
                      {(c.found_on || []).length > 0 && (
                        <details><summary className="cursor-pointer hover:text-foreground">list</summary>
                          <div className="mt-1 space-y-0.5">
                            {(c.found_on || []).map((u, k) => (
                              <div key={k} className="font-mono break-all">{u}</div>
                            ))}
                          </div>
                        </details>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          </>
        )}

        {aiResults && aiResults.length > 0 && (
          <div>
            <h4 className="font-medium mb-2 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-red-500" />
              AI Flagged Suspicious CSS ({aiResults.length})
            </h4>
            <div className="space-y-2">
              {aiResults.map((f: any, i: number) => (
                <div key={i} className="rounded-lg border p-3">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <Badge variant="outline" className={sevColor[String(f.severity || "").toLowerCase()] || ""}>
                      {f.severity || "?"}
                    </Badge>
                    <Badge variant="outline" className="text-xs">{f.category || "Suspicious CSS"}</Badge>
                    {isExternalCss(f) && (
                      <Badge variant="outline" className="text-xs bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300">
                        External/CDN
                      </Badge>
                    )}
                    <span className="text-xs font-mono text-muted-foreground break-all">{f.filename || f.css_url}</span>
                  </div>
                  {f.snippet && (
                    <pre className="text-xs font-mono bg-muted/50 rounded p-2 overflow-x-auto mb-1">{f.snippet}</pre>
                  )}
                  {f.explanation && (
                    <p className="text-xs text-muted-foreground">{f.explanation}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ===========================================================================
// DIRECTORY BRUTE-FORCE PANEL
// ===========================================================================

/**
 * Displays directory brute-forcing results — paths that returned 200/301/401/403.
 */
function DirectoryPanel({
  scanId,
  isRunning,
}: {
  scanId: string;
  isRunning: boolean;
}) {
  const [findings, setFindings] = useState<
    Array<{ path: string; url: string; status: number; title: string; note: string; base?: string }>
  >([]);
  const [crawlMap, setCrawlMap] = useState<
    Array<{ url: string; depth: number; source: string; in_scope: boolean; method: string }>
  >([]);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<"sitemap" | "bruteforce">("sitemap");
  // Sitemap sub-view scope filter + brute sub-view status chips.
  const [scopeView, setScopeView] = useState<"all" | "in" | "out">("all");
  const [statusOff, setStatusOff] = useState<Set<number>>(new Set());

  useEffect(() => {
    let cancelled = false;
    async function fetchAll() {
      try {
        const [dirResp, crawlResp] = await Promise.all([
          fetch(`/api/scans/${scanId}/directory`),
          fetch(`/api/scans/${scanId}/crawl-map`),
        ]);
        if (!cancelled) {
          // Dir brute
          try {
            const dirJson = await dirResp.json();
            setFindings(dirJson.findings || []);
          } catch { setFindings([]); }
          // Crawl map
          try {
            const crawlJson = await crawlResp.json();
            setCrawlMap(crawlJson.crawlMap || []);
          } catch { setCrawlMap([]); }
          setLoading(false);
        }
      } catch {
        if (!cancelled) setLoading(false);
      }
    }
    fetchAll();
    const interval = setInterval(() => {
      if (!isRunning) { clearInterval(interval); return; }
      fetchAll();
    }, 2000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [scanId, isRunning]);

  if (loading) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            Crawling + brute-forcing directories...
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileSearch className="w-5 h-5" />
          Site Map & Directory Brute-Force
        </CardTitle>
        <CardDescription>
          {crawlMap.length} URLs crawled · {findings.length} paths found via brute-force
        </CardDescription>
        <div className="flex gap-2 mt-2">
          <Button
            variant={view === "sitemap" ? "default" : "outline"}
            size="sm"
            onClick={() => setView("sitemap")}
          >
            Crawl Sitemap ({crawlMap.length})
          </Button>
          <Button
            variant={view === "bruteforce" ? "default" : "outline"}
            size="sm"
            onClick={() => setView("bruteforce")}
          >
            Dir Brute-Force ({findings.length})
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {view === "sitemap" ? (
          // Crawl sitemap
          crawlMap.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No URLs crawled yet. The crawler hasn't run or found no links.
            </p>
          ) : (
            <>
            <div className="flex gap-2 mb-3">
              <Button variant={scopeView === "all" ? "default" : "outline"} size="sm"
                      onClick={() => setScopeView("all")}>
                All ({crawlMap.length})
              </Button>
              <Button variant={scopeView === "in" ? "default" : "outline"} size="sm"
                      onClick={() => setScopeView("in")}>
                In scope ({crawlMap.filter((c) => c.in_scope).length})
              </Button>
              <Button variant={scopeView === "out" ? "default" : "outline"} size="sm"
                      onClick={() => setScopeView("out")}>
                Out of scope ({crawlMap.filter((c) => !c.in_scope).length})
              </Button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="bg-muted">
                    <th className="border p-2 text-left">URL</th>
                    <th className="border p-2 text-center">Depth</th>
                    <th className="border p-2 text-left">Source</th>
                    <th className="border p-2 text-center">Scope</th>
                    <th className="border p-2 text-center">Method</th>
                  </tr>
                </thead>
                <tbody>
                  {crawlMap
                    .filter((c) => scopeView === "all" || (scopeView === "in" ? c.in_scope : !c.in_scope))
                    .map((c, i) => (
                    <tr key={i} className="hover:bg-accent/50">
                      <td className="border p-2">
                        <a
                          href={c.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-mono text-blue-600 dark:text-blue-400 hover:underline break-all"
                        >
                          {c.url}
                        </a>
                      </td>
                      <td className="border p-2 text-center">{c.depth}</td>
                      <td className="border p-2">
                        <Badge variant="outline" className="text-xs">
                          {c.source}
                        </Badge>
                      </td>
                      <td className="border p-2 text-center">
                        {c.in_scope ? (
                          <CheckCircle2 className="w-4 h-4 text-green-600 mx-auto" />
                        ) : (
                          <XCircle className="w-4 h-4 text-red-600 mx-auto" />
                        )}
                      </td>
                      <td className="border p-2 text-center font-mono">{c.method}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            </>
          )
        ) : (
          // Dir brute-force results
          findings.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No accessible paths found from the wordlist.
            </p>
          ) : (
            <>
            <div className="flex gap-2 mb-3 flex-wrap items-center">
              <span className="text-xs text-muted-foreground">Status:</span>
              {Array.from(new Set(findings.map((f) => f.status)))
                .sort((a, b) => a - b)
                .map((s) => (
                  <Button
                    key={s}
                    variant={statusOff.has(s) ? "outline" : "default"}
                    size="sm"
                    onClick={() =>
                      setStatusOff((prev) => {
                        const next = new Set(prev);
                        if (next.has(s)) next.delete(s);
                        else next.add(s);
                        return next;
                      })
                    }
                  >
                    {s} ({findings.filter((f) => f.status === s).length})
                  </Button>
                ))}
              {statusOff.size > 0 && (
                <Button variant="ghost" size="sm" onClick={() => setStatusOff(new Set())}>
                  Show all
                </Button>
              )}
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="bg-muted">
                    <th className="border p-2 text-left">Path</th>
                    <th className="border p-2 text-left">Base</th>
                    <th className="border p-2 text-center">Status</th>
                    <th className="border p-2 text-left">Note</th>
                    <th className="border p-2 text-left">Page Title</th>
                  </tr>
                </thead>
                <tbody>
                  {findings
                    .filter((f) => !statusOff.has(f.status))
                    .map((f, i) => (
                    <tr key={i} className="hover:bg-accent/50">
                      <td className="border p-2">
                        <a
                          href={f.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-mono text-blue-600 dark:text-blue-400 hover:underline"
                        >
                          {f.path}
                        </a>
                      </td>
                      <td className="border p-2">
                        <Badge
                          variant="outline"
                          className={
                            f.base === "(llm-discovered)"
                              ? "bg-purple-50 dark:bg-purple-950 text-purple-700 dark:text-purple-300 text-xs"
                              : "text-xs"
                          }
                        >
                          {f.base || "/"}
                        </Badge>
                      </td>
                      <td className="border p-2 text-center">
                        <Badge
                          variant="outline"
                          className={
                            f.status === 200
                              ? "bg-green-50 dark:bg-green-950"
                              : f.status === 301 || f.status === 302
                                ? "bg-blue-50 dark:bg-blue-950"
                                : "bg-yellow-50 dark:bg-yellow-950"
                          }
                        >
                        {f.status}
                      </Badge>
                    </td>
                    <td className="border p-2 text-muted-foreground">{f.note}</td>
                    <td className="border p-2 font-mono text-xs">{f.title || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
            </>
          )
        )}
      </CardContent>
    </Card>
  );
}

// ===========================================================================
// SECURITY CHECKS PANEL (Error Messages + Cookie Config + Sensitive Info)
// ===========================================================================

/**
 * Displays passive security checks:
 *   1. Error Messages — stack traces, SQL errors, file paths (A10/A05)
 *   2. Session Cookie Config — expiry, domain, path issues (A07)
 *   3. Sensitive Information — API keys, emails, IPs, tokens (A02/A01)
 */
function SecurityChecksPanel({
  scanId,
  isRunning,
}: {
  scanId: string;
  isRunning: boolean;
}) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  // Active sub-tab. Declared up here (NOT after the early returns) because
  // React hooks must run in the same order on every render.
  const [subTab, setSubTab] = useState<"cookies" | "errors" | "sensitive" | "mixed">("errors");

  useEffect(() => {
    let cancelled = false;
    async function fetchPassive() {
      try {
        const resp = await fetch(`/api/scans/${scanId}/passive`);
        if (resp.status === 404) {
          if (!cancelled) { setData(null); setLoading(isRunning); }
          return;
        }
        const json = await resp.json();
        if (!cancelled) { setData(json.passive); setLoading(false); }
      } catch { if (!cancelled) setLoading(false); }
    }
    fetchPassive();
    const interval = setInterval(() => {
      if (data || !isRunning) { clearInterval(interval); return; }
      fetchPassive();
    }, 2000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [scanId, isRunning]);

  if (loading) {
    return (
      <Card><CardContent className="p-12 text-center">
        <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
        <p className="text-sm text-muted-foreground">Running passive security checks...</p>
      </CardContent></Card>
    );
  }

  if (!data) {
    return (
      <Card><CardContent className="p-12 text-center">
        <ShieldAlert className="w-8 h-8 mx-auto text-muted-foreground mb-3" />
        <p className="text-sm text-muted-foreground">No passive security checks data available.</p>
      </CardContent></Card>
    );
  }

  const errorMessages = data.error_messages || [];
  const cookieConfig = data.session_cookie_config || [];
  const sensitiveInfo = data.sensitive_info || [];
  const insecureCookies = data.insecure_cookies || [];
  const mixedContent = data.mixed_content || [];

  const sevColor: Record<string, string> = {
    high: "bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300",
    medium: "bg-yellow-50 dark:bg-yellow-950 text-yellow-700 dark:text-yellow-300",
    low: "bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300",
  };

  // Screenshot captured at passive-scan time (when errors or sensitive info
  // were found). Optional — old scans won't have it.
  const screenshotPath: string | undefined = data?.screenshot_path;
  const hasCookieAttrs = insecureCookies.some((c: any) =>
    typeof c.secure === "boolean" || typeof c.http_only === "boolean" || typeof c.same_site === "string");

  // Render a single green/red attribute pill. Used for the cookie table.
  const attrPill = (ok: boolean, label: string) => (
    <Badge
      variant="outline"
      className={
        ok
          ? "bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300"
          : "bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300"
      }
    >
      {label}: {ok ? "✓" : "✗"}
    </Badge>
  );
  // SameSite pill: Strict=green, Lax=blue (partial), None/unset=red.
  const sameSitePill = (ss: string) => {
    const lower = (ss || "").toLowerCase();
    const cls =
      lower === "strict"
        ? "bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300"
        : lower === "lax"
          ? "bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300"
          : "bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300";
    return (
      <Badge variant="outline" className={cls}>
        SameSite: {ss || "unset"}
      </Badge>
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5" />
          Passive Security Checks
        </CardTitle>
        <CardDescription>
          {errorMessages.length} error messages · {cookieConfig.length} cookie config issues ·{" "}
          {sensitiveInfo.length} sensitive info items · {insecureCookies.length} insecure cookies ·{" "}
          {mixedContent.length} mixed content items
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs value={subTab} onValueChange={(v) => setSubTab(v as typeof subTab)}>
          <TabsList>
            <TabsTrigger value="errors">
              <AlertCircle className="w-4 h-4 mr-2" />
              Error Messages ({errorMessages.length})
            </TabsTrigger>
            <TabsTrigger value="sensitive">
              <FileWarning className="w-4 h-4 mr-2" />
              Sensitive Info ({sensitiveInfo.length})
            </TabsTrigger>
            <TabsTrigger value="cookies">
              <KeyRound className="w-4 h-4 mr-2" />
              Cookies ({insecureCookies.length + cookieConfig.length})
            </TabsTrigger>
            <TabsTrigger value="mixed">
              <FileWarning className="w-4 h-4 mr-2" />
              Mixed Content ({mixedContent.length})
            </TabsTrigger>
          </TabsList>

          {/* --- Error Messages sub-tab --- */}
          <TabsContent forceMount value="errors" className="mt-4 space-y-4">
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-xs">A10/A05</Badge>
              <span className="text-xs text-muted-foreground">
                Stack traces, SQL errors, file paths, debug output found in page responses.
              </span>
            </div>
            {screenshotPath && (
              <div>
                <h4 className="font-medium mb-2 flex items-center gap-2">
                  <Camera className="w-4 h-4" />
                  Page Screenshot at Detection
                </h4>
                <ScreenshotImage scanId={scanId} name={screenshotPath} />
              </div>
            )}
            {errorMessages.length === 0 ? (
              <p className="text-xs text-muted-foreground">No error messages detected in page responses.</p>
            ) : (
              <div className="space-y-2">
                {errorMessages.map((e: any, i: number) => (
                  <div key={i} className="rounded-lg border p-3">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <Badge variant="outline" className={sevColor[e.severity] || ""}>{e.severity}</Badge>
                      <Badge variant="outline" className="text-xs">{e.category}</Badge>
                      <Badge variant="outline" className="text-xs">{e.owasp}</Badge>
                    </div>
                    {e.url && (
                      <a href={e.url} target="_blank" rel="noopener noreferrer"
                         className="text-xs font-mono text-blue-600 dark:text-blue-400 hover:underline break-all mb-1 inline-block">
                        {e.url}
                      </a>
                    )}
                    <p className="text-xs font-mono bg-muted/50 rounded p-2 break-all">{e.snippet}</p>
                    {e.screenshot && (
                      <div className="mt-2">
                        <ScreenshotImage scanId={scanId} name={e.screenshot} />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </TabsContent>

          {/* --- Sensitive Information sub-tab --- */}
          <TabsContent forceMount value="sensitive" className="mt-4 space-y-4">
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-xs">A02/A01</Badge>
              <span className="text-xs text-muted-foreground">
                Emails, API keys, internal IPs, credit-card/SSN patterns, private keys, JWTs found in page content.
              </span>
            </div>
            {screenshotPath && (
              <div>
                <h4 className="font-medium mb-2 flex items-center gap-2">
                  <Camera className="w-4 h-4" />
                  Page Screenshot at Detection
                </h4>
                <ScreenshotImage scanId={scanId} name={screenshotPath} />
              </div>
            )}
            {sensitiveInfo.length === 0 ? (
              <p className="text-xs text-muted-foreground">No sensitive information detected in page content.</p>
            ) : (
              <div className="space-y-2">
                {sensitiveInfo.map((s: any, i: number) => (
                  <div key={i} className="rounded-lg border p-3">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <Badge variant="outline" className={sevColor[s.severity] || ""}>{s.severity}</Badge>
                      <Badge variant="outline" className="text-xs">{s.category}</Badge>
                      <Badge variant="outline" className="text-xs">{s.owasp}</Badge>
                    </div>
                    {s.url && (
                      <a href={s.url} target="_blank" rel="noopener noreferrer"
                         className="text-xs font-mono text-blue-600 dark:text-blue-400 hover:underline break-all mb-1 inline-block">
                        {s.url}
                      </a>
                    )}
                    <p className="text-xs font-mono bg-muted/50 rounded p-2 break-all">{s.value}</p>
                    {s.screenshot && (
                      <div className="mt-2">
                        <ScreenshotImage scanId={scanId} name={s.screenshot} />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </TabsContent>

          {/* --- Cookies sub-tab --- */}
          <TabsContent forceMount value="cookies" className="mt-4 space-y-6">
            {/* Insecure Cookies — with explicit attribute pills (Secure/HttpOnly/SameSite) */}
            {insecureCookies.length > 0 && (
              <div>
                <h4 className="font-medium mb-2 flex items-center gap-2">
                  <KeyRound className="w-4 h-4 text-yellow-500" />
                  Insecure Cookies ({insecureCookies.length})
                </h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs border-collapse">
                    <thead>
                      <tr className="bg-muted">
                        <th className="border p-2 text-left">Cookie</th>
                        <th className="border p-2 text-left">Domain</th>
                        {hasCookieAttrs ? (
                          <>
                            <th className="border p-2 text-left">Secure</th>
                            <th className="border p-2 text-left">HttpOnly</th>
                            <th className="border p-2 text-left">SameSite</th>
                          </>
                        ) : (
                          <th className="border p-2 text-left">Issues</th>
                        )}
                      </tr>
                    </thead>
                    <tbody>
                      {insecureCookies.map((c: any, i: number) => (
                        <tr key={i} className="hover:bg-muted/50 align-top">
                          <td className="border p-2 font-mono">{c.name}</td>
                          <td className="border p-2 font-mono">{c.domain}</td>
                          {hasCookieAttrs ? (
                            <>
                              <td className="border p-2">{attrPill(c.secure === true, "Secure")}</td>
                              <td className="border p-2">{attrPill(c.http_only === true, "HttpOnly")}</td>
                              <td className="border p-2">{sameSitePill(c.same_site)}</td>
                            </>
                          ) : (
                            <td className="border p-2 text-xs">{c.issues.join(", ")}</td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {hasCookieAttrs && (
                  <p className="text-xs text-muted-foreground mt-1">
                    Issues list for each cookie:{" "}
                    {insecureCookies.map((c: any) => `${c.name} (${(c.issues || []).join("; ")})`).join(" · ")}
                  </p>
                )}
              </div>
            )}

            {/* Session Cookie Configuration */}
            <div>
              <h4 className="font-medium mb-2 flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-orange-500" />
                Session Cookie Configuration ({cookieConfig.length})
                <Badge variant="outline" className="text-xs">A07</Badge>
              </h4>
              {cookieConfig.length === 0 ? (
                <p className="text-xs text-muted-foreground">No session cookie configuration issues detected.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs border-collapse">
                    <thead>
                      <tr className="bg-muted">
                        <th className="border p-2 text-left">Cookie Name</th>
                        <th className="border p-2 text-left">Domain</th>
                        <th className="border p-2 text-left">Path</th>
                        <th className="border p-2 text-left">Issues</th>
                      </tr>
                    </thead>
                    <tbody>
                      {cookieConfig.map((c: any, i: number) => (
                        <tr key={i} className="hover:bg-muted/50 align-top">
                          <td className="border p-2 font-mono">{c.name}</td>
                          <td className="border p-2 font-mono">{c.domain}</td>
                          <td className="border p-2 font-mono">{c.path}</td>
                          <td className="border p-2">
                            <ul className="list-disc list-inside space-y-0.5">
                              {c.issues.map((issue: string, j: number) => (
                                <li key={j} className="text-xs">{issue}</li>
                              ))}
                            </ul>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </TabsContent>

          {/* --- Mixed Content sub-tab --- */}
          <TabsContent forceMount value="mixed" className="mt-4 space-y-2">
            <div className="flex items-center gap-2">
              <FileWarning className="w-4 h-4 text-blue-500" />
              <span className="text-xs text-muted-foreground">
                HTTPS page loading HTTP sub-resources (browsers may block or downgrade these).
              </span>
            </div>
            {mixedContent.length === 0 ? (
              <p className="text-xs text-muted-foreground">No mixed content detected.</p>
            ) : (
              mixedContent.map((m: any, i: number) => (
                <div key={i} className="text-xs font-mono bg-muted/50 rounded p-2 break-all">
                  &lt;{m.tag}&gt; {m.attr}={m.url}
                </div>
              ))
            )}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}

// ===========================================================================
// SSL/TLS PANEL
// ===========================================================================

interface SSLData {
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
  // Weak key sizes / signature algorithms in the cert chain (optional — old scans).
  weak_key_sizes_detected?: string[];
  weak_signature_algorithms_detected?: string[];
  pem_chain: string;
  // --- NEW: testssl-style cipher enumeration + decoded chain ---
  // All optional/nullable so old scans (pre-dating these fields) render
  // without errors — the sections just stay hidden.
  supported_ciphers?: Array<{
    cipher: string;
    protocol: string;
    accepted: boolean;
    strength: "weak" | "strong";
    reason: string;
    severity: string;
    detail?: string;
  }>;
  cert_chain_details?: Array<{
    position: number;
    role: string;
    subject?: string;
    issuer?: string;
    not_before?: string;
    not_after?: string;
    is_ca?: boolean;
    is_self_signed?: boolean;
    signature_algorithm?: string;
    key_algorithm?: string;
    key_size?: number;
    weak_key?: string;
    weak_signature?: string;
    parse_error?: string;
  }>;
  supports_tls_1_0?: boolean;
  supports_tls_1_1?: boolean;
  supports_tls_1_2?: boolean;
  supports_tls_1_3?: boolean;
  supports_sslv2?: boolean;
  supports_sslv3?: boolean;
}

/**
 * Displays SSL/TLS certificate details, cipher suite info, and
 * security issues (expired, self-signed, weak protocols, etc.).
 */
function SSLPanel({
  scanId,
  isRunning,
}: {
  scanId: string;
  isRunning: boolean;
}) {
  const [ssl, setSsl] = useState<SSLData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function fetchSSL() {
      try {
        const resp = await fetch(`/api/scans/${scanId}/ssl`);
        if (resp.status === 404) {
          if (!cancelled) {
            setSsl(null);
            setError(null);
            setLoading(isRunning);
          }
          return;
        }
        const data = await resp.json();
        if (!cancelled) {
          setSsl(data.ssl || null);
          setError(null);
          setLoading(false);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
          setLoading(false);
        }
      }
    }
    fetchSSL();
    const interval = setInterval(() => {
      if (ssl || !isRunning) {
        clearInterval(interval);
        return;
      }
      fetchSSL();
    }, 2000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [scanId, isRunning]);

  if (loading) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            Inspecting SSL/TLS certificate...
          </p>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <AlertCircle className="w-8 h-8 mx-auto text-destructive mb-3" />
          <p className="text-sm">{error}</p>
        </CardContent>
      </Card>
    );
  }

  if (!ssl) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Lock className="w-8 h-8 mx-auto text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            No SSL/TLS data available. This scan may target an HTTP
            (non-HTTPS) URL, or the SSL inspection phase hasn't completed yet.
          </p>
        </CardContent>
      </Card>
    );
  }

  // Build issue list
  const issues: Array<{ type: string; severity: "high" | "medium" | "low" | "info"; message: string }> = [];
  if (ssl.is_expired) {
    issues.push({ type: "Expired Certificate", severity: "high", message: `Certificate expired on ${ssl.not_after}` });
  }
  if (ssl.is_self_signed) {
    issues.push({ type: "Self-Signed Certificate", severity: "medium", message: "The certificate is self-signed (not issued by a trusted CA)" });
  }
  if (ssl.hostname_mismatch) {
    issues.push({ type: "Hostname Mismatch", severity: "high", message: `Certificate subject does not match hostname ${ssl.hostname}` });
  }
  if (ssl.is_untrusted_root) {
    issues.push({ type: "Untrusted Root", severity: "medium", message: "Certificate chain leads to an untrusted root CA" });
  }
  if (ssl.days_until_expiry !== null && ssl.days_until_expiry < 30 && !ssl.is_expired) {
    issues.push({ type: "Expiring Soon", severity: "medium", message: `Certificate expires in ${ssl.days_until_expiry} days` });
  }
  if (ssl.weak_protocols_detected.length > 0) {
    issues.push({ type: "Weak Protocol", severity: "high", message: `Server supports weak protocols: ${ssl.weak_protocols_detected.join(", ")}` });
  }
  if (ssl.weak_ciphers_detected.length > 0) {
    issues.push({ type: "Weak Cipher", severity: "medium", message: `Server supports weak ciphers: ${ssl.weak_ciphers_detected.join(", ")}` });
  }
  if ((ssl.weak_key_sizes_detected ?? []).length > 0) {
    issues.push({ type: "Weak Key Size", severity: "high", message: `Weak public-key size(s) in chain: ${(ssl.weak_key_sizes_detected ?? []).join("; ")}` });
  }
  if ((ssl.weak_signature_algorithms_detected ?? []).length > 0) {
    issues.push({ type: "Weak Signature Algorithm", severity: "high", message: `Weak/deprecated signature algorithm(s) in chain: ${(ssl.weak_signature_algorithms_detected ?? []).join("; ")}` });
  }
  if (!ssl.negotiated_protocol) {
    issues.push({ type: "No SSL/TLS", severity: "info", message: "Could not establish an SSL/TLS connection (server may not support HTTPS)" });
  }
  if (issues.length === 0 && ssl.negotiated_protocol) {
    issues.push({ type: "No Issues Found", severity: "info", message: "No SSL/TLS issues detected. Certificate is valid and uses strong protocols/ciphers." });
  }

  const sevColor = {
    high: "bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300",
    medium: "bg-yellow-50 dark:bg-yellow-950 text-yellow-700 dark:text-yellow-300",
    low: "bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300",
    info: "bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300",
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Lock className="w-5 h-5" />
          SSL/TLS Inspection — {ssl.hostname}:{ssl.port}
        </CardTitle>
        <CardDescription>
          Certificate details, cipher suite, and protocol security review.
          The scanner connects directly to the TLS port (bypassing Playwright)
          to inspect the raw certificate and negotiated parameters.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Issues */}
        <div>
          <h4 className="font-medium mb-2">Security Issues ({issues.length})</h4>
          <div className="space-y-2">
            {issues.map((issue, i) => (
              <div key={i} className="flex items-center gap-2 rounded-lg border p-3">
                <Badge variant="outline" className={sevColor[issue.severity]}>
                  {issue.type}
                </Badge>
                <span className="text-sm text-muted-foreground">{issue.message}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Protocol Support (testssl-style) — hidden for old scans */}
        {Array.isArray(ssl.supported_ciphers) && ssl.supported_ciphers.length > 0 && (
          <div>
            <h4 className="font-medium mb-2">Protocol Support</h4>
            <p className="text-xs text-muted-foreground mb-2">
              Each version was probed with one pinned TLS handshake. SSLv2/v3
              are not testable on modern Python builds and show as unsupported
              even if the server might still accept them.
            </p>
            <div className="flex flex-wrap gap-2">
              {([
                ["SSLv2", ssl.supports_sslv2, true],
                ["SSLv3", ssl.supports_sslv3, true],
                ["TLS 1.0", ssl.supports_tls_1_0, true],
                ["TLS 1.1", ssl.supports_tls_1_1, true],
                ["TLS 1.2", ssl.supports_tls_1_2, false],
                ["TLS 1.3", ssl.supports_tls_1_3, false],
              ] as const).map(([label, supported, weakIfSupported]) => {
                const isWeak = supported && weakIfSupported;
                return (
                  <Badge
                    key={label}
                    variant="outline"
                    className={
                      supported
                        ? isWeak
                          ? "bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300"
                          : "bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300"
                        : "bg-muted text-muted-foreground"
                    }
                  >
                    {label}: {supported ? (isWeak ? "Accepted ⚠" : "Accepted") : "Not offered"}
                  </Badge>
                );
              })}
            </div>
          </div>
        )}

        {/* Certificate Details */}
        <div>
          <h4 className="font-medium mb-2">Certificate Details</h4>
          <div className="overflow-x-auto">
            <table className="w-full text-xs border-collapse">
              <tbody>
                <tr className="hover:bg-muted/50">
                  <td className="border p-2 font-medium bg-muted/30">Hostname</td>
                  <td className="border p-2 font-mono">{ssl.hostname}</td>
                </tr>
                <tr className="hover:bg-muted/50">
                  <td className="border p-2 font-medium bg-muted/30">Port</td>
                  <td className="border p-2 font-mono">{ssl.port}</td>
                </tr>
                <tr className="hover:bg-muted/50">
                  <td className="border p-2 font-medium bg-muted/30">Issuer</td>
                  <td className="border p-2 font-mono break-all">{ssl.issuer || "—"}</td>
                </tr>
                <tr className="hover:bg-muted/50">
                  <td className="border p-2 font-medium bg-muted/30">Subject</td>
                  <td className="border p-2 font-mono break-all">{ssl.subject || "—"}</td>
                </tr>
                <tr className="hover:bg-muted/50">
                  <td className="border p-2 font-medium bg-muted/30">Valid From</td>
                  <td className="border p-2 font-mono">{ssl.not_before || "—"}</td>
                </tr>
                <tr className="hover:bg-muted/50">
                  <td className="border p-2 font-medium bg-muted/30">Valid Until</td>
                  <td className="border p-2 font-mono">
                    {ssl.not_after || "—"}
                    {ssl.days_until_expiry !== null && (
                      <span className={`ml-2 ${ssl.days_until_expiry < 0 ? "text-red-600" : ssl.days_until_expiry < 30 ? "text-yellow-600" : "text-green-600"}`}>
                        ({ssl.days_until_expiry < 0 ? "EXPIRED" : `${ssl.days_until_expiry} days left`})
                      </span>
                    )}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Decoded Certificate Chain (testssl-style) */}
        {Array.isArray(ssl.cert_chain_details) && ssl.cert_chain_details.length > 0 && (
          <div>
            <h4 className="font-medium mb-2 flex items-center gap-2">
              Certificate Chain
              <Badge variant="outline" className="text-xs">
                {ssl.cert_chain_details.length} cert{ssl.cert_chain_details.length === 1 ? "" : "s"}
              </Badge>
            </h4>
            <p className="text-xs text-muted-foreground mb-2">
              Decoded from the chain the server presented. The raw PEM
              (inspectable with <code>openssl x509 -text</code>) is in the
              collapsible section below.
            </p>
            <div className="space-y-3">
              {ssl.cert_chain_details.map((cert, i) => (
                <div key={i} className="rounded-lg border p-3 text-xs">
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <Badge variant="outline" className="capitalize">{cert.role}</Badge>
                    <span className="font-mono text-muted-foreground">#{cert.position}</span>
                    {cert.is_ca && (
                      <Badge variant="outline" className="bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300">CA</Badge>
                    )}
                    {cert.is_self_signed && (
                      <Badge variant="outline" className="bg-yellow-50 dark:bg-yellow-950 text-yellow-700 dark:text-yellow-300">Self-Signed</Badge>
                    )}
                    {cert.key_algorithm && (
                      <Badge variant="outline" className="text-xs">
                        {cert.key_algorithm}{cert.key_size ? ` ${cert.key_size}-bit` : ""}
                      </Badge>
                    )}
                    {cert.signature_algorithm && (
                      <Badge variant="outline" className={
                        (cert as any).weak_signature
                          ? "text-xs bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300"
                          : "text-xs"
                      }>{cert.signature_algorithm}</Badge>
                    )}
                    {(cert as any).weak_key && (
                      <Badge variant="outline" className="text-xs bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300">Weak Key</Badge>
                    )}
                  </div>
                  {cert.parse_error ? (
                    <p className="text-destructive font-mono break-all">{cert.parse_error}</p>
                  ) : (
                    <div className="space-y-1 font-mono">
                      {cert.subject && (
                        <div><span className="text-muted-foreground">Subject:</span> <span className="break-all">{cert.subject}</span></div>
                      )}
                      {cert.issuer && (
                        <div><span className="text-muted-foreground">Issuer:</span> <span className="break-all">{cert.issuer}</span></div>
                      )}
                      {(cert.not_before || cert.not_after) && (
                        <div className="text-muted-foreground">
                          Validity: <span className="text-foreground">{cert.not_before || "?"}</span> → <span className="text-foreground">{cert.not_after || "?"}</span>
                        </div>
                      )}
                      {(cert as any).weak_key && (
                        <div className="text-red-700 dark:text-red-300">⚠ {(cert as any).weak_key}</div>
                      )}
                      {(cert as any).weak_signature && (
                        <div className="text-red-700 dark:text-red-300">⚠ Signature uses a deprecated/broken hash</div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Protocol & Cipher */}
        <div>
          <h4 className="font-medium mb-2">Negotiated Connection</h4>
          <div className="overflow-x-auto">
            <table className="w-full text-xs border-collapse">
              <tbody>
                <tr className="hover:bg-muted/50">
                  <td className="border p-2 font-medium bg-muted/30">Protocol</td>
                  <td className="border p-2 font-mono">
                    {ssl.negotiated_protocol || "—"}
                    {ssl.negotiated_protocol && (
                      <Badge variant="outline" className={`ml-2 ${ssl.negotiated_protocol.includes("1.0") || ssl.negotiated_protocol.includes("1.1") ? "bg-red-50 text-red-700" : "bg-green-50 text-green-700"}`}>
                        {ssl.negotiated_protocol.includes("1.0") || ssl.negotiated_protocol.includes("1.1") ? "WEAK" : "OK"}
                      </Badge>
                    )}
                  </td>
                </tr>
                <tr className="hover:bg-muted/50">
                  <td className="border p-2 font-medium bg-muted/30">Cipher Suite</td>
                  <td className="border p-2 font-mono break-all">{ssl.negotiated_cipher || "—"}</td>
                </tr>
                {ssl.weak_protocols_detected.length > 0 && (
                  <tr className="hover:bg-muted/50">
                    <td className="border p-2 font-medium bg-muted/30 text-red-600">Weak Protocols</td>
                    <td className="border p-2 font-mono text-red-600">{ssl.weak_protocols_detected.join(", ")}</td>
                  </tr>
                )}
                {ssl.weak_ciphers_detected.length > 0 && (
                  <tr className="hover:bg-muted/50">
                    <td className="border p-2 font-medium bg-muted/30 text-yellow-600">Weak Ciphers</td>
                    <td className="border p-2 font-mono text-yellow-600">{ssl.weak_ciphers_detected.join(", ")}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Supported Cipher Suites (testssl-style enumeration) */}
        {Array.isArray(ssl.supported_ciphers) && ssl.supported_ciphers.length > 0 && (
          <div>
            <h4 className="font-medium mb-2 flex items-center gap-2">
              Supported Cipher Suites
              <Badge variant="outline" className="text-xs">
                {ssl.supported_ciphers.filter((c) => c.accepted).length} accepted / {ssl.supported_ciphers.length} probed
              </Badge>
            </h4>
            <p className="text-xs text-muted-foreground mb-2">
              Each cipher was probed with one pinned TLS handshake (TLS 1.2,
              and TLS 1.3 where the Python build supports it). Weak ciphers
              the server actually <em>accepted</em> are the ones to remediate.
              The policy that decides "weak" vs "strong" is the editable
              <code>bin/weak_ciphers.txt</code> — add a CVE there and it
              takes effect on the next scan.
            </p>
            {(() => {
              const tls13Rows = ssl.supported_ciphers.filter(
                (c) => c.protocol === "TLSv1.3",
              );
              // "limited" = we fell back to the single negotiated cipher
              // (marked in its detail field) because this Python build can't
              // pin individual TLS 1.3 ciphers.
              const limited = tls13Rows.some(
                (c) => c.detail && c.detail.includes("set_ciphersuites"),
              );
              if (!ssl.supports_tls_1_3) return null;
              if (tls13Rows.length === 0 || limited) {
                return (
                  <p className="text-xs text-yellow-700 dark:text-yellow-400 mb-2 italic">
                    {tls13Rows.length === 0
                      ? "The server supports TLS 1.3, but no TLS 1.3 cipher rows could be captured."
                      : "Showing the single TLS 1.3 cipher the server negotiated."}{" "}
                    Full per-cipher TLS 1.3 enumeration requires a Python build
                    with <code>ssl.SSLContext.set_ciphersuites</code> (this
                    build lacks it). The negotiated TLS 1.3 cipher is also
                    shown in the Negotiated Connection table above.
                  </p>
                );
              }
              return null;
            })()}
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="bg-muted">
                    <th className="border p-2 text-left">Cipher Suite</th>
                    <th className="border p-2 text-left">Protocol</th>
                    <th className="border p-2 text-left">Status</th>
                    <th className="border p-2 text-left">Strength</th>
                  </tr>
                </thead>
                <tbody>
                  {ssl.supported_ciphers.map((c, i) => {
                    const weakAccepted = c.accepted && c.strength === "weak";
                    return (
                      <tr
                        key={i}
                        className={weakAccepted ? "bg-red-50 dark:bg-red-950/40" : "hover:bg-muted/50"}
                      >
                        <td className="border p-2 font-mono break-all">{c.cipher}</td>
                        <td className="border p-2 font-mono">{c.protocol}</td>
                        <td className="border p-2">
                          {c.accepted ? (
                            <Badge variant="outline" className="bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300">Accepted</Badge>
                          ) : (
                            <Badge variant="outline" className="text-muted-foreground">Rejected</Badge>
                          )}
                        </td>
                        <td className="border p-2">
                          {c.strength === "weak" ? (
                            <span className={weakAccepted ? "text-red-700 dark:text-red-300 font-medium" : "text-red-600 dark:text-red-400"}>
                              Weak{c.reason ? ` — ${c.reason}` : ""}
                            </span>
                          ) : (
                            <span className="text-green-700 dark:text-green-300">Strong</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Certificate Chain (PEM) */}
        {ssl.pem_chain && (
          <div>
            <h4 className="font-medium mb-2">Certificate Chain (PEM)</h4>
            <details>
              <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">
                Click to expand PEM certificate chain
              </summary>
              <pre className="text-xs bg-black text-green-400 p-3 rounded mt-2 overflow-x-auto max-h-96">
                {ssl.pem_chain}
              </pre>
            </details>
          </div>
        )}

        <p className="text-xs text-muted-foreground">
          SSL inspection is performed using Python's <code>ssl</code> module
          (not Playwright) to get low-level access to the negotiated cipher
          and protocol. The scanner connects with a permissive SSLContext
          (all protocols allowed, no cert verification) to detect weak
          protocols that a stricter client would refuse.
        </p>
      </CardContent>
    </Card>
  );
}

// ===========================================================================
// HEADERS PANEL (Table A / B / C)
// ===========================================================================

interface HeaderRecord {
  name: string;
  value: string;
  in_reference: boolean;
  expected_value: string;
  value_matches_expected: boolean;
  source_url?: string;
}

/**
 * Displays the header comparison tables:
 *
 * Table A: All captured headers with columns:
 *   - Header Name
 *   - Header Value (actual)
 *   - In Reference List? (Yes/No badge)
 *   - Expected Value (from whitelist)
 *   - Matches Expected? (Yes/No/N-A badge)
 *
 * Table B: Headers NOT in the reference list (potential anomalies).
 *
 * Table C: Headers IN the reference list but with values that DON'T match
 * the declared expected value (policy violations).
 *
 * Also shows the landing page screenshot (pre-fuzz).
 */
function HeadersPanel({
  scanId,
  isRunning,
}: {
  scanId: string;
  isRunning: boolean;
}) {
  const [headers, setHeaders] = useState<HeaderRecord[]>([]);
  const [missingHeaders, setMissingHeaders] = useState<Array<{ name: string; expected_value: string }>>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedSource, setSelectedSource] = useState<string | "all">("all");

  useEffect(() => {
    let cancelled = false;
    async function fetchHeaders() {
      try {
        const resp = await fetch(`/api/scans/${scanId}/headers`);
        if (resp.status === 404) {
          if (!cancelled) {
            setHeaders([]);
            setMissingHeaders([]);
            setError(null);
            setLoading(isRunning);
          }
          return;
        }
        const data = await resp.json();
        if (!cancelled) {
          setHeaders(data.headers || []);
          setMissingHeaders(data.missing_headers || []);
          setError(null);
          setLoading(false);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
          setLoading(false);
        }
      }
    }
    fetchHeaders();
    const interval = setInterval(() => {
      if (headers.length > 0 || !isRunning) {
        clearInterval(interval);
        return;
      }
      fetchHeaders();
    }, 2000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [scanId, isRunning]);

  if (loading) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            Capturing headers...
          </p>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <AlertCircle className="w-8 h-8 mx-auto text-destructive mb-3" />
          <p className="text-sm">{error}</p>
        </CardContent>
      </Card>
    );
  }

  if (headers.length === 0) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <FileText className="w-8 h-8 mx-auto text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            No headers captured yet.
          </p>
        </CardContent>
      </Card>
    );
  }

  // Group headers by source URL so the user can see which response
  // each header came from (main HTML page vs CSS/JS/images).
  const sourceUrls = [...new Set(headers.map((h) => h.source_url || "(unknown)"))].sort();

  // Filter headers by selected source URL.
  const filteredHeaders = selectedSource === "all"
    ? headers
    : headers.filter((h) => (h.source_url || "(unknown)") === selectedSource);

  // Build Table B (anomalies) + Table C (mismatches) from filtered headers.
  const anomalies = filteredHeaders.filter((h) => !h.in_reference);
  const mismatches = filteredHeaders.filter(
    (h) => h.in_reference && h.expected_value && !h.value_matches_expected
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileText className="w-5 h-5" />
          Header Analysis — Whitelist Comparison
        </CardTitle>
        <CardDescription>
          {headers.length} headers captured from {sourceUrls.length} response(s) ·{" "}
          {anomalies.length} anomalies (not in whitelist) ·{" "}
          {mismatches.length} policy violations (value mismatch).
          The engineer must manually review Table B + C to determine if any
          headers represent security misconfigurations.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Landing page screenshot */}
        <div>
          <h4 className="font-medium mb-2">Landing Page Screenshot (pre-fuzz)</h4>
          <ScreenshotImage scanId={scanId} name="screenshot_before.png" />
        </div>

        {/* Response filter — show which response's headers we're viewing */}
        {sourceUrls.length > 1 && (
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-medium">Filter by response:</span>
            <button
              onClick={() => setSelectedSource("all")}
              className={`text-xs px-2 py-1 rounded border ${
                selectedSource === "all"
                  ? "bg-primary text-primary-foreground border-primary"
                  : "bg-card hover:bg-accent border-border"
              }`}
            >
              All ({headers.length})
            </button>
            {sourceUrls.map((url) => {
              const count = headers.filter((h) => (h.source_url || "(unknown)") === url).length;
              const shortUrl = url.replace(/^https?:\/\/[^/]+/, "") || url;
              return (
                <button
                  key={url}
                  onClick={() => setSelectedSource(url)}
                  className={`text-xs font-mono px-2 py-1 rounded border truncate max-w-xs ${
                    selectedSource === url
                      ? "bg-primary text-primary-foreground border-primary"
                      : "bg-card hover:bg-accent border-border"
                  }`}
                  title={url}
                >
                  {shortUrl} ({count})
                </button>
              );
            })}
          </div>
        )}

        {/* Table A: All headers with comparison */}
        <div>
          <h4 className="font-medium mb-2">
            Table A: All Headers (Cross-referenced with Whitelist)
          </h4>
          <p className="text-xs text-muted-foreground mb-2">
            "Expected Value" shows the value(s) declared in your whitelist.
            "N/A" in the Matches column means no expected value was declared
            (only presence was required).
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-xs border-collapse">
              <thead>
                <tr className="bg-muted">
                  <th className="border p-2 text-left">Header Name</th>
                  <th className="border p-2 text-left">Header Value</th>
                  <th className="border p-2 text-center">In Whitelist?</th>
                  <th className="border p-2 text-left">Expected Value</th>
                  <th className="border p-2 text-center">Matches?</th>
                  {selectedSource === "all" && sourceUrls.length > 1 && (
                    <th className="border p-2 text-left">Source</th>
                  )}
                </tr>
              </thead>
              <tbody>
                {filteredHeaders.map((h, i) => (
                  <tr key={i} className="hover:bg-accent/50">
                    <td className="border p-2 font-mono">{h.name}</td>
                    <td className="border p-2 font-mono break-all">{h.value}</td>
                    <td className="border p-2 text-center">
                      {h.in_reference ? (
                        <Badge variant="outline" className="bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300">
                          Yes
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="bg-orange-50 dark:bg-orange-950 text-orange-700 dark:text-orange-300">
                          No
                        </Badge>
                      )}
                    </td>
                    <td className="border p-2 font-mono text-muted-foreground">
                      {h.expected_value || "—"}
                    </td>
                    <td className="border p-2 text-center">
                      {!h.in_reference || !h.expected_value ? (
                        <Badge variant="outline" className="bg-muted text-muted-foreground">
                          N/A
                        </Badge>
                      ) : h.value_matches_expected ? (
                        <Badge variant="outline" className="bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300">
                          Yes
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300">
                          No
                        </Badge>
                      )}
                    </td>
                    {selectedSource === "all" && sourceUrls.length > 1 && (
                      <td className="border p-2 font-mono text-xs text-muted-foreground truncate max-w-[200px]" title={h.source_url}>
                        {h.source_url ? h.source_url.replace(/^https?:\/\/[^/]+/, "") : "—"}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Table B: Anomalies */}
        <div>
          <h4 className="font-medium mb-2">
            Table B: Headers NOT in Whitelist (Potential Anomalies) — {anomalies.length}
          </h4>
          {anomalies.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No anomalies — every response header was in the whitelist.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="bg-muted">
                    <th className="border p-2 text-left">Header Name</th>
                    <th className="border p-2 text-left">Header Value</th>
                  </tr>
                </thead>
                <tbody>
                  {anomalies.map((h, i) => (
                    <tr key={i}>
                      <td className="border p-2 font-mono">{h.name}</td>
                      <td className="border p-2 font-mono break-all">{h.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Table C: Policy Violations */}
        {mismatches.length > 0 && (
          <Alert className="border-red-300 dark:border-red-700">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>
              ⚠ {mismatches.length} Header Value Mismatch(es) Detected
            </AlertTitle>
            <AlertDescription>
              These headers ARE in your whitelist but their values DON'T match
              the expected values. Review each mismatch — it may represent a
              security weakness (e.g. HSTS with max-age=0 effectively disables
              HSTS despite the header being present).
            </AlertDescription>
          </Alert>
        )}
        <div>
          <h4 className="font-medium mb-2">
            Table C: Headers with Unexpected Values (Policy Violations) — {mismatches.length}
          </h4>
          {mismatches.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No value mismatches — every whitelist header with a declared
              expected value matched.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="bg-muted">
                    <th className="border p-2 text-left">Header Name</th>
                    <th className="border p-2 text-left">Actual Value</th>
                    <th className="border p-2 text-left">Expected Value</th>
                  </tr>
                </thead>
                <tbody>
                  {mismatches.map((h, i) => (
                    <tr key={i} className="bg-red-50 dark:bg-red-950/30">
                      <td className="border p-2 font-mono">{h.name}</td>
                      <td className="border p-2 font-mono break-all text-red-700 dark:text-red-300">
                        {h.value}
                      </td>
                      <td className="border p-2 font-mono text-muted-foreground">
                        {h.expected_value}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Table D: Missing Headers */}
        {missingHeaders.length > 0 && (
          <div className="mt-4">
            <h3 className="font-medium text-red-600 dark:text-red-400 mb-2 flex items-center gap-2">
              <AlertCircle className="w-4 h-4" />
              ✗ {missingHeaders.length} Missing Security Header(s) Detected
            </h3>
            <p className="text-xs text-muted-foreground mb-2">
              These headers are in your whitelist but were NOT found in the
              response. Their absence may indicate a security misconfiguration.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="bg-red-50 dark:bg-red-950/30">
                    <th className="border p-2 text-left">Missing Header</th>
                    <th className="border p-2 text-left">Expected Value</th>
                  </tr>
                </thead>
                <tbody>
                  {missingHeaders.map((h, i) => (
                    <tr key={i} className="hover:bg-muted/50">
                      <td className="border p-2 font-mono font-medium text-red-700 dark:text-red-300">
                        {h.name}
                      </td>
                      <td className="border p-2 font-mono text-muted-foreground">
                        {h.expected_value || "(any value — presence required)"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        <p className="text-xs text-muted-foreground mt-4">
          Raw header data is also saved to <code>headers_raw.json</code> in the
          output folder for import into Burp or other tooling.
        </p>
      </CardContent>
    </Card>
  );
}

/**
 * Helper: renders a screenshot image from the evidence directory.
 */
function ScreenshotImage({ scanId, name }: { scanId: string; name: string }) {
  const [src, setSrc] = useState<string | null>(null);

  useEffect(() => {
    fetch(`/api/scans/${scanId}/evidence/${encodeURIComponent(name)}`)
      .then((r) => r.blob())
      .then((blob) => {
        const reader = new FileReader();
        reader.onloadend = () => setSrc(reader.result as string);
        reader.readAsDataURL(blob);
      })
      .catch(() => {});
  }, [scanId, name]);

  if (!src) {
    return (
      <div className="text-xs text-muted-foreground">Loading screenshot...</div>
    );
  }
  return (
    <img
      src={src}
      alt={name}
      className="max-w-full border rounded"
    />
  );
}

// ===========================================================================
// OWASP COVERAGE PANEL
// ===========================================================================

/**
 * Shows the OWASP Top 10 (2025) categories and which ones the scanner
 * has checks for, with the current status derived from the live logs.
 *
 * The scanner.py currently covers:
 *   - A02 Cryptographic Failures (SSL/TLS inspection)
 *   - A03 Injection (XSS + SQLi active checks)
 *   - A05 Security Misconfiguration (missing headers, cookies, mixed content)
 *
 * The other categories are marked "not covered" with a note that manual
 * testing is required. This is intentional — the tool automates the grunt
 * work, not the full OWASP assessment.
 */
function OwaspCoveragePanel({
  scan,
  logs,
  scanId,
}: {
  scan: ScanSummary | undefined;
  logs: TrailEntry[];
  scanId: string;
}) {
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedCategory, setExpandedCategory] = useState<string | null>(null);
  const [aiResults, setAiResults] = useState<Record<string, {confidence: string; reasoning: string; suggested_test: string}>>({});
  const [aiSummary, setAiSummary] = useState<{total: number; agreed: number; disagreed: number; percent: number} | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiProgress, setAiProgress] = useState<{ done: number; total: number } | null>(null);
  const aiPollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [filterMode, setFilterMode] = useState<"all" | "agreed">("all");
  const [humanVerdicts, setHumanVerdicts] = useState<Record<string, "verified" | "false_positive">>({});

  useEffect(() => {
    let cancelled = false;
    async function fetchFindings() {
      try {
        const resp = await fetch(`/api/scans/${scanId}/findings`);
        if (resp.status === 404) { if (!cancelled) { setFindings([]); setLoading(scan?.status === "running" || scan?.status === "pending"); } return; }
        const data = await resp.json();
        if (!cancelled) { setFindings(data.findings || []); setLoading(false); }
      } catch { if (!cancelled) setLoading(false); }
    }
    fetchFindings();
    const interval = setInterval(fetchFindings, 5000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [scanId]);

  // Merge AI confidence results from a polled GET into state (progressive —
  // badges appear as new finding_ids arrive).
  const applyAiData = (data: any) => {
    if (data?.results) {
      setAiResults((prev) => {
        const map = { ...prev };
        for (const r of data.results) {
          if (r.finding_id) {
            map[r.finding_id] = { confidence: r.confidence, reasoning: r.reasoning, suggested_test: r.suggested_test };
          }
        }
        return map;
      });
      setAiSummary(data.summary);
    }
    const p = data?.progress;
    if (p) setAiProgress({ done: p.done, total: p.total });
    return p;
  };

  const stopAiPoll = () => {
    if (aiPollRef.current) { clearInterval(aiPollRef.current); aiPollRef.current = null; }
  };

  const pollAiConfidence = () => {
    fetch(`/api/scans/${scanId}/ai-confidence`)
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!data) return;
        const p = applyAiData(data);
        if (p && p.running === false) {
          stopAiPoll();
          setAiLoading(false);
          setAiProgress(null);
          if (p.error) setAiError(p.error);
        }
      })
      .catch(() => {});
  };

  // Clean up the poll interval if the panel unmounts mid-evaluation.
  useEffect(() => () => { stopAiPoll(); }, []);

  useEffect(() => {
    if (scan?.status !== "completed" && scan?.status !== "interrupted") return;
    if (findings.length === 0) return;
    let cancelled = false;
    fetch(`/api/scans/${scanId}/ai-confidence`)
      .then((r) => {
        if (r.status === 404) {
          // No evaluation yet — start one.
          if (!cancelled) runAIConfidence();
          return null;
        }
        return r.json();
      })
      .then((data) => {
        if (!data || cancelled) return;
        const p = applyAiData(data);
        // If a job is already mid-run (e.g. user navigated away + back),
        // follow it with the poller.
        if (p?.running) {
          setAiLoading(true);
          stopAiPoll();
          pollAiConfidence();
          aiPollRef.current = setInterval(pollAiConfidence, 1500);
        }
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [scanId, scan?.status, findings.length]);

  const runAIConfidence = async () => {
    setAiLoading(true); setAiError(null);
    setAiProgress({ done: 0, total: findings.length });
    try {
      // POST starts a background job server-side and returns immediately.
      const resp = await fetch(`/api/scans/${scanId}/ai-confidence`, { method: "POST" });
      const data = await resp.json();
      if (!resp.ok) {
        setAiError(data.error || "AI analysis failed.");
        setAiLoading(false); setAiProgress(null);
        return;
      }
      // If everything was already evaluated, finalize from a fresh GET.
      if (data.nothingToDo) {
        stopAiPoll();
        setAiLoading(false);
        setAiProgress(null);
        pollAiConfidence(); // loads the existing results into state
        return;
      }
      // Poll for progressive results.
      stopAiPoll();
      pollAiConfidence();
      aiPollRef.current = setInterval(pollAiConfidence, 1500);
    } catch (e) {
      setAiError(e instanceof Error ? e.message : String(e));
      setAiLoading(false); setAiProgress(null);
    }
  };

  const setVerdict = (fid: string, v: "verified" | "false_positive") => setHumanVerdicts((p) => ({ ...p, [fid]: v }));

  const exportCSV = () => {
    const rows = [["Finding ID", "Title", "Severity", "AI Agreed", "AI Confidence", "Human Verdict"]];
    for (const f of findings) {
      const ai = aiResults[f.finding_id];
      rows.push([f.finding_id, f.title.replace(/,/g, ";"), f.severity, ai ? (ai.confidence === "High" || ai.confidence === "Medium" ? "Yes" : "No") : "N/A", ai?.confidence || "N/A", humanVerdicts[f.finding_id] || ""]);
    }
    const csv = rows.map((r) => r.map((c) => `"${c}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `findings-${scanId.slice(-8)}.csv`; a.click();
    URL.revokeObjectURL(url);
  };

  const categories = [
    { id: "A01", name: "Broken Access Control", covered: scan?.testAccessControl || false, note: scan?.testAccessControl ? "Forced browsing." : "Enable 'Test Broken Access Control'." },
    { id: "A02", name: "Security Misconfiguration", covered: true, note: "Missing headers, cookies, mixed content." },
    { id: "A03", name: "Software Supply Chain Failures", covered: false, note: "Manual." },
    { id: "A04", name: "Cryptographic Failures", covered: true, note: "SSL/TLS inspection." },
    { id: "A05", name: "Injection (All)", covered: true, note: "All injection findings — XSS, SQLi, Path Traversal, CMDi, Open Redirect, SSTI.", isParent: true },
    { id: "A05-XSS", name: "Injection → XSS", covered: true, note: "Cross-Site Scripting reflections.", parentId: "A05" },
    { id: "A05-SQLi", name: "Injection → SQLi", covered: true, note: "SQL Injection (error-based, auth bypass, UNION, time-based).", parentId: "A05" },
    { id: "A05-Path", name: "Injection → Path Traversal", covered: true, note: "Directory traversal / LFI.", parentId: "A05" },
    { id: "A05-CMDi", name: "Injection → CMDi", covered: true, note: "Command Injection.", parentId: "A05" },
    { id: "A05-SSTI", name: "Injection → SSTI", covered: true, note: "Server-Side Template Injection.", parentId: "A05" },
    { id: "A05-Redirect", name: "Injection → Open Redirect", covered: true, note: "Unvalidated redirects.", parentId: "A05" },
    { id: "A06", name: "Insecure Design", covered: scan?.deepLogic || false, note: scan?.deepLogic ? "Deep logic." : "Enable 'Deep Logic Scan'." },
    { id: "A07", name: "Authentication Failures", covered: false, note: "Manual." },
    { id: "A08", name: "Software or Data Integrity Failures", covered: false, note: "Manual." },
    { id: "A09", name: "Security Logging and Alerting Failures", covered: false, note: "Manual." },
    { id: "A10", name: "Mishandling of Exceptional Conditions", covered: false, note: "Manual." },
  ];

  // Group findings by OWASP category. For A05 sub-categories, also filter
  // by the patterns_matched field (e.g. "XSS:script_alert" → A05-XSS).
  const findingsByCategory: Record<string, ScanFinding[]> = {};
  for (const f of findings) {
    const c = f.owasp_category || "Uncategorized";
    // Add to the parent category (e.g. "A05:2025 Injection")
    if (!findingsByCategory[c]) findingsByCategory[c] = [];
    findingsByCategory[c].push(f);

    // Also add to sub-categories based on patterns_matched
    const patterns = (f.patterns_matched || []) as string[];
    const hasXSS = patterns.some((p: string) => p.startsWith("XSS:"));
    const hasSQLi = patterns.some((p: string) => p.startsWith("SQLi:"));
    const hasPath = patterns.some((p: string) => p.startsWith("PathTraversal:"));
    const hasCMDi = patterns.some((p: string) => p.startsWith("CMDi:"));
    const hasSSTI = patterns.some((p: string) => p.startsWith("SSTI:"));
    const hasRedirect = patterns.some((p: string) => p.startsWith("OpenRedirect:"));

    if (c.includes("A05") || c.includes("Injection")) {
      if (hasXSS) {
        if (!findingsByCategory["A05-XSS"]) findingsByCategory["A05-XSS"] = [];
        findingsByCategory["A05-XSS"].push(f);
      }
      if (hasSQLi) {
        if (!findingsByCategory["A05-SQLi"]) findingsByCategory["A05-SQLi"] = [];
        findingsByCategory["A05-SQLi"].push(f);
      }
      if (hasPath) {
        if (!findingsByCategory["A05-Path"]) findingsByCategory["A05-Path"] = [];
        findingsByCategory["A05-Path"].push(f);
      }
      if (hasCMDi) {
        if (!findingsByCategory["A05-CMDi"]) findingsByCategory["A05-CMDi"] = [];
        findingsByCategory["A05-CMDi"].push(f);
      }
      if (hasSSTI) {
        if (!findingsByCategory["A05-SSTI"]) findingsByCategory["A05-SSTI"] = [];
        findingsByCategory["A05-SSTI"].push(f);
      }
      if (hasRedirect) {
        if (!findingsByCategory["A05-Redirect"]) findingsByCategory["A05-Redirect"] = [];
        findingsByCategory["A05-Redirect"].push(f);
      }
    }
  }

  const hasSslCheck = logs.some((l) => l.action === "ssl_inspect");
  const hasActiveChecks = logs.some((l) => l.action === "active_match" || l.action?.startsWith("active_"));
  const hasPassiveChecks = logs.some((l) => l.action?.startsWith("passive_") || (l.action === "phase" && String(l.result).includes("passive")));
  const hasAccessControl = logs.some((l) => l.action?.startsWith("access_control_"));
  const passiveDone = logs.some((l) => l.action === "phase" && String(l.result).includes("active checks"));
  const activeDone = logs.some((l) => l.action === "phase" && String(l.result).includes("active checks complete"));
  const accessControlDone = logs.some((l) => l.action === "access_control_done");

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><ShieldCheck className="w-5 h-5" /> OWASP Top 10 (2025) — Findings by Category</CardTitle>
        <CardDescription>Click a category to expand. AI badges are visual only — status remains UNVERIFIED.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {findings.length > 0 && (
          <div className="flex items-center justify-between flex-wrap gap-2 p-3 rounded-lg border bg-muted/30">
            <div className="flex items-center gap-3">
              {aiLoading && <Loader2 className="w-4 h-4 animate-spin text-purple-600" />}
              {aiLoading && aiProgress && (
                <span className="text-xs text-purple-600 dark:text-purple-400 font-medium tabular-nums">
                  Evaluating… {aiProgress.done}/{aiProgress.total}
                </span>
              )}
              {aiSummary ? (
                <Badge variant="outline" className="bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300"><CheckCircle2 className="w-3 h-3 mr-1" />AI Agreed: {aiSummary.agreed}/{aiSummary.total} ({aiSummary.percent}%)</Badge>
              ) : aiError ? (
                <Badge variant="outline" className="bg-muted text-muted-foreground text-xs">{aiError.includes("not configured") ? "AI analysis skipped: LLM not configured." : aiError.slice(0, 60)}</Badge>
              ) : !aiLoading ? (
                <Badge variant="outline" className="bg-muted text-muted-foreground text-xs">AI confidence: not evaluated</Badge>
              ) : null}
              <Button variant="outline" size="sm" onClick={runAIConfidence} disabled={aiLoading} className="text-xs h-7">{aiLoading ? (aiProgress ? `Evaluating ${aiProgress.done}/${aiProgress.total}` : "Evaluating…") : "Re-run AI"}</Button>
            </div>
            <div className="flex items-center gap-2">
              <select value={filterMode} onChange={(e) => setFilterMode(e.target.value as "all" | "agreed")} className="text-xs rounded border px-2 py-1 bg-background"><option value="all">Show All</option><option value="agreed">Show AI Agreed Only</option></select>
              <Button variant="outline" size="sm" onClick={exportCSV} className="text-xs h-7"><Download className="w-3 h-3 mr-1" />Export CSV</Button>
            </div>
          </div>
        )}
        {loading && (<div className="text-center py-8 text-sm text-muted-foreground"><Loader2 className="w-6 h-6 mx-auto animate-spin mb-2" /> Loading findings...</div>)}
        {!loading && categories.map((cat) => {
          let status: "covered" | "testing" | "done" | "manual" = cat.covered ? "covered" : "manual";
          if (cat.covered) {
            if (cat.id === "A01" && accessControlDone) status = "done"; else if (cat.id === "A01" && hasAccessControl) status = "testing";
            else if (cat.id === "A02" && passiveDone) status = "done"; else if (cat.id === "A02" && hasPassiveChecks) status = "testing";
            else if (cat.id === "A04" && hasSslCheck) status = "done";
            else if (cat.id === "A05" && activeDone) status = "done"; else if (cat.id === "A05" && hasActiveChecks) status = "testing";
          }
          // Match findings for this category. For sub-categories (A05-XSS etc.),
          // use the sub-category ID directly. For parent categories, use the
          // OWASP category string variants.
          let cf: ScanFinding[];
          if (cat.parentId) {
            // Sub-category — use the ID directly (e.g. "A05-XSS")
            cf = findingsByCategory[cat.id] || [];
          } else if (cat.isParent) {
            // Parent A05 — show ALL injection findings
            cf = [
              ...(findingsByCategory["A05:2025 Injection"] || []),
              ...(findingsByCategory["A05 Injection"] || []),
            ];
            // Deduplicate
            const seen = new Set<string>();
            cf = cf.filter((f) => {
              if (seen.has(f.finding_id)) return false;
              seen.add(f.finding_id);
              return true;
            });
          } else {
            const ck = `${cat.id}:2025 ${cat.name}`; const ok2 = `${cat.id} ${cat.name}`;
            cf = [...(findingsByCategory[ck] || []), ...(findingsByCategory[ok2] || [])];
          }
          if (filterMode === "agreed") cf = cf.filter((f) => { const a = aiResults[f.finding_id]; return a && (a.confidence === "High" || a.confidence === "Medium"); });
          const fc = cf.length;
          const sb = { covered: <Badge variant="outline" className="bg-blue-50 dark:bg-blue-950">auto</Badge>, testing: <Badge variant="outline" className="bg-yellow-50 dark:bg-yellow-950">testing...</Badge>, done: <Badge variant="outline" className="bg-green-50 dark:bg-green-950">done</Badge>, manual: <Badge variant="outline" className="bg-muted">manual</Badge> }[status];
          const ex = expandedCategory === cat.id;
          return (
            <div key={cat.id} className={`rounded-lg border overflow-hidden ${cat.parentId ? "ml-6 border-l-4 border-l-blue-300 dark:border-l-blue-700" : ""}`}>
              <button className="w-full flex items-start gap-3 p-3 text-left hover:bg-accent transition-colors" onClick={() => setExpandedCategory(ex ? null : cat.id)}>
                <div className="flex-shrink-0 w-12"><span className="font-bold text-sm">{cat.id.replace("A05-", "")}</span></div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap"><span className={`text-sm ${cat.parentId ? "font-normal text-muted-foreground" : "font-medium"}`}>{cat.name}</span>{sb}{fc > 0 && <Badge variant="outline" className="bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300">{fc} finding{fc !== 1 ? "s" : ""}</Badge>}</div>
                  <p className="text-xs text-muted-foreground">{cat.note}</p>
                </div>
                {fc > 0 && <div className="flex-shrink-0 text-muted-foreground text-xs">{ex ? "▲ collapse" : "▼ expand"}</div>}
              </button>
              {ex && cf.length > 0 && (<div className="border-t bg-muted/30 p-3 space-y-3">{cf.map((f, i) => <FindingDetail key={`${f.finding_id ?? ""}-${i}`} finding={f} scanId={scanId} aiResult={aiResults[f.finding_id]} humanVerdict={humanVerdicts[f.finding_id]} onSetVerdict={setVerdict} />)}</div>)}
              {ex && cf.length === 0 && (<div className="border-t bg-muted/30 p-3 text-sm text-muted-foreground">{filterMode === "agreed" ? "No AI-agreed findings." : "No findings."}</div>)}
            </div>
          );
        })}
        <Alert className="mt-4"><ShieldCheck className="h-4 w-4" /><AlertTitle>Coverage note</AlertTitle><AlertDescription>AI badges are visual only. Human must click Verified/False Positive to change status.</AlertDescription></Alert>
      </CardContent>
    </Card>
  );
}

function FindingDetail({ finding, scanId, aiResult, humanVerdict, onSetVerdict }: {
  finding: ScanFinding;
  scanId: string;
  aiResult?: { confidence: string; reasoning: string; suggested_test: string };
  humanVerdict?: "verified" | "false_positive";
  onSetVerdict?: (findingId: string, verdict: "verified" | "false_positive") => void;
}) {
  const [showRaw, setShowRaw] = useState(false);
  const [rechecking, setRechecking] = useState(false);
  const [localAiResult, setLocalAiResult] = useState(aiResult);
  const aiAgreed = localAiResult && (localAiResult.confidence === "High" || localAiResult.confidence === "Medium");

  const handleRecheckAI = async () => {
    setRechecking(true);
    try {
      const resp = await fetch(`/api/scans/${scanId}/ai-confidence/recheck`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: finding.finding_id }),
      });
      const data = await resp.json();
      if (data.result) {
        setLocalAiResult(data.result);
      }
    } catch {}
    setRechecking(false);
  };

  return (
    <div className="rounded border bg-card p-3">
      <div className="flex items-center gap-2 mb-2 flex-wrap">
        <Badge variant="outline" className={
          finding.severity === "High" ? "bg-red-50 dark:bg-red-950"
          : finding.severity === "Medium" ? "bg-yellow-50 dark:bg-yellow-950"
          : finding.severity === "Info" ? "bg-blue-50 dark:bg-blue-950"
          : "bg-muted"
        }>
          {finding.severity}
        </Badge>
        <span className="font-medium text-sm flex-1">{finding.title}</span>
        {aiResult && (aiAgreed ? (
          <Badge variant="outline" className="bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300"><CheckCircle2 className="w-3 h-3 mr-1" />AI Agreed ({aiResult.confidence})</Badge>
        ) : (
          <Badge variant="outline" className="bg-yellow-50 dark:bg-yellow-950 text-yellow-700 dark:text-yellow-300">AI Disagreed ({aiResult.confidence})</Badge>
        ))}
        <Badge variant="outline" className="text-xs">UNVERIFIED</Badge>
        {humanVerdict === "verified" && <Badge variant="outline" className="bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300">✓ Verified</Badge>}
        {humanVerdict === "false_positive" && <Badge variant="outline" className="bg-muted text-muted-foreground">✗ False Positive</Badge>}
      </div>
      <div className="text-xs space-y-1 mb-2">
        <div><span className="text-muted-foreground">URL:</span> <code className="font-mono break-all">{finding.url}</code></div>
        {finding.payload && finding.payload !== "(no cookies — forced browsing)" && (
          <div><span className="text-muted-foreground">Payload:</span> <code className="font-mono break-all">{finding.payload}</code></div>
        )}
        {finding.patterns_matched.length > 0 && (
          <div><span className="text-muted-foreground">Patterns:</span> {finding.patterns_matched.join(", ")}</div>
        )}
      </div>
      {/* AI Confidence section */}
      {localAiResult && (
        <div className="mb-2 p-2 rounded bg-purple-50 dark:bg-purple-950/30 border border-purple-200 dark:border-purple-800">
          <div className="flex items-center justify-between mb-1">
            <div className="text-xs font-medium text-purple-700 dark:text-purple-300">AI Confidence: {localAiResult.confidence}</div>
            <Button
              variant="ghost"
              size="sm"
              className="h-6 px-2 text-xs text-purple-600 hover:text-purple-700"
              onClick={handleRecheckAI}
              disabled={rechecking}
              title="Re-check this finding with AI"
            >
              {rechecking ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <RefreshCw className="w-3 h-3 mr-1" />}
              Re-check
            </Button>
          </div>
          <p className="text-xs text-muted-foreground mb-1">{localAiResult.reasoning}</p>
          {localAiResult.suggested_test && <p className="text-xs text-purple-600 dark:text-purple-400">Suggested test: {localAiResult.suggested_test}</p>}
        </div>
      )}
      {!localAiResult && (
        <div className="mb-2">
          <Button
            variant="outline"
            size="sm"
            className="text-xs h-7 border-purple-300 text-purple-700 dark:border-purple-700 dark:text-purple-300"
            onClick={handleRecheckAI}
            disabled={rechecking}
          >
            {rechecking ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Bot className="w-3 h-3 mr-1" />}
            Check with AI
          </Button>
        </div>
      )}
      {/* Human verdict buttons */}
      {onSetVerdict && (
        <div className="mb-2 flex gap-2">
          <Button variant="outline" size="sm" onClick={() => onSetVerdict(finding.finding_id, "verified")} className={`text-xs h-7 ${humanVerdict === "verified" ? "border-green-500 bg-green-50 dark:bg-green-950" : ""}`}>
            <CheckCircle2 className="w-3 h-3 mr-1" /> Mark Verified
          </Button>
          <Button variant="outline" size="sm" onClick={() => onSetVerdict(finding.finding_id, "false_positive")} className={`text-xs h-7 ${humanVerdict === "false_positive" ? "border-muted bg-muted" : ""}`}>
            <XCircle className="w-3 h-3 mr-1" /> Mark False Positive
          </Button>
        </div>
      )}
      {finding.has_screenshot && finding.screenshot_path && (
        <div className="mb-2">
          <img
            src={`/api/scans/${scanId}/evidence/${encodeURIComponent(finding.screenshot_path)}`}
            alt={`Screenshot of finding ${finding.finding_id}`}
            className="max-w-full border-2 border-red-500 rounded my-2"
          />
        </div>
      )}
      {finding.execution_trail && finding.execution_trail.length > 0 && (
        <div className="mb-2">
          <h5 className="text-xs font-medium mb-1">Steps to Reproduce:</h5>
          <ol className="list-decimal list-inside text-xs space-y-0.5 bg-muted/50 rounded p-2">
            {finding.execution_trail.map((step, i) => (
              <li key={i} className="font-mono">{step}</li>
            ))}
          </ol>
        </div>
      )}
      <Button variant="outline" size="sm" onClick={() => setShowRaw(!showRaw)} className="text-xs mb-2">
        {showRaw ? "Hide" : "Show"} Raw HTTP Evidence
      </Button>
      {showRaw && (
        <div className="space-y-2">
          {finding.request_raw && (
            <div>
              <h5 className="text-xs font-medium mb-1">Request:</h5>
              <pre className="text-xs bg-black text-green-400 p-2 rounded overflow-x-auto max-h-60">
                {finding.request_raw}
              </pre>
            </div>
          )}
          {finding.response_raw && (
            <div>
              <h5 className="text-xs font-medium mb-1">Response:</h5>
              <pre className="text-xs bg-black text-green-400 p-2 rounded overflow-x-auto max-h-60">
                {finding.response_raw.slice(0, 3000)}
                {finding.response_raw.length > 3000 ? "\n...[truncated]" : ""}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ===========================================================================
// DEEP LOGIC PANEL
// ===========================================================================

interface DeepLogicFinding {
  finding_id: string;
  title: string;
  severity: string;
  owasp_category: string;
  url: string;
  input_name: string;
  mutation: string;
  happy_path: string[];
  mutation_applied: string;
  baseline_status: number;
  mutated_status: number;
  baseline_snippet: string;
  mutated_snippet: string;
  anomaly: string;
  screenshot_path: string | null;
  has_screenshot: boolean;
  execution_trail: string[];
  unverified: boolean;
}

/**
 * Displays business logic flaws found by the DeepLogicTester.
 *
 * Each finding shows:
 *   - The happy path (normal request sequence)
 *   - The mutation applied (e.g. "Changed 'quantity' to '-1'")
 *   - The anomaly detected (e.g. "Negative total price appeared")
 *   - Baseline vs mutated response snippets
 *   - Steps to reproduce
 *   - Screenshot (if available)
 *
 * All findings are UNVERIFIED — the engineer must manually confirm.
 */
function DeepLogicPanel({
  scanId,
  isRunning,
}: {
  scanId: string;
  isRunning: boolean;
}) {
  const [findings, setFindings] = useState<DeepLogicFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function fetchFindings() {
      try {
        const resp = await fetch(`/api/scans/${scanId}/deep-logic`);
        if (resp.status === 404) {
          if (!cancelled) {
            setFindings([]);
            setError(null);
            setLoading(isRunning);
          }
          return;
        }
        const data = await resp.json();
        if (!cancelled) {
          setFindings(data.findings || []);
          setError(null);
          setLoading(false);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
          setLoading(false);
        }
      }
    }
    fetchFindings();
    const interval = setInterval(() => {
      if (findings.length > 0 || !isRunning) {
        clearInterval(interval);
        return;
      }
      fetchFindings();
    }, 2000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [scanId, isRunning]);

  if (loading) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            Running deep logic tests... (this is SLOW — be patient)
          </p>
          <p className="text-xs text-muted-foreground mt-1">
            Mutating numeric parameters + comparing responses to baseline.
          </p>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <AlertCircle className="w-8 h-8 mx-auto text-destructive mb-3" />
          <p className="text-sm">{error}</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FlaskConical className="w-5 h-5" />
          Deep Logic Findings (Business Logic Flaws)
        </CardTitle>
        <CardDescription>
          EXPERIMENTAL: These findings were generated by mutating numeric
          parameters (negative, zero, extreme values) and comparing responses
          to the baseline. All findings are UNVERIFIED — expect false positives.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {findings.length === 0 && (
          <Alert>
            <FlaskConical className="h-4 w-4" />
            <AlertDescription>
              No business logic anomalies were detected. This can mean:
              (a) the target has no numeric parameters to mutate,
              (b) the target correctly validated all mutations (good!),
              or (c) the target is stateless (deep logic works best on
              stateful apps like e-commerce, banking, multi-step forms).
            </AlertDescription>
          </Alert>
        )}

        {findings.map((f, i) => (
          <DeepLogicFindingCard key={i} finding={f} scanId={scanId} index={i} />
        ))}
      </CardContent>
    </Card>
  );
}

// ===========================================================================
// UPLOADS PANEL (File Upload Testing)
// ===========================================================================

interface UploadRow {
  probe_id: string;
  filename: string;
  mime_sent: string;
  content_desc: string;
  input_url: string;
  input_name: string;
  http_status: number;
  accepted: boolean;
  filename_reflected: boolean;
  landing_urls: string[];
  candidate_urls: string[];
  response_preview: string;
  screenshot: string | null;
  severity: string;
  owasp: string;
  rationale: string;
}

/**
 * Displays the file-upload probe table generated by FileUploadTester.
 *
 * One row per probe attempt (accepted AND rejected). The key column is the
 * landing URL — where the uploaded file can be reached — shown as a
 * clickable link so the engineer can manually confirm whether it's served.
 * Candidate URLs (under /uploads/, /files/, etc.) are shown with a
 * "candidate" badge when no concrete landing URL was reflected.
 *
 * Accepted dangerous uploads ALSO appear as findings in the OWASP tab
 * (A05:2025 Injection); this tab is the full audit trail.
 */
function UploadsPanel({
  scanId,
  isRunning,
}: {
  scanId: string;
  isRunning: boolean;
}) {
  const [uploads, setUploads] = useState<UploadRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function fetchUploads() {
      try {
        const resp = await fetch(`/api/scans/${scanId}/file-uploads`);
        if (resp.status === 404) {
          if (!cancelled) {
            setUploads([]);
            setError(null);
            setLoading(isRunning);
          }
          return;
        }
        const data = await resp.json();
        if (!cancelled) {
          setUploads(data.uploads || []);
          setError(null);
          setLoading(false);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
          setLoading(false);
        }
      }
    }
    fetchUploads();
    const interval = setInterval(() => {
      if (uploads.length > 0 || !isRunning) {
        clearInterval(interval);
        return;
      }
      fetchUploads();
    }, 2000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [scanId, isRunning]);

  if (loading) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            Running file-upload probes... (browser-driven; one submit per probe)
          </p>
          <p className="text-xs text-muted-foreground mt-1">
            Extension bypass, MIME spoof, polyglot, and XSS payloads against
            every &lt;input type=file&gt;.
          </p>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <AlertCircle className="w-8 h-8 mx-auto text-destructive mb-3" />
          <p className="text-sm">{error}</p>
        </CardContent>
      </Card>
    );
  }

  const acceptedCount = uploads.filter((u) => u.accepted).length;
  const dangerousAccepted = uploads.filter(
    (u) => u.accepted && u.probe_id !== "txt_benign",
  ).length;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Upload className="w-5 h-5" />
          File Upload Probes ({uploads.length})
        </CardTitle>
        <CardDescription>
          Every probe attempt against &lt;input type=file&gt; fields. Accepted
          dangerous uploads ({dangerousAccepted}) also appear in the OWASP tab
          as A05 findings. Open the landing URL to manually confirm the file is
          served. All results are UNVERIFIED.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {uploads.length === 0 ? (
          <Alert>
            <Upload className="h-4 w-4" />
            <AlertDescription>
              No upload probes recorded. This scan either found no{" "}
              &lt;input type=file&gt; fields, or the file-upload phase has not
              run yet.
            </AlertDescription>
          </Alert>
        ) : (
          <>
            <div className="flex gap-4 mb-3 text-sm">
              <span>
                <Badge variant="outline" className="bg-green-50 dark:bg-green-950 mr-1">
                  {acceptedCount} accepted
                </Badge>
                of {uploads.length} probes
              </span>
              {dangerousAccepted > 0 && (
                <span className="text-destructive font-medium">
                  ⚠ {dangerousAccepted} dangerous upload(s) accepted
                </span>
              )}
            </div>
            <div className="overflow-x-auto rounded-lg border">
              <table className="w-full text-sm">
                <thead className="bg-muted/50">
                  <tr className="text-left">
                    <th className="p-2 font-medium">Result</th>
                    <th className="p-2 font-medium">Filename</th>
                    <th className="p-2 font-medium">MIME sent</th>
                    <th className="p-2 font-medium">HTTP</th>
                    <th className="p-2 font-medium">Reflected</th>
                    <th className="p-2 font-medium">Landing URL (click to verify)</th>
                    <th className="p-2 font-medium">Shot</th>
                  </tr>
                </thead>
                <tbody>
                  {uploads.map((u, i) => {
                    const dangerous = u.probe_id !== "txt_benign";
                    const landing = u.landing_urls[0];
                    const candidate = u.candidate_urls[0];
                    return (
                      <tr key={i} className="border-t align-top">
                        <td className="p-2 whitespace-nowrap">
                          {u.accepted ? (
                            <Badge variant="outline" className="bg-green-50 dark:bg-green-950 text-xs">
                              <CheckCircle2 className="w-3 h-3 mr-1" /> accepted
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="bg-red-50 dark:bg-red-950 text-xs">
                              <XCircle className="w-3 h-3 mr-1" /> rejected
                            </Badge>
                          )}
                          {dangerous && u.accepted && (
                            <div className="text-xs text-destructive mt-1">{u.severity}</div>
                          )}
                        </td>
                        <td className="p-2">
                          <code className="text-xs font-mono">{u.filename}</code>
                          <div className="text-xs text-muted-foreground mt-0.5">{u.content_desc}</div>
                        </td>
                        <td className="p-2">
                          <code className="text-xs font-mono">{u.mime_sent}</code>
                        </td>
                        <td className="p-2 text-xs">{u.http_status || "?"}</td>
                        <td className="p-2 text-xs">
                          {u.filename_reflected ? "✓" : "✗"}
                        </td>
                        <td className="p-2 max-w-md">
                          {landing ? (
                            <a
                              href={landing}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs font-mono text-blue-600 dark:text-blue-400 hover:underline break-all"
                            >
                              {landing}
                            </a>
                          ) : candidate ? (
                            <span>
                              <a
                                href={candidate}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-xs font-mono text-blue-600 dark:text-blue-400 hover:underline break-all"
                              >
                                {candidate}
                              </a>
                              <Badge variant="outline" className="ml-1 text-xs text-muted-foreground">
                                candidate
                              </Badge>
                            </span>
                          ) : (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                          {u.landing_urls.length > 1 && (
                            <div className="text-xs text-muted-foreground mt-0.5">
                              +{u.landing_urls.length - 1} more
                            </div>
                          )}
                        </td>
                        <td className="p-2">
                          {u.screenshot ? (
                            <a
                              href={`/api/scans/${scanId}/evidence/${encodeURIComponent(u.screenshot)}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs text-blue-600 dark:text-blue-400 hover:underline"
                            >
                              view
                            </a>
                          ) : (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Expandable card for a single deep logic finding.
 * Collapsed: shows title + badges only.
 * Expanded: shows anomaly, mutation, screenshot, response comparison, steps.
 */
function DeepLogicFindingCard({
  finding: f,
  scanId,
  index,
}: {
  finding: DeepLogicFinding;
  scanId: string;
  index: number;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-lg border overflow-hidden">
      {/* Collapsed header — click to expand */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2 p-3 hover:bg-accent/50 transition-colors text-left"
      >
        <Badge variant="outline" className="bg-purple-50 dark:bg-purple-950 text-xs shrink-0">
          {f.owasp_category}
        </Badge>
        <Badge variant="outline" className="bg-yellow-50 dark:bg-yellow-950 text-xs shrink-0">
          {f.severity}
        </Badge>
        <span className="font-medium text-sm flex-1 truncate">{f.title}</span>
        <Badge variant="outline" className="text-xs shrink-0">#{index + 1}</Badge>
        <span className="text-xs text-muted-foreground shrink-0">
          {expanded ? "▲" : "▼"}
        </span>
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="p-4 space-y-3 border-t bg-muted/20">
          {/* Anomaly */}
          <div>
            <h5 className="text-xs font-medium text-purple-600 dark:text-purple-400 mb-1">
              Anomaly Detected:
            </h5>
            <p className="text-sm">{f.anomaly}</p>
          </div>

          {/* Mutation */}
          <div>
            <h5 className="text-xs font-medium text-purple-600 dark:text-purple-400 mb-1">
              Mutation Applied:
            </h5>
            <p className="text-xs font-mono">{f.mutation_applied}</p>
          </div>

          {/* Screenshot */}
          {f.has_screenshot && f.screenshot_path && (
            <div>
              <h5 className="text-xs font-medium text-purple-600 dark:text-purple-400 mb-1">
                Screenshot (Mutated Response):
              </h5>
              <img
                src={`/api/scans/${scanId}/evidence/${encodeURIComponent(f.screenshot_path)}`}
                alt={`Screenshot of deep logic finding ${f.finding_id}`}
                className="max-w-full border-2 border-purple-500 rounded my-2"
              />
            </div>
          )}

          {/* Response comparison */}
          <div className="grid grid-cols-2 gap-2">
            <div>
              <h5 className="text-xs font-medium text-green-600 dark:text-green-400 mb-1">
                Baseline (Status {f.baseline_status}):
              </h5>
              <pre className="text-xs bg-black text-green-400 p-2 rounded overflow-x-auto max-h-40">
                {f.baseline_snippet.slice(0, 500)}
              </pre>
            </div>
            <div>
              <h5 className="text-xs font-medium text-red-600 dark:text-red-400 mb-1">
                Mutated (Status {f.mutated_status}):
              </h5>
              <pre className="text-xs bg-black text-red-400 p-2 rounded overflow-x-auto max-h-40">
                {f.mutated_snippet.slice(0, 500)}
              </pre>
            </div>
          </div>

          {/* Steps to reproduce */}
          <div>
            <h5 className="text-xs font-medium text-purple-600 dark:text-purple-400 mb-1">
              Steps to Reproduce:
            </h5>
            <ol className="list-decimal list-inside text-xs space-y-0.5 bg-muted/50 rounded p-2">
              {f.execution_trail.map((step, j) => (
                <li key={j} className="font-mono">{step}</li>
              ))}
            </ol>
          </div>
        </div>
      )}
    </div>
  );
}

// ===========================================================================
// INTERESTING LOCATIONS PANEL
// ===========================================================================

interface InterestingLocationsData {
  url_findings: Array<{
    url: string;
    category: string;
    description: string;
    source: string;
  }>;
  param_findings: Array<{
    url: string;
    param_name: string;
    location: string;
    method: string;
    input_type: string;
    category: string;
    description: string;
  }>;
  header_findings: Array<{
    header: string;
    value: string;
    category: string;
    description: string;
  }>;
  summary: Record<string, number>;
}

/**
 * Displays high-value URLs + inputs the pentester should test first.
 *
 * This panel reads interesting_locations.json (generated by the scanner
 * after attack surface mapping). It groups findings into three sections:
 *   1. Interesting URLs — admin panels, API endpoints, auth pages, file ops
 *   2. Interesting Parameters — IDOR candidates, redirect params, cmd params, etc.
 *   3. Interesting Headers — server banners, debug headers (info disclosure)
 *
 * Each item includes a description of WHAT to test + WHY it's interesting.
 * This is the pentester's "what should I look at first?" triage view.
 *
 * Each item has an "Explain with AI" button that sends the item to the
 * LLM for a detailed explanation of the vulnerability class + how to test it.
 */

// --- ExplainButton: reusable component for LLM explanations ---
function ExplainButton({
  scanId,
  type,
  item,
}: {
  scanId: string;
  type: "url" | "param" | "header";
  item: Record<string, unknown>;
}) {
  const [explanation, setExplanation] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);

  const handleExplain = async () => {
    if (explanation) {
      setExpanded(!expanded);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(
        `/api/scans/${scanId}/interesting-locations/explain`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ type, item }),
        },
      );
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
      setExplanation(data.explanation);
      setExpanded(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mt-2">
      <Button
        variant="outline"
        size="sm"
        onClick={handleExplain}
        disabled={loading}
        className="text-xs"
      >
        {loading ? (
          <Loader2 className="w-3 h-3 mr-1 animate-spin" />
        ) : (
          <Bot className="w-3 h-3 mr-1" />
        )}
        {loading ? "Asking AI..." : explanation ? (expanded ? "Hide AI Explanation" : "Show AI Explanation") : "Explain with AI"}
      </Button>
      {error && (
        <p className="text-xs text-destructive mt-1">{error}</p>
      )}
      {expanded && explanation && (
        <div className="mt-2 rounded border bg-muted/30 p-3 text-xs whitespace-pre-wrap">
          {explanation}
        </div>
      )}
    </div>
  );
}

function InterestingLocationsPanel({
  scanId,
  isRunning,
}: {
  scanId: string;
  isRunning: boolean;
}) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedUrl, setSelectedUrl] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function fetchLocations() {
      try {
        const resp = await fetch(`/api/scans/${scanId}/interesting-locations`);
        if (resp.status === 404) {
          if (!cancelled) {
            setData(null);
            setError(null);
            setLoading(isRunning);
          }
          return;
        }
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const json = await resp.json();
        if (!cancelled) {
          setData(json.locations);
          setError(null);
          setLoading(false);
          // Auto-select the first URL.
          const urls = Object.keys(json.locations?.urls || {});
          if (urls.length > 0 && !selectedUrl) {
            setSelectedUrl(urls[0]);
          }
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
          setLoading(false);
        }
      }
    }
    fetchLocations();
    const interval = setInterval(() => {
      if (data || !isRunning) {
        clearInterval(interval);
        return;
      }
      fetchLocations();
    }, 2000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [scanId, isRunning]);

  if (loading) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            Analyzing crawl results for interesting locations...
          </p>
          <p className="text-xs text-muted-foreground mt-1">
            Runs after attack surface mapping + source code analysis completes.
          </p>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <AlertCircle className="w-8 h-8 mx-auto text-destructive mb-3" />
          <p className="text-sm">{error}</p>
        </CardContent>
      </Card>
    );
  }

  if (!data) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Crosshair className="w-8 h-8 mx-auto text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            No interesting locations data available.
          </p>
        </CardContent>
      </Card>
    );
  }

  // Build the URL-grouped data structure.
  // We combine: url_findings, param_findings, source_findings, input_surface
  // into a single dict keyed by URL.
  const urlData: Record<string, {
    heuristic: any[];
    source: any[];
    inputSurface: any;
    params: any[];
  }> = {};

  // Populate from url_findings (heuristic URL analysis).
  for (const f of (data.url_findings || [])) {
    if (!urlData[f.url]) urlData[f.url] = { heuristic: [], source: [], inputSurface: null, params: [] };
    urlData[f.url].heuristic.push(f);
  }

  // Populate from param_findings (heuristic param analysis).
  for (const f of (data.param_findings || [])) {
    if (!urlData[f.url]) urlData[f.url] = { heuristic: [], source: [], inputSurface: null, params: [] };
    urlData[f.url].params.push(f);
  }

  // Populate from source_findings (source code analysis).
  const sourceFindings = data.source_findings || {};
  for (const url of Object.keys(sourceFindings)) {
    if (!urlData[url]) urlData[url] = { heuristic: [], source: [], inputSurface: null, params: [] };
    urlData[url].source = sourceFindings[url];
  }

  // Populate from input_surface (input surface mapping).
  const inputSurface = data.input_surface || {};
  for (const url of Object.keys(inputSurface)) {
    if (!urlData[url]) urlData[url] = { heuristic: [], source: [], inputSurface: null, params: [] };
    urlData[url].inputSurface = inputSurface[url];
  }

  const urls = Object.keys(urlData).sort();
  const headerFindings = data.header_findings || [];
  const totalUrls = urls.length;
  const totalSourceFindings = Object.values(sourceFindings).reduce((sum: number, arr: any) => sum + arr.length, 0);
  const totalHidden = Object.values(inputSurface).reduce((sum: number, d: any) => sum + (d.hidden_inputs_flagged?.length || 0), 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Crosshair className="w-5 h-5" />
          Interesting Locations — URL-Grouped Attack Surface
        </CardTitle>
        <CardDescription>
          {totalUrls} URLs with findings · {totalSourceFindings} source code patterns · {totalHidden} hidden inputs flagged.
          Click a URL sub-tab to see: Why interesting, Where found, Evidence Snapshot, Suggested Test, and AI Insight.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {totalUrls === 0 && headerFindings.length === 0 && (
          <Alert>
            <Crosshair className="h-4 w-4" />
            <AlertDescription>
              No interesting locations detected. This may indicate a minimal target
              or that the crawl didn't reach depth 2+.
            </AlertDescription>
          </Alert>
        )}

        {/* URL sub-tabs (horizontal scrollable list) */}
        {totalUrls > 0 && (
          <div>
            <h4 className="text-sm font-medium mb-2">URLs ({totalUrls}):</h4>
            <div className="flex flex-wrap gap-1 mb-4 max-h-32 overflow-y-auto border rounded p-2 bg-muted/30">
              {urls.map((url) => {
                const d = urlData[url];
                const count = d.heuristic.length + d.source.length + d.params.length +
                  (d.inputSurface?.hidden_inputs_flagged?.length || 0);
                const isSelected = selectedUrl === url;
                return (
                  <button
                    key={url}
                    onClick={() => setSelectedUrl(url)}
                    className={`text-xs font-mono px-2 py-1 rounded border transition-colors ${
                      isSelected
                        ? "bg-primary text-primary-foreground border-primary"
                        : "bg-card hover:bg-accent border-border"
                    }`}
                    title={url}
                  >
                    {url.replace(/^https?:\/\/[^/]+/, "")}
                    {count > 0 && (
                      <span className="ml-1 opacity-70">({count})</span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Selected URL detail */}
        {selectedUrl && urlData[selectedUrl] && (
          <UrlDetailPanel
            url={selectedUrl}
            data={urlData[selectedUrl]}
            scanId={scanId}
          />
        )}

        {/* Header findings (not URL-specific — shown at bottom) */}
        {headerFindings.length > 0 && (
          <div className="mt-6">
            <h4 className="font-medium mb-2 flex items-center gap-2">
              <Server className="w-4 h-4" />
              Interesting Headers ({headerFindings.length})
            </h4>
            <div className="space-y-2">
              {headerFindings.map((f: any, i: number) => (
                <div key={i} className="rounded-lg border p-3">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <Badge variant="outline" className="bg-yellow-50 dark:bg-yellow-950">
                      {f.category}
                    </Badge>
                    <code className="text-xs font-mono">
                      {f.header}: {f.value}
                    </code>
                  </div>
                  <p className="text-xs text-muted-foreground">{f.description}</p>
                  <ExplainButton scanId={scanId} type="header" item={f} />
                </div>
              ))}
            </div>
          </div>
        )}

        {totalUrls > 0 && (
          <Alert>
            <FileSearch className="h-4 w-4" />
            <AlertTitle>How to use this</AlertTitle>
            <AlertDescription>
              These are SUGGESTED targets for manual testing. Each URL sub-tab shows
              5 sections: why it's interesting, where the finding was found, the
              exact evidence snippet, a suggested static test, and AI insight
              (click "Explain with AI"). Start with hidden inputs (privilege
              escalation), then IDOR candidates, then source code patterns.
            </AlertDescription>
          </Alert>
        )}

        {/* AI Interesting Findings section */}
        <AIInterestingFindings scanId={scanId} isRunning={isRunning} />
      </CardContent>
    </Card>
  );
}

/**
 * Renders the detail panel for a single URL. Shows 5 sections:
 *   1. Why is this interesting? (heuristic summary)
 *   2. Where was it found? (source location)
 *   3. Evidence Snapshot (exact snippet)
 *   4. Suggested Test (static)
 *   5. AI Insight (if LLM configured + user clicks Explain)
 */
// ===========================================================================
// AI INTERESTING FINDINGS (LLM-Driven Content Analysis)
// ===========================================================================

interface LLMInterestingFinding {
  title: string;
  reason: string;
  suggested_test: string;
  url: string;
}

/**
 * Displays LLM-generated interesting content findings.
 *
 * After the scan, the user clicks "Run AI Content Analysis" to send
 * the crawled HTML/JS to the LLM. The LLM identifies hardcoded
 * credentials, hidden endpoints, developer comments, logic flaws, etc.
 *
 * These are kept SEPARATE from the regex-based Interesting Locations
 * so the user can see what the AI caught vs. the heuristics.
 */
function AIInterestingFindings({
  scanId,
  isRunning,
}: {
  scanId: string;
  isRunning: boolean;
}) {
  const [findings, setFindings] = useState<LLMInterestingFinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasRun, setHasRun] = useState(false);

  // Load saved results (scan-time AI Content Analysis writes this file
  // incrementally, so partial results exist mid-scan).
  const fetchSaved = useCallback(() => {
    fetch(`/api/scans/${scanId}/llm-interesting`)
      .then((r) => {
        if (r.status === 404) return null;
        return r.json();
      })
      .then((data) => {
        if (data && data.findings && data.findings.length > 0) {
          setFindings(data.findings);
          setHasRun(true);
        }
      })
      .catch(() => {});
  }, [scanId]);

  // Auto-check for saved results on mount.
  useEffect(() => {
    fetchSaved();
  }, [fetchSaved]);

  // Poll while the scan is running so streaming results appear live (the
  // old one-shot fetch left the panel frozen at its mount-time 404). One
  // final fetch when the scan stops to catch the last write.
  useEffect(() => {
    if (!isRunning) {
      fetchSaved();
      return;
    }
    const interval = setInterval(fetchSaved, 2000);
    return () => clearInterval(interval);
  }, [isRunning, fetchSaved]);

  const runAnalysis = async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(`/api/scans/${scanId}/llm-interesting`, {
        method: "POST",
      });
      const data = await resp.json();
      if (!resp.ok) {
        setError(data.error || "AI analysis failed.");
        return;
      }
      setFindings(data.findings || []);
      setHasRun(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mt-6 rounded-lg border border-purple-200 dark:border-purple-800 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Bot className="w-5 h-5 text-purple-600 dark:text-purple-400" />
          <h4 className="font-medium">AI Interesting Findings</h4>
          <Badge variant="outline" className="bg-purple-50 dark:bg-purple-950 text-purple-700 dark:text-purple-300 text-xs">
            LLM-driven
          </Badge>
        </div>
        {!hasRun && (
          <Button
            variant="outline"
            size="sm"
            onClick={runAnalysis}
            disabled={loading}
            className="border-purple-300 dark:border-purple-700 text-purple-700 dark:text-purple-300"
          >
            {loading ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Wand2 className="w-4 h-4 mr-2" />}
            {loading ? "Analyzing..." : "Run AI Content Analysis"}
          </Button>
        )}
        {hasRun && (
          <Button variant="outline" size="sm" onClick={runAnalysis} disabled={loading} className="text-xs h-7">
            {loading ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <RefreshCw className="w-3 h-3 mr-1" />}
            Re-run
          </Button>
        )}
      </div>

      <p className="text-xs text-muted-foreground">
        Sends crawled HTML + inline JS to the LLM. The AI identifies hardcoded
        credentials, hidden API endpoints, developer comments, and logic flaws
        that the regex-based heuristics might miss. Findings below are AI-generated
        and separate from the regex-based Interesting Locations above.
      </p>

      {error && (
        <p className="text-xs text-destructive">
          {error.includes("not configured") ? "LLM analysis skipped: LLM not configured." : error}
        </p>
      )}

      {loading && (
        <div className="text-center py-4">
          <Loader2 className="w-6 h-6 mx-auto animate-spin text-purple-600 mb-2" />
          <p className="text-xs text-muted-foreground">Analyzing page sources with AI...</p>
        </div>
      )}

      {!loading && hasRun && findings.length === 0 && !error && (
        <p className="text-xs text-muted-foreground">
          AI analysis complete — no additional interesting content found beyond
          what the regex heuristics already detected.
        </p>
      )}

      {!loading && findings.length > 0 && (
        <div className="space-y-2">
          {findings.map((f, i) => (
            <div key={i} className="rounded border bg-purple-50/50 dark:bg-purple-950/20 p-3">
              <div className="flex items-start gap-2">
                <Badge variant="outline" className="bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300 text-xs shrink-0">
                  AI #{i + 1}
                </Badge>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium">{f.title}</p>
                  <p className="text-xs text-muted-foreground mt-1">{f.reason}</p>
                  {f.url && (
                    <p className="text-xs font-mono text-muted-foreground mt-1 break-all">URL: {f.url}</p>
                  )}
                  {f.suggested_test && (
                    <p className="text-xs text-purple-600 dark:text-purple-400 mt-1">
                      <strong>Suggested test:</strong> {f.suggested_test}
                    </p>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ===========================================================================
// PAYLOAD MANIFEST PANEL (exactly what was sent to the target)
// ===========================================================================

interface ManifestJwtToken {
  token?: string;
  source?: string;
  cookie_name?: string;
  url?: string;
}

function PayloadManifestPanel({
  scanId,
  isRunning,
}: {
  scanId: string;
  isRunning: boolean;
}) {
  const [manifest, setManifest] = useState<Record<string, any> | null>(null);
  const [jwtTokens, setJwtTokens] = useState<ManifestJwtToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    payloads: false, wordlist: false, uploads: false, auth: false,
  });

  const fetchManifest = useCallback(() => {
    fetch(`/api/scans/${scanId}/payload-manifest`)
      .then((r) => (r.status === 404 ? null : r.json()))
      .then((data) => {
        if (data && data.manifest) {
          setManifest(data.manifest);
          setJwtTokens(Array.isArray(data.jwt_tokens) ? data.jwt_tokens : []);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [scanId]);

  useEffect(() => {
    fetchManifest();
  }, [fetchManifest]);

  // The manifest is written once near scan end — refetch when it stops.
  useEffect(() => {
    if (!isRunning) fetchManifest();
  }, [isRunning, fetchManifest]);

  const toggle = (k: string) =>
    setOpenSections((p) => ({ ...p, [k]: !p[k] }));

  if (loading) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">Loading payload manifest...</p>
        </CardContent>
      </Card>
    );
  }

  if (!manifest) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <FileText className="w-8 h-8 mx-auto text-muted-foreground mb-3" />
          <p className="text-sm font-medium">Payload manifest not generated yet</p>
          <p className="text-xs text-muted-foreground mt-1">
            It's written near the END of the scan — check back once the scan completes.
          </p>
        </CardContent>
      </Card>
    );
  }

  const fp = manifest.fuzzing_payloads || {};
  const dw = manifest.directory_wordlist || {};
  const up = manifest.file_upload_probes || {};
  const jwt = manifest.jwt_alg_none_forge || {};
  const auth = manifest.authentication || {};
  const payloadItems: string[] = Array.isArray(fp.items) ? fp.items : [];
  const wordlistItems: string[] = Array.isArray(dw.items) ? dw.items : [];
  const llmAdds: any[] = Array.isArray(dw.llm_discovered_additions) ? dw.llm_discovered_additions : [];
  const probes: any[] = Array.isArray(up.probes) ? up.probes : [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileText className="w-5 h-5" />
          Payload Manifest — exactly what was sent to the target
        </CardTitle>
        <CardDescription>
          Audit record for your client report / scope proof. {manifest.data_flow_note}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Summary chips */}
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline" className="text-xs">{payloadItems.length} payloads</Badge>
          <Badge variant="outline" className="text-xs">{wordlistItems.length} wordlist paths</Badge>
          {llmAdds.length > 0 && <Badge variant="outline" className="bg-purple-50 dark:bg-purple-950 text-xs">{llmAdds.length} LLM-discovered</Badge>}
          <Badge variant="outline" className={up.ran ? "bg-amber-50 dark:bg-amber-950 text-xs" : "text-xs"}>
            {up.ran ? "upload probes ran" : "no upload probes"}
          </Badge>
          <Badge variant="outline" className={jwt.ran ? "bg-amber-50 dark:bg-amber-950 text-xs" : "text-xs"}>
            {jwt.ran ? "JWT alg=none tested" : "no JWT forge"}
          </Badge>
          <Badge variant="outline" className="text-xs">{auth.login_performed ? "authenticated" : "unauthenticated"}</Badge>
          {auth.custom_headers_used && <Badge variant="outline" className="text-xs">custom headers</Badge>}
        </div>

        {/* Fuzzing payloads */}
        <div className="rounded-lg border">
          <button onClick={() => toggle("payloads")} className="w-full flex items-center gap-2 p-3 hover:bg-accent/50 text-left">
            <span className="font-medium text-sm flex-1">Fuzzing payloads ({payloadItems.length})</span>
            <span className="text-xs text-muted-foreground font-mono truncate max-w-[40%]">{fp.source}</span>
            <span className="text-xs text-muted-foreground">{openSections.payloads ? "▲" : "▼"}</span>
          </button>
          {openSections.payloads && (
            <div className="p-3 pt-0 border-t bg-muted/20">
              <div className="flex justify-end mb-2">
                <Button variant="outline" size="sm" className="text-xs h-7"
                        onClick={() => navigator.clipboard.writeText(payloadItems.join("\n"))}>
                  <Copy className="w-3 h-3 mr-1" /> Copy All
                </Button>
              </div>
              <pre className="text-xs font-mono bg-black text-green-400 p-3 rounded border max-h-72 overflow-y-auto">{payloadItems.join("\n")}</pre>
              <p className="text-xs text-muted-foreground mt-1">{fp.note}</p>
            </div>
          )}
        </div>

        {/* Directory wordlist */}
        <div className="rounded-lg border">
          <button onClick={() => toggle("wordlist")} className="w-full flex items-center gap-2 p-3 hover:bg-accent/50 text-left">
            <span className="font-medium text-sm flex-1">Directory wordlist ({wordlistItems.length})</span>
            {llmAdds.length > 0 && <Badge variant="outline" className="bg-purple-50 dark:bg-purple-950 text-xs">+{llmAdds.length} LLM-discovered</Badge>}
            <span className="text-xs text-muted-foreground">{openSections.wordlist ? "▲" : "▼"}</span>
          </button>
          {openSections.wordlist && (
            <div className="p-3 pt-0 border-t bg-muted/20 space-y-2">
              <pre className="text-xs font-mono bg-black text-green-400 p-3 rounded border max-h-60 overflow-y-auto">{wordlistItems.join("\n")}</pre>
              <p className="text-xs text-muted-foreground">{dw.note}</p>
              {llmAdds.length > 0 && (
                <div>
                  <p className="text-xs font-medium mb-1">LLM-discovered additions (probed):</p>
                  <div className="overflow-x-auto rounded border">
                    <table className="w-full text-xs">
                      <thead className="bg-muted/50"><tr className="text-left">
                        <th className="p-2 font-medium">Path</th><th className="p-2 font-medium">Status</th><th className="p-2 font-medium">Found via</th>
                      </tr></thead>
                      <tbody>
                        {llmAdds.map((a, i) => (
                          <tr key={i} className="border-t">
                            <td className="p-2 font-mono">{a.path}</td>
                            <td className="p-2">
                              <Badge variant="outline" className={a.status === 200 ? "bg-green-50 dark:bg-green-950 text-xs" : "text-xs"}>{a.status}</Badge>
                            </td>
                            <td className="p-2 text-muted-foreground">{a.found_via}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* File-upload probes */}
        {up.ran && probes.length > 0 && (
          <div className="rounded-lg border">
            <button onClick={() => toggle("uploads")} className="w-full flex items-center gap-2 p-3 hover:bg-accent/50 text-left">
              <span className="font-medium text-sm flex-1">File-upload probes ({probes.length})</span>
              <span className="text-xs text-muted-foreground">{openSections.uploads ? "▲" : "▼"}</span>
            </button>
            {openSections.uploads && (
              <div className="p-3 pt-0 border-t bg-muted/20 overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="bg-muted/50"><tr className="text-left">
                    <th className="p-2 font-medium">Filename</th><th className="p-2 font-medium">MIME</th><th className="p-2 font-medium">Sev</th><th className="p-2 font-medium">Rationale</th>
                  </tr></thead>
                  <tbody>
                    {probes.map((p, i) => (
                      <tr key={i} className="border-t align-top">
                        <td className="p-2 font-mono">{p.filename}</td>
                        <td className="p-2 font-mono">{p.declared_mime}</td>
                        <td className="p-2"><Badge variant="outline" className="text-xs">{p.severity_if_accepted}</Badge></td>
                        <td className="p-2 text-muted-foreground">{p.rationale}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="text-xs text-muted-foreground mt-2">{up.note}</p>
              </div>
            )}
          </div>
        )}

        {/* Auth & JWT */}
        <div className="rounded-lg border">
          <button onClick={() => toggle("auth")} className="w-full flex items-center gap-2 p-3 hover:bg-accent/50 text-left">
            <span className="font-medium text-sm flex-1">Auth &amp; JWT{jwtTokens.length > 0 ? ` (${jwtTokens.length} token${jwtTokens.length === 1 ? "" : "s"} harvested)` : ""}</span>
            <span className="text-xs text-muted-foreground">{openSections.auth ? "▲" : "▼"}</span>
          </button>
          {openSections.auth && (
            <div className="p-3 pt-0 border-t bg-muted/20 space-y-2">
              <div className="flex flex-wrap gap-2">
                <Badge variant="outline" className="text-xs">login: {auth.login_performed ? "yes" : "no"}</Badge>
                <Badge variant="outline" className="text-xs">custom headers: {auth.custom_headers_used ? "yes" : "no"}</Badge>
                <Badge variant="outline" className="text-xs">JWT forge: {jwt.ran ? "ran" : "not run"}</Badge>
                {jwt.tokens_found !== undefined && <Badge variant="outline" className="text-xs">tokens found: {jwt.tokens_found ? "yes" : "no"}</Badge>}
              </div>
              {jwt.note && <p className="text-xs text-muted-foreground">{jwt.note}</p>}
              {jwtTokens.length > 0 && (
                <div className="space-y-2">
                  {jwtTokens.map((t, i) => {
                    const tok = t.token || "";
                    const masked = tok.length > 24 ? tok.slice(0, 12) + "…" + tok.slice(-8) : tok;
                    return (
                      <div key={i} className="flex items-center gap-2 flex-wrap">
                        <Badge variant="outline" className="text-xs shrink-0">{t.source || "?"}</Badge>
                        <code className="text-xs font-mono break-all">{masked}</code>
                        {t.url && <span className="text-xs text-muted-foreground truncate max-w-[30%]">{t.url}</span>}
                        <Button variant="outline" size="sm" className="text-xs h-6 ml-auto shrink-0"
                                onClick={() => navigator.clipboard.writeText(tok)}>
                          <Copy className="w-3 h-3 mr-1" /> Copy
                        </Button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ===========================================================================
// ATTACK SURFACE PANEL (every discovered input — what fuzzing targeted)
// ===========================================================================

function AttackSurfacePanel({
  scanId,
  isRunning,
}: {
  scanId: string;
  isRunning: boolean;
}) {
  const [inputs, setInputs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  const fetchSurface = useCallback(() => {
    fetch(`/api/scans/${scanId}/attack-surface`)
      .then((r) => (r.status === 404 ? null : r.json()))
      .then((data) => {
        if (data) {
          setInputs(Array.isArray(data.inputs) ? data.inputs : []);
          setNotFound(false);
        } else {
          setNotFound(true);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [scanId]);

  useEffect(() => {
    fetchSurface();
  }, [fetchSurface]);

  // Poll while the scan runs (the surface grows during the scan) + one final
  // fetch when it stops.
  useEffect(() => {
    if (!isRunning) {
      fetchSurface();
      return;
    }
    const interval = setInterval(fetchSurface, 2000);
    return () => clearInterval(interval);
  }, [isRunning, fetchSurface]);

  if (loading) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">Loading attack surface...</p>
        </CardContent>
      </Card>
    );
  }

  if (notFound) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Target className="w-8 h-8 mx-auto text-muted-foreground mb-3" />
          <p className="text-sm font-medium">Attack surface not written yet</p>
          <p className="text-xs text-muted-foreground mt-1">
            attack_surface.json appears after the crawl phase.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Target className="w-5 h-5" />
          Attack Surface ({inputs.length} inputs)
        </CardTitle>
        <CardDescription>
          Every input active fuzzing targeted — including dir-brute re-crawl
          additions. The full crawled-URL list lives in the Sitemap tab.
          {isRunning && " Still growing — the scan is running."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full text-xs">
            <thead className="bg-muted/50"><tr className="text-left">
              <th className="p-2 font-medium">Name</th><th className="p-2 font-medium">Type</th>
              <th className="p-2 font-medium">Location</th><th className="p-2 font-medium">Method</th>
              <th className="p-2 font-medium">URL</th>
            </tr></thead>
            <tbody>
              {inputs.map((inp, i) => (
                <tr key={i} className="border-t">
                  <td className="p-2 font-mono">{inp.name}</td>
                  <td className="p-2"><Badge variant="outline" className="text-xs">{inp.input_type || "?"}</Badge></td>
                  <td className="p-2">{inp.location || "?"}</td>
                  <td className="p-2">{inp.method || "GET"}</td>
                  <td className="p-2 max-w-md">
                    <a href={inp.url} target="_blank" rel="noopener noreferrer"
                       className="font-mono text-blue-600 dark:text-blue-400 hover:underline break-all">{inp.url}</a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ===========================================================================
// SITEMAP PANEL (the full crawl map, tree-grouped by path section)
// ===========================================================================

function SitemapPanel({
  scanId,
  isRunning,
}: {
  scanId: string;
  isRunning: boolean;
}) {
  const [crawlMap, setCrawlMap] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});
  const [mapScopeView, setMapScopeView] = useState<"all" | "in" | "out">("all");

  const fetchMap = useCallback(() => {
    fetch(`/api/scans/${scanId}/attack-surface`)
      .then((r) => (r.status === 404 ? null : r.json()))
      .then((data) => {
        if (data) {
          setCrawlMap(Array.isArray(data.crawlMap) ? data.crawlMap : []);
          setNotFound(false);
        } else {
          setNotFound(true);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [scanId]);

  useEffect(() => {
    fetchMap();
  }, [fetchMap]);

  // Poll while the scan runs (the map grows during the crawl + dir-brute
  // re-crawl + LLM discovery) + one final fetch when it stops.
  useEffect(() => {
    if (!isRunning) {
      fetchMap();
      return;
    }
    const interval = setInterval(fetchMap, 2000);
    return () => clearInterval(interval);
  }, [isRunning, fetchMap]);

  if (loading) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">Loading sitemap...</p>
        </CardContent>
      </Card>
    );
  }

  if (notFound) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Network className="w-8 h-8 mx-auto text-muted-foreground mb-3" />
          <p className="text-sm font-medium">Sitemap not written yet</p>
          <p className="text-xs text-muted-foreground mt-1">
            crawl_map.json appears after the crawl phase.
          </p>
        </CardContent>
      </Card>
    );
  }

  // Apply the scope filter BEFORE grouping so group counts match what's shown.
  const visibleMap = crawlMap.filter((c) =>
    mapScopeView === "all" || (mapScopeView === "in" ? c.in_scope !== false : c.in_scope === false),
  );

  // Group URLs by their path's directory prefix ("/" for root pages).
  const groups: Record<string, any[]> = {};
  for (const c of visibleMap) {
    let dir = "/";
    try {
      const u = new URL(c.url);
      const segs = u.pathname.replace(/\/+$/, "").split("/").filter(Boolean);
      dir = segs.length <= 1 ? "/" : "/" + segs.slice(0, -1).join("/");
    } catch {
      dir = "(invalid)";
    }
    (groups[dir] = groups[dir] || []).push(c);
  }
  const groupNames = Object.keys(groups).sort();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Network className="w-5 h-5" />
          Sitemap ({crawlMap.length} URLs · {groupNames.length} section{groupNames.length === 1 ? "" : "s"})
        </CardTitle>
        <CardDescription>
          Every URL the crawler discovered, grouped by path section. Source badges show
          how each was found (link, form, JS, comment, dir-brute, LLM).
          {isRunning && " Still growing — the scan is running."}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="flex gap-2">
          <Button variant={mapScopeView === "all" ? "default" : "outline"} size="sm"
                  onClick={() => setMapScopeView("all")}>
            All ({crawlMap.length})
          </Button>
          <Button variant={mapScopeView === "in" ? "default" : "outline"} size="sm"
                  onClick={() => setMapScopeView("in")}>
            In scope ({crawlMap.filter((c) => c.in_scope !== false).length})
          </Button>
          <Button variant={mapScopeView === "out" ? "default" : "outline"} size="sm"
                  onClick={() => setMapScopeView("out")}>
            Out of scope ({crawlMap.filter((c) => c.in_scope === false).length})
          </Button>
        </div>
        {groupNames.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No URLs match this filter.
          </p>
        ) : (
        groupNames.map((g) => {
          const entries = groups[g];
          const open = openGroups[g] !== false; // default open
          return (
            <div key={g} className="rounded-lg border">
              <button
                onClick={() => setOpenGroups((p) => ({ ...p, [g]: !open }))}
                className="w-full flex items-center gap-2 p-2.5 hover:bg-accent/50 text-left"
              >
                <span className="text-xs text-muted-foreground">{open ? "▼" : "▶"}</span>
                <code className="text-sm font-mono font-medium">{g === "/" ? "/ (root pages)" : g + "/"}</code>
                <Badge variant="outline" className="text-xs ml-auto">{entries.length}</Badge>
              </button>
              {open && (
                <div className="border-t">
                  {entries.map((c, i) => {
                    let label = c.url;
                    try {
                      const u = new URL(c.url);
                      const segs = u.pathname.replace(/\/+$/, "").split("/").filter(Boolean);
                      label = segs.length ? "/" + segs[segs.length - 1] : "/";
                      if (u.search) label += u.search;
                    } catch { /* keep full URL */ }
                    return (
                      <div key={i} className="flex items-center gap-2 px-3 py-1.5 border-b last:border-b-0 text-xs">
                        <span className="font-mono text-muted-foreground w-6 shrink-0">d{c.depth ?? "?"}</span>
                        <Badge variant="outline" className="text-xs shrink-0">{c.source || "?"}</Badge>
                        <a href={c.url} target="_blank" rel="noopener noreferrer"
                           className="font-mono text-blue-600 dark:text-blue-400 hover:underline truncate">{label}</a>
                        {!c.in_scope && <Badge variant="outline" className="text-xs ml-auto shrink-0 bg-red-50 dark:bg-red-950">out of scope</Badge>}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })
        )}
      </CardContent>
    </Card>
  );
}

function UrlDetailPanel({
  url,
  data,
  scanId,
}: {
  url: string;
  data: {
    heuristic: any[];
    source: any[];
    inputSurface: any;
    params: any[];
  };
  scanId: string;
}) {
  const allFindings: any[] = [];

  // Collect all findings for this URL into a unified list with sections.
  // Heuristic findings.
  for (const h of data.heuristic) {
    allFindings.push({
      why: h.category,
      where: h.source || "crawl",
      evidence: h.url,
      test: h.description,
      type: "heuristic",
    });
  }

  // Source code findings.
  for (const s of data.source) {
    const where = s.line
      ? `HTML source line ${s.line}`
      : "HTML/JS source";
    allFindings.push({
      why: s.type.replace(/_/g, " ").replace(/\w/g, (c: string) => c.toUpperCase()),
      where,
      evidence: s.evidence,
      test: s.suggested_test,
      description: s.description,
      type: "source",
    });
  }

  // Param findings (heuristic param analysis).
  for (const p of data.params) {
    allFindings.push({
      why: p.category,
      where: `${p.location} parameter "${p.param_name}"`,
      evidence: `${p.param_name} (${p.method} ${p.location})`,
      test: p.description,
      type: "param",
    });
  }

  // Hidden inputs flagged (high-priority).
  if (data.inputSurface?.hidden_inputs_flagged) {
    for (const h of data.inputSurface.hidden_inputs_flagged) {
      allFindings.push({
        why: "⚠ HIGH PRIORITY: Hidden Parameter — Privilege Escalation Risk",
        where: `Hidden input "${h.name}" in form`,
        evidence: `<input type="hidden" name="${h.name}" value="${h.value}">`,
        test: h.suggested_test,
        type: "hidden_input",
      });
    }
  }

  // Input surface summary.
  const inputSurface = data.inputSurface;
  const formsCount = inputSurface?.forms?.length || 0;
  const inputsCount = inputSurface?.inputs?.length || 0;
  const textareasCount = inputSurface?.textareas?.length || 0;
  const selectsCount = inputSurface?.selects?.length || 0;
  const fetchCount = inputSurface?.fetch_calls?.length || 0;

  return (
    <div className="rounded-lg border p-4 space-y-4 bg-muted/20">
      {/* URL header */}
      <div>
        <h4 className="font-mono text-sm break-all mb-2">{url}</h4>
        {inputSurface && (
          <div className="flex flex-wrap gap-2 text-xs">
            <Badge variant="secondary">{formsCount} forms</Badge>
            <Badge variant="secondary">{inputsCount} inputs</Badge>
            <Badge variant="secondary">{textareasCount} textareas</Badge>
            <Badge variant="secondary">{selectsCount} selects</Badge>
            <Badge variant="secondary">{fetchCount} fetch calls</Badge>
          </div>
        )}
      </div>

      {/* Findings — each one shows the 5 sections */}
      {allFindings.length === 0 && (
        <p className="text-sm text-muted-foreground">
          No specific findings for this URL beyond the crawl itself.
        </p>
      )}

      {allFindings.map((f, i) => (
        <div key={i} className="rounded border bg-card p-3 space-y-3">
          {/* 1. Why is this interesting? */}
          <div>
            <h5 className="text-xs font-medium text-blue-600 dark:text-blue-400 mb-1">
              1. Why is this interesting?
            </h5>
            <p className="text-sm">{f.why}</p>
          </div>

          {/* 2. Where was it found? */}
          <div>
            <h5 className="text-xs font-medium text-blue-600 dark:text-blue-400 mb-1">
              2. Where was it found?
            </h5>
            <p className="text-xs text-muted-foreground">{f.where}</p>
          </div>

          {/* 3. Evidence Snapshot */}
          <div>
            <h5 className="text-xs font-medium text-blue-600 dark:text-blue-400 mb-1">
              3. Evidence Snapshot
            </h5>
            <pre className="text-xs bg-black text-green-400 p-2 rounded overflow-x-auto max-h-40">
              {f.evidence}
            </pre>
          </div>

          {/* 4. Suggested Test (Static) */}
          <div>
            <h5 className="text-xs font-medium text-blue-600 dark:text-blue-400 mb-1">
              4. Suggested Test (Static)
            </h5>
            <p className="text-xs">{f.test}</p>
            {f.description && (
              <p className="text-xs text-muted-foreground mt-1">{f.description}</p>
            )}
          </div>

          {/* 5. AI Insight */}
          <div>
            <h5 className="text-xs font-medium text-blue-600 dark:text-blue-400 mb-1">
              5. AI Insight
            </h5>
            <ExplainButton
              scanId={scanId}
              type={f.type === "hidden_input" ? "param" : f.type === "source" ? "url" : "url"}
              item={{ url, ...f }}
            />
          </div>
        </div>
      ))}

      {/* Input surface details (if available) */}
      {inputSurface && (formsCount > 0 || inputsCount > 0 || fetchCount > 0) && (
        <details className="rounded border p-2">
          <summary className="text-xs font-medium cursor-pointer">
            Full Input Surface Inventory ({formsCount} forms, {inputsCount} inputs, {fetchCount} fetch calls)
          </summary>
          <div className="mt-2 space-y-2 text-xs">
            {inputSurface.forms?.map((form: any, i: number) => (
              <div key={i} className="bg-muted/50 rounded p-2">
                <code>{form.method} {form.action}</code> — {form.input_count} inputs
              </div>
            ))}
            {inputSurface.fetch_calls?.map((fc: any, i: number) => (
              <div key={i} className="bg-muted/50 rounded p-2">
                <code>{fc.method} {fc.url}</code>
                {fc.body_params?.length > 0 && ` — body: ${fc.body_params.join(", ")}`}
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

// ===========================================================================
// LLM PLAN PANEL
// ===========================================================================

interface LLMPlan {
  priority_inputs: string[];
  custom_payloads: string[];
  additional_urls: string[];
  reasoning: string;
  llm_error: string | null;
}

/**
 * Displays the LLM's scan plan (generated when --llm-assist is enabled).
 *
 * The plan is fetched from /api/scans/[id]/llm-plan, which reads the
 * llm_plan.json file the scanner wrote after the crawling phase. The
 * plan shows:
 *   - Priority inputs (which inputs the LLM thinks are most promising)
 *   - Custom payloads (tech-stack-specific payloads added to the scan)
 *   - Additional URLs (URLs the LLM suggested crawling — NOT auto-crawled)
 *   - Reasoning (the LLM's explanation)
 *
 * The panel polls every 5s while the scan is running (the plan appears
 * after crawling completes, which may take a while on deep scans).
 */

// ===========================================================================
// LLM PLAN APPROVAL BANNER
// ===========================================================================
// Shows a prominent banner at the top of the Live View when the scanner
// is waiting for the user to approve the LLM-generated plan.
// The banner shows:
//   - The custom payloads the LLM suggested
//   - The priority inputs (which will be tested first)
//   - The LLM's reasoning
//   - Approve / Reject buttons
// The scanner pauses (polls every 2s) until the user clicks a button.

interface PendingLLMPlan {
  pending: boolean;
  plan?: {
    custom_payloads: string[];
    priority_inputs: string[];
    additional_urls: string[];
    reasoning: string;
    llm_error: string | null;
  };
  pending_info?: {
    created_at: string;
    custom_payloads_count: number;
    priority_inputs_count: number;
    additional_urls_count: number;
  };
}

function LLMPlanApprovalBanner({
  scanId,
  isRunning,
}: {
  scanId: string;
  isRunning: boolean;
}) {
  const [pendingPlan, setPendingPlan] = useState<PendingLLMPlan | null>(null);
  const [loading, setLoading] = useState(false);
  const [action, setAction] = useState<"approve" | "reject" | null>(null);

  // Poll for pending plan while the scan is running
  useEffect(() => {
    if (!isRunning) {
      setPendingPlan(null);
      return;
    }
    let cancelled = false;
    const poll = async () => {
      try {
        const resp = await fetch(`/api/scans/${scanId}/llm-plan-pending`);
        if (cancelled) return;
        const data: PendingLLMPlan = await resp.json();
        setPendingPlan(data);
      } catch {
        // ignore — will retry
      }
    };
    poll(); // immediate first poll
    const interval = setInterval(poll, 3000); // poll every 3s
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [scanId, isRunning]);

  const handleApprove = async (act: "approve" | "reject") => {
    setAction(act);
    setLoading(true);
    try {
      await fetch(`/api/scans/${scanId}/approve-llm-plan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: act }),
      });
      // The scanner will pick up the marker and continue
      setPendingPlan(null);
    } catch (e) {
      console.error("Failed to approve/reject plan:", e);
    } finally {
      setLoading(false);
      setAction(null);
    }
  };

  if (!pendingPlan?.pending) return null;

  const plan = pendingPlan.plan;
  const info = pendingPlan.pending_info;

  return (
    <Alert className="border-purple-400 dark:border-purple-600 bg-purple-50 dark:bg-purple-950/30">
      <Wand2 className="h-4 w-4 text-purple-600" />
      <AlertTitle className="text-purple-700 dark:text-purple-300">
        LLM Scan Plan Awaiting Your Approval
      </AlertTitle>
      <AlertDescription className="space-y-3">
        <p className="text-sm">
          The LLM analysed the crawl results and suggests the following changes
          to the active scan. <strong>Review and approve</strong> to merge them,
          or <strong>reject</strong> to continue with default payloads only.
        </p>
        <p className="text-xs text-muted-foreground">
          The scan is paused and waiting. It will auto-approve after 10 minutes
          if you don't respond.
        </p>

        {info && (
          <div className="flex gap-4 text-xs">
            <Badge variant="outline" className="bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300">
              {info.custom_payloads_count} custom payloads
            </Badge>
            <Badge variant="outline" className="bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300">
              {info.priority_inputs_count} priority inputs
            </Badge>
            <Badge variant="outline" className="bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300">
              {info.additional_urls_count} additional URLs
            </Badge>
          </div>
        )}

        {plan?.reasoning && (
          <div className="rounded border bg-card p-3">
            <p className="text-xs font-medium mb-1">LLM Reasoning:</p>
            <p className="text-xs text-muted-foreground whitespace-pre-wrap">{plan.reasoning}</p>
          </div>
        )}

        {plan?.custom_payloads && plan.custom_payloads.length > 0 && (
          <div className="rounded border bg-card p-3">
            <p className="text-xs font-medium mb-2">Custom Payloads to Add ({plan.custom_payloads.length}):</p>
            <div className="space-y-1 max-h-40 overflow-y-auto">
              {plan.custom_payloads.map((p, i) => (
                <div key={i} className="text-xs font-mono bg-muted/50 rounded px-2 py-1 break-all">
                  {p}
                </div>
              ))}
            </div>
          </div>
        )}

        {plan?.priority_inputs && plan.priority_inputs.length > 0 && (
          <div className="rounded border bg-card p-3">
            <p className="text-xs font-medium mb-2">Priority Inputs (tested first):</p>
            <div className="flex flex-wrap gap-1">
              {plan.priority_inputs.map((inp, i) => (
                <Badge key={i} variant="outline" className="text-xs bg-blue-50 dark:bg-blue-950 text-blue-700 dark:text-blue-300">
                  {inp}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {plan?.additional_urls && plan.additional_urls.length > 0 && (
          <div className="rounded border bg-card p-3">
            <p className="text-xs font-medium mb-2">Additional URLs (NOT auto-crawled — for your reference):</p>
            <div className="space-y-1">
              {plan.additional_urls.map((u, i) => (
                <div key={i} className="text-xs font-mono text-muted-foreground break-all">{u}</div>
              ))}
            </div>
          </div>
        )}

        {plan?.llm_error && (
          <Alert variant="destructive" className="mt-2">
            <AlertDescription className="text-xs">
              <strong>LLM Error:</strong> {plan.llm_error}
            </AlertDescription>
          </Alert>
        )}

        <div className="flex gap-2 pt-2">
          <Button
            variant="default"
            size="sm"
            onClick={() => handleApprove("approve")}
            disabled={loading}
            className="bg-purple-600 hover:bg-purple-700 text-white"
          >
            {loading && action === "approve" ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <CheckCircle2 className="w-4 h-4 mr-2" />}
            Approve & Continue
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => handleApprove("reject")}
            disabled={loading}
          >
            {loading && action === "reject" ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <XCircle className="w-4 h-4 mr-2" />}
            Reject (use defaults)
          </Button>
        </div>
        <p className="text-xs text-muted-foreground pt-1">
          💡 If you reject, the LLM-suggested payloads will be saved to
          <code className="mx-1 bg-muted px-1 rounded">bin/llm_suggested_payloads.txt</code>
          and the scan's evidence folder
          (<code className="mx-1 bg-muted px-1 rounded">rejected_llm_payloads.txt</code>)
          so you can review them later and add to your default payloads if desired.
        </p>
      </AlertDescription>
    </Alert>
  );
}

function LLMPlanPanel({
  scanId,
  isRunning,
}: {
  scanId: string;
  isRunning: boolean;
}) {
  const [plan, setPlan] = useState<LLMPlan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchPlan() {
      try {
        const resp = await fetch(`/api/scans/${scanId}/llm-plan`);
        if (resp.status === 404) {
          // Plan not generated yet — scan may still be crawling.
          if (!cancelled) {
            setPlan(null);
            setError(null);
            setLoading(isRunning); // keep loading if scan is running
          }
          return;
        }
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        if (!cancelled) {
          setPlan(data.plan);
          setError(null);
          setLoading(false);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
          setLoading(false);
        }
      }
    }

    fetchPlan();
    // Poll every 5s while the scan is running (the plan appears after
    // crawling completes). Stop polling once we have the plan.
    const interval = setInterval(() => {
      if (plan || !isRunning) {
        clearInterval(interval);
        return;
      }
      fetchPlan();
    }, 2000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [scanId, isRunning]);

  if (loading) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            Waiting for the LLM to generate a scan plan...
          </p>
          <p className="text-xs text-muted-foreground mt-1">
            The planner runs after crawling completes. This may take a while
            on deep scans.
          </p>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <AlertCircle className="w-8 h-8 mx-auto text-destructive mb-3" />
          <p className="text-sm">{error}</p>
        </CardContent>
      </Card>
    );
  }

  if (!plan) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Bot className="w-8 h-8 mx-auto text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            No LLM plan was generated for this scan.
          </p>
          <p className="text-xs text-muted-foreground mt-1">
            This happens if the scan was interrupted before crawling
            completed, or if the LLM endpoint was not configured.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bot className="w-5 h-5" />
          LLM Scan Plan
        </CardTitle>
        <CardDescription>
          The LLM analysed the crawl results and suggested the following
          focus areas. These suggestions were merged into the active scan —
          priority inputs were tested first, and custom payloads were added
          to the payload list.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {plan.llm_error && (
          <Alert>
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>LLM Planning Skipped</AlertTitle>
            <AlertDescription>
              {plan.llm_error}. The scanner proceeded with default behaviour
              (default payloads, default input order). The scan still works —
              you just don't get AI-optimised payloads for this target.
              Configure the LLM in Settings if you want AI-assisted planning.
            </AlertDescription>
          </Alert>
        )}

        {/* Reasoning */}
        {plan.reasoning && (
          <div>
            <h4 className="font-medium mb-2 flex items-center gap-2">
              <Bot className="w-4 h-4" />
              Reasoning
            </h4>
            <div className="rounded-lg border bg-muted/30 p-3 text-sm">
              {plan.reasoning}
            </div>
          </div>
        )}

        {/* Priority Inputs */}
        <div>
          <h4 className="font-medium mb-2">
            Priority Inputs ({plan.priority_inputs.length})
          </h4>
          {plan.priority_inputs.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No priority inputs suggested.
            </p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {plan.priority_inputs.map((name, i) => (
                <Badge key={i} variant="outline" className="font-mono">
                  {name}
                </Badge>
              ))}
            </div>
          )}
          <p className="text-xs text-muted-foreground mt-2">
            These inputs were moved to the front of the active-scan queue.
          </p>
        </div>

        {/* Custom Payloads */}
        <div>
          <h4 className="font-medium mb-2">
            Custom Payloads Added ({plan.custom_payloads.length})
          </h4>
          {plan.custom_payloads.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No custom payloads suggested.
            </p>
          ) : (
            <ScrollArea className="h-[200px] w-full rounded border">
              <div className="p-3 space-y-1">
                {plan.custom_payloads.map((p, i) => (
                  <div key={i} className="font-mono text-xs bg-muted/50 rounded px-2 py-1">
                    {p}
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
          <p className="text-xs text-muted-foreground mt-2">
            These payloads were added to the default XSS/SQLi list (deduplicated).
          </p>
        </div>

        {/* Additional URLs */}
        <div>
          <h4 className="font-medium mb-2">
            Additional URLs Suggested ({plan.additional_urls.length})
          </h4>
          {plan.additional_urls.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No additional URLs suggested.
            </p>
          ) : (
            <div className="space-y-1">
              {plan.additional_urls.map((url, i) => (
                <div key={i} className="font-mono text-xs bg-muted/50 rounded px-2 py-1">
                  {url}
                </div>
              ))}
            </div>
          )}
          <Alert className="mt-2">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>
              These URLs were <strong>NOT</strong> auto-crawled (to prevent
              scope escape). The engineer should review them and manually
              add them to a follow-up scan if they're in scope.
            </AlertDescription>
          </Alert>
        </div>
      </CardContent>
    </Card>
  );
}

// ===========================================================================
// LLM ANALYSIS PANEL
// ===========================================================================

interface LLMAnalysis {
  owasp_classifications: Array<{
    finding_id: string;
    owasp_category: string;
    confidence: string;
    reasoning: string;
  }>;
  llm_detected_vulns: Array<{
    title: string;
    owasp_category: string;
    url: string;
    severity: string;
    reasoning: string;
  }>;
  false_positive_candidates: Array<{
    finding_id: string;
    reasoning: string;
  }>;
  follow_up_tests: string[];
  summary: string;
  llm_error: string | null;
}

/**
 * Displays the LLM's post-scan vulnerability analysis.
 *
 * The LLM reviews the scanner's findings + raw responses and provides:
 *   - OWASP classifications for each regex-detected finding
 *   - Additional vulnerabilities the regex missed (LLM-detected)
 *   - False positive candidates
 *   - Suggested follow-up tests
 *   - Overall summary
 *
 * All LLM-detected vulnerabilities are UNVERIFIED — the engineer must
 * manually confirm them.
 */
function LLMAnalysisPanel({
  scanId,
  isRunning,
}: {
  scanId: string;
  isRunning: boolean;
}) {
  const [analysis, setAnalysis] = useState<LLMAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchAnalysis() {
      try {
        const resp = await fetch(`/api/scans/${scanId}/llm-analysis`);
        if (resp.status === 404) {
          if (!cancelled) {
            setAnalysis(null);
            setError(null);
            setLoading(isRunning);
          }
          return;
        }
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        if (!cancelled) {
          setAnalysis(data.analysis);
          setError(null);
          setLoading(false);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
          setLoading(false);
        }
      }
    }

    fetchAnalysis();
    const interval = setInterval(() => {
      if (analysis || !isRunning) {
        clearInterval(interval);
        return;
      }
      fetchAnalysis();
    }, 2000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [scanId, isRunning]);

  if (loading) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Loader2 className="w-8 h-8 mx-auto animate-spin text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            Waiting for the LLM to complete vulnerability analysis...
          </p>
          <p className="text-xs text-muted-foreground mt-1">
            The analyzer runs after active scanning completes.
          </p>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <AlertCircle className="w-8 h-8 mx-auto text-destructive mb-3" />
          <p className="text-sm">{error}</p>
        </CardContent>
      </Card>
    );
  }

  if (!analysis) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Bot className="w-8 h-8 mx-auto text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            No LLM analysis was generated for this scan.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bot className="w-5 h-5" />
          LLM Vulnerability Analysis
        </CardTitle>
        <CardDescription>
          The LLM reviewed the scan results to detect vulnerabilities the
          regex missed, classify findings into OWASP categories, and
          identify likely false positives. All items are UNVERIFIED.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {analysis.llm_error && (
          <Alert>
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>LLM Analysis Skipped</AlertTitle>
            <AlertDescription>
              {analysis.llm_error}. The scan report was generated without
              LLM analysis. You can still review all findings manually below —
              the OWASP Findings, Interesting Locations, and Evidence tabs
              have complete results from the regex-based scanner.
              <div className="mt-3 flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    const tabs = document.querySelectorAll('[role="tab"]');
                    const findingsTab = Array.from(tabs).find(t =>
                      t.textContent?.includes("OWASP"));
                    if (findingsTab) (findingsTab as HTMLElement).click();
                  }}
                >
                  Review Findings
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    const tabs = document.querySelectorAll('[role="tab"]');
                    const reportTab = Array.from(tabs).find(t =>
                      t.textContent?.includes("Report"));
                    if (reportTab) (reportTab as HTMLElement).click();
                  }}
                >
                  View Report
                </Button>
              </div>
            </AlertDescription>
          </Alert>
        )}

        {/* Summary */}
        {analysis.summary && (
          <div>
            <h4 className="font-medium mb-2">Overall Assessment</h4>
            <div className="rounded-lg border bg-muted/30 p-3 text-sm whitespace-pre-wrap">
              {analysis.summary}
            </div>
          </div>
        )}

        {/* LLM-detected vulnerabilities (the key feature — vulns regex missed) */}
        <div>
          <h4 className="font-medium mb-2 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-500" />
            LLM-Detected Vulnerabilities ({analysis.llm_detected_vulns.length})
          </h4>
          {analysis.llm_detected_vulns.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              The LLM did not detect additional vulnerabilities beyond what
              the regex found.
            </p>
          ) : (
            <div className="space-y-2">
              {analysis.llm_detected_vulns.map((v, i) => (
                <div key={i} className="rounded-lg border p-3">
                  <div className="flex items-center gap-2 mb-1">
                    <Badge
                      variant="outline"
                      className={
                        v.severity === "High"
                          ? "bg-red-50 dark:bg-red-950"
                          : v.severity === "Medium"
                            ? "bg-yellow-50 dark:bg-yellow-950"
                            : "bg-blue-50 dark:bg-blue-950"
                      }
                    >
                      {v.severity}
                    </Badge>
                    <Badge variant="outline">{v.owasp_category}</Badge>
                    <span className="font-medium text-sm">{v.title}</span>
                  </div>
                  {v.url && (
                    <p className="text-xs font-mono text-muted-foreground mb-1">
                      {v.url}
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground">{v.reasoning}</p>
                  <p className="text-xs text-red-600 mt-1 font-medium">
                    ⚠ UNVERIFIED — Requires Manual Confirmation
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* OWASP classifications for regex findings */}
        {analysis.owasp_classifications.length > 0 && (
          <div>
            <h4 className="font-medium mb-2">
              OWASP Classifications for Regex Findings ({analysis.owasp_classifications.length})
            </h4>
            <div className="space-y-1">
              {analysis.owasp_classifications.map((c, i) => (
                <div key={i} className="text-xs rounded border p-2">
                  <div className="flex items-center gap-2 mb-1">
                    <Badge variant="outline">{c.owasp_category}</Badge>
                    <Badge
                      variant="outline"
                      className={
                        c.confidence === "high"
                          ? "bg-green-50"
                          : c.confidence === "medium"
                            ? "bg-yellow-50"
                            : "bg-muted"
                      }
                    >
                      {c.confidence} confidence
                    </Badge>
                    <code className="text-muted-foreground">{c.finding_id}</code>
                  </div>
                  <p className="text-muted-foreground">{c.reasoning}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* False positive candidates */}
        {analysis.false_positive_candidates.length > 0 && (
          <div>
            <h4 className="font-medium mb-2">
              False Positive Candidates ({analysis.false_positive_candidates.length})
            </h4>
            <div className="space-y-1">
              {analysis.false_positive_candidates.map((fp, i) => (
                <div key={i} className="text-xs rounded border p-2 bg-yellow-50 dark:bg-yellow-950/30">
                  <code className="text-muted-foreground">{fp.finding_id}</code>
                  <p className="text-muted-foreground mt-1">{fp.reasoning}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Follow-up tests */}
        {analysis.follow_up_tests.length > 0 && (
          <div>
            <h4 className="font-medium mb-2">
              Suggested Follow-Up Tests ({analysis.follow_up_tests.length})
            </h4>
            <ul className="space-y-1 list-disc list-inside text-sm">
              {analysis.follow_up_tests.map((t, i) => (
                <li key={i}>{t}</li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ===========================================================================
// AI CHAT PANEL
// ===========================================================================

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

/**
 * AI Assistant chat panel.
 *
 * The pentester can ask the LLM questions about the scan findings. The LLM
 * receives the scan context (findings, headers, SSL info) and replies with
 * analysis/suggestions. The LLM NEVER makes scanning decisions — it only
 * advises.
 *
 * If the LLM is not configured (no endpoint/API key in Settings), the panel
 * shows a message directing the user to Settings.
 */
function AIChatPanel({
  scanId,
  scanStatus,
}: {
  scanId: string;
  scanStatus?: ScanSummary["status"];
}) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [llmConfigured, setLlmConfigured] = useState<boolean | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Check if the LLM is configured on mount.
  useEffect(() => {
    fetch("/api/settings")
      .then((r) => r.json())
      .then((data) => {
        setLlmConfigured(
          Boolean(data.settings?.llmBaseUrl) && Boolean(data.settings?.llmApiKeySet),
        );
      })
      .catch(() => setLlmConfigured(false));
  }, []);

  // Auto-scroll to the bottom when new messages arrive.
  useEffect(() => {
    scrollRef.current?.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [messages]);

  const handleSend = async () => {
    const msg = input.trim();
    if (!msg || sending) return;
    setInput("");
    setError(null);
    setSending(true);

    // Add the user's message immediately for responsiveness.
    const newMessages = [...messages, { role: "user" as const, content: msg }];
    setMessages(newMessages);

    try {
      const resp = await fetch(`/api/scans/${scanId}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: msg,
          history: messages, // previous messages for multi-turn context
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `HTTP ${resp.status}`);
      }
      setMessages([...newMessages, { role: "assistant", content: data.reply }]);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      // Remove the user's message on error so they can retry.
      setMessages(messages);
    } finally {
      setSending(false);
    }
  };

  // Suggested questions (quick-fill buttons).
  const suggestions = [
    "Which findings should I prioritize?",
    "Suggest additional XSS payloads to try",
    "Explain the SSL/TLS issues found",
    "What headers are missing and why do they matter?",
  ];

  if (llmConfigured === false) {
    return (
      <Card>
        <CardContent className="p-12 text-center">
          <Bot className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
          <CardTitle className="mb-2">LLM not configured</CardTitle>
          <CardDescription>
            Go to <strong>Settings</strong> to configure the LLM endpoint URL
            and API key. The AI Assistant uses the LLM to help you analyze
            findings — it never makes scanning decisions.
          </CardDescription>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bot className="w-5 h-5" />
          AI Assistant
        </CardTitle>
        <CardDescription>
          Ask the LLM about the scan findings. It can analyze results, suggest
          payloads, and explain issues. It <strong>cannot</strong> run tools
          or make scanning decisions — it only advises. All findings remain
          UNVERIFIED.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {/* Chat messages */}
        <div
          ref={scrollRef}
          className="h-[400px] overflow-y-auto rounded border p-4 space-y-3 mb-3 bg-muted/30"
        >
          {messages.length === 0 && (
            <div className="text-center text-muted-foreground py-8">
              <Bot className="w-10 h-10 mx-auto mb-2 opacity-50" />
              <p className="text-sm">
                Ask a question about the scan to get started.
              </p>
              {scanStatus === "running" && (
                <p className="text-xs mt-1">
                  (You can chat while the scan runs — the AI will analyze
                  whatever findings exist so far.)
                </p>
              )}
            </div>
          )}
          {messages.map((m, i) => (
            <div
              key={i}
              className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}
            >
              <div
                className={`max-w-[80%] rounded-lg px-3 py-2 text-sm ${
                  m.role === "user"
                    ? "bg-primary text-primary-foreground"
                    : "bg-card border"
                }`}
              >
                <div className="text-xs opacity-70 mb-1">
                  {m.role === "user" ? "You" : "AI Assistant"}
                </div>
                <div className="whitespace-pre-wrap font-mono text-xs">
                  {m.content}
                </div>
              </div>
            </div>
          ))}
          {sending && (
            <div className="flex justify-start">
              <div className="bg-card border rounded-lg px-3 py-2 text-sm">
                <Loader2 className="w-4 h-4 animate-spin inline mr-2" />
                Thinking...
              </div>
            </div>
          )}
        </div>

        {error && (
          <Alert variant="destructive" className="mb-3">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Suggested questions */}
        {messages.length === 0 && (
          <div className="flex flex-wrap gap-2 mb-3">
            {suggestions.map((s) => (
              <Button
                key={s}
                variant="outline"
                size="sm"
                onClick={() => setInput(s)}
                className="text-xs"
              >
                {s}
              </Button>
            ))}
          </div>
        )}

        {/* Input */}
        <div className="flex gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                handleSend();
              }
            }}
            placeholder="Ask about the scan findings..."
            disabled={sending}
          />
          <Button onClick={handleSend} disabled={sending || !input.trim()}>
            {sending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Send className="w-4 h-4" />
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ===========================================================================
// LOG LINE + EVIDENCE FILE LIST (shared helpers)
// ===========================================================================

function LogLine({ entry }: { entry: TrailEntry }) {
  let color = "text-green-400";
  if (entry.action.includes("error") || entry.action.includes("failed")) {
    color = "text-red-400";
  } else if (entry.action.includes("warn")) {
    color = "text-yellow-400";
  } else if (entry.action.includes("match")) {
    color = "text-red-400 font-bold";
  } else if (entry.action === "phase") {
    color = "text-cyan-400 font-bold";
  } else if (entry.action.includes("done") || entry.action.includes("success")) {
    color = "text-green-300";
  }

  const ts = entry.ts ? new Date(entry.ts).toLocaleTimeString() : "";
  const parts: string[] = [];
  for (const [k, v] of Object.entries(entry)) {
    if (k === "ts" || k === "action" || k === "result") continue;
    parts.push(`${k}=${v}`);
  }
  const text = `${ts} ${entry.action}: ${entry.result || ""}${parts.length ? " | " + parts.join(" | ") : ""}`;

  return <div className={color}>{text}</div>;
}

function EvidenceFileList({
  scanId,
  files,
}: {
  scanId: string;
  files: { name: string; sizeBytes: number; modified: string }[];
}) {
  return (
    <ScrollArea className="h-[600px] w-full rounded border">
      <div className="divide-y">
        {files.map((f) => (
          <a
            key={f.name}
            href={`/api/scans/${scanId}/evidence/${encodeURIComponent(f.name)}`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-between p-3 hover:bg-accent transition-colors"
          >
            <div className="flex items-center gap-3 min-w-0">
              <FileText className="w-4 h-4 text-muted-foreground shrink-0" />
              <span className="font-mono text-sm truncate">{f.name}</span>
            </div>
            <div className="flex items-center gap-4 text-xs text-muted-foreground shrink-0">
              <span>{(f.sizeBytes / 1024).toFixed(1)} KB</span>
              <span>{new Date(f.modified).toLocaleTimeString()}</span>
              <ExternalLink className="w-3 h-3" />
            </div>
          </a>
        ))}
      </div>
    </ScrollArea>
  );
}
