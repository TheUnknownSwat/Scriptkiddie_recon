"use client";

import { useEffect, useState } from "react";
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
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Save,
  TestTube2,
  Loader2,
  CheckCircle2,
  XCircle,
  Bot,
  FileText,
  Wand2,
  Copy,
  Plus,
} from "lucide-react";

interface SettingsData {
  llmBaseUrl: string;
  llmApiKeySet: boolean;
  llmApiKeyMasked: string;
  llmModel: string;
  llmMaxTokens: number;
  defaultWhitelist: string;
  defaultPayloads: string;
  defaultWordlist: string;
  defaultWeakCiphers: string;
  updatedAt: string;
}

interface ScanOption {
  id: string;
  targetUrl: string;
  createdAt: string;
}

/**
 * Settings panel — two sub-tabs:
 *   1. LLM Configuration — endpoint, API key, model, max tokens, test connection
 *   2. Reference Files — whitelist, payloads (with AI generator), wordlist (with AI generator)
 */
export function SettingsPanel() {
  const [data, setData] = useState<SettingsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  // LLM state
  const [llmBaseUrl, setLlmBaseUrl] = useState("");
  const [llmApiKey, setLlmApiKey] = useState("");
  const [llmModel, setLlmModel] = useState("gpt-4o-mini");
  // Held as a STRING so the field can be cleared / select-all-replaced
  // freely (a number-typed state snaps "" back via `parseInt("") || default`,
  // making the field undeletable). Parsed + clamped to a number on save.
  const [llmMaxTokens, setLlmMaxTokens] = useState("4000");

  // Reference files state
  const [defaultWhitelist, setDefaultWhitelist] = useState("");
  const [defaultPayloads, setDefaultPayloads] = useState("");
  const [defaultWordlist, setDefaultWordlist] = useState("");
  const [defaultWeakCiphers, setDefaultWeakCiphers] = useState("");

  // AI Payload Generator state
  const [genPayloadsRunning, setGenPayloadsRunning] = useState(false);
  const [generatedPayloads, setGeneratedPayloads] = useState<string[]>([]);
  const [genPayloadsError, setGenPayloadsError] = useState<string | null>(null);
  const [genPayloadsNote, setGenPayloadsNote] = useState<string | null>(null);
  const [genPayloadCategory, setGenPayloadCategory] = useState("all");
  const [genPayloadScanId, setGenPayloadScanId] = useState("");

  // AI Wordlist Generator state
  const [genWordlistRunning, setGenWordlistRunning] = useState(false);
  const [generatedPaths, setGeneratedPaths] = useState<string[]>([]);
  const [genWordlistError, setGenWordlistError] = useState<string | null>(null);
  const [genWordlistNote, setGenWordlistNote] = useState<string | null>(null);
  const [genWordlistScanId, setGenWordlistScanId] = useState("");

  // Available scans for dropdowns
  const [availableScans, setAvailableScans] = useState<ScanOption[]>([]);

  // Load settings + scans on mount.
  useEffect(() => {
    fetchSettings();
    fetch("/api/scans?limit=50")
      .then((r) => r.json())
      .then((d) => {
        const scans = (d.scans || [])
          .filter((s: any) => s.status === "completed" || s.status === "interrupted")
          .map((s: any) => ({
            id: s.id,
            targetUrl: s.targetUrl,
            createdAt: new Date(s.createdAt).toLocaleString(),
          }));
        setAvailableScans(scans);
      })
      .catch(() => {});
  }, []);

  async function fetchSettings() {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch("/api/settings");
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const json = await resp.json();
      setData(json.settings);
      setLlmBaseUrl(json.settings.llmBaseUrl);
      setLlmModel(json.settings.llmModel);
      setLlmMaxTokens(String(json.settings.llmMaxTokens ?? 4000));
      setDefaultWhitelist(json.settings.defaultWhitelist);
      setDefaultPayloads(json.settings.defaultPayloads);
      setDefaultWordlist(json.settings.defaultWordlist);
      setDefaultWeakCiphers(json.settings.defaultWeakCiphers);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  async function handleSave() {
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      // Parse the free-text max-tokens field: empty / non-numeric → 4000,
      // then clamp to the same range as the input's min/max attributes.
      const parsedTokens = parseInt(llmMaxTokens, 10);
      let tokensToSend = Number.isFinite(parsedTokens) ? parsedTokens : 4000;
      tokensToSend = Math.min(128000, Math.max(256, tokensToSend));
      const resp = await fetch("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          llmBaseUrl,
          llmApiKey: llmApiKey || "",
          llmModel,
          llmMaxTokens: tokensToSend,
          defaultWhitelist,
          defaultPayloads,
          defaultWordlist,
          defaultWeakCiphers,
        }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${resp.status}`);
      }
      const json = await resp.json();
      setData(json.settings);
      // Reflect the actually-saved (clamped) value back into the field, so
      // e.g. an empty or out-of-range entry shows the normalized result.
      setLlmMaxTokens(String(json.settings?.llmMaxTokens ?? tokensToSend));
      setLlmApiKey("");
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    try {
      await handleSave();
      const resp = await fetch("/api/settings/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ llmBaseUrl, llmApiKey: llmApiKey || undefined, llmModel }),
      });
      // Guard against non-JSON responses (e.g. a 404 HTML page if the route
      // is missing). Without this, resp.json() throws the cryptic
      // "JSON.parse: unexpected character at line 1 column 1" error.
      const respContentType = resp.headers.get("content-type") || "";
      if (!respContentType.toLowerCase().includes("application/json")) {
        const text = await resp.text().catch(() => "");
        setTestResult({
          ok: false,
          message:
            `Test endpoint returned HTML (HTTP ${resp.status}) instead of JSON. ` +
            `The /api/settings/test route may be missing or the dev server needs a restart. ` +
            (text ? `First 200 chars: ${text.slice(0, 200)}` : ""),
        });
        return;
      }
      const json = await resp.json();
      setTestResult({ ok: json.ok, message: json.ok ? json.message : json.error });
    } catch (e) {
      setTestResult({ ok: false, message: e instanceof Error ? e.message : String(e) });
    } finally {
      setTesting(false);
    }
  }

  // --- AI Payload Generator ---
  const handleGeneratePayloads = async () => {
    setGenPayloadsRunning(true);
    setGenPayloadsError(null);
    setGenPayloadsNote(null);
    setGeneratedPayloads([]);
    try {
      const resp = await fetch("/api/payloads/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scanId: genPayloadScanId || undefined,
          category: genPayloadCategory,
          currentPayloads: defaultPayloads,
        }),
      });
      const json = await resp.json();
      if (!resp.ok) throw new Error(json.error || `HTTP ${resp.status}`);
      setGeneratedPayloads(json.payloads || []);
      setGenPayloadsNote(json.note ?? null);
    } catch (e) {
      setGenPayloadsError(e instanceof Error ? e.message : String(e));
    } finally {
      setGenPayloadsRunning(false);
    }
  };

  const handleAddPayloads = () => {
    const existing = defaultPayloads.trimEnd();
    setDefaultPayloads(existing + "\n\n# --- AI-Generated Payloads ---\n" + generatedPayloads.join("\n"));
    setGeneratedPayloads([]);
  };

  // --- AI Wordlist Generator ---
  const handleGenerateWordlist = async () => {
    setGenWordlistRunning(true);
    setGenWordlistError(null);
    setGenWordlistNote(null);
    setGeneratedPaths([]);
    try {
      const resp = await fetch("/api/wordlist/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scanId: genWordlistScanId || undefined,
          currentWordlist: defaultWordlist,
        }),
      });
      const json = await resp.json();
      if (!resp.ok) throw new Error(json.error || `HTTP ${resp.status}`);
      setGeneratedPaths(json.paths || []);
      setGenWordlistNote(json.note ?? null);
    } catch (e) {
      setGenWordlistError(e instanceof Error ? e.message : String(e));
    } finally {
      setGenWordlistRunning(false);
    }
  };

  const handleAddWordlist = () => {
    const existing = defaultWordlist.trimEnd();
    setDefaultWordlist(existing + "\n\n# --- AI-Generated Paths ---\n" + generatedPaths.join("\n"));
    setGeneratedPaths([]);
  };

  // --- Shared scan dropdown ---
  const ScanDropdown = ({ value, onChange }: { value: string; onChange: (v: string) => void }) => (
    <div className="space-y-1">
      <label className="text-xs text-muted-foreground">Select Scan for Context (optional)</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full text-xs rounded border px-2 py-1 bg-background"
      >
        <option value="">No scan (generic)</option>
        {availableScans.length === 0 ? (
          <option value="" disabled>No scans available. Run a scan first.</option>
        ) : (
          availableScans.map((s) => (
            <option key={s.id} value={s.id}>
              {s.targetUrl} - {s.createdAt}
            </option>
          ))
        )}
      </select>
    </div>
  );

  // --- Shared AI generator section ---
  const AIGeneratorSection = ({
    title,
    icon,
    running,
    onGenerate,
    items,
    setItems,
    onAdd,
    error,
    note,
    scanId,
    setScanId,
    categorySelector,
  }: {
    title: string;
    icon: React.ReactNode;
    running: boolean;
    onGenerate: () => void;
    items: string[];
    setItems: (v: string[]) => void;
    onAdd: () => void;
    error: string | null;
    note: string | null;
    scanId: string;
    setScanId: (v: string) => void;
    categorySelector?: React.ReactNode;
  }) => (
    <div className="rounded-lg border p-3 space-y-3 bg-muted/30">
      <div className="flex items-center gap-2">
        {icon}
        <span className="text-sm font-medium">{title}</span>
        {data?.llmApiKeySet ? (
          <Badge variant="outline" className="bg-green-50 dark:bg-green-950 text-green-700 dark:text-green-300 text-xs">
            LLM connected
          </Badge>
        ) : (
          <Badge variant="outline" className="bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300 text-xs">
            LLM not configured
          </Badge>
        )}
      </div>
      <div className="grid grid-cols-2 gap-2">
        {categorySelector}
        <ScanDropdown value={scanId} onChange={setScanId} />
      </div>
      <Button
        variant="outline"
        size="sm"
        onClick={onGenerate}
        disabled={running || !data?.llmBaseUrl}
        className="border-purple-300 dark:border-purple-700 text-purple-700 dark:text-purple-300"
      >
        {running ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Wand2 className="w-4 h-4 mr-2" />}
        {running ? "Generating..." : `Generate ${title.includes("Payload") ? "Payloads" : "Wordlist"} with AI`}
      </Button>
      {error && (
        <p className="text-xs text-destructive">
          {error.includes("not configured") || error.includes("not reachable")
            ? "LLM not configured or unreachable. Please check Settings."
            : error}
        </p>
      )}
      {note && (
        <p className="text-xs text-amber-700 dark:text-amber-400">{note}</p>
      )}
      {items.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium">Generated {items.length} items:</span>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(items.join("\n"))} className="text-xs h-7">
                <Copy className="w-3 h-3 mr-1" /> Copy All
              </Button>
              <Button variant="default" size="sm" onClick={onAdd} className="text-xs h-7">
                <Plus className="w-3 h-3 mr-1" /> Add to List
              </Button>
            </div>
          </div>
          <pre className="text-xs font-mono bg-black text-green-400 p-3 rounded border max-h-60 overflow-y-auto">
            {items.join("\n")}
          </pre>
          <p className="text-xs text-muted-foreground">
            Review the items above. Click "Add to List" to append them, then click "Save Settings".
          </p>
        </div>
      )}
    </div>
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Settings</h2>
        <p className="text-sm text-muted-foreground">
          Configure the LLM assistant and default scan parameters. These
          settings are used by all new scans unless overridden.
        </p>
      </div>

      {error && (
        <Alert variant="destructive">
          <XCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Tabs defaultValue="llm">
        <TabsList>
          <TabsTrigger value="llm">
            <Bot className="w-4 h-4 mr-2" />
            LLM Configuration
          </TabsTrigger>
          <TabsTrigger value="whitelist">
            <FileText className="w-4 h-4 mr-2" />
            Whitelist
          </TabsTrigger>
          <TabsTrigger value="payloads">
            <FileText className="w-4 h-4 mr-2" />
            Payloads
          </TabsTrigger>
          <TabsTrigger value="wordlist">
            <FileText className="w-4 h-4 mr-2" />
            Wordlist
          </TabsTrigger>
          <TabsTrigger value="weak-ciphers">
            <FileText className="w-4 h-4 mr-2" />
            Weak Ciphers
          </TabsTrigger>
        </TabsList>

        {/* ===== TAB 1: LLM Configuration ===== */}
        <TabsContent value="llm" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Bot className="w-5 h-5" />
                LLM Configuration
              </CardTitle>
              <CardDescription>
                The LLM is used for executive summary generation, AI payload/wordlist
                generation, the AI Assistant chat, and the "Explain with AI" buttons.
                It NEVER makes scanning decisions. If unreachable, all LLM features
                degrade gracefully.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="llmBaseUrl">LLM Endpoint URL</Label>
                <Input
                  id="llmBaseUrl"
                  placeholder="https://api.openai.com/v1/chat/completions"
                  value={llmBaseUrl}
                  onChange={(e) => setLlmBaseUrl(e.target.value)}
                  className="font-mono text-sm"
                />
                <p className="text-xs text-muted-foreground">
                  OpenAI-compatible endpoint. Also works with Ollama
                  (http://localhost:11434/v1/chat/completions), LM Studio, vLLM.
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="llmApiKey">
                  API Key{" "}
                  <span className="text-xs font-normal text-muted-foreground">(optional for local LLMs like Ollama, LM Studio)</span>{" "}
                  {data?.llmApiKeySet && (
                    <Badge variant="secondary" className="ml-2">
                      <CheckCircle2 className="w-3 h-3 mr-1" /> set
                    </Badge>
                  )}
                </Label>
                <Input
                  id="llmApiKey"
                  type="password"
                  placeholder={data?.llmApiKeySet ? "•••••••• (leave blank to keep)" : "sk-... (leave blank for local LLMs)"}
                  value={llmApiKey}
                  onChange={(e) => setLlmApiKey(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  {data?.llmApiKeySet
                    ? "A key is stored. Leave blank to keep it, or type a new key to replace."
                    : "No key stored yet."}
                </p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="llmModel">Model</Label>
                  <Input
                    id="llmModel"
                    placeholder="gpt-4o-mini"
                    value={llmModel}
                    onChange={(e) => setLlmModel(e.target.value)}
                    className="font-mono text-sm"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="llmMaxTokens">Max Tokens per Request</Label>
                  <Input
                    id="llmMaxTokens"
                    type="number"
                    min={256}
                    max={128000}
                    value={llmMaxTokens}
                    onChange={(e) => setLlmMaxTokens(e.target.value)}
                  />
                </div>
              </div>

              {testResult && (
                <Alert variant={testResult.ok ? "default" : "destructive"}>
                  {testResult.ok ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
                  <AlertTitle>{testResult.ok ? "Connection successful" : "Connection failed"}</AlertTitle>
                  <AlertDescription>{testResult.message}</AlertDescription>
                </Alert>
              )}

              <div className="flex gap-2">
                <Button onClick={handleSave} disabled={saving}>
                  {saving ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Save className="w-4 h-4 mr-2" />}
                  {saving ? "Saving..." : "Save Settings"}
                </Button>
                <Button variant="outline" onClick={handleTest} disabled={testing || !llmBaseUrl}>
                  {testing ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <TestTube2 className="w-4 h-4 mr-2" />}
                  {testing ? "Testing..." : "Test Connection"}
                </Button>
                {saved && (
                  <span className="text-sm text-green-600 flex items-center gap-1">
                    <CheckCircle2 className="w-4 h-4" /> Saved
                  </span>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ===== TAB 2: Whitelist ===== */}
        <TabsContent value="whitelist" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="w-5 h-5" />
                Default Whitelist (Header Policy)
              </CardTitle>
              <CardDescription>
                Defines which headers are expected + their expected values.
                Format: <code>Header-Name</code> (presence) or{" "}
                <code>Header: value</code> (policy) or{" "}
                <code>Header: v1|v2</code> (alternatives).
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Textarea
                value={defaultWhitelist}
                onChange={(e) => setDefaultWhitelist(e.target.value)}
                className="font-mono text-xs min-h-[300px]"
                placeholder={"Strict-Transport-Security: max-age=31536000\nX-Content-Type-Options: nosniff\nX-Frame-Options: DENY|SAMEORIGIN"}
              />
            </CardContent>
          </Card>
          <div className="flex gap-2 mt-4">
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Save className="w-4 h-4 mr-2" />}
              {saving ? "Saving..." : "Save Settings"}
            </Button>
            {saved && (
              <span className="text-sm text-green-600 flex items-center gap-1">
                <CheckCircle2 className="w-4 h-4" /> Saved
              </span>
            )}
          </div>
        </TabsContent>

        {/* ===== TAB 3: Payloads ===== */}
        <TabsContent value="payloads" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="w-5 h-5" />
                Default Payloads
              </CardTitle>
              <CardDescription>
                One payload per line; lines starting with # are comments. This is
                the ONLY source of payloads — there is no hardcoded fallback.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Textarea
                value={defaultPayloads}
                onChange={(e) => setDefaultPayloads(e.target.value)}
                className="font-mono text-xs min-h-[300px]"
                placeholder={"<script>alert(1)</script>\n' OR '1'='1"}
              />
              <AIGeneratorSection
                title="AI Payload Generator"
                icon={<Wand2 className="w-4 h-4 text-purple-600 dark:text-purple-400" />}
                running={genPayloadsRunning}
                onGenerate={handleGeneratePayloads}
                items={generatedPayloads}
                setItems={setGeneratedPayloads}
                onAdd={handleAddPayloads}
                error={genPayloadsError}
                note={genPayloadsNote}
                scanId={genPayloadScanId}
                setScanId={setGenPayloadScanId}
                categorySelector={
                  <div className="space-y-1">
                    <label className="text-xs text-muted-foreground">Category</label>
                    <select
                      value={genPayloadCategory}
                      onChange={(e) => setGenPayloadCategory(e.target.value)}
                      className="w-full text-xs rounded border px-2 py-1 bg-background"
                    >
                      <option value="all">All types</option>
                      <option value="xss">XSS</option>
                      <option value="sqli">SQL Injection</option>
                      <option value="path_traversal">Path Traversal</option>
                      <option value="cmdi">Command Injection</option>
                      <option value="open_redirect">Open Redirect</option>
                      <option value="ssti">SSTI</option>
                    </select>
                  </div>
                }
              />
            </CardContent>
          </Card>
          <div className="flex gap-2 mt-4">
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Save className="w-4 h-4 mr-2" />}
              {saving ? "Saving..." : "Save Settings"}
            </Button>
            {saved && (
              <span className="text-sm text-green-600 flex items-center gap-1">
                <CheckCircle2 className="w-4 h-4" /> Saved
              </span>
            )}
          </div>
        </TabsContent>

        {/* ===== TAB 4: Wordlist ===== */}
        <TabsContent value="wordlist" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="w-5 h-5" />
                Default Wordlist (Directory Brute-Force)
              </CardTitle>
              <CardDescription>
                One path per line; lines starting with # are comments. The LLM
                reorders this list based on detected technology during scans.
                Replace with a larger list (e.g. SecLists common.txt) for full
                engagements.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Textarea
                value={defaultWordlist}
                onChange={(e) => setDefaultWordlist(e.target.value)}
                className="font-mono text-xs min-h-[300px]"
                placeholder={"admin\n.git/config\n.env\nwp-admin"}
              />
              <AIGeneratorSection
                title="AI Wordlist Generator"
                icon={<Wand2 className="w-4 h-4 text-purple-600 dark:text-purple-400" />}
                running={genWordlistRunning}
                onGenerate={handleGenerateWordlist}
                items={generatedPaths}
                setItems={setGeneratedPaths}
                onAdd={handleAddWordlist}
                error={genWordlistError}
                note={genWordlistNote}
                scanId={genWordlistScanId}
                setScanId={setGenWordlistScanId}
              />
            </CardContent>
          </Card>
          <div className="flex gap-2 mt-4">
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Save className="w-4 h-4 mr-2" />}
              {saving ? "Saving..." : "Save Settings"}
            </Button>
            {saved && (
              <span className="text-sm text-green-600 flex items-center gap-1">
                <CheckCircle2 className="w-4 h-4" /> Saved
              </span>
            )}
          </div>
        </TabsContent>

        {/* ===== TAB 5: Weak Ciphers (TLS cipher / protocol policy) ===== */}
        <TabsContent value="weak-ciphers" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="w-5 h-5" />
                Weak Cipher &amp; TLS Protocol Policy
              </CardTitle>
              <CardDescription>
                The single source of truth for what the scanner flags as a weak
                cipher suite or TLS protocol. Format: <code>TLS_VERSION | cipher | severity</code>,
                one rule per line. Lines starting with <code>#</code> are comments. The scanner
                reads this at the start of each scan, so edits here apply to the <strong>next</strong>
                scan (a running scan keeps its loaded policy).
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Textarea
                value={defaultWeakCiphers}
                onChange={(e) => setDefaultWeakCiphers(e.target.value)}
                className="font-mono text-xs min-h-[300px]"
                placeholder={"TLSv1.0 | * | medium\nNULL | * | high\nTLSv1.1 | * | medium"}
              />
            </CardContent>
          </Card>
          <div className="flex gap-2 mt-4">
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Save className="w-4 h-4 mr-2" />}
              {saving ? "Saving..." : "Save Settings"}
            </Button>
            {saved && (
              <span className="text-sm text-green-600 flex items-center gap-1">
                <CheckCircle2 className="w-4 h-4" /> Saved
              </span>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
