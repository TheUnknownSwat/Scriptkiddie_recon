"use client";

import { useState, useCallback } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Shield, Plus, Activity, ListChecks, Settings as SettingsIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScanList } from "@/components/scan-list";
import { NewScanForm } from "@/components/new-scan-form";
import { ScanDetail } from "@/components/scan-detail";
import { SettingsPanel } from "@/components/settings-panel";
import { ThemeToggle } from "@/components/theme-toggle";
import type { ScanSummary } from "@/lib/types";

/**
 * Home page — single-page app with four tabs:
 *   1. Dashboard  — list of past + running scans.
 *   2. New Scan   — form mirroring all scanner.py CLI flags.
 *   3. Live View  — selected scan's streaming logs + report + AI chat.
 *   4. Settings   — LLM config + default whitelist/payloads.
 *
 * The dark mode toggle is in the header (top-right).
 */
export default function Home() {
  const [activeTab, setActiveTab] = useState<
    "dashboard" | "new" | "detail" | "settings"
  >("dashboard");
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const handleScanCreated = useCallback((scanId: string) => {
    setSelectedScanId(scanId);
    setActiveTab("detail");
    setRefreshKey((k) => k + 1);
  }, []);

  const handleSelectScan = useCallback((scan: ScanSummary) => {
    setSelectedScanId(scan.id);
    setActiveTab("detail");
  }, []);

  const handleBackToDashboard = useCallback(() => {
    setActiveTab("dashboard");
    setSelectedScanId(null);
    setRefreshKey((k) => k + 1);
  }, []);

  // Navigate directly to a different scan's detail view (used by
  // "Kill Chrome & Restart" to switch to the new scan's live view).
  const handleNavigateToScan = useCallback((newScanId: string) => {
    setSelectedScanId(newScanId);
    setActiveTab("detail");
    setRefreshKey((k) => k + 1);
  }, []);

  return (
    <div className="min-h-screen flex flex-col bg-background">
      {/* Header */}
      <header className="border-b bg-card">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
		<img src="/my-logo.png" alt="logo" className="w-10 h-10 rounded-lg" />
            <div>
              <h1 className="text-xl font-bold tracking-tight">
                ScriptKiddie-Recon
              </h1>
              <p className="text-xs text-muted-foreground">
                Offline web security assessment · all findings UNVERIFIED
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              onClick={() => setActiveTab("new")}
              size="sm"
            >
              <Plus className="w-4 h-4 mr-2" />
              New Scan
            </Button>
            <ThemeToggle />
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="flex-1 container mx-auto px-4 py-6">
        <Tabs
          value={activeTab}
          onValueChange={(v) =>
            setActiveTab(v as "dashboard" | "new" | "detail" | "settings")
          }
        >
          <TabsList className="mb-6">
            <TabsTrigger value="dashboard">
              <ListChecks className="w-4 h-4 mr-2" />
              Dashboard
            </TabsTrigger>
            <TabsTrigger value="new">
              <Plus className="w-4 h-4 mr-2" />
              New Scan
            </TabsTrigger>
            {selectedScanId && (
              <TabsTrigger value="detail">
                <Activity className="w-4 h-4 mr-2" />
                Live View
              </TabsTrigger>
            )}
            <TabsTrigger value="settings">
              <SettingsIcon className="w-4 h-4 mr-2" />
              Settings
            </TabsTrigger>
          </TabsList>

          <TabsContent value="dashboard" className="mt-0">
            <ScanList
              key={refreshKey}
              onSelectScan={handleSelectScan}
              onNewScan={() => setActiveTab("new")}
            />
          </TabsContent>

          <TabsContent value="new" className="mt-0">
            <NewScanForm onScanCreated={handleScanCreated} />
          </TabsContent>

          {selectedScanId && (
            <TabsContent value="detail" className="mt-0">
              <ScanDetail
                scanId={selectedScanId}
                onBack={handleBackToDashboard}
                onNavigateToScan={handleNavigateToScan}
              />
            </TabsContent>
          )}

          <TabsContent value="settings" className="mt-0">
            <SettingsPanel />
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t bg-card mt-auto">
        <div className="container mx-auto px-4 py-3 text-xs text-muted-foreground">
          ScriptKiddie-Recon · All findings are UNVERIFIED and require manual
          confirmation by a qualified engineer before remediation.
        </div>
      </footer>
    </div>
  );
}
