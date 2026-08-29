"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Plus, RefreshCw, ShieldAlert, ExternalLink, Trash2, Pencil, Check, X } from "lucide-react";
import type { ScanSummary } from "@/lib/types";

interface ScanListProps {
  onSelectScan: (scan: ScanSummary) => void;
  onNewScan: () => void;
}

/**
 * Dashboard list of all scans (past + running).
 *
 * Fetches /api/scans on mount and on manual refresh. Each row shows the
 * target URL, status badge, finding counts, and timestamps. Clicking a
 * row calls onSelectScan, which the parent uses to switch to the Live
 * View tab.
 */
export function ScanList({ onSelectScan, onNewScan }: ScanListProps) {
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchScans = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch("/api/scans?limit=100");
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setScans(data.scans || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans();
    // Poll every 5s while there are running scans, so the dashboard
    // updates without manual refresh. We stop polling when no scans are
    // running to avoid unnecessary requests.
    const interval = setInterval(() => {
      setScans((current) => {
        if (current && current.some((s) => s.status === "running" || s.status === "pending")) {
          fetchScans();
        }
        return current;
      });
    }, 5000);
    return () => clearInterval(interval);
  }, [fetchScans]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Scan History</h2>
          <p className="text-sm text-muted-foreground">
            All scans, most recent first. Click a scan to view its live logs
            and report.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={fetchScans}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button size="sm" onClick={onNewScan}>
            <Plus className="w-4 h-4 mr-2" />
            New Scan
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <ShieldAlert className="h-4 w-4" />
          <AlertTitle>Failed to load scans</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {loading && (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <Card key={i}>
              <CardContent className="p-4">
                <Skeleton className="h-12 w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {!loading && scans && scans.length === 0 && (
        <Card>
          <CardContent className="p-12 text-center">
            <ShieldAlert className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
            <CardTitle className="mb-2">No scans yet</CardTitle>
            <CardDescription>
              Click "New Scan" to launch your first web security assessment.
            </CardDescription>
          </CardContent>
        </Card>
      )}

      {!loading && scans && scans.length > 0 && (
        <div className="space-y-3">
          {scans.map((scan) => (
            <ScanRow
              key={scan.id}
              scan={scan}
              onClick={() => onSelectScan(scan)}
              onDeleted={() => fetchScans()}
              onTitleUpdated={(newTitle) => {
                // Update the local state so the UI reflects the change
                // immediately without a full refetch.
                setScans(prev => prev?.map(s =>
                  s.id === scan.id ? { ...s, title: newTitle } : s
                ) || null);
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * One row in the scan list. Shows status, target, findings, and timing.
 * Includes delete + edit-title buttons (shown on hover).
 */
function ScanRow({
  scan,
  onClick,
  onDeleted,
  onTitleUpdated,
}: {
  scan: ScanSummary;
  onClick: () => void;
  onDeleted: () => void;
  onTitleUpdated: (newTitle: string | null) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [titleValue, setTitleValue] = useState(scan.title || "");
  const [deleting, setDeleting] = useState(false);
  const [saving, setSaving] = useState(false);

  const statusColor = {
    pending: "bg-muted text-muted-foreground",
    running: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
    completed: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
    failed: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
    interrupted:
      "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
  }[scan.status];

  const duration = scan.endedAt && scan.startedAt
    ? `${Math.round(
        (new Date(scan.endedAt).getTime() -
          new Date(scan.startedAt).getTime()) /
          1000,
      )}s`
    : scan.startedAt
      ? "running..."
      : "—";

  const canDelete = scan.status !== "running" && scan.status !== "pending";

  const handleDelete = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(`Delete this scan?\n\n${scan.title || scan.targetUrl}\n\nThis removes the DB row + all scan output files. This cannot be undone.`)) return;
    setDeleting(true);
    try {
      const resp = await fetch(`/api/scans/${scan.id}/delete`, { method: "DELETE" });
      if (!resp.ok) {
        const data = await resp.json();
        throw new Error(data.error || `HTTP ${resp.status}`);
      }
      onDeleted();
    } catch (e) {
      alert(`Failed to delete: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setDeleting(false);
    }
  };

  const handleSaveTitle = async (e: React.MouseEvent) => {
    e.stopPropagation();
    setSaving(true);
    try {
      const resp = await fetch(`/api/scans/${scan.id}/edit`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: titleValue }),
      });
      if (!resp.ok) {
        const data = await resp.json();
        throw new Error(data.error || `HTTP ${resp.status}`);
      }
      onTitleUpdated(titleValue.trim() || null);
      setEditing(false);
    } catch (e) {
      alert(`Failed to save title: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setSaving(false);
    }
  };

  const handleStartEdit = (e: React.MouseEvent) => {
    e.stopPropagation();
    setTitleValue(scan.title || "");
    setEditing(true);
  };

  const handleCancelEdit = (e: React.MouseEvent) => {
    e.stopPropagation();
    setEditing(false);
    setTitleValue(scan.title || "");
  };

  return (
    <Card
      className="cursor-pointer hover:shadow-md transition-shadow group"
      onClick={onClick}
    >
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
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
                  {scan.loginSucceeded === true
                    ? "auth: yes"
                    : scan.loginSucceeded === false
                      ? "auth: failed"
                      : "auth: ?"}
                </Badge>
              )}
            </div>
            {editing ? (
              <div className="flex items-center gap-2 mb-1" onClick={(e) => e.stopPropagation()}>
                <input
                  type="text"
                  value={titleValue}
                  onChange={(e) => setTitleValue(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleSaveTitle(e as any);
                    if (e.key === "Escape") handleCancelEdit(e as any);
                  }}
                  placeholder="Scan title (optional)"
                  className="flex-1 px-2 py-1 text-sm border rounded font-medium"
                  autoFocus
                />
                <Button size="sm" variant="ghost" onClick={handleSaveTitle} disabled={saving}>
                  <Check className="w-4 h-4" />
                </Button>
                <Button size="sm" variant="ghost" onClick={handleCancelEdit}>
                  <X className="w-4 h-4" />
                </Button>
              </div>
            ) : (
              <>
                {scan.title && (
                  <p className="font-medium text-sm truncate">{scan.title}</p>
                )}
                <p className={`font-mono text-sm truncate ${scan.title ? "text-muted-foreground" : ""}`}>
                  {scan.targetUrl}
                </p>
              </>
            )}
            <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-xs text-muted-foreground">
              <span>Findings: {scan.findingsCount}</span>
              {scan.findingsHigh > 0 && (
                <span className="text-red-600 font-medium">
                  High: {scan.findingsHigh}
                </span>
              )}
              <span>URLs: {scan.urlsCrawled}</span>
              <span>Inputs: {scan.inputsDiscovered}</span>
              <span>Duration: {duration}</span>
              <span>
                Started:{" "}
                {scan.startedAt
                  ? new Date(scan.startedAt).toLocaleString()
                  : "—"}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-1 shrink-0">
            {!editing && (
              <Button
                variant="ghost"
                size="sm"
                className="opacity-0 group-hover:opacity-100 transition-opacity h-8 w-8 p-0"
                onClick={handleStartEdit}
                title="Edit title"
              >
                <Pencil className="w-4 h-4" />
              </Button>
            )}
            {canDelete && (
              <Button
                variant="ghost"
                size="sm"
                className="opacity-0 group-hover:opacity-100 transition-opacity h-8 w-8 p-0 text-red-600 hover:text-red-700"
                onClick={handleDelete}
                disabled={deleting}
                title="Delete scan"
              >
                {deleting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
              </Button>
            )}
            <ExternalLink className="w-4 h-4 text-muted-foreground" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
