import { NextRequest } from "next/server";
import { db } from "@/lib/db";
import { trailPath } from "@/lib/scanner-paths";
import { isScanRunning } from "@/lib/scanner-runner";
import fs from "fs";

/**
 * GET /api/scans/[id]/logs
 *
 * Server-Sent Events (SSE) stream of the scanner's execution_trail.jsonl.
 *
 * The scanner writes one JSON object per line to execution_trail.jsonl as
 * it runs. This route tails that file and pushes each new line to the
 * client as an SSE event. When the scanner subprocess exits, we send a
 * final 'done' event and close the stream.
 *
 * SSE format:
 *   event: log
 *   data: {"ts":"...","action":"...","result":"..."}
 *
 *   event: done
 *   data: {"status":"completed","findingsCount":3}
 *
 * Why SSE (not WebSocket):
 *  - SSE is one-way (server → client), which is exactly what we need
 *    (the client doesn't push log lines to the server).
 *  - SSE auto-reconnects on network blips; WebSocket requires manual
 *    reconnect logic.
 *  - SSE works over plain HTTP; no Upgrade handshake needed.
 *  - Next.js App Router supports SSE via ReadableStream responses.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const scan = await db.scan.findUnique({ where: { id } });
  if (!scan) {
    return new Response("Scan not found", { status: 404 });
  }

  const filePath = trailPath(id);

  // Encode SSE events. Each event is two newlines-terminated blocks.
  const encoder = new TextEncoder();
  const sse = (event: string, data: unknown) =>
    encoder.encode(
      `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`,
    );

  const stream = new ReadableStream({
    async start(controller) {
      // --- Track whether the controller is still writable ---
      // Once a client disconnects, Next.js calls our `cancel` callback
      // (which sets `stopped = true`). But there's a race: `poll()` may
      // already be mid-iteration and try to `controller.enqueue()` AFTER
      // the controller has been closed by the runtime. That throws
      // `TypeError: Invalid state: Controller is already closed`
      // (ERR_INVALID_STATE), which the catch() block logs — and since
      // the user typically triggers a reconnect (e.g. clicking "kill
      // chrome & restart" re-subscribes to SSE), we see the error
      // repeated for every reconnect that races with the old stream
      // closing.
      //
      // Mitigation: guard every enqueue with `controller.desiredSize`.
      // `desiredSize` is `null` once the stream is closed/errored, and
      // a non-negative number otherwise. We use it as a cheap "is the
      // stream still writable?" check before each enqueue.
      let closed = false;
      const safeEnqueue = (chunk: Uint8Array): boolean => {
        if (closed) return false;
        try {
          // desiredSize is null once the stream is closed.
          if (controller.desiredSize === null) {
            closed = true;
            return false;
          }
          controller.enqueue(chunk);
          return true;
        } catch {
          // Controller was closed between our check and enqueue.
          closed = true;
          return false;
        }
      };
      const safeClose = () => {
        if (closed) return;
        closed = true;
        try {
          controller.close();
        } catch {
          // already closed — ignore
        }
      };

      // --- 1. Replay existing trail content (if any) ---
      // If the user opens the live view mid-scan, we want them to see
      // all log lines written so far, not just new ones. We read the
      // file from the start and enqueue each line.
      let initialSize = 0;
      try {
        const content = await fs.promises.readFile(filePath, "utf-8");
        initialSize = Buffer.byteLength(content);
        for (const line of content.split("\n")) {
          if (!line.trim()) continue;
          try {
            const entry = JSON.parse(line);
            if (!safeEnqueue(sse("log", entry))) break;
          } catch {
            // Skip malformed lines (truncated on crash).
          }
        }
      } catch {
        // File doesn't exist yet — scanner hasn't written its first line.
      }

      // --- 1b. Fast path: scan already finished ---
      // If the DB says the scan reached a terminal status and the trail
      // has been quiet for 30s+, the replay above already sent every
      // line — emit the done event immediately instead of making the
      // client sit through the post-exit grace window below.
      if (
        scan.status === "completed" ||
        scan.status === "failed" ||
        scan.status === "interrupted"
      ) {
        try {
          const stat = await fs.promises.stat(filePath);
          if (Date.now() - stat.mtimeMs > 30000) {
            safeEnqueue(
              sse("done", {
                status: scan.status,
                findingsCount: scan.findingsCount || 0,
                findingsHigh: scan.findingsHigh || 0,
                interrupted: scan.interrupted || false,
              }),
            );
            safeClose();
            return;
          }
        } catch {
          // stat failed — fall through to normal tailing
        }
      }

      // --- 2. Tail the file for new lines ---
      // We poll the file every 500ms for new content. This is simpler
      // than fs.watch() (which has platform-specific quirks) and is
      // fast enough for a single-user tool.
      let offset = initialSize;
      let stopped = false;
      // Post-exit liveness tracking. When isScanRunning(id) first turns
      // false we record how much of the trail we've consumed. If NEW
      // bytes appear after that, a restarted scanner (supervisor crash
      // recovery) is writing — keep tailing and keep the scan "running".
      // If nothing appears, the scanner is really done: emit done with
      // whatever status finalizeScan wrote (completed / interrupted /
      // failed). We must NEVER guess "restarted" from trail mtime alone —
      // a graceful stop also leaves a fresh mtime, and flipping the DB
      // back to "running" in that case resurrects the "stopped scan shows
      // running forever, no Resume button" bug.
      let exitSeenAt: number | null = null;
      let exitOffset = 0;
      let restartConfirmed = false;

      const poll = async () => {
        while (!stopped && !closed) {
          try {
            const stat = await fs.promises.stat(filePath);
            if (stat.size > offset) {
              // Read the new bytes.
              const handle = await fs.promises.open(filePath, "r");
              const buf = Buffer.alloc(stat.size - offset);
              await handle.read(buf, 0, buf.length, offset);
              await handle.close();
              offset = stat.size;
              // Split into lines and enqueue each.
              const text = buf.toString("utf-8");
              for (const line of text.split("\n")) {
                if (!line.trim()) continue;
                try {
                  const entry = JSON.parse(line);
                  if (!safeEnqueue(sse("log", entry))) {
                    stopped = true;
                    break;
                  }
                } catch {
                  // Partial line — will be retried on the next poll
                  // (the scanner may be mid-write).
                }
              }
            }
          } catch {
            // File was deleted or rotated — stop polling.
            break;
          }

          if (stopped || closed) break;

          // Check if the scanner subprocess has exited. If it has, we
          // do a final read (to catch any lines written between the
          // last poll and exit) and then close the stream.
          //
          // EXCEPTION: If the supervisor restarted the scanner, the new
          // scanner process is NOT tracked by isScanRunning() (the
          // supervisor spawns it via subprocess.Popen, not launchScan()).
          // We detect this by checking if the trail was recently updated
          // (within last 30s). If it was, the scan is still running —
          // we keep tailing instead of sending "done".
          if (!isScanRunning(id)) {
            if (exitSeenAt === null) {
              // First poll after the scanner left the running registry.
              // Don't decide anything yet — a supervisor restart needs a
              // moment to spawn the new scanner and write its first line.
              exitSeenAt = Date.now();
              exitOffset = offset;
            } else if (offset > exitOffset) {
              // Bytes written AFTER the scanner exited → the supervisor
              // really did restart it. Keep tailing; reflect the restart
              // in the DB so the UI goes back to the running state.
              restartConfirmed = true;
              exitSeenAt = Date.now();
              exitOffset = offset;
              try {
                const currentScan = await db.scan.findUnique({ where: { id } });
                if (currentScan && currentScan.status !== "running" && currentScan.status !== "completed") {
                  await db.scan.update({
                    where: { id },
                    data: { status: "running" },
                  });
                }
              } catch {}
            } else {
              // No growth since the exit. Give a restarted scanner a
              // grace window to produce output (15s normally; 60s once a
              // restart has been confirmed, since a live scan can pause
              // trail writes during long LLM calls), then finish up.
              const graceMs = restartConfirmed ? 60000 : 15000;
              if (Date.now() - exitSeenAt > graceMs) {
                // Final read.
                try {
                  const stat = await fs.promises.stat(filePath);
                  if (stat.size > offset) {
                    const handle = await fs.promises.open(filePath, "r");
                    const buf = Buffer.alloc(stat.size - offset);
                    await handle.read(buf, 0, buf.length, offset);
                    await handle.close();
                    const text = buf.toString("utf-8");
                    for (const line of text.split("\n")) {
                      if (!line.trim()) continue;
                      try {
                        const entry = JSON.parse(line);
                        if (!safeEnqueue(sse("log", entry))) break;
                      } catch {
                        // ignore
                      }
                    }
                  }
                } catch {
                  // ignore
                }
                // Re-fetch the scan to get the final status written by
                // finalizeScan. NOTE: we deliberately do NOT write to the
                // DB here — the status belongs to the exit handler, and
                // this stream must only report it.
                const finalScan = await db.scan.findUnique({ where: { id } });
                // Guard: if the client already disconnected (e.g. by
                // clicking "Kill Chrome & Restart" which re-subscribes),
                // skip the final done event — there's no one to read it.
                if (!closed) {
                  safeEnqueue(
                    sse("done", {
                      status: finalScan?.status || "unknown",
                      findingsCount: finalScan?.findingsCount || 0,
                      findingsHigh: finalScan?.findingsHigh || 0,
                      interrupted: finalScan?.interrupted || false,
                    }),
                  );
                }
                safeClose();
                return;
              }
            }
          }

          // Wait 500ms before the next poll.
          await new Promise((r) => setTimeout(r, 500));
        }
        // Loop exited — make sure we close if we never sent `done`.
        safeClose();
      };

      // Start polling. If the client disconnects, we set `stopped` and
      // the poll loop exits on its next iteration.
      poll().catch((e) => {
        // Only log if it's NOT the expected "controller already closed"
        // race. That error is benign and floods the console every time
        // the user reconnects to a still-running SSE stream.
        const msg = e instanceof Error ? e.message : String(e);
        if (msg.includes("Controller is already closed") ||
            msg.includes("ERR_INVALID_STATE")) {
          // Benign — client disconnected before we could send the final
          // event. Just close silently.
          safeClose();
          return;
        }
        console.error(`[sse:logs:${id}] poll error:`, e);
        safeClose();
      });

      // On client disconnect (cancel), stop polling.
      // Next.js fires the cancel callback when the client closes the
      // connection (page navigation, refresh, etc.).
      // Note: we don't use this to stop the SCAN — only to stop
      // STREAMING. The scan continues running; the user can re-subscribe
      // by reopening the live view.
      return () => {
        stopped = true;
        // Mark closed so any in-flight enqueue is skipped.
        closed = true;
      };
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      // X-Accel-Buffering: no disables nginx buffering (not strictly
      // needed in dev, but good practice for production proxies).
      "X-Accel-Buffering": "no",
    },
  });
}
