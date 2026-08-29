#!/usr/bin/env python3
"""
External supervisor for ScriptKiddie-Recon scanner.

Monitors a scanner's heartbeat file and restarts the scanner if it hangs.

USAGE:
    python3 bin/supervisor.py <scan_output_dir> [options]

OPTIONS:
    --threshold N    Stale threshold in seconds (default: 180).
                     If heartbeat.json is older than N seconds, the
                     scanner is considered hung.
    --poll-interval  How often to check heartbeat.json (default: 10s).
    --max-restarts   Maximum number of restarts before giving up
                     (default: 10).
    --no-restart     Monitor only — log stale heartbeats but DON'T
                     restart. Useful for dry-run testing.
    --verbose        Log every poll, not just stale/restart events.

HOW IT WORKS:

1. The scanner writes scan-output/<id>/heartbeat.json after every test:
     {"pid": 12345, "timestamp": 1691234567.12, "tests_done": 410, ...}

2. This supervisor polls that file every --poll-interval seconds.

3. If the file's timestamp is older than --threshold seconds:
   a. Read scanner.pid to get the scanner's OS PID.
   b. Kill the PID (SIGKILL the process group, then pkill Chrome).
   c. Read scan_args.json to get the original CLI args.
   d. Reconstruct the command line with --resume --skip-tests <tests_done>.
   e. Execute it (replaces the hung scanner with a fresh one).

4. The supervisor exits when:
   - The scan completes normally (scan_complete in the trail).
   - --max-restarts is exceeded.
   - The heartbeat file disappears (scan output dir deleted).
   - Ctrl+C (SIGINT).

WHY THIS IS BETTER THAN IN-PROCESS WATCHDOGS:

The scanner has in-process watchdog threads (per-test 60s, progress 120s).
But they have a fatal flaw: when Playwright's C code blocks the asyncio
event loop, the Python thread that sends the pkill command may also be
blocked (if it needs the GIL or any Python-level resource). The supervisor
is a completely separate OS process — it is unaffected by anything that
happens inside the scanner's Python process.

The supervisor can be run:
  - Manually: `python3 bin/supervisor.py scan-output/<id> &`
  - Automatically: launched by scanner-runner.ts alongside the scanner
    (see the WEBRECON_SUPERVISOR=1 env var).
  - As a daemon: `nohup python3 bin/supervisor.py scan-output/<id> &`

AIR-GAPPED ENVIRONMENT NOTE:

This script has ZERO external dependencies — it uses only Python stdlib
(os, sys, json, time, signal, subprocess, pathlib, argparse). It can
run in any air-gapped environment with Python 3.8+.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


# --- Helpers ---

def read_json(path: Path, default=None):
    """Read a JSON file, returning `default` on any error."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def kill_process_group(pid: int) -> bool:
    """Kill a process and its entire process group.

    The scanner is spawned with `detached: true` by scanner-runner.ts,
    which puts it in a new process group. Killing the group (-pid) also
    kills Chrome (which is a child of the scanner).

    We send SIGTERM first (graceful) and wait 5s for the scanner to:
      - Save its scan_state.json
      - Write a final heartbeat
      - Close Playwright cleanly
    If it doesn't exit in 5s, we escalate to SIGKILL.

    This is important because scanner-runner.ts's finalizeScan() checks
    the exit code/signal:
      - SIGTERM → marks scan as "interrupted" (resumable)
      - SIGKILL → marks scan as "failed" (not resumable via UI)
    We want "interrupted" so the UI's rescan button works.
    """
    killed_anything = False

    # --- Stage 1: SIGTERM (graceful) ---
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
        killed_anything = True
    except (ProcessLookupError, PermissionError):
        pass

    # Wait up to 5s for graceful exit
    import time as _time
    deadline = _time.time() + 5.0
    while _time.time() < deadline:
        try:
            os.kill(pid, 0)  # signal 0 = check if process exists
        except (ProcessLookupError, PermissionError):
            break  # process exited gracefully
        _time.sleep(0.2)

    # --- Stage 2: SIGKILL (forceful) if still alive ---
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass

    return killed_anything


def kill_chrome() -> None:
    """Kill any orphaned Chrome/Chromium processes.

    Belt-and-braces: even after killing the scanner PID, there may be
    orphaned Chrome processes (if the scanner's pkill didn't run before
    being killed). This ensures a clean slate for the restart.
    """
    try:
        subprocess.run(
            "pkill -9 -f chromium; pkill -9 -f chrome; "
            "pkill -9 -f headless; pkill -9 -f chrome-headless-shell; "
            "pkill -9 -f remote-debugging-pipe",
            shell=True, timeout=10, capture_output=True,
        )
    except Exception:
        pass


def build_restart_command(scan_args: dict, skip_tests: int, scan_id: str) -> list:
    """Build the command line to restart the scanner with --resume --skip-tests.

    Reads the saved scan_args.json (written by the scanner on startup)
    and reconstructs the CLI args, adding --resume and --skip-tests.
    """
    python = scan_args.get("_python") or sys.executable
    scanner_path = scan_args.get("_scanner_path") or str(
        Path(__file__).resolve().parent / "scanner.py")

    cmd = [python, scanner_path]

    # Map arg names to CLI flags. We skip internal/private fields
    # (starting with _) and None values.
    #
    # Boolean args use --flag (store_true). String/int args use --flag value.
    # We need to know which is which. Rather than hardcode, we infer:
    #   - bool True → --flag
    #   - bool False → skip (default)
    #   - None → skip
    #   - other → --flag value
    bool_flags = {
        "ignore_robots", "allow_external", "llm_assist", "llm_analyze",
        "test_access_control", "manual_login_state", "deep_logic",
        "crawl_only", "browser_headless", "no_browser_headless",
        "verbose_tests", "debug", "no_watchdog", "ignore_session_expiry",
        "resume",
    }

    # Arg name → CLI flag mapping (underscores → hyphens)
    arg_map = {
        "url": "--url",
        "output": "--output",
        "depth": "--depth",
        "delay": "--delay",
        "concurrency": "--concurrency",
        "max_payload_bytes": "--max-payload-bytes",
        "llm_tokens": "--llm-tokens",
        "scope_patterns": "--scope",
        "exclude_patterns": "--exclude",
        "ignore_robots": "--ignore-robots",
        "allow_external": "--allow-external",
        "headers": "--headers",
        "payloads": "--payloads",
        "login_url": "--login-url",
        "login_user": "--login-user",
        "llm_assist": "--llm-assist",
        "llm_analyze": "--llm-analyze",
        "custom_headers": "--custom-headers",
        "test_access_control": "--test-access-control",
        "manual_login_state": "--load-state",
        "manual_login_state_path": None,  # handled via --load-state above
        "deep_logic": "--deep-logic",
        "crawl_only": "--crawl-only",
        "browser_headless": "--browser-headless",
        "no_browser_headless": "--no-browser-headless",
        "verbose_tests": "--verbose-tests",
        "debug": "--debug",
        "no_watchdog": "--no-watchdog",
        "ignore_session_expiry": "--ignore-session-expiry",
    }

    for key, value in scan_args.items():
        if key.startswith("_"):
            continue  # internal field
        if key == "resume":
            continue  # we'll add --resume explicitly below
        if key == "skip_tests":
            continue  # we'll add --skip-tests explicitly below
        if key not in arg_map:
            continue  # unknown arg — skip
        flag = arg_map[key]
        if flag is None:
            continue  # handled elsewhere
        if value is None:
            continue
        if key in bool_flags:
            if value:
                cmd.append(flag)
        else:
            cmd.append(flag)
            cmd.append(str(value))

    # Add --resume (so the scanner loads scan_state.json and skips
    # completed phases like crawl/headers/SSL/attack-surface/passive).
    if "--resume" not in cmd:
        cmd.append("--resume")

    # Add --skip-tests with the last known test count (so active_scan
    # resumes from where it left off, not from test 1).
    if skip_tests > 0:
        cmd.extend(["--skip-tests", str(skip_tests)])

    return cmd


def scan_is_complete(scan_dir: Path) -> bool:
    """Check if the scan has completed (scan_complete in the trail)."""
    trail_path = scan_dir / "execution_trail.jsonl"
    if not trail_path.exists():
        return False
    try:
        # Read the last 5KB of the trail (scan_complete should be near
        # the end — no need to read the whole file).
        with open(trail_path, "rb") as f:
            f.seek(0, 2)  # end
            size = f.tell()
            f.seek(max(0, size - 5120))
            tail = f.read().decode("utf-8", errors="ignore")
        for line in reversed(tail.strip().split("\n")):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                if entry.get("action") == "scan_complete":
                    return True
            except Exception:
                continue
    except Exception:
        pass
    return False


# --- Main supervisor loop ---

def main():
    parser = argparse.ArgumentParser(
        description="External supervisor for ScriptKiddie-Recon scanner. "
                    "Monitors heartbeat.json and restarts the scanner on hang.",
    )
    parser.add_argument("scan_dir", help="Path to the scan's output directory")
    parser.add_argument("--threshold", type=int, default=180,
                        help="Stale threshold in seconds (default: 180)")
    parser.add_argument("--poll-interval", type=int, default=10,
                        help="How often to check heartbeat (default: 10s)")
    parser.add_argument("--max-restarts", type=int, default=10,
                        help="Max restarts before giving up (default: 10)")
    parser.add_argument("--no-restart", action="store_true",
                        help="Monitor only — log stale heartbeats but DON'T restart")
    parser.add_argument("--verbose", action="store_true",
                        help="Log every poll")
    args = parser.parse_args()

    scan_dir = Path(args.scan_dir).resolve()
    if not scan_dir.is_dir():
        print(f"[supervisor] ERROR: {scan_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    heartbeat_path = scan_dir / "heartbeat.json"
    pid_path = scan_dir / "scanner.pid"
    args_path = scan_dir / "scan_args.json"
    trail_path = scan_dir / "execution_trail.jsonl"

    print(f"[supervisor] Monitoring {scan_dir}")
    print(f"[supervisor] Threshold: {args.threshold}s, Poll: {args.poll_interval}s")
    if args.no_restart:
        print("[supervisor] DRY RUN — will NOT restart, only log stale heartbeats")
    print(f"[supervisor] Max restarts: {args.max_restarts}")
    print(f"[supervisor] Press Ctrl+C to stop")

    restarts = 0

    # Handle Ctrl+C gracefully
    def sigint_handler(sig, frame):
        print(f"\n[supervisor] Stopping (Ctrl+C). {restarts} restarts performed.")
        sys.exit(0)
    signal.signal(signal.SIGINT, sigint_handler)

    while True:
        time.sleep(args.poll_interval)

        # --- Check if the user clicked Stop ---
        # scanner-runner.ts writes a `supervisor_stop` marker file when
        # stopScan() is called. We check for it here and exit cleanly.
        stop_marker = scan_dir / "supervisor_stop"
        if stop_marker.exists():
            print(f"[supervisor] Stop marker found — user clicked Stop. "
                  f"{restarts} restarts performed. Exiting.")
            try:
                stop_marker.unlink()
            except Exception:
                pass
            sys.exit(0)

        # --- Check if scan completed ---
        if scan_is_complete(scan_dir):
            print(f"[supervisor] Scan complete (scan_complete found in trail). "
                  f"{restarts} restarts performed. Exiting.")
            sys.exit(0)

        # --- Check if heartbeat file exists ---
        if not heartbeat_path.exists():
            if args.verbose:
                print(f"[supervisor] No heartbeat.json yet — scanner may still "
                      f"be in pre-scan phases (crawl/headers/etc.)")
            continue

        # --- Read heartbeat ---
        hb = read_json(heartbeat_path)
        if hb is None:
            if args.verbose:
                print(f"[supervisor] heartbeat.json unreadable — retrying next poll")
            continue

        hb_time = hb.get("timestamp", 0)
        if not hb_time:
            if args.verbose:
                print(f"[supervisor] heartbeat.json has no timestamp — retrying")
            continue

        # --- Check if the heartbeat's PID matches the current scanner PID ---
        # After a restart, the OLD heartbeat may still be on disk (written
        # by the previous scanner process). If the PID doesn't match
        # scanner.pid, the heartbeat is STALE and should be ignored —
        # otherwise we'd immediately kill the new scanner based on the
        # old scanner's stale heartbeat, causing an infinite restart loop.
        hb_pid = hb.get("pid", 0)
        current_pid = 0
        try:
            current_pid = int(pid_path.read_text(encoding="utf-8").strip())
        except Exception:
            pass
        if hb_pid and current_pid and hb_pid != current_pid:
            if args.verbose:
                print(f"[supervisor] Heartbeat PID ({hb_pid}) != scanner.pid "
                      f"({current_pid}) — stale heartbeat from previous run, ignoring")
            continue

        age = time.time() - hb_time
        tests_done = hb.get("tests_done", 0)
        phase = hb.get("phase", "?")

        if age < args.threshold:
            if args.verbose:
                print(f"[supervisor] OK — heartbeat {age:.0f}s old, "
                      f"tests_done={tests_done}, phase={phase}")
            continue

        # --- HEARTBEAT IS STALE — scanner is hung ---
        print(f"\n[supervisor] !!! HEARTBEAT STALE !!!")
        print(f"[supervisor] Heartbeat is {age:.0f}s old (threshold: {args.threshold}s)")
        print(f"[supervisor] Last known: tests_done={tests_done}, phase={phase}")
        print(f"[supervisor] Restart #{restarts + 1}/{args.max_restarts}")

        if args.no_restart:
            print("[supervisor] DRY RUN — not restarting (--no-restart)")
            continue

        if restarts >= args.max_restarts:
            print(f"[supervisor] Max restarts ({args.max_restarts}) exceeded. "
                  f"Giving up. The scan is still hung — manual intervention required.")
            sys.exit(1)

        # --- Kill the hung scanner ---
        pid = None
        if pid_path.exists():
            try:
                pid = int(pid_path.read_text(encoding="utf-8").strip())
            except Exception:
                pid = None

        if pid:
            print(f"[supervisor] Killing scanner PID {pid} (SIGKILL process group)")
            killed = kill_process_group(pid)
            if killed:
                print(f"[supervisor] Scanner PID {pid} killed")
            else:
                print(f"[supervisor] Scanner PID {pid} not found — may have already died")
        else:
            print(f"[supervisor] No scanner.pid file — cannot kill by PID")

        # Kill any orphaned Chrome processes
        print("[supervisor] Killing orphaned Chrome processes")
        kill_chrome()

        # Wait for OS to clean up
        time.sleep(3)

        # --- Read saved scan args ---
        scan_args = read_json(args_path)
        if scan_args is None:
            print(f"[supervisor] ERROR: Cannot read scan_args.json — "
                  f"cannot reconstruct restart command. Giving up.")
            sys.exit(1)

        # --- Build + execute restart command ---
        cmd = build_restart_command(scan_args, tests_done, scan_dir.name)
        print(f"[supervisor] Restarting scanner with --resume --skip-tests {tests_done}")
        print(f"[supervisor] Command: {' '.join(cmd[:6])}... --resume --skip-tests {tests_done}")

        try:
            # Build the environment for the restarted scanner.
            # We inherit the current env (supervisor's env) and then
            # OVERRIDE with the saved LLM env vars from scan_args.json.
            # This is critical: the supervisor's env may NOT have
            # LLM_BASE_URL/LLM_API_KEY (they were passed to the ORIGINAL
            # scanner by scanner-runner.ts, not to the supervisor).
            # Without this, the restarted scanner's LLM features
            # (analyzer, executive summary) fail with "not configured".
            restart_env = dict(os.environ)
            saved_env = scan_args.get("_env", {})
            for key, value in saved_env.items():
                if value:  # only set non-empty values
                    restart_env[key] = value

            # Spawn the new scanner as a DETACHED process (new process
            # group) so we can kill it by PGID if it hangs again.
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                start_new_session=True,  # new process group
                env=restart_env,
            )
            # Write the new PID to scanner.pid so we can kill it next time
            try:
                pid_path.write_text(str(proc.pid), encoding="utf-8")
            except Exception:
                pass
            print(f"[supervisor] New scanner started: PID {proc.pid}")
            print(f"[supervisor] Resuming from test {tests_done + 1}")
            restarts += 1

            # Write a supervisor event to the trail so it's visible in the UI
            try:
                with open(trail_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "ts": time.strftime("%I:%M:%S %p"),
                        "action": "supervisor_restart",
                        "result": f"heartbeat stale after {age:.0f}s — "
                                  f"killed PID {pid}, restarted as PID {proc.pid}, "
                                  f"resuming at test {tests_done + 1} "
                                  f"(restart #{restarts}/{args.max_restarts})",
                    }) + "\n")
            except Exception:
                pass

        except Exception as e:
            print(f"[supervisor] ERROR: Failed to restart scanner: {e}")
            sys.exit(1)

        # Give the new scanner time to start + write its first heartbeat
        # before we check again.
        time.sleep(15)


if __name__ == "__main__":
    main()
