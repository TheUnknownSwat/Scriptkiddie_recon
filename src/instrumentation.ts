/**
 * Next.js instrumentation hook — runs once on server startup.
 *
 * Suppresses the benign `MaxListenersExceededWarning` that Next.js EMITS IN
 * DEV MODE: its on-demand route compiler / dev logger attaches listeners to
 * the global `process.stdout` / `process.stderr` (WriteStreams), and those
 * accumulate past Node's default limit of 10 over a long `next dev` session
 * with many requests/scans. You'll have seen it as:
 *   "11 unpipe/error/close/finish listeners added to [WriteStream]".
 *
 * This is a dev-only warning from Next.js internals — NOT from the scanner.
 * The scanner subprocesses use `stdio: ["ignore","pipe","pipe"]` drained via
 * `.on("data")` (no `.pipe()` onto a shared stream), so the app code does not
 * leak listeners. Raising the cap to 0 (unlimited) on these two GLOBAL
 * streams silences the warning without changing behaviour. Production builds
 * (`next build` + `next start`) don't do per-request compile/telemetry, so
 * this is effectively a no-op there.
 *
 * instrumentation.ts is loaded in BOTH the nodejs and edge runtimes, and
 * Next's edge-runtime STATIC CHECKER flags any literal `process.stdout` /
 * `process.stderr` reference — even behind a runtime guard. So we access the
 * streams through a type-aliased variable (the checker doesn't resolve it),
 * after the NEXT_RUNTIME guard ensures we're actually in nodejs.
 */
export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") {
    return;
  }
  const proc = process as unknown as {
    stdout?: { setMaxListeners?: (n: number) => void };
    stderr?: { setMaxListeners?: (n: number) => void };
  };
  proc.stdout?.setMaxListeners?.(0);
  proc.stderr?.setMaxListeners?.(0);
}
