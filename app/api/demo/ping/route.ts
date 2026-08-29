import { NextRequest } from "next/server";
import { demoHtml, demoPage } from "../store";

/**
 * GET/POST /api/demo/ping?host=...
 *
 * DELIBERATELY VULNERABLE: Command Injection (simulated).
 *
 * The "ping" feature shells out to the OS with the user-supplied host —
 * everything here is SIMULATED (no real command runs). The simulated
 * output mimics what the injected commands would really print, so the
 * scanner's CMDi detection regexes fire:
 *   - id       → "uid=0(root) gid=0(root) groups=0(root)"
 *   - whoami   → "root"
 *   - echo canary (wrcanda7ry) → echoed back
 *   - ping     → "PING 127.0.0.1 ..." statistics block
 */

function simulate(host: string): string {
  const h = host.toLowerCase();
  if (h.includes("whoami")) return "root";
  if (h.includes("wrcanda7ry")) return "wrcanda7ry";
  if (/\bid\b/.test(h)) return "uid=0(root) gid=0(root) groups=0(root)";
  if (h.includes("ping")) {
    return [
      "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.",
      "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.042 ms",
      "",
      "--- 127.0.0.1 ping statistics ---",
      "1 packets transmitted, 1 received, 0% packet loss, time 0ms",
    ].join("\n");
  }
  return `Pinging ${host} with 32 bytes of data:\nReply from ${host}: bytes=32 time=1ms TTL=64`;
}

function renderPage(host: string, output: string | null): string {
  return demoPage(
    "Network Tools",
    `
  <h1>Network Tools — Ping Utility</h1>
  <div class="warning"><strong>Simulated:</strong> no real command runs on this server.</div>
  <form action="/api/demo/ping" method="GET">
    <input type="text" name="host" placeholder="hostname or IP" value="${host}">
    <button type="submit">Ping</button>
  </form>
  ${output !== null ? `<h2>Output</h2><p><code>$ ping -c1 ${host}</code></p><pre>${output}</pre>` : ""}
  `,
  );
}

export async function GET(req: NextRequest) {
  const host = req.nextUrl.searchParams.get("host") || "";
  if (!host) return demoHtml(renderPage("", null));
  return demoHtml(renderPage(host, simulate(host)));
}

export async function POST(req: NextRequest) {
  const formData = await req.formData().catch(() => new FormData());
  const host = String(formData.get("host") || "");
  if (!host) return demoHtml(renderPage("", null));
  return demoHtml(renderPage(host, simulate(host)));
}
