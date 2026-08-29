import { NextRequest, NextResponse } from "next/server";

/**
 * GET /api/demo/user?id=...
 *
 * DELIBERATELY VULNERABLE: IDOR (Insecure Direct Object Reference).
 *
 * Any user ID returns that user's profile — there is NO access control
 * check. User 1, 2, 3, 999 all return data. This is the classic IDOR
 * pattern (OWASP A01: Broken Access Control).
 *
 * The scanner's LLM analyzer should flag this as a potential IDOR.
 */

const USERS: Record<number, { name: string; email: string; role: string; ssn: string }> = {
  1: { name: "Admin User", email: "admin@vulntest.local", role: "admin", ssn: "123-45-6789" },
  2: { name: "Alice Smith", email: "alice@vulntest.local", role: "user", ssn: "234-56-7890" },
  3: { name: "Bob Jones", email: "bob@vulntest.local", role: "user", ssn: "345-67-8901" },
  4: { name: "Charlie Brown", email: "charlie@vulntest.local", role: "moderator", sss: "456-78-9012", ssn: "456-78-9012" },
  5: { name: "Diana Prince", email: "diana@vulntest.local", role: "user", ssn: "567-89-0123" },
};

export async function GET(req: NextRequest) {
  const idStr = req.nextUrl.searchParams.get("id") || "1";
  const id = parseInt(idStr, 10) || 1;

  // VULNERABILITY: No access control check. Any ID returns data.
  // A secure implementation would verify the requesting user has
  // permission to view this profile.
  const user = USERS[id];

  const html = `<!DOCTYPE html>
<html>
<head>
  <title>User ${id} — VulnTest</title>
  <style>
    body { font-family: sans-serif; max-width: 600px; margin: 2rem auto; padding: 1rem; }
    .profile { border: 1px solid #ddd; padding: 1rem; border-radius: 4px; }
    .field { margin: 0.5rem 0; }
    .label { font-weight: bold; display: inline-block; width: 100px; }
    .back { margin-bottom: 1rem; }
    .nav { margin: 1rem 0; }
    .nav a { margin-right: 0.5rem; }
  </style>
</head>
<body>
  <div class="back"><a href="/api/demo">← Back to VulnTest</a></div>
  <h1>User Profile #${id}</h1>
  <div class="nav">
    <a href="/api/demo/user?id=1">User 1</a>
    <a href="/api/demo/user?id=2">User 2</a>
    <a href="/api/demo/user?id=3">User 3</a>
    <a href="/api/demo/user?id=4">User 4</a>
    <a href="/api/demo/user?id=5">User 5</a>
  </div>
  ${user ? `
  <div class="profile">
    <div class="field"><span class="label">Name:</span> ${user.name}</div>
    <div class="field"><span class="label">Email:</span> ${user.email}</div>
    <div class="field"><span class="label">Role:</span> ${user.role}</div>
    <div class="field"><span class="label">SSN:</span> ${user.ssn}</div>
  </div>
  <p style="color:#c62828;font-size:0.8em">⚠ Sensitive data (SSN) exposed for any user ID — no access control!</p>
  ` : `
  <div class="profile">
    <div class="field">User not found.</div>
  </div>
  `}
</body>
</html>`;

  return new NextResponse(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Server": "VulnTest/1.0",
      "X-Powered-By": "VulnTest-Express/0.0.1",
      "Set-Cookie": "sessionid=vulnsession123; Path=/; SameSite=None",
    },
  });
}
