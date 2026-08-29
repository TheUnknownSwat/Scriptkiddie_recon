import { NextRequest, NextResponse } from "next/server";
import { DEMO_JWT } from "../store";

/**
 * POST /api/demo/login
 * GET /api/demo/login
 *
 * DELIBERATELY VULNERABLE: SQL Injection (error-based + auth bypass).
 *
 * This endpoint simulates a login form backed by a "SQL database". The
 * "SQL query" is constructed by string concatenation (the classic
 * vulnerability), and when the input contains SQL metacharacters, we
 * simulate a MySQL syntax error message — the exact pattern the scanner's
 * SQLi regex patterns look for.
 *
 * IMPORTANT: This form REQUIRES both username AND password to be filled.
 * If either is empty, it returns an error WITHOUT running the SQL query.
 * This tests the scanner's multi-field injection capability — the scanner
 * must fill BOTH fields to trigger the SQLi.
 *
 * SQLi login bypass: username = admin' -- (comments out the password check)
 * The simulated query becomes: SELECT * FROM users WHERE username='admin' --' AND password='...'
 */

const USERS: Record<string, { password: string; name: string; email: string }> = {
  admin: { password: "admin123", name: "Admin User", email: "admin@vulntest.local" },
  alice: { password: "password", name: "Alice Smith", email: "alice@vulntest.local" },
  bob: { password: "bob123", name: "Bob Jones", email: "bob@vulntest.local" },
};

function renderLogin(errorMsg: string = ""): string {
  return `<!DOCTYPE html>
<html>
<head>
  <title>Login — VulnTest</title>
  <style>
    body { font-family: sans-serif; max-width: 400px; margin: 4rem auto; padding: 1rem; }
    .error { color: #c62828; background: #ffebee; padding: 0.5rem; border-radius: 3px; margin: 0.5rem 0; }
    .back { margin-bottom: 1rem; }
    input { display: block; margin: 0.5rem 0; padding: 4px 8px; width: 100%; box-sizing: border-box; }
    button { padding: 6px 16px; background: #1976d2; color: white; border: none; border-radius: 3px; cursor: pointer; }
  </style>
  <script>
    // Client-side validation: BOTH fields must be filled.
    // This tests the scanner's multi-field + co-field injection capability.
    function validateForm() {
      var u = document.querySelector('input[name=username]').value;
      var p = document.querySelector('input[name=password]').value;
      if (!u || !p) {
        alert('Both username and password are required.');
        return false;
      }
      return true;
    }
  </script>
</head>
<body>
  <div class="back"><a href="/api/demo">← Back to VulnTest</a></div>
  <h1>Login</h1>
  ${errorMsg ? `<div class="error">${errorMsg}</div>` : ""}
  <form action="/api/demo/login" method="POST" onsubmit="return validateForm()">
    <input type="text" name="username" placeholder="Username" value="" required>
    <input type="password" name="password" placeholder="Password" value="" required>
    <button type="submit">Login</button>
  </form>
  <p style="font-size:0.8em;color:#666">Demo users: admin/admin123, alice/password, bob/bob123</p>
  <p style="font-size:0.8em;color:#c62828">SQLi bypass: username = admin' -- (password = anything)</p>
</body>
</html>`;
}

function renderSuccess(name: string): string {
  return `<!DOCTYPE html>
<html>
<head><title>Welcome — VulnTest</title></head>
<body>
  <h1>Welcome, ${name}!</h1>
  <p>Login successful. <a href="/api/demo">Back</a></p>
</body>
</html>`;
}

export async function GET() {
  return new NextResponse(renderLogin(), {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Server": "VulnTest/1.0",
      "X-Powered-By": "VulnTest-PHP/5.6.40",
      "Set-Cookie": "sessionid=vulnsession123; Path=/; SameSite=None",
    },
  });
}

export async function POST(req: NextRequest) {
  const formData = await req.formData().catch(() => new FormData());
  const username = String(formData.get("username") || "");
  const password = String(formData.get("password") || "");

  // REQUIRE BOTH FIELDS — if either is empty, return an error.
  // This tests the scanner's multi-field injection: it must fill BOTH
  // username and password for the SQL query to run.
  if (!username || !password) {
    return new NextResponse(renderLogin("Both username and password are required."), {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Server": "VulnTest/1.0",
        "X-Powered-By": "VulnTest-PHP/5.6.40",
      },
    });
  }

  // VULNERABILITY: Simulated SQL string concatenation.
  // Real query: "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
  //
  // SQLi login bypass: if username = "admin' --", the query becomes:
  //   SELECT * FROM users WHERE username='admin' --' AND password='...'
  // Everything after -- is commented out, so password check is skipped.
  //
  // We detect SQL injection patterns and return appropriate responses:

  // Check for SQL comment bypass (admin' -- or admin'-- or ' OR '1'='1' --)
  if (username.includes("'") && (username.includes("--") || username.toLowerCase().includes(" or "))) {
    // SQLi bypass successful — the query comments out the password check.
    // Return the admin user's data (simulating successful auth bypass).
    const res = new NextResponse(renderSuccess("Admin User (via SQLi bypass)"), {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Server": "VulnTest/1.0",
        "X-Powered-By": "VulnTest-PHP/5.6.40",
        "Set-Cookie": `auth=admin; Path=/; SameSite=None`,
      },
    });
    // Also issue the weak demo JWT (no exp claim) as a cookie — the
    // scanner harvests it from the cookie jar for JWT analysis.
    res.headers.append("Set-Cookie", `token=${DEMO_JWT}; Path=/; SameSite=None`);
    return res;
  }

  // Check for other SQL injection patterns (error-based)
  const sqlPattern = /'|--| or |union|select|drop|insert|;/i;
  if (sqlPattern.test(username) || sqlPattern.test(password)) {
    // Simulate a MySQL syntax error (the pattern the scanner looks for).
    const errorHtml = renderLogin(
      `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${username}' at line 1`
    );
    return new NextResponse(errorHtml, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Server": "VulnTest/1.0",
        "X-Powered-By": "VulnTest-PHP/5.6.40",
        "Set-Cookie": "sessionid=vulnsession123; Path=/; SameSite=None",
      },
    });
  }

  // Normal auth check.
  const user = USERS[username];
  if (user && user.password === password) {
    const res = new NextResponse(renderSuccess(user.name), {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Server": "VulnTest/1.0",
        "X-Powered-By": "VulnTest-PHP/5.6.40",
        "Set-Cookie": `auth=${username}; Path=/; SameSite=None`,
      },
    });
    // Issue the weak demo JWT (no exp claim) alongside the auth cookie.
    res.headers.append("Set-Cookie", `token=${DEMO_JWT}; Path=/; SameSite=None`);
    return res;
  }

  return new NextResponse(renderLogin("Invalid username or password."), {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Server": "VulnTest/1.0",
      "X-Powered-By": "VulnTest-PHP/5.6.40",
    },
  });
}
