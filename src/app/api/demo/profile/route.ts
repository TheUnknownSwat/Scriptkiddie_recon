import { NextRequest } from "next/server";
import { demoHtml, demoPage } from "../store";

/**
 * GET/POST /api/demo/profile
 *
 * Deliberately rich attack surface: this form exercises the scanner's
 * input cataloguing with every common field type — select, textarea,
 * checkbox, radio, and a HIDDEN field pre-filled with value="admin"
 * (flagged by the scanner as a hidden form default / privilege-
 * escalation risk). POST reflects all values without encoding (also an
 * XSS surface).
 */
function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function form(values: Record<string, string> = {}): string {
  const v = (k: string, d = "") => esc(values[k] ?? d);
  return demoPage(
    "Profile Settings",
    `<h1>Profile Settings</h1>
     <form action="/api/demo/profile" method="POST">
       <label>Display name: <input type="text" name="display_name" value="${v("display_name")}"></label><br>
       <label>Department:
         <select name="department">
           <option value="engineering"${values.department === "engineering" ? " selected" : ""}>Engineering</option>
           <option value="finance"${values.department === "finance" ? " selected" : ""}>Finance</option>
           <option value="hr"${values.department === "hr" ? " selected" : ""}>HR</option>
         </select></label><br>
       <label>Bio: <textarea name="bio" rows="3" cols="40">${v("bio")}</textarea></label><br>
       <label><input type="checkbox" name="newsletter" value="yes"${values.newsletter === "yes" ? " checked" : ""}> Email me the newsletter</label><br>
       <label>Plan:
         <input type="radio" name="tier" value="free"${values.tier !== "pro" ? " checked" : ""}> Free
         <input type="radio" name="tier" value="pro"${values.tier === "pro" ? " checked" : ""}> Pro</label><br>
       <input type="hidden" name="role" value="admin">
       <button type="submit">Save</button>
     </form>`,
  );
}

export async function GET() {
  return demoHtml(form());
}

export async function POST(req: NextRequest) {
  const formData = await req.formData().catch(() => new FormData());
  const values: Record<string, string> = {};
  for (const [k, val] of formData.entries()) values[k] = String(val);
  if (!values.newsletter) values.newsletter = "";

  const confirmed = demoPage(
    "Profile Saved",
    `<h1>Profile saved</h1>
     <table border="1" cellpadding="6">
       <tr><th>field</th><th>value</th></tr>
       <tr><td>display_name</td><td>${values.display_name ?? ""}</td></tr>
       <tr><td>department</td><td>${values.department ?? ""}</td></tr>
       <tr><td>bio</td><td>${values.bio ?? ""}</td></tr>
       <tr><td>newsletter</td><td>${values.newsletter || "no"}</td></tr>
       <tr><td>tier</td><td>${values.tier ?? ""}</td></tr>
       <tr><td>role</td><td>${values.role ?? ""}</td></tr>
     </table>
     <p><a href="/api/demo/profile">Back to profile</a></p>`,
  );
  return demoHtml(confirmed);
}
