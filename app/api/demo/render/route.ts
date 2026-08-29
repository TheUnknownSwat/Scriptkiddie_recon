import { NextRequest } from "next/server";
import { demoHtml, demoPage } from "../store";

/**
 * GET /api/demo/render?tpl=...
 *
 * DELIBERATELY VULNERABLE: Server-Side Template Injection (SSTI).
 *
 * The template preview feature evaluates the user-supplied template
 * string (simulated). When the input contains a template expression
 * ({{7*7}}, ${7*7}, #{7*7}, <%=7*7%>), the "rendered" page contains the
 * EVALUATED result (49) — not the raw payload. The scanner's SSTI check
 * looks for `49` in the response while the payload itself is absent.
 */
const TPL_EXPR = /\{\{7\*7\}\}|\$\{7\*7\}|\#\{7\*7\}|<%=7\*7%>/;

export async function GET(req: NextRequest) {
  const tpl = req.nextUrl.searchParams.get("tpl") || "";
  if (!tpl) {
    return demoHtml(
      demoPage(
        "Template Preview",
        `<h1>Email Template Preview</h1>
         <p>Preview your email templates before sending.</p>
         <form action="/api/demo/render" method="GET">
           <input type="text" name="tpl" placeholder="Hello {{name}}!" style="width:400px">
           <button type="submit">Preview</button>
         </form>`,
      ),
    );
  }
  if (TPL_EXPR.test(tpl)) {
    // Simulated evaluation: the expression is evaluated server-side.
    // The response contains "49" (the result) but NOT the raw payload.
    return demoHtml(
      demoPage("Template Preview", `<h1>Rendered template</h1><pre>49</pre>`),
    );
  }
  return demoHtml(
    demoPage("Template Preview", `<h1>Rendered template</h1><pre>${tpl}</pre>`),
  );
}
