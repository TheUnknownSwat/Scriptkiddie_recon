import { demoHtml, demoPage } from "../store";

/**
 * GET /api/demo/docs
 *
 * Documentation hub — exists to give the crawler a multi-hop link chain
 * (landing → docs → leaf endpoints) so depth 3 crawling visibly pays
 * off, and to link the quieter endpoints the landing page doesn't
 * feature prominently.
 */
export async function GET() {
  return demoHtml(
    demoPage(
      "Documentation",
      `<h1>VulnTest Documentation</h1>
       <h2>Guides</h2>
       <ul>
         <li><a href="/api/demo/profile">Account &amp; profile settings</a></li>
         <li><a href="/api/demo/theme">Customising your theme</a></li>
         <li><a href="/api/demo/upload">Uploading an avatar</a></li>
         <li><a href="/api/demo/ping">Network tools reference</a></li>
       </ul>
       <h2>Developer API</h2>
       <ul>
         <li><a href="/api/demo/render">Email template preview</a></li>
         <li><a href="/api/demo/fetch">URL preview service</a></li>
         <li><a href="/api/demo/xml">XML import</a></li>
         <li><a href="/api/demo/token">API tokens</a></li>
       </ul>
       <h2>Internal</h2>
       <ul>
         <li><a href="/api/demo/admin">Admin dashboard</a></li>
       </ul>`,
    ),
  );
}
