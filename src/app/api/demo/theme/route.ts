import { NextRequest } from "next/server";
import { demoHtml, demoPage } from "../store";

/**
 * GET /api/demo/theme?color=...
 *
 * DELIBERATELY VULNERABLE: CSS Injection.
 *
 * The theme customizer reflects the color parameter straight into a
 * <style> block with no sanitisation. A reflected payload therefore
 * lands INSIDE a CSS context (the scanner flags reflected input inside
 * <style>…</style> as a CSS-injection finding).
 */
export async function GET(req: NextRequest) {
  const color = req.nextUrl.searchParams.get("color") || "#ffffff";
  const html = demoPage(
    "Theme Customizer",
    `<h1>Theme Customizer</h1>
     <form action="/api/demo/theme" method="GET">
       <input type="text" name="color" placeholder="#ffffff or red" value="${color}">
       <button type="submit">Apply</button>
     </form>
     <p>Current theme applied below.</p>`,
    // VULNERABILITY: the parameter is interpolated directly into the stylesheet.
    `<style>
       body { background: ${color}; }
       h1 { border-bottom: 2px solid ${color}; }
     </style>`,
  );
  return demoHtml(html);
}
