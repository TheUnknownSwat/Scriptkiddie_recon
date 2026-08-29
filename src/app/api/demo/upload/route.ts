import { NextRequest } from "next/server";
import { demoHtml, demoPage, uploadStore } from "../store";

/**
 * GET/POST /api/demo/upload
 *
 * DELIBERATELY VULNERABLE: Unrestricted File Upload.
 *
 * GET serves a form with a real <input type=file> (plus a text field so
 * the scanner exercises multi-field forms). POST accepts ANY file — no
 * extension allowlist, no content inspection — stores it in memory, and
 * responds 200 with the filename reflected plus a clickable landing URL
 * (/api/demo/uploads/<name>, served by the catch-all route). This gives
 * the scanner's FileUploadTester everything it records: acceptance,
 * reflection, and an extractable landing URL.
 *
 * Storage is IN-MEMORY only (nothing touches the filesystem, and the
 * store resets when the dev server restarts).
 */

function renderForm(message = ""): string {
  return demoPage(
    "Avatar Upload",
    `<h1>Upload an Avatar</h1>
     ${message}
     <form action="/api/demo/upload" method="POST" enctype="multipart/form-data">
       <input type="file" name="file" accept="image/*,.txt,.svg,.html,.php">
       <br>
       <input type="text" name="caption" placeholder="Caption (optional)">
       <br>
       <button type="submit">Upload</button>
     </form>`,
  );
}

export async function GET() {
  return demoHtml(renderForm());
}

export async function POST(req: NextRequest) {
  const formData = await req.formData().catch(() => new FormData());
  const file = formData.get("file");
  const caption = String(formData.get("caption") || "");

  if (!(file instanceof File)) {
    return demoHtml(renderForm(`<p style="color:#c62828">No file received.</p>`));
  }

  // VULNERABILITY: no validation whatsoever — extension, MIME type, and
  // content are all accepted as-is.
  const body = await file.text().catch(() => "");
  uploadStore.set(file.name, { body, type: file.type || "application/octet-stream" });
  const landingUrl = `/api/demo/uploads/${encodeURIComponent(file.name)}`;

  return demoHtml(
    demoPage(
      "Upload Complete",
      `<h1>Upload complete</h1>
       <p>Uploaded file: <strong>${file.name}</strong> (${body.length} bytes, declared ${file.type || "unknown"})</p>
       ${caption ? `<p>Caption: ${caption}</p>` : ""}
       <p>Your file is available at: <a href="${landingUrl}">${landingUrl}</a></p>`,
    ),
  );
}
