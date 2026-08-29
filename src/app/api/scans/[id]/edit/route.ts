import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

/**
 * PATCH /api/scans/[id]
 *
 * Updates a scan's editable fields. Currently only supports:
 *   - title: a user-defined label shown in the dashboard
 *
 * Body: { title?: string }
 *
 * Returns the updated scan row.
 */
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const scan = await db.scan.findUnique({ where: { id } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  let body: { title?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  // Build the update data — only update fields that were provided.
  const data: { title?: string | null } = {};
  if (typeof body.title === "string") {
    // Allow empty string (clears the title → dashboard shows targetUrl).
    // Trim to prevent whitespace-only titles.
    data.title = body.title.trim() || null;
  }

  if (Object.keys(data).length === 0) {
    return NextResponse.json({ error: "No fields to update" }, { status: 400 });
  }

  const updated = await db.scan.update({
    where: { id },
    data,
  });

  return NextResponse.json({ ok: true, scan: updated });
}
