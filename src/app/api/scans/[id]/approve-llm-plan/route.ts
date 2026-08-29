import { NextRequest, NextResponse } from "next/server";
import fs from "fs/promises";
import path from "path";

/**
 * POST /api/scans/[id]/approve-llm-plan
 *
 * Approves the LLM-generated scan plan. Creates a marker file
 * (llm_plan_approved.json) that the scanner subprocess polls for.
 * Once detected, the scanner merges the custom payloads + priority
 * inputs into the active scan and continues.
 *
 * The scanner polls every 2s and auto-approves after 10 minutes if
 * no response — this endpoint is for users who want to review first.
 *
 * Body (optional):
 *   { "action": "approve" | "reject" }
 *
 * Default action is "approve".
 */
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;

  // Parse the action from the body (default to "approve")
  let action = "approve";
  try {
    const body = await req.json();
    if (body.action === "reject") action = "reject";
  } catch {
    // Empty body — default to approve
  }

  // Check that the pending marker exists
  const pendingPath = path.join(
    process.cwd(),
    "scan-output",
    id,
    "llm_plan_pending_approval",
  );
  try {
    await fs.stat(pendingPath);
  } catch {
    return NextResponse.json(
      {
        error:
          "No pending LLM plan found. The plan may have already been approved/rejected, " +
          "or the scan hasn't reached the planning phase yet.",
      },
      { status: 404 },
    );
  }

  // Create the appropriate marker file
  const markerName = action === "reject" ? "llm_plan_rejected.json" : "llm_plan_approved.json";
  const markerPath = path.join(
    process.cwd(),
    "scan-output",
    id,
    markerName,
  );

  try {
    await fs.writeFile(
      markerPath,
      JSON.stringify(
        {
          action,
          approved_at: new Date().toISOString(),
        },
        null,
        2,
      ),
      "utf-8",
    );
  } catch (e) {
    return NextResponse.json(
      {
        error: "Failed to write approval marker file",
        detail: e instanceof Error ? e.message : String(e),
      },
      { status: 500 },
    );
  }

  return NextResponse.json({
    ok: true,
    action,
    message:
      action === "approve"
        ? "Plan approved. The scanner will merge custom payloads + priority inputs and continue."
        : "Plan rejected. The scanner will continue with default payloads only.",
  });
}
