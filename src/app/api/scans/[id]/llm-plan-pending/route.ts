import { NextResponse } from "next/server";
import fs from "fs/promises";
import path from "path";

/**
 * GET /api/scans/[id]/llm-plan-pending
 *
 * Checks if the scanner is waiting for user approval of the LLM plan.
 * Returns the pending plan details (custom payloads, priority inputs,
 * reasoning) so the UI can display them for review.
 *
 * The scanner creates "llm_plan_pending_approval" when it's waiting,
 * and removes it when the user approves/rejects (or after 10 min timeout).
 *
 * Response:
 *   { pending: true, plan: {...} }  — waiting for approval
 *   { pending: false }              — not waiting (scan may not have reached planning phase yet)
 */
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const pendingPath = path.join(
    process.cwd(),
    "scan-output",
    id,
    "llm_plan_pending_approval",
  );

  try {
    const pendingContent = await fs.readFile(pendingPath, "utf-8");
    const pendingInfo = JSON.parse(pendingContent);

    // Also read the full plan (if it exists)
    const planPath = path.join(
      process.cwd(),
      "scan-output",
      id,
      "llm_plan.json",
    );
    let fullPlan: Record<string, unknown> = {};
    try {
      const planContent = await fs.readFile(planPath, "utf-8");
      fullPlan = JSON.parse(planContent);
    } catch {
      // Plan file might not exist yet — just return the pending info
    }

    return NextResponse.json({
      pending: true,
      plan: {
        custom_payloads: (fullPlan.custom_payloads as string[]) || [],
        priority_inputs: (fullPlan.priority_inputs as string[]) || [],
        additional_urls: (fullPlan.additional_urls as string[]) || [],
        reasoning: (fullPlan.reasoning as string) || "",
        llm_error: (fullPlan.llm_error as string) || null,
      },
      pending_info: pendingInfo,
    });
  } catch {
    return NextResponse.json({
      pending: false,
      message:
        "No pending LLM plan. The scan may not have reached the planning phase, " +
        "or the plan may have already been approved/rejected.",
    });
  }
}
