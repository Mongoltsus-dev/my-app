import { persistResidualRisk } from "@/lib/residual-risk";
import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  try {
    const { risk_register_id } = await req.json();
    if (!risk_register_id) {
      return NextResponse.json(
        { error: "risk_register_id is required" },
        { status: 400 },
      );
    }

    const result = await persistResidualRisk(Number(risk_register_id));
    if (!result) {
      return NextResponse.json(
        { error: "No risk analysis found for this risk" },
        { status: 404 },
      );
    }

    return NextResponse.json({ success: true, risk_register_id, ...result });
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Failed to recalculate residual risk";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
