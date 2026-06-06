import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params;
    const body = await req.json();

    const allowed: Record<string, true> = {
      status: true,
      severity: true,
      cvss_score: true,
      remediation_notes: true,
      remediated_at: true,
      reference_url: true,
      title: true,
      description: true,
      cve_id: true,
      vulnerability_type: true,
      asset_id: true,
      threat_id: true,
    };

    const sets: string[] = [];
    const values: unknown[] = [];

    for (const [key, value] of Object.entries(body)) {
      if (!allowed[key]) continue;
      values.push(value);
      sets.push(`${key} = $${values.length}`);
    }

    // Auto-set remediated_at when status flips to remediated
    if (body.status === "remediated" && !("remediated_at" in body)) {
      sets.push(`remediated_at = CURRENT_TIMESTAMP`);
    }

    if (sets.length === 0) {
      return NextResponse.json(
        { message: "No fields to update" },
        { status: 400 },
      );
    }

    sets.push(`updated_at = CURRENT_TIMESTAMP`);
    values.push(Number(id));

    const result = await pool.query(
      `UPDATE vulnerabilities
          SET ${sets.join(", ")}
        WHERE id = $${values.length}
       RETURNING *`,
      values,
    );

    if (result.rows.length === 0) {
      return NextResponse.json({ message: "Not found" }, { status: 404 });
    }

    return NextResponse.json({ vulnerability: result.rows[0] });
  } catch (error) {
    console.error("Update vulnerability error:", error);
    const msg =
      error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ message: msg }, { status: 500 });
  }
}

export async function DELETE(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params;
    const result = await pool.query(
      "DELETE FROM vulnerabilities WHERE id = $1 RETURNING id",
      [Number(id)],
    );
    if (result.rows.length === 0) {
      return NextResponse.json({ message: "Not found" }, { status: 404 });
    }
    return NextResponse.json({ message: "Deleted" });
  } catch (error) {
    console.error("Delete vulnerability error:", error);
    const msg =
      error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ message: msg }, { status: 500 });
  }
}
