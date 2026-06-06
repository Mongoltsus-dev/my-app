import { pool } from "@/lib/db";
import fs from "fs";
import { NextRequest, NextResponse } from "next/server";
import path from "path";

// ─── POST — upload PDF evidence ───────────────────────────────────────────────

export async function POST(req: NextRequest) {
  try {
    const formData = await req.formData();
    const file = formData.get("file") as File | null;
    const id = formData.get("id") as string | null;

    if (!file || !id) {
      return NextResponse.json({ message: "file and id required" }, { status: 400 });
    }
    if (!file.name.toLowerCase().endsWith(".pdf")) {
      return NextResponse.json({ message: "Only PDF files are accepted" }, { status: 400 });
    }
    if (file.size > 20 * 1024 * 1024) {
      return NextResponse.json({ message: "File too large (max 20 MB)" }, { status: 400 });
    }

    const bytes = await file.arrayBuffer();
    const buffer = Buffer.from(bytes);

    const uploadDir = path.join(process.cwd(), "public", "uploads", "evidence");
    fs.mkdirSync(uploadDir, { recursive: true });

    const safeId = String(Number(id));
    const filename = `ctl-${safeId}-${Date.now()}.pdf`;
    fs.writeFileSync(path.join(uploadDir, filename), buffer);

    const filePath = `/uploads/evidence/${filename}`;
    await pool.query(
      `UPDATE control_recommendations
          SET evidence_file_path     = $1,
              evidence_original_name = $2,
              evidence_uploaded_at   = NOW()
        WHERE id = $3`,
      [filePath, file.name, Number(id)],
    );

    return NextResponse.json({ path: filePath, original_name: file.name }, { status: 201 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ message }, { status: 500 });
  }
}

// ─── DELETE — remove evidence file ────────────────────────────────────────────

export async function DELETE(req: NextRequest) {
  try {
    const id = req.nextUrl.searchParams.get("id");
    if (!id) return NextResponse.json({ message: "id required" }, { status: 400 });

    const { rows } = await pool.query(
      `UPDATE control_recommendations
          SET evidence_file_path = NULL, evidence_original_name = NULL, evidence_uploaded_at = NULL
        WHERE id = $1
        RETURNING evidence_file_path`,
      [Number(id)],
    );

    // Delete file from disk (best effort)
    const old = rows[0]?.evidence_file_path as string | null;
    if (old) {
      const abs = path.join(process.cwd(), "public", old);
      try { fs.unlinkSync(abs); } catch { /* file may already be gone */ }
    }

    return NextResponse.json({ ok: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ message }, { status: 500 });
  }
}
