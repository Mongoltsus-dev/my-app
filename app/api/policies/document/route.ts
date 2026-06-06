import { pool } from "@/lib/db";
import { MANAGEMENT_APPROVER_LABEL } from "@/lib/current-user";
import fs from "fs";
import { NextRequest, NextResponse } from "next/server";
import path from "path";

const MAX_FILE_SIZE = 20 * 1024 * 1024;
const UPLOAD_DIR = path.join(process.cwd(), "public", "uploads", "policies");

async function ensurePolicyDocumentColumns() {
  const cols = [
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS document_file_path TEXT",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS document_original_name TEXT",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS document_uploaded_at TIMESTAMP",
    "ALTER TABLE policies ADD COLUMN IF NOT EXISTS document_note TEXT",
  ];
  for (const col of cols) await pool.query(col);
}

async function getPolicyById(id: number) {
  const res = await pool.query(
    `SELECT p.*, cu.full_name AS created_by_name,
            CASE
              WHEN p.status = 'Approved' AND p.approved_at IS NOT NULL
                THEN $2
              ELSE NULL
            END AS approved_by_name,
            (p.status = 'Approved' AND p.next_review_at IS NOT NULL AND p.next_review_at < NOW()) AS is_due_for_review
       FROM policies p
       LEFT JOIN users cu ON cu.id = p.created_by
      WHERE p.id = $1`,
    [id, MANAGEMENT_APPROVER_LABEL],
  );
  return res.rows[0] ?? null;
}

function safePublicUploadPath(filePath: string | null | undefined) {
  if (!filePath) return null;
  const clean = filePath.replace(/^\/+/, "");
  const abs = path.resolve(process.cwd(), "public", clean);
  const root = path.resolve(UPLOAD_DIR);
  return abs.startsWith(root + path.sep) ? abs : null;
}

function toPolicyId(value: FormDataEntryValue | string | null) {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : null;
}

// ── POST upload policy PDF ──────────────────────────────────────────────────
export async function POST(req: NextRequest) {
  try {
    await ensurePolicyDocumentColumns();

    const formData = await req.formData();
    const file = formData.get("file") as File | null;
    const id = toPolicyId(formData.get("id"));
    const noteValue = formData.get("document_note");
    const documentNote =
      typeof noteValue === "string" && noteValue.trim().length
        ? noteValue.trim()
        : null;

    if (!file || !id) {
      return NextResponse.json({ message: "PDF файл болон policy ID шаардлагатай" }, { status: 400 });
    }
    if (!file.name.toLowerCase().endsWith(".pdf")) {
      return NextResponse.json({ message: "Зөвхөн PDF файл оруулна уу" }, { status: 400 });
    }
    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json({ message: "PDF файл 20 MB-аас ихгүй байх ёстой" }, { status: 400 });
    }

    const current = await pool.query(
      "SELECT document_file_path FROM policies WHERE id = $1",
      [id],
    );
    if (current.rowCount === 0) {
      return NextResponse.json({ message: "Дүрэм журам олдсонгүй" }, { status: 404 });
    }

    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    const filename = `policy-${id}-${Date.now()}.pdf`;
    const filePath = `/uploads/policies/${filename}`;

    const bytes = await file.arrayBuffer();
    fs.writeFileSync(path.join(UPLOAD_DIR, filename), Buffer.from(bytes));

    await pool.query(
      `UPDATE policies
          SET document_file_path     = $1,
              document_original_name = $2,
              document_uploaded_at   = NOW(),
              document_note          = COALESCE($3, document_note),
              updated_at             = NOW()
        WHERE id = $4`,
      [filePath, file.name, documentNote, id],
    );

    const oldAbs = safePublicUploadPath(current.rows[0]?.document_file_path);
    if (oldAbs) {
      try {
        fs.unlinkSync(oldAbs);
      } catch {
        // Existing file may have already been removed outside the app.
      }
    }

    const policy = await getPolicyById(id);
    return NextResponse.json({ success: true, policy }, { status: 201 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "PDF оруулах үед алдаа гарлаа";
    return NextResponse.json({ message }, { status: 500 });
  }
}

// ── DELETE remove policy PDF ────────────────────────────────────────────────
export async function DELETE(req: NextRequest) {
  try {
    await ensurePolicyDocumentColumns();

    const id = toPolicyId(req.nextUrl.searchParams.get("id"));
    if (!id) {
      return NextResponse.json({ message: "Policy ID шаардлагатай" }, { status: 400 });
    }

    const current = await pool.query(
      "SELECT document_file_path FROM policies WHERE id = $1",
      [id],
    );
    if (current.rowCount === 0) {
      return NextResponse.json({ message: "Дүрэм журам олдсонгүй" }, { status: 404 });
    }

    await pool.query(
      `UPDATE policies
          SET document_file_path = NULL,
              document_original_name = NULL,
              document_uploaded_at = NULL,
              updated_at = NOW()
        WHERE id = $1`,
      [id],
    );

    const oldAbs = safePublicUploadPath(current.rows[0]?.document_file_path);
    if (oldAbs) {
      try {
        fs.unlinkSync(oldAbs);
      } catch {
        // Existing file may have already been removed outside the app.
      }
    }

    const policy = await getPolicyById(id);
    return NextResponse.json({ success: true, policy });
  } catch (error) {
    const message = error instanceof Error ? error.message : "PDF устгах үед алдаа гарлаа";
    return NextResponse.json({ message }, { status: 500 });
  }
}
