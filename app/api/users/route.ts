import { pool } from "@/lib/db";
import bcrypt from "bcrypt";
import { NextRequest, NextResponse } from "next/server";

async function ensureUsersSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      full_name VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role_id INTEGER NOT NULL DEFAULT 2,
      status VARCHAR(50) NOT NULL DEFAULT 'active',
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()`,
  );
  await pool.query(
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()`,
  );
  // Case-insensitive uniqueness is best-effort: if the table already contains
  // emails that collide only by case, the index build fails. That must not take
  // down every users GET/POST — log and continue (the POST handler still does
  // its own duplicate check below).
  try {
    await pool.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique_idx ON users (LOWER(email))`,
    );
  } catch (err) {
    console.warn(
      "Could not create users_email_unique_idx (likely case-duplicate emails):",
      err instanceof Error ? err.message : err,
    );
  }
}

// GET — бүх хэрэглэгчдийн жагсаалт
export async function GET() {
  try {
    await ensureUsersSchema();
    const result = await pool.query(
      `SELECT id, full_name, email, role_id, status, created_at, updated_at
         FROM users
        ORDER BY created_at DESC`,
    );
    return NextResponse.json({ users: result.rows });
  } catch (error) {
    console.error("Users fetch error:", error);
    return NextResponse.json({ message: "Хэрэглэгчид татаж чадсангүй" }, { status: 500 });
  }
}

// POST — шинэ хэрэглэгч үүсгэх
export async function POST(req: NextRequest) {
  try {
    await ensureUsersSchema();
    const { full_name, email, password, role_id, status } = await req.json();

    if (!full_name || !email || !password) {
      return NextResponse.json({ message: "Нэр, имэйл, нууц үг шаардлагатай" }, { status: 400 });
    }
    if (String(password).length < 6) {
      return NextResponse.json({ message: "Нууц үг хамгийн багадаа 6 тэмдэгт байна" }, { status: 400 });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const normalizedRole = [1, 2, 3].includes(Number(role_id))
      ? Number(role_id)
      : 3;
    const normalizedStatus = ["active", "inactive", "suspended"].includes(
      String(status),
    )
      ? String(status)
      : "active";

    const existing = await pool.query("SELECT id FROM users WHERE LOWER(email) = LOWER($1)", [
      normalizedEmail,
    ]);
    if (existing.rows.length > 0) {
      return NextResponse.json({ message: "Энэ имэйл аль хэдийн бүртгэлтэй байна" }, { status: 409 });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (full_name, email, password_hash, role_id, status)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, full_name, email, role_id, status, created_at`,
      [full_name.trim(), normalizedEmail, hashedPassword, normalizedRole, normalizedStatus],
    );

    return NextResponse.json({ user: result.rows[0] }, { status: 201 });
  } catch (error) {
    console.error("User create error:", error);
    return NextResponse.json({ message: "Хэрэглэгч үүсгэж чадсангүй" }, { status: 500 });
  }
}

// PUT — хэрэглэгч засах (дүр, статус, нэр)
export async function PUT(req: NextRequest) {
  try {
    await ensureUsersSchema();
    const { id, full_name, role_id, status, password } = await req.json();

    if (!id) {
      return NextResponse.json({ message: "Хэрэглэгчийн ID шаардлагатай" }, { status: 400 });
    }

    if (password && password.length > 0) {
      const hashedPassword = await bcrypt.hash(password, 10);
      await pool.query(
        `UPDATE users SET full_name=$1, role_id=$2, status=$3, password_hash=$4, updated_at=NOW() WHERE id=$5`,
        [full_name, role_id, status, hashedPassword, id],
      );
    } else {
      await pool.query(
        `UPDATE users SET full_name=$1, role_id=$2, status=$3, updated_at=NOW() WHERE id=$4`,
        [full_name, role_id, status, id],
      );
    }

    const result = await pool.query(
      `SELECT id, full_name, email, role_id, status, created_at, updated_at FROM users WHERE id=$1`,
      [id],
    );
    return NextResponse.json({ user: result.rows[0] });
  } catch (error) {
    console.error("User update error:", error);
    return NextResponse.json({ message: "Хэрэглэгч шинэчилж чадсангүй" }, { status: 500 });
  }
}

// DELETE — хэрэглэгч устгах
export async function DELETE(req: NextRequest) {
  try {
    await ensureUsersSchema();
    const { searchParams } = new URL(req.url);
    const id = searchParams.get("id");

    if (!id) {
      return NextResponse.json({ message: "ID шаардлагатай" }, { status: 400 });
    }

    await pool.query("DELETE FROM users WHERE id=$1", [id]);
    return NextResponse.json({ message: "Хэрэглэгч устгагдлаа", deletedId: Number(id) });
  } catch (error) {
    console.error("User delete error:", error);
    return NextResponse.json({ message: "Хэрэглэгч устгаж чадсангүй" }, { status: 500 });
  }
}
