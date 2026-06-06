import { pool } from "@/lib/db";
import { persistControlEffectivenessResidual } from "@/lib/residual-risk";
import { NextRequest, NextResponse } from "next/server";

async function ensureColumns() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS control_recommendations (
      id SERIAL PRIMARY KEY,
      risk_register_id INTEGER,
      control_name VARCHAR(255),
      nist_function VARCHAR(50),
      priority VARCHAR(30),
      implementation_status VARCHAR(30) DEFAULT 'not_started',
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);
  for (const ddl of [
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS risk_register_id INTEGER",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS control_name VARCHAR(255)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS nist_function VARCHAR(50)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS priority VARCHAR(30)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS control_id VARCHAR(50)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS domain VARCHAR(255)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS implementation_priority VARCHAR(30)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS implementation_status VARCHAR(30) DEFAULT 'not_started'",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()",
  ]) {
    await pool.query(ddl);
  }
}

async function tableExists(tableName: string) {
  const result = await pool.query("SELECT to_regclass($1) AS name", [
    tableName,
  ]);
  return Boolean(result.rows[0]?.name);
}

// Control-effectiveness residual model lives in lib/residual-risk.ts so the
// formula and 5×5 threshold bands have a single definition. Saving the selected
// control must not fail just because residual columns are missing on an older DB.
async function recomputeCE(riskRegisterId: number) {
  if (!(await tableExists("public.risk_analysis"))) return;
  try {
    await persistControlEffectivenessResidual(riskRegisterId);
  } catch {
    // Residual calculation is best-effort; ignore on older schemas.
  }
}

async function findControl(controlId: string): Promise<{
  control_name: string | null;
  domain: string | null;
  nist_function: string | null;
  priority: string | null;
}> {
  if (await tableExists("public.nist_controls")) {
    try {
      const result = await pool.query(
        `SELECT control_name,
                domain,
                nist_csf_function AS nist_function,
                priority::text AS priority
           FROM nist_controls
          WHERE control_id = $1
          LIMIT 1`,
        [controlId],
      );
      if (result.rows[0]) return result.rows[0];
    } catch {
      // Fall through to the request payload fallback.
    }
  }

  return {
    control_name: null,
    domain: null,
    nist_function: null,
    priority: null,
  };
}

// POST – link a user-selected control to a risk
export async function POST(req: NextRequest) {
  try {
    await ensureColumns();
    const {
      risk_register_id,
      control_id,
      control_name,
      nist_function,
      domain,
      priority,
      implementation_status,
    } =
      await req.json();

    if (!risk_register_id || !control_id) {
      return NextResponse.json(
        { error: "risk_register_id and control_id are required" },
        { status: 400 },
      );
    }

    const catalogControl = await findControl(control_id);
    const resolvedControlName =
      control_name ?? catalogControl.control_name ?? "Recommended control";
    const resolvedDomain = domain ?? catalogControl.domain ?? null;
    const resolvedFunction =
      nist_function ?? catalogControl.nist_function ?? null;
    const resolvedPriority = priority ?? catalogControl.priority ?? "Medium";
    const resolvedStatus = implementation_status ?? "not_started";
    const formattedName = `${control_id} – ${resolvedControlName}`;

    // Idempotent: return existing row if already linked
    const existing = await pool.query(
      `SELECT id FROM control_recommendations
        WHERE risk_register_id = $1 AND (control_id = $2 OR control_name = $3)`,
      [risk_register_id, control_id, formattedName],
    );
    if (existing.rows.length > 0) {
      const result = await pool.query(
        `UPDATE control_recommendations
            SET control_id              = $2,
                domain                  = COALESCE($3, domain),
                control_name            = $4,
                nist_function           = COALESCE($5, nist_function),
                priority                = $6,
                implementation_priority = $6,
                implementation_status   = $7,
                updated_at              = NOW()
          WHERE id = $1
          RETURNING id, control_id, control_name, implementation_status`,
        [
          existing.rows[0].id,
          control_id,
          resolvedDomain,
          formattedName,
          resolvedFunction,
          resolvedPriority,
          resolvedStatus,
        ],
      );
      await recomputeCE(Number(risk_register_id));
      return NextResponse.json({ rec: result.rows[0] });
    }

    const result = await pool.query(
      `INSERT INTO control_recommendations
         (risk_register_id, control_id, domain, control_name, nist_function,
          priority, implementation_priority, implementation_status, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $6, $7, NOW(), NOW())
       RETURNING id`,
      [
        risk_register_id,
        control_id,
        resolvedDomain,
        formattedName,
        resolvedFunction,
        resolvedPriority,
        resolvedStatus,
      ],
    );

    await recomputeCE(Number(risk_register_id));
    return NextResponse.json({ rec: result.rows[0] });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Failed to save control";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

// DELETE – remove a control recommendation by its row id
export async function DELETE(req: NextRequest) {
  try {
    const id = req.nextUrl.searchParams.get("id");
    if (!id) {
      return NextResponse.json({ error: "id is required" }, { status: 400 });
    }
    await pool.query("DELETE FROM control_recommendations WHERE id = $1", [
      Number(id),
    ]);
    return NextResponse.json({ success: true });
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : "Failed to remove control";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
