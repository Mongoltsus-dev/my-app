import { pool } from "@/lib/db";
import { persistControlEffectivenessResidual } from "@/lib/residual-risk";
import { NextRequest, NextResponse } from "next/server";

// ─── Schema bootstrap ─────────────────────────────────────────────────────────
//
// The nist_controls table is now seeded from scripts/seed-nist-800-53.sql (NIST
// SP 800-53 Rev 5 base controls). This bootstrap creates the table on a fresh
// DB but does NOT seed any data — run the seed script for that.

async function ensureNistControls() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS nist_controls (
      id                  SERIAL PRIMARY KEY,
      control_id          VARCHAR(50)  UNIQUE,
      domain              VARCHAR(100),
      control_name        VARCHAR(255),
      description         TEXT,
      nist_csf_function   VARCHAR(50),
      nist_csf_category   VARCHAR(50),
      implementation_note TEXT,
      priority            INT          DEFAULT 3,
      is_active           BOOLEAN      DEFAULT TRUE,
      created_at          TIMESTAMP    DEFAULT NOW()
    )
  `);
}

async function tableExists(tableName: string) {
  const result = await pool.query("SELECT to_regclass($1) AS name", [tableName]);
  return Boolean(result.rows[0]?.name);
}

async function columnExists(tableName: string, columnName: string) {
  const result = await pool.query(
    `SELECT 1
       FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name   = $1
        AND column_name  = $2
      LIMIT 1`,
    [tableName, columnName],
  );
  return result.rows.length > 0;
}

async function ensureControlRecommendations() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS control_recommendations (
      id SERIAL PRIMARY KEY,
      risk_register_id INTEGER,
      control_name VARCHAR(255),
      nist_function VARCHAR(50),
      priority VARCHAR(30),
      implementation_status VARCHAR(30) DEFAULT 'not_started',
      assigned_to VARCHAR(255),
      approval_status VARCHAR(30) DEFAULT 'pending',
      approved_by VARCHAR(255),
      approved_at TIMESTAMP,
      approval_notes TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);
  for (const ddl of [
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS risk_register_id INTEGER",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS control_name VARCHAR(255)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS nist_function VARCHAR(50)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS priority VARCHAR(30)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS implementation_status VARCHAR(30) DEFAULT 'not_started'",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS assigned_to VARCHAR(255)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS approval_status VARCHAR(30) DEFAULT 'pending'",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS approved_by VARCHAR(255)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS approval_notes TEXT",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()",
  ]) {
    await pool.query(ddl);
  }
}

// ─── Types ────────────────────────────────────────────────────────────────────

type NistControlRow = {
  id: number;
  control_id: string;
  domain: string | null;
  control_name: string | null;
  description: string | null;
  nist_csf_function: string | null;
  nist_csf_category: string | null;
  implementation_note: string | null;
  priority: number | null;
};

type RecommendationRow = {
  id: number;
  control_id: string | null;
  control_name: string | null;
  nist_function: string | null;
  nist_csf_function: string | null;
  nist_csf_category: string | null;
  implementation_priority: string | null;
  priority: string | null;
  implementation_status: string | null;
  assigned_to: string | null;
  risk_register_id: number | null;
  risk_title: string | null;
  asset_name: string | null;
  risk_score: number | null;
  risk_level: string | null;
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

// Control-effectiveness residual model lives in lib/residual-risk.ts so the
// formula and 5×5 threshold bands have a single definition.
async function recomputeCE(riskRegisterId: number) {
  await persistControlEffectivenessResidual(riskRegisterId);
}

// ─── GET ──────────────────────────────────────────────────────────────────────

export async function GET(req: NextRequest) {
  const riskId = req.nextUrl.searchParams.get("risk_id");

  // Fast path: return only recs for one risk (no full NIST load)
  if (riskId) {
    try {
      await ensureControlRecommendations();
      const { rows } = await pool.query(
        `SELECT id, control_id, control_name, nist_function, priority, implementation_status, assigned_to,
                evidence_file_path, evidence_original_name, evidence_uploaded_at,
                approval_status, approved_by, approved_at, approval_notes
           FROM control_recommendations
          WHERE risk_register_id = $1
          ORDER BY id ASC`,
        [Number(riskId)],
      );
      return NextResponse.json({ recommendations: rows });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Internal server error";
      return NextResponse.json({ message }, { status: 500 });
    }
  }

  // Management view: all recs with risk + asset + catalog info
  if (req.nextUrl.searchParams.get("all") === "true") {
    try {
      const { rows } = await pool.query(
        `SELECT cr.id, cr.control_name, cr.nist_function, cr.priority,
                cr.implementation_status, cr.assigned_to,
                cr.evidence_file_path, cr.evidence_original_name, cr.evidence_uploaded_at,
                cr.approval_status, cr.approved_by, cr.approved_at, cr.approval_notes,
                cr.risk_register_id, cr.created_at,
                rr.risk_title, rr.risk_code,
                ra.inherent_risk_score, ra.inherent_risk_level,
                a.asset_name,
                nc.domain            AS catalog_domain,
                nc.nist_csf_category AS catalog_category_code,
                nc.implementation_note
           FROM control_recommendations cr
           LEFT JOIN risk_register rr ON rr.id = cr.risk_register_id
           LEFT JOIN risk_analysis  ra ON ra.risk_register_id = cr.risk_register_id
           LEFT JOIN assets          a ON a.id = rr.asset_id
           LEFT JOIN nist_controls  nc ON nc.control_id = cr.control_id
          ORDER BY cr.approval_status ASC, cr.id DESC`,
      );
      return NextResponse.json({ recommendations: rows });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Internal server error";
      return NextResponse.json({ message }, { status: 500 });
    }
  }

  try {
    await ensureNistControls();

    const controlsResult = await pool.query<NistControlRow>(
      `SELECT id, control_id, domain, control_name, description,
              nist_csf_function, nist_csf_category, implementation_note, priority
         FROM nist_controls
        WHERE COALESCE(is_active, true) = true
        ORDER BY nist_csf_function, nist_csf_category, control_id`,
    );

    const hasRecommendations = await tableExists("control_recommendations");
    if (!hasRecommendations) {
      return NextResponse.json({
        controls: controlsResult.rows,
        recommendations: [],
      });
    }

    const [
      hasControlName, hasNistFunction, hasPriority,
      hasImplementationPriority, hasImplementationStatus,
      hasAssignedTo, hasControlId, hasRiskRegisterId,
    ] = await Promise.all([
      columnExists("control_recommendations", "control_name"),
      columnExists("control_recommendations", "nist_function"),
      columnExists("control_recommendations", "priority"),
      columnExists("control_recommendations", "implementation_priority"),
      columnExists("control_recommendations", "implementation_status"),
      columnExists("control_recommendations", "assigned_to"),
      columnExists("control_recommendations", "control_id"),
      columnExists("control_recommendations", "risk_register_id"),
    ]);

    const hasRiskRegister = await tableExists("risk_register");
    const hasRiskAnalysis  = await tableExists("risk_analysis");
    const hasAssets        = await tableExists("assets");

    const [
      hasRiskTitle, hasRiskFunction, hasRiskCategory,
      hasRiskAssetId, hasRaRiskRegisterId, hasRaRiskId,
      hasRaScore, hasRaLevel, hasAssetName,
    ] = await Promise.all([
      hasRiskRegister ? columnExists("risk_register", "risk_title")        : Promise.resolve(false),
      hasRiskRegister ? columnExists("risk_register", "nist_csf_function") : Promise.resolve(false),
      hasRiskRegister ? columnExists("risk_register", "nist_csf_category") : Promise.resolve(false),
      hasRiskRegister ? columnExists("risk_register", "asset_id")          : Promise.resolve(false),
      hasRiskAnalysis ? columnExists("risk_analysis",  "risk_register_id") : Promise.resolve(false),
      hasRiskAnalysis ? columnExists("risk_analysis",  "risk_id")          : Promise.resolve(false),
      hasRiskAnalysis ? columnExists("risk_analysis",  "risk_score")       : Promise.resolve(false),
      hasRiskAnalysis ? columnExists("risk_analysis",  "risk_level")       : Promise.resolve(false),
      hasAssets       ? columnExists("assets",         "asset_name")       : Promise.resolve(false),
    ]);

    const riskRegisterJoin =
      hasRiskRegister && hasRiskRegisterId
        ? "LEFT JOIN risk_register rr ON rr.id = cr.risk_register_id"
        : "";
    const riskAnalysisJoin =
      hasRiskAnalysis && hasRiskRegisterId && hasRaRiskRegisterId
        ? "LEFT JOIN risk_analysis ra ON ra.risk_register_id = cr.risk_register_id"
        : hasRiskAnalysis && hasRiskRegisterId && hasRaRiskId
        ? "LEFT JOIN risk_analysis ra ON ra.risk_id = cr.risk_register_id"
        : "";
    const assetsJoin =
      hasAssets && hasAssetName && hasRiskRegister && hasRiskRegisterId && hasRiskAssetId
        ? "LEFT JOIN assets a ON a.id = rr.asset_id"
        : "";

    const recommendationsResult = await pool.query<RecommendationRow>(
      `SELECT cr.id,
              ${hasControlId            ? "cr.control_id"               : "NULL::varchar"}  AS control_id,
              ${hasControlName          ? "cr.control_name"             : "NULL::varchar"}  AS control_name,
              ${hasNistFunction         ? "cr.nist_function"            : "NULL::varchar"}  AS nist_function,
              ${hasRiskFunction         ? "rr.nist_csf_function"        : "NULL::varchar"}  AS nist_csf_function,
              ${hasRiskCategory         ? "rr.nist_csf_category"        : "NULL::varchar"}  AS nist_csf_category,
              ${hasImplementationPriority ? "cr.implementation_priority" : "NULL::varchar"} AS implementation_priority,
              ${hasPriority             ? "cr.priority"                 : "NULL::varchar"}  AS priority,
              ${hasImplementationStatus ? "cr.implementation_status"    : "NULL::varchar"}  AS implementation_status,
              ${hasAssignedTo           ? "cr.assigned_to"              : "NULL::varchar"}  AS assigned_to,
              ${hasRiskRegisterId       ? "cr.risk_register_id"         : "NULL::integer"}  AS risk_register_id,
              ${hasRiskTitle            ? "rr.risk_title"               : "NULL::varchar"}  AS risk_title,
              ${assetsJoin              ? "a.asset_name"                : "NULL::varchar"}  AS asset_name,
              ${riskAnalysisJoin && hasRaScore ? "ra.risk_score"        : "NULL::integer"}  AS risk_score,
              ${riskAnalysisJoin && hasRaLevel ? "ra.risk_level"        : "NULL::varchar"}  AS risk_level
         FROM control_recommendations cr
              ${riskRegisterJoin}
              ${riskAnalysisJoin}
              ${assetsJoin}
        ORDER BY cr.id DESC`,
    );

    return NextResponse.json({
      controls: controlsResult.rows,
      recommendations: recommendationsResult.rows,
    });
  } catch (error) {
    console.error("Controls API error:", error);
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ message }, { status: 500 });
  }
}

// ─── POST — create control rec ────────────────────────────────────────────────

export async function POST(req: NextRequest) {
  try {
    await ensureControlRecommendations();
    const { risk_register_id, control_name, nist_function, priority } =
      await req.json();
    if (!risk_register_id || !control_name) {
      return NextResponse.json({ message: "risk_register_id and control_name required" }, { status: 400 });
    }
    const { rows } = await pool.query(
      `INSERT INTO control_recommendations (risk_register_id, control_name, nist_function, priority, implementation_status)
       VALUES ($1, $2, $3, $4, 'not_started')
       RETURNING id, control_name, nist_function, priority, implementation_status, assigned_to`,
      [risk_register_id, control_name, nist_function ?? null, priority ?? "Medium"],
    );
    await recomputeCE(Number(risk_register_id));
    return NextResponse.json({ recommendation: rows[0] }, { status: 201 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ message }, { status: 500 });
  }
}

// ─── PATCH — update status or approval ───────────────────────────────────────

export async function PATCH(req: NextRequest) {
  try {
    const body = await req.json();
    const { id } = body;
    if (!id) return NextResponse.json({ message: "id required" }, { status: 400 });

    // Approval update
    if (body.approval_status !== undefined) {
      const { approval_status, approved_by, approval_notes } = body;
      const { rows } = await pool.query(
        `UPDATE control_recommendations
            SET approval_status = $1,
                approved_by     = $2,
                approved_at     = CASE WHEN $1 = 'approved' THEN NOW() ELSE NULL END,
                approval_notes  = $3
          WHERE id = $4
          RETURNING id, risk_register_id, approval_status, approved_by, approved_at, approval_notes`,
        [approval_status, approved_by ?? null, approval_notes ?? null, id],
      );
      if (rows.length === 0) return NextResponse.json({ message: "Not found" }, { status: 404 });
      return NextResponse.json({ recommendation: rows[0] });
    }

    // Status update
    const { implementation_status } = body;
    if (!implementation_status) {
      return NextResponse.json({ message: "implementation_status or approval_status required" }, { status: 400 });
    }
    const { rows } = await pool.query(
      `UPDATE control_recommendations
          SET implementation_status = $1
        WHERE id = $2
        RETURNING id, risk_register_id, control_name, nist_function, priority, implementation_status, assigned_to`,
      [implementation_status, id],
    );
    if (rows.length === 0) {
      return NextResponse.json({ message: "Not found" }, { status: 404 });
    }
    await recomputeCE(Number(rows[0].risk_register_id));
    return NextResponse.json({ recommendation: rows[0] });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ message }, { status: 500 });
  }
}

// ─── DELETE — remove control rec ─────────────────────────────────────────────

export async function DELETE(req: NextRequest) {
  try {
    const id = req.nextUrl.searchParams.get("id");
    if (!id) return NextResponse.json({ message: "id required" }, { status: 400 });
    const { rows } = await pool.query(
      `DELETE FROM control_recommendations WHERE id = $1 RETURNING risk_register_id`,
      [Number(id)],
    );
    if (rows.length === 0) return NextResponse.json({ message: "Not found" }, { status: 404 });
    await recomputeCE(Number(rows[0].risk_register_id));
    return NextResponse.json({ ok: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ message }, { status: 500 });
  }
}
