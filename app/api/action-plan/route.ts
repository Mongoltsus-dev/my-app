import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

type ActionPayload = {
  id?: unknown;
  title?: unknown;
  description?: unknown;
  mapped_subcategory?: unknown;
  priority?: unknown;
  risk_reduction_value?: unknown;
  owner?: unknown;
  due_date?: unknown;
  status?: unknown;
  notes?: unknown;
  assigned_user_id?: unknown;
  approved_by?: unknown;
  approve?: unknown; // true = approve, false = reject
};

const LEGACY_DEMO_TITLES = [
  "Deploy MFA across all systems",
  "Implement SIEM and EDR monitoring",
  "Conduct tabletop exercise and update IR plan",
  "Document and test backup/recovery procedures",
];

async function tableExists(tableName: string) {
  const result = await pool.query("SELECT to_regclass($1) AS name", [
    tableName,
  ]);
  return Boolean(result.rows[0]?.name);
}

async function ensureActionPlanSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS action_plan_items (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      mapped_subcategory VARCHAR(50),
      priority VARCHAR(20) DEFAULT 'Medium',
      risk_reduction_value INTEGER DEFAULT 3 CHECK (risk_reduction_value BETWEEN 1 AND 5),
      owner VARCHAR(255),
      due_date DATE,
      status VARCHAR(50) DEFAULT 'Not Started',
      notes TEXT,
      source_type VARCHAR(50),
      source_id INTEGER,
      risk_register_id INTEGER,
      control_recommendation_id INTEGER,
      asset_id INTEGER,
      generated_from VARCHAR(100),
      assigned_user_id INTEGER,
      approved_by INTEGER,
      approved_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);

  const columns = [
    "ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS source_type VARCHAR(50)",
    "ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS source_id INTEGER",
    "ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS risk_register_id INTEGER",
    "ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS control_recommendation_id INTEGER",
    "ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS asset_id INTEGER",
    "ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS generated_from VARCHAR(100)",
    "ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS assigned_user_id INTEGER",
    "ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS approved_by INTEGER",
    "ALTER TABLE action_plan_items ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP",
  ];

  for (const statement of columns) {
    await pool.query(statement);
  }

  await pool.query(
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_action_plan_control_recommendation
        ON action_plan_items(control_recommendation_id)
      WHERE control_recommendation_id IS NOT NULL`,
  );

  // Do not seed demo actions. This page should reflect only real remediation
  // actions created by users or generated from live control recommendations.

  await pool.query(`
    UPDATE action_plan_items
       SET description = 'Холбогдсон эрсдэлийг бууруулахын тулд энэ хяналтыг хэрэгжүүлж, хэрэгжилтийн нотолгоог бүрдүүлнэ.',
           notes = CASE
             WHEN notes LIKE 'Risk score:%' THEN
               replace(replace(notes, 'Risk score:', 'Эрсдэлийн оноо:'), 'Risk level:', 'Эрсдэлийн түвшин:')
             ELSE notes
           END,
           updated_at = NOW()
     WHERE source_type = 'control_recommendation'
       AND (
         description LIKE 'Implement the recommended control%'
         OR description LIKE '%Linked risk:%'
         OR notes LIKE 'Risk score:%'
       )
  `);
}

async function ensureControlRecommendationColumns() {
  if (!(await tableExists("control_recommendations"))) return false;

  const columns = [
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS risk_register_id INTEGER",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS control_id VARCHAR(50)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS control_name VARCHAR(255)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS nist_function VARCHAR(50)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS nist_csf_category VARCHAR(100)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS implementation_priority VARCHAR(20)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS priority VARCHAR(20)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS implementation_status VARCHAR(50) DEFAULT 'Not Started'",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS recommendation_rationale TEXT",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS assigned_to VARCHAR(255)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS target_implementation_date DATE",
  ];

  for (const statement of columns) {
    await pool.query(statement);
  }

  return true;
}

function dueDateExpression(priorityExpression: string) {
  return `CASE COALESCE(${priorityExpression}, 'Medium')
            WHEN 'Critical' THEN CURRENT_DATE + INTERVAL '30 days'
            WHEN 'High' THEN CURRENT_DATE + INTERVAL '60 days'
            WHEN 'Medium' THEN CURRENT_DATE + INTERVAL '90 days'
            ELSE CURRENT_DATE + INTERVAL '120 days'
          END`;
}

async function syncControlRecommendationsToActions() {
  const hasRecommendations = await ensureControlRecommendationColumns();
  if (!hasRecommendations) return 0;

  const hasRiskRegister = await tableExists("risk_register");
  const hasRiskAnalysis = await tableExists("risk_analysis");
  const hasAssets = await tableExists("assets");
  const hasNistControls = await tableExists("nist_controls");
  const priorityExpression =
    "COALESCE(cr.implementation_priority, cr.priority, 'Medium')";
  const statusExpression = "COALESCE(cr.implementation_status, 'Not Started')";
  const controlNameExpression = hasNistControls
    ? "COALESCE(cr.control_name, nc.control_name, cr.control_id, 'Recommended control')"
    : "COALESCE(cr.control_name, cr.control_id, 'Recommended control')";
  const categoryExpression = hasNistControls
    ? "COALESCE(cr.nist_csf_category, rr.nist_csf_category, nc.nist_csf_category, cr.nist_function)"
    : "COALESCE(cr.nist_csf_category, rr.nist_csf_category, cr.nist_function)";

  const joins = [
    hasRiskRegister
      ? "LEFT JOIN risk_register rr ON rr.id = cr.risk_register_id"
      : "LEFT JOIN (SELECT NULL::integer AS id, NULL::text AS risk_title, NULL::integer AS asset_id, NULL::text AS nist_csf_category) rr ON false",
    hasRiskAnalysis
      ? "LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id"
      : "LEFT JOIN (SELECT NULL::integer AS risk_register_id, NULL::integer AS risk_score, NULL::text AS risk_level) ra ON false",
    hasAssets
      ? "LEFT JOIN assets a ON a.id = rr.asset_id"
      : "LEFT JOIN (SELECT NULL::integer AS id, NULL::text AS asset_name) a ON false",
    hasNistControls
      ? "LEFT JOIN nist_controls nc ON nc.control_id = cr.control_id"
      : "LEFT JOIN (SELECT NULL::text AS control_id, NULL::text AS control_name, NULL::text AS nist_csf_category) nc ON false",
  ].join("\n");

  const result = await pool.query(
    `WITH candidate_actions AS (
       SELECT cr.id AS control_recommendation_id,
              rr.id AS risk_register_id,
              a.id AS asset_id,
              ${controlNameExpression} AS control_name,
              ${categoryExpression} AS mapped_subcategory,
              ${priorityExpression} AS priority,
              COALESCE(cr.assigned_to, 'Security Team') AS owner,
              COALESCE(cr.target_implementation_date, ${dueDateExpression(priorityExpression)}::date) AS due_date,
              COALESCE(cr.recommendation_rationale,
                       'Холбогдсон эрсдэлийг бууруулахын тулд санал болгосон хяналтыг хэрэгжүүлэх шаардлагатай.') AS rationale,
              rr.risk_title,
              a.asset_name,
              COALESCE(ra.risk_score, 0) AS risk_score,
              COALESCE(ra.risk_level, '') AS risk_level
         FROM control_recommendations cr
              ${joins}
        WHERE LOWER(${statusExpression}) NOT IN ('implemented', 'complete', 'completed', 'deferred')
     )
     INSERT INTO action_plan_items
       (title, description, mapped_subcategory, priority, risk_reduction_value,
        owner, due_date, status, notes, source_type, source_id,
        risk_register_id, control_recommendation_id, asset_id, generated_from,
        created_at, updated_at)
     SELECT LEFT(control_name, 255),
            CONCAT_WS(' ',
              rationale,
              CASE WHEN risk_title IS NOT NULL THEN 'Холбогдсон эрсдэл: ' || risk_title || '.' END,
              CASE WHEN asset_name IS NOT NULL THEN 'Хөрөнгө: ' || asset_name || '.' END
            ),
            mapped_subcategory,
            priority,
            CASE priority
              WHEN 'Critical' THEN 5
              WHEN 'High' THEN 4
              WHEN 'Medium' THEN 3
              ELSE 2
            END,
            owner,
            due_date,
            'Not Started',
            CONCAT_WS(' ',
              CASE WHEN risk_score > 0 THEN 'Risk score: ' || risk_score || '.' END,
              CASE WHEN risk_level <> '' THEN 'Risk level: ' || risk_level || '.' END
            ),
            'control_recommendation',
            control_recommendation_id,
            risk_register_id,
            control_recommendation_id,
            asset_id,
            'recommendation-sync',
            NOW(),
            NOW()
       FROM candidate_actions ca
      WHERE NOT EXISTS (
        SELECT 1
          FROM action_plan_items api
         WHERE api.control_recommendation_id = ca.control_recommendation_id
      )
      RETURNING id`,
  );

  return result.rows.length;
}

export async function GET() {
  try {
    await ensureActionPlanSchema();
    const syncedCount = await syncControlRecommendationsToActions();
    const result = await pool.query(
      `SELECT a.id, a.title, a.description, a.mapped_subcategory, a.priority,
              a.risk_reduction_value, a.owner, a.due_date, a.status, a.notes,
              a.source_type, a.source_id, a.risk_register_id,
              a.control_recommendation_id, a.asset_id, a.generated_from,
              a.assigned_user_id, a.approved_by, a.approved_at,
              a.created_at, a.updated_at,
              rr.risk_code,
              rr.risk_title,
              COALESCE(ra.inherent_risk_score, ra.risk_score, 0) AS risk_score,
              COALESCE(ra.inherent_risk_level, ra.risk_level, '') AS risk_level,
              asset.asset_name,
              asset.asset_type,
              u.full_name  AS assigned_user_name,
              u.email      AS assigned_user_email,
              ap.full_name AS approved_by_name
         FROM action_plan_items a
         LEFT JOIN risk_register rr ON rr.id = a.risk_register_id
         LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id
         LEFT JOIN assets asset ON asset.id = COALESCE(a.asset_id, rr.asset_id)
         LEFT JOIN users u  ON u.id  = a.assigned_user_id
         LEFT JOIN users ap ON ap.id = a.approved_by
        WHERE NOT (
          a.source_type IS NULL
          AND a.generated_from IS NULL
          AND a.risk_register_id IS NULL
          AND a.control_recommendation_id IS NULL
          AND a.title = ANY($1::text[])
        )
        ORDER BY
          CASE a.status
            WHEN 'Done'     THEN 4
            WHEN 'Accepted' THEN 5
            ELSE 1
          END,
          a.risk_reduction_value DESC,
          CASE a.priority
            WHEN 'Critical' THEN 1
            WHEN 'High'     THEN 2
            WHEN 'Medium'   THEN 3
            WHEN 'Low'      THEN 4
            ELSE 5
          END,
          a.created_at DESC`,
      [LEGACY_DEMO_TITLES],
    );

    return NextResponse.json({
      success: true,
      syncedCount,
      actions: result.rows,
    });
  } catch (error) {
    console.error("Action plan fetch error:", error);
    const message =
      error instanceof Error ? error.message : "Failed to fetch action plan";
    return NextResponse.json({ message }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    await ensureActionPlanSchema();
    const body = (await req.json()) as ActionPayload;
    const title = toStringValue(body.title);

    if (!title) {
      return NextResponse.json(
        { message: "Action title is required" },
        { status: 400 },
      );
    }

    const result = await pool.query(
      `INSERT INTO action_plan_items
         (title, description, mapped_subcategory, priority, risk_reduction_value,
          owner, due_date, status, notes, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
       RETURNING id, title, description, mapped_subcategory, priority,
                 risk_reduction_value, owner, due_date, status, notes,
                 created_at, updated_at`,
      [
        title,
        toStringValue(body.description),
        toStringValue(body.mapped_subcategory),
        toStringValue(body.priority) || "Medium",
        clampReduction(body.risk_reduction_value, 3),
        toStringValue(body.owner),
        toDateOrNull(body.due_date),
        toStringValue(body.status) || "Not Started",
        toStringValue(body.notes),
      ],
    );

    return NextResponse.json(
      { success: true, action: result.rows[0] },
      { status: 201 },
    );
  } catch (error) {
    console.error("Action plan create error:", error);
    const message =
      error instanceof Error ? error.message : "Failed to create action item";
    return NextResponse.json({ message }, { status: 500 });
  }
}

export async function PATCH(req: NextRequest) {
  try {
    await ensureActionPlanSchema();
    const body = (await req.json()) as ActionPayload;
    const id = Number(body.id);

    if (!Number.isInteger(id) || id <= 0) {
      return NextResponse.json(
        { message: "A valid action id is required" },
        { status: 400 },
      );
    }

    // Approval / reject shortcut
    if (body.approve !== undefined) {
      const isApprove = Boolean(body.approve);
      const approvedById = body.approved_by ? Number(body.approved_by) : null;
      await pool.query(
        `UPDATE action_plan_items
            SET status      = $1,
                approved_by = $2,
                approved_at = $3,
                updated_at  = NOW()
          WHERE id = $4`,
        [
          isApprove ? "Accepted" : "In Progress",
          isApprove ? approvedById : null,
          isApprove ? new Date() : null,
          id,
        ],
      );
      const res = await pool.query(
        `SELECT a.*, u.full_name AS assigned_user_name, u.email AS assigned_user_email,
                ap.full_name AS approved_by_name
           FROM action_plan_items a
           LEFT JOIN users u  ON u.id  = a.assigned_user_id
           LEFT JOIN users ap ON ap.id = a.approved_by
          WHERE a.id = $1`,
        [id],
      );
      return NextResponse.json({ success: true, action: res.rows[0] });
    }

    const assignedUserId =
      body.assigned_user_id === null
        ? null
        : body.assigned_user_id !== undefined
          ? Number(body.assigned_user_id)
          : undefined;

    const result = await pool.query(
      `UPDATE action_plan_items
          SET title = COALESCE($1, title),
              description = COALESCE($2, description),
              mapped_subcategory = COALESCE($3, mapped_subcategory),
              priority = COALESCE($4, priority),
              risk_reduction_value = COALESCE($5, risk_reduction_value),
              owner = COALESCE($6, owner),
              due_date = COALESCE($7, due_date),
              status = COALESCE($8, status),
              notes = COALESCE($9, notes),
              assigned_user_id = COALESCE($10, assigned_user_id),
              updated_at = NOW()
        WHERE id = $11
        RETURNING id`,
      [
        toStringValue(body.title),
        toStringValue(body.description),
        toStringValue(body.mapped_subcategory),
        toStringValue(body.priority),
        body.risk_reduction_value === undefined
          ? null
          : clampReduction(body.risk_reduction_value, 3),
        toStringValue(body.owner),
        toDateOrNull(body.due_date),
        toStringValue(body.status),
        toStringValue(body.notes),
        assignedUserId ?? null,
        id,
      ],
    );

    if (result.rows.length === 0) {
      return NextResponse.json(
        { message: "Action not found" },
        { status: 404 },
      );
    }

    const updated = await pool.query(
      `SELECT a.*, u.full_name AS assigned_user_name, u.email AS assigned_user_email,
              ap.full_name AS approved_by_name
         FROM action_plan_items a
         LEFT JOIN users u  ON u.id  = a.assigned_user_id
         LEFT JOIN users ap ON ap.id = a.approved_by
        WHERE a.id = $1`,
      [id],
    );

    return NextResponse.json({ success: true, action: updated.rows[0] });
  } catch (error) {
    console.error("Action plan update error:", error);
    const message =
      error instanceof Error ? error.message : "Failed to update action item";
    return NextResponse.json({ message }, { status: 500 });
  }
}

function toStringValue(value: unknown) {
  if (value === undefined || value === null) return null;
  const trimmed = String(value).trim();
  return trimmed.length > 0 ? trimmed : null;
}

function clampReduction(value: unknown, fallback: number) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(5, Math.max(1, Math.trunc(parsed)));
}

function toDateOrNull(value: unknown) {
  const raw = toStringValue(value);
  if (!raw) return null;
  return /^\d{4}-\d{2}-\d{2}$/.test(raw) ? raw : null;
}
