import { pool } from "@/lib/db";
import { ensureBusinessProcessSchema } from "@/lib/business-processes-schema";
import { NextRequest, NextResponse } from "next/server";

/**
 * Business Process registry — the "Business Process → Assets → Data → Owner → Criticality"
 * mapping that lets the org know which business functions are affected by an asset
 * compromise or control gap.
 *
 * GET    /api/business-processes        — list all + linked asset/risk counts
 * POST   /api/business-processes        — create (body may include asset_ids[])
 * PATCH  /api/business-processes        — update (body.id required)
 * DELETE /api/business-processes?id=X   — delete
 */

const FUNCTION_OPTIONS = [
  "Operations",
  "Sales",
  "Finance",
  "HR",
  "IT",
  "Customer Service",
  "Compliance",
  "Marketing",
  "Procurement",
  "Other",
];

const CRITICALITY_OPTIONS = ["Critical", "High", "Medium", "Low"];

const DATA_CLASS_OPTIONS = ["Public", "Internal", "Confidential", "Restricted"];

const DEPENDENCY_TYPES = ["Primary", "Supporting", "Optional"];

async function generateProcessCode(): Promise<string> {
  const r = await pool.query(
    `SELECT COALESCE(MAX(substring(process_code FROM '^BP-([0-9]+)$')::integer), 0) + 1 AS n
       FROM business_processes WHERE process_code ~ '^BP-[0-9]+$'`,
  );
  return `BP-${String(Number(r.rows[0]?.n ?? 1)).padStart(3, "0")}`;
}

const toStr = (v: unknown): string | null => {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  return s.length ? s : null;
};
const toNum = (v: unknown): number | null => {
  if (v === undefined || v === null || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};

async function tableExists(tableName: string) {
  const result = await pool.query(
    "SELECT to_regclass($1) IS NOT NULL AS exists",
    [`public.${tableName}`],
  );
  return Boolean(result.rows[0]?.exists);
}

async function columnExists(tableName: string, columnName: string) {
  const result = await pool.query(
    `SELECT 1
       FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = $1
        AND column_name = $2
      LIMIT 1`,
    [tableName, columnName],
  );
  return result.rows.length > 0;
}

// ─────────────────────────────────────────────────────────────── GET ────

export async function GET() {
  try {
    await ensureBusinessProcessSchema();
    const hasAssets = await tableExists("assets");
    const hasRiskRegister = await tableExists("risk_register");
    const hasRiskAnalysis =
      hasAssets && hasRiskRegister && (await tableExists("risk_analysis"));
    const hasRiskAnalysisRegisterId =
      hasRiskAnalysis &&
      (await columnExists("risk_analysis", "risk_register_id"));
    const hasRiskAnalysisRiskId =
      hasRiskAnalysis && (await columnExists("risk_analysis", "risk_id"));
    const hasRiskAnalysisInherentScore =
      hasRiskAnalysis &&
      (await columnExists("risk_analysis", "inherent_risk_score"));
    const hasRiskAnalysisScore =
      hasRiskAnalysis && (await columnExists("risk_analysis", "risk_score"));
    const hasRiskAnalysisInherentLevel =
      hasRiskAnalysis &&
      (await columnExists("risk_analysis", "inherent_risk_level"));
    const hasRiskAnalysisLevel =
      hasRiskAnalysis && (await columnExists("risk_analysis", "risk_level"));
    const hasRiskAnalysisResidualScore =
      hasRiskAnalysis &&
      (await columnExists("risk_analysis", "residual_risk_score"));
    const hasRiskAnalysisResidualLevel =
      hasRiskAnalysis &&
      (await columnExists("risk_analysis", "residual_risk_level"));
    const hasRiskCode =
      hasRiskRegister && (await columnExists("risk_register", "risk_code"));
    const hasRiskId =
      hasRiskRegister && (await columnExists("risk_register", "risk_id"));
    const riskAnalysisJoinSql = hasRiskAnalysisRegisterId
      ? "LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id"
      : hasRiskAnalysisRiskId
        ? "LEFT JOIN risk_analysis ra ON ra.risk_id = rr.id"
        : "";
    const inherentRiskScoreColumn = hasRiskAnalysisInherentScore
      ? "ra.inherent_risk_score"
      : "NULL::integer";
    const riskScoreColumn = hasRiskAnalysisScore
      ? "ra.risk_score"
      : "NULL::integer";
    const inherentRiskLevelColumn = hasRiskAnalysisInherentLevel
      ? "ra.inherent_risk_level"
      : "NULL::text";
    const riskLevelColumn = hasRiskAnalysisLevel
      ? "ra.risk_level"
      : "NULL::text";
    const riskScoreExpr = hasRiskAnalysis
      ? `COALESCE(${inherentRiskScoreColumn}, ${riskScoreColumn})`
      : "NULL::integer";
    const residualScoreExpr = hasRiskAnalysis
      ? hasRiskAnalysisResidualScore
        ? "ra.residual_risk_score"
        : "NULL::integer"
      : "NULL::integer";
    const riskLevelExpr = hasRiskAnalysis
      ? `COALESCE(
          ${inherentRiskLevelColumn},
          ${riskLevelColumn},
          CASE
            WHEN ${riskScoreExpr} >= 17 THEN 'Critical'
            WHEN ${riskScoreExpr} >= 10 THEN 'High'
            WHEN ${riskScoreExpr} >= 5 THEN 'Medium'
            WHEN ${riskScoreExpr} >= 1 THEN 'Low'
            ELSE NULL
          END
        )`
      : "NULL::text";
    const residualLevelExpr = hasRiskAnalysis
      ? hasRiskAnalysisResidualLevel
        ? "ra.residual_risk_level"
        : "NULL::text"
      : "NULL::text";
    const riskCodeExpr = hasRiskCode
      ? hasRiskId
        ? "COALESCE(rr.risk_code::text, rr.risk_id::text, 'RSK-' || rr.id::text)"
        : "COALESCE(rr.risk_code::text, 'RSK-' || rr.id::text)"
      : hasRiskId
        ? "COALESCE(rr.risk_id::text, 'RSK-' || rr.id::text)"
        : "'RSK-' || rr.id::text";
    const riskSourceSql =
      hasAssets && hasRiskRegister
        ? `FROM business_process_assets bpa
           JOIN risk_register rr ON rr.asset_id = bpa.asset_id
           LEFT JOIN assets a ON a.id = rr.asset_id
           ${riskAnalysisJoinSql}
          WHERE bpa.business_process_id = bp.id`
        : "";
    const linkedAssetsSql = hasAssets
      ? `COALESCE(
          (SELECT json_agg(
                    json_build_object(
                      'asset_id', bpa.asset_id,
                      'asset_name', a.asset_name,
                      'asset_type', a.asset_type,
                      'criticality', a.criticality,
                      'dependency_type', bpa.dependency_type
                    )
                  )
             FROM business_process_assets bpa
             JOIN assets a ON a.id = bpa.asset_id
            WHERE bpa.business_process_id = bp.id),
          '[]'::json
        ) AS linked_assets`
      : `'[]'::json AS linked_assets`;
    const assetCountSql = hasAssets
      ? `(SELECT COUNT(*)::int
           FROM business_process_assets bpa
          WHERE bpa.business_process_id = bp.id) AS asset_count`
      : `0::int AS asset_count`;
    const riskCountSql =
      hasAssets && hasRiskRegister
        ? `(SELECT COUNT(*)::int
           FROM risk_register rr
          WHERE rr.asset_id IN (
            SELECT asset_id FROM business_process_assets
             WHERE business_process_id = bp.id
          )) AS risk_count`
        : `0::int AS risk_count`;
    const highestRiskScoreSql =
      hasAssets && hasRiskRegister
        ? `(SELECT COALESCE(MAX(${riskScoreExpr}), 0)::int ${riskSourceSql}) AS highest_risk_score`
        : `0::int AS highest_risk_score`;
    const highestRiskLevelSql =
      hasAssets && hasRiskRegister
        ? `(SELECT CASE
              WHEN COALESCE(MAX(${riskScoreExpr}), 0) >= 17 THEN 'Critical'
              WHEN COALESCE(MAX(${riskScoreExpr}), 0) >= 10 THEN 'High'
              WHEN COALESCE(MAX(${riskScoreExpr}), 0) >= 5 THEN 'Medium'
              WHEN COALESCE(MAX(${riskScoreExpr}), 0) >= 1 THEN 'Low'
              ELSE NULL
            END
            ${riskSourceSql}) AS highest_risk_level`
        : `NULL::text AS highest_risk_level`;
    const avgRiskScoreSql =
      hasAssets && hasRiskRegister
        ? `(SELECT ROUND(AVG(NULLIF(${riskScoreExpr}, 0))::numeric, 1) ${riskSourceSql}) AS avg_risk_score`
        : `NULL::numeric AS avg_risk_score`;
    const linkedRisksSql =
      hasAssets && hasRiskRegister
        ? `COALESCE(
            (SELECT json_agg(
                      json_build_object(
                        'risk_register_id', risk_rows.risk_register_id,
                        'risk_code', risk_rows.risk_code,
                        'risk_title', risk_rows.risk_title,
                        'asset_id', risk_rows.asset_id,
                        'asset_name', risk_rows.asset_name,
                        'risk_score', risk_rows.risk_score,
                        'risk_level', risk_rows.risk_level,
                        'residual_risk_score', risk_rows.residual_risk_score,
                        'residual_risk_level', risk_rows.residual_risk_level,
                        'status', risk_rows.status
                      )
                      ORDER BY risk_rows.risk_score DESC NULLS LAST,
                               risk_rows.risk_register_id
                    )
               FROM (
                 SELECT DISTINCT
                        rr.id AS risk_register_id,
                        ${riskCodeExpr} AS risk_code,
                        rr.risk_title,
                        rr.asset_id,
                        a.asset_name,
                        ${riskScoreExpr} AS risk_score,
                        ${riskLevelExpr} AS risk_level,
                        ${residualScoreExpr} AS residual_risk_score,
                        ${residualLevelExpr} AS residual_risk_level,
                        rr.status
                   ${riskSourceSql}
                  ORDER BY ${riskScoreExpr} DESC NULLS LAST, rr.id
                  LIMIT 5
               ) risk_rows),
            '[]'::json
          ) AS linked_risks`
        : `'[]'::json AS linked_risks`;
    const r = await pool.query(`
      SELECT
        bp.*,
        ${linkedAssetsSql},
        ${assetCountSql},
        ${riskCountSql},
        ${highestRiskScoreSql},
        ${highestRiskLevelSql},
        ${avgRiskScoreSql},
        ${linkedRisksSql}
      FROM business_processes bp
      ORDER BY
        CASE LOWER(bp.criticality)
          WHEN 'critical' THEN 1
          WHEN 'high'     THEN 2
          WHEN 'medium'   THEN 3
          WHEN 'low'      THEN 4
          ELSE 5
        END,
        bp.created_at DESC
    `);

    // Summary stats
    const stats = await pool.query(`
      SELECT
        COUNT(*)::int AS total,
        SUM(CASE WHEN LOWER(criticality)='critical' THEN 1 ELSE 0 END)::int AS critical,
        SUM(CASE WHEN LOWER(criticality)='high'     THEN 1 ELSE 0 END)::int AS high,
        SUM(CASE WHEN LOWER(criticality)='medium'   THEN 1 ELSE 0 END)::int AS medium,
        SUM(CASE WHEN LOWER(criticality)='low'      THEN 1 ELSE 0 END)::int AS low,
        SUM(CASE WHEN status='Active' THEN 1 ELSE 0 END)::int AS active
        FROM business_processes
    `);

    return NextResponse.json({
      processes: r.rows,
      count: r.rows.length,
      stats: stats.rows[0] ?? {},
      options: {
        business_functions: FUNCTION_OPTIONS,
        criticality: CRITICALITY_OPTIONS,
        data_classification: DATA_CLASS_OPTIONS,
        dependency_types: DEPENDENCY_TYPES,
      },
    });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "fetch failed" },
      { status: 500 },
    );
  }
}

// ─────────────────────────────────────────────────────────────── POST ───

export async function POST(req: NextRequest) {
  const client = await pool.connect();
  try {
    await ensureBusinessProcessSchema();
    const body = await req.json();
    const name = toStr(body?.process_name);
    const criticality = toStr(body?.criticality);

    if (!name || !criticality) {
      return NextResponse.json(
        { error: "process_name and criticality are required" },
        { status: 400 },
      );
    }
    if (!CRITICALITY_OPTIONS.includes(criticality)) {
      return NextResponse.json(
        { error: `criticality must be one of: ${CRITICALITY_OPTIONS.join(", ")}` },
        { status: 400 },
      );
    }

    await client.query("BEGIN");
    const code = await generateProcessCode();

    const inserted = await client.query(
      `INSERT INTO business_processes
         (process_code, process_name, description, business_function,
          business_owner, business_owner_email, criticality,
          rto_hours, rpo_hours, data_types, data_classification,
          revenue_impact_per_hour, customers_affected, regulatory_scope,
          status, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
       RETURNING id`,
      [
        code,
        name,
        toStr(body.description),
        toStr(body.business_function),
        toStr(body.business_owner),
        toStr(body.business_owner_email),
        criticality,
        toNum(body.rto_hours),
        toNum(body.rpo_hours),
        toStr(body.data_types),
        toStr(body.data_classification),
        toNum(body.revenue_impact_per_hour),
        toNum(body.customers_affected),
        toStr(body.regulatory_scope),
        toStr(body.status) ?? "Active",
        toStr(body.notes),
      ],
    );
    const bpId = inserted.rows[0].id;

    // Optional: link asset IDs
    const assetIds: number[] = Array.isArray(body.asset_ids)
      ? body.asset_ids.map((x: unknown) => Number(x)).filter((n: number) => Number.isFinite(n))
      : [];
    for (const aid of assetIds) {
      await client.query(
        `INSERT INTO business_process_assets (business_process_id, asset_id, dependency_type)
         VALUES ($1, $2, 'Primary')
         ON CONFLICT (business_process_id, asset_id) DO NOTHING`,
        [bpId, aid],
      );
    }

    await client.query("COMMIT");
    return NextResponse.json(
      { success: true, id: bpId, process_code: code },
      { status: 201 },
    );
  } catch (err) {
    await client.query("ROLLBACK");
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "create failed" },
      { status: 500 },
    );
  } finally {
    client.release();
  }
}

// ─────────────────────────────────────────────────────────────── PATCH ──

export async function PATCH(req: NextRequest) {
  const client = await pool.connect();
  try {
    await ensureBusinessProcessSchema();
    const body = await req.json();
    const id = Number(body?.id);
    if (!Number.isFinite(id) || id <= 0) {
      return NextResponse.json({ error: "id is required" }, { status: 400 });
    }

    await client.query("BEGIN");

    await client.query(
      `UPDATE business_processes SET
         process_name            = COALESCE($1,  process_name),
         description             = COALESCE($2,  description),
         business_function       = COALESCE($3,  business_function),
         business_owner          = COALESCE($4,  business_owner),
         business_owner_email    = COALESCE($5,  business_owner_email),
         criticality             = COALESCE($6,  criticality),
         rto_hours               = COALESCE($7,  rto_hours),
         rpo_hours               = COALESCE($8,  rpo_hours),
         data_types              = COALESCE($9,  data_types),
         data_classification     = COALESCE($10, data_classification),
         revenue_impact_per_hour = COALESCE($11, revenue_impact_per_hour),
         customers_affected      = COALESCE($12, customers_affected),
         regulatory_scope        = COALESCE($13, regulatory_scope),
         status                  = COALESCE($14, status),
         notes                   = COALESCE($15, notes),
         updated_at              = NOW()
       WHERE id = $16`,
      [
        toStr(body.process_name),
        toStr(body.description),
        toStr(body.business_function),
        toStr(body.business_owner),
        toStr(body.business_owner_email),
        toStr(body.criticality),
        toNum(body.rto_hours),
        toNum(body.rpo_hours),
        toStr(body.data_types),
        toStr(body.data_classification),
        toNum(body.revenue_impact_per_hour),
        toNum(body.customers_affected),
        toStr(body.regulatory_scope),
        toStr(body.status),
        toStr(body.notes),
        id,
      ],
    );

    // If asset_ids supplied, replace the link set entirely.
    if (Array.isArray(body.asset_ids)) {
      const assetIds: number[] = body.asset_ids
        .map((x: unknown) => Number(x))
        .filter((n: number) => Number.isFinite(n));
      await client.query(
        `DELETE FROM business_process_assets WHERE business_process_id = $1`,
        [id],
      );
      for (const aid of assetIds) {
        await client.query(
          `INSERT INTO business_process_assets (business_process_id, asset_id, dependency_type)
           VALUES ($1, $2, 'Primary')
           ON CONFLICT (business_process_id, asset_id) DO NOTHING`,
          [id, aid],
        );
      }
    }

    await client.query("COMMIT");
    return NextResponse.json({ success: true });
  } catch (err) {
    await client.query("ROLLBACK");
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "update failed" },
      { status: 500 },
    );
  } finally {
    client.release();
  }
}

// ─────────────────────────────────────────────────────────────── DELETE ─

export async function DELETE(req: NextRequest) {
  try {
    await ensureBusinessProcessSchema();
    const { searchParams } = new URL(req.url);
    const id = Number(searchParams.get("id"));
    if (!Number.isFinite(id) || id <= 0) {
      return NextResponse.json({ error: "id is required" }, { status: 400 });
    }
    const r = await pool.query(
      `DELETE FROM business_processes WHERE id = $1 RETURNING process_code`,
      [id],
    );
    if (r.rows.length === 0) {
      return NextResponse.json({ error: "not found" }, { status: 404 });
    }
    return NextResponse.json({ success: true, deleted: r.rows[0].process_code });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "delete failed" },
      { status: 500 },
    );
  }
}
