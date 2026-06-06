import { pool } from "@/lib/db";
import { NextResponse } from "next/server";

const LEVELS = ["Critical", "High", "Medium", "Low"] as const;
const TREATMENTS = ["Treat", "Transfer", "Tolerate", "Terminate"] as const;

function scoreToLevel(score: number): string {
  if (score >= 17) return "Critical";
  if (score >= 10) return "High";
  if (score >= 5) return "Medium";
  return "Low";
}

async function tableExists(tableName: string) {
  const result = await pool.query("SELECT to_regclass($1) AS name", [tableName]);
  return Boolean(result.rows[0]?.name);
}

export async function GET() {
  try {
    const hasControls = await tableExists("control_recommendations");

    const controlsExpr = hasControls
      ? `(SELECT json_agg(json_build_object(
            'control_name', cr.control_name,
            'status',       COALESCE(cr.implementation_status, 'not_started'),
            'assigned_to',  cr.assigned_to
          ) ORDER BY cr.id)
           FROM control_recommendations cr
           WHERE cr.risk_register_id = rr.id)`
      : "NULL::json";

    const { rows } = await pool.query(`
      SELECT
        rr.id                                                             AS risk_id,
        rr.risk_code,
        rr.risk_title,
        t.threat_name,
        rr.nist_csf_function,
        rr.nist_csf_category,
        rr.department_control_owner,
        CASE rr.risk_treatment
          WHEN 'Mitigate' THEN 'Treat'
          WHEN 'Accept'   THEN 'Tolerate'
          WHEN 'Avoid'    THEN 'Terminate'
          ELSE rr.risk_treatment
        END                                                               AS risk_treatment,
        rr.treatment_rationale,
        rr.treatment_owner,
        rr.treatment_date,
        rr.status,
        a.asset_name,
        a.asset_type,
        a.criticality,
        COALESCE(ra.inherent_risk_score, ra.risk_score, 0)               AS inherent_score,
        COALESCE(ra.inherent_risk_level, ra.risk_level, 'Unknown')       AS inherent_level,
        COALESCE(ra.inherent_likelihood, ra.likelihood, 0)               AS inherent_likelihood,
        COALESCE(ra.inherent_impact, ra.impact, 0)                       AS inherent_impact,
        ra.residual_risk_score,
        ra.residual_risk_level,
        ra.inherent_review_status,
        ${controlsExpr}                                                   AS selected_controls
      FROM risk_register rr
      LEFT JOIN assets a ON a.id = rr.asset_id
      LEFT JOIN threats t ON t.id = rr.threat_id
      LEFT JOIN LATERAL (
        SELECT *
          FROM risk_analysis ra
         WHERE ra.risk_register_id = rr.id OR ra.risk_id = rr.id
         ORDER BY ra.id DESC
         LIMIT 1
      ) ra ON true
      ORDER BY
        CASE rr.risk_treatment
          WHEN 'Terminate' THEN 1  WHEN 'Avoid'    THEN 1
          WHEN 'Treat'     THEN 2  WHEN 'Mitigate' THEN 2
          WHEN 'Transfer'  THEN 3
          WHEN 'Tolerate'  THEN 4  WHEN 'Accept'   THEN 4
          ELSE 5
        END,
        COALESCE(ra.inherent_risk_score, ra.risk_score, 0) DESC
    `);

    const total = rows.length;
    const byTreatment: Record<string, typeof rows> = {
      Treat: [], Transfer: [], Tolerate: [], Terminate: [], Untreated: [],
    };
    for (const row of rows) {
      const key = (TREATMENTS as readonly string[]).includes(row.risk_treatment)
        ? row.risk_treatment
        : "Untreated";
      byTreatment[key].push(row);
    }

    const treated = total - byTreatment.Untreated.length;
    const coverage_pct = total > 0 ? Math.round((treated / total) * 100) : 0;

    const counts: Record<string, number> = {};
    for (const key of Object.keys(byTreatment)) counts[key] = byTreatment[key].length;

    const levelMatrix: Record<string, Record<string, number>> = {};
    for (const level of LEVELS) {
      levelMatrix[level] = { Treat: 0, Transfer: 0, Tolerate: 0, Terminate: 0, Untreated: 0 };
    }
    for (const row of rows) {
      const level = (LEVELS as readonly string[]).includes(row.inherent_level)
        ? row.inherent_level
        : scoreToLevel(Number(row.inherent_score));
      const treatment = (TREATMENTS as readonly string[]).includes(row.risk_treatment)
        ? row.risk_treatment
        : "Untreated";
      if (levelMatrix[level]) levelMatrix[level][treatment]++;
    }

    return NextResponse.json({
      generated_at: new Date().toISOString(),
      total,
      treated,
      untreated: byTreatment.Untreated.length,
      coverage_pct,
      counts,
      by_treatment: byTreatment,
      level_matrix: levelMatrix,
    });
  } catch (err) {
    console.error("Risk treatment report error:", err);
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Failed to generate report" },
      { status: 500 },
    );
  }
}
