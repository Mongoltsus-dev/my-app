import { pool } from "@/lib/db";
import { NextResponse } from "next/server";

/**
 * GET /api/risks/gap-analysis
 *
 * Returns risks whose NIST CSF category has NO implemented controls — i.e.
 * the "policy / control coverage gap" for the organization.
 *
 * Logic:
 *   - For each risk_register row, look at its nist_csf_category.
 *   - Check if there exists a nist_controls row with the same category_code
 *     AND control_status ILIKE 'implemented' (or 'fully implemented').
 *   - If not → that risk is "uncovered" — show it.
 *
 * Also returns suggested controls (from nist_controls matching the category)
 * so the user knows what to implement.
 */
export async function GET() {
  try {
    // Risks grouped by category, with implemented-control status
    const gaps = await pool.query(`
      WITH risk_summary AS (
        SELECT rr.id                AS risk_register_id,
               rr.risk_title,
               rr.risk_description,
               rr.nist_csf_function,
               rr.nist_csf_category,
               rr.asset_id,
               a.asset_name,
               a.asset_type,
               COALESCE(ra.inherent_risk_score, ra.risk_score, 0) AS risk_score,
               COALESCE(ra.inherent_risk_level, ra.risk_level, 'Unknown') AS risk_level,
               ra.residual_risk_score,
               ra.residual_risk_level
          FROM risk_register rr
          LEFT JOIN assets a         ON a.id = rr.asset_id
          LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id
      ),
      cat_coverage AS (
        SELECT category_code,
               BOOL_OR(LOWER(control_status) LIKE '%implement%'
                       AND LOWER(control_status) NOT LIKE 'not%') AS has_implemented
          FROM nist_controls
         WHERE is_active = TRUE
         GROUP BY category_code
      )
      SELECT rs.*,
             COALESCE(cc.has_implemented, FALSE) AS category_has_implemented_control,
             (SELECT COUNT(*)::int
                FROM control_recommendations cr
               WHERE cr.risk_register_id = rs.risk_register_id
                 AND cr.implementation_status = 'existing') AS implemented_count,
             (SELECT COUNT(*)::int
                FROM control_recommendations cr
               WHERE cr.risk_register_id = rs.risk_register_id) AS total_recommended
        FROM risk_summary rs
        LEFT JOIN cat_coverage cc ON cc.category_code = rs.nist_csf_category
       ORDER BY rs.risk_score DESC, rs.risk_register_id
    `);

    // Suggested controls per category (so UI can show "implement these")
    const suggestions = await pool.query(`
      SELECT category_code,
             control_id,
             control_name,
             nist_function,
             control_status
        FROM nist_controls
       WHERE is_active = TRUE
       ORDER BY category_code, control_id
    `);

    const suggestionsByCategory: Record<
      string,
      Array<{ control_id: string; control_name: string; status: string }>
    > = {};
    for (const row of suggestions.rows) {
      const cat = row.category_code as string;
      if (!suggestionsByCategory[cat]) suggestionsByCategory[cat] = [];
      suggestionsByCategory[cat].push({
        control_id: row.control_id,
        control_name: row.control_name,
        status: row.control_status,
      });
    }

    const uncovered = gaps.rows.filter(
      (r) => !r.category_has_implemented_control || r.implemented_count === 0,
    );
    const covered = gaps.rows.filter(
      (r) => r.category_has_implemented_control && r.implemented_count > 0,
    );

    return NextResponse.json({
      total_risks: gaps.rows.length,
      uncovered_count: uncovered.length,
      covered_count: covered.length,
      uncovered,
      covered,
      suggestions_by_category: suggestionsByCategory,
    });
  } catch (err) {
    console.error("gap-analysis error:", err);
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "gap analysis failed" },
      { status: 500 },
    );
  }
}
