import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

/**
 * POST /api/csf-subcategories/identify-risks
 * Body: { min_gap?: number, only_risk_levels?: string[] }
 *
 * For each csf_subcategories row that has a maturity gap (target_tier >
 * current_tier) OR a risk_level set, create a corresponding risk_register +
 * risk_analysis entry. These are *organization-level* risks (asset_id is
 * NULL) representing the policy/process gap, not a specific asset risk.
 *
 * Scoring:
 *   inherent_impact     = derived from CSF risk_level (Low=2, Medium=3, High=4, Critical=5)
 *                         falls back to gap-based (gap=1→3, gap=2→4, gap=3+→5)
 *   inherent_likelihood = gap + 1, clamped to 1..5
 *                         (no gap → 2, gap=1 → 2, gap=2 → 3, gap=3 → 4, gap=4 → 5)
 *
 * Idempotent: identifies by (nist_csf_category, risk_title) — re-running
 * updates the risk_analysis but doesn't create duplicates.
 */

const LIKELIHOOD_LABELS = ["", "Rare", "Unlikely", "Possible", "Likely", "Very Likely"];
const IMPACT_LABELS = ["", "Negligible", "Minor", "Moderate", "Major", "Critical"];

function calcLevel(score: number): string {
  if (score <= 4) return "Low";
  if (score <= 9) return "Medium";
  if (score <= 16) return "High";
  return "Critical";
}

function impactFromRiskLevel(level: string | null): number {
  switch ((level ?? "").toLowerCase()) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    default:
      return 0;
  }
}

function impactFromGap(gap: number): number {
  if (gap >= 3) return 5;
  if (gap === 2) return 4;
  if (gap === 1) return 3;
  return 2;
}

async function generateRiskCode(): Promise<string> {
  const r = await pool.query(
    `SELECT COALESCE(MAX(substring(risk_code FROM '^RSK-([0-9]+)$')::integer), 0) + 1 AS n
       FROM risk_register WHERE risk_code ~ '^RSK-[0-9]+$'`,
  );
  return `RSK-${String(Number(r.rows[0]?.n ?? 1)).padStart(4, "0")}`;
}

export async function POST(req: NextRequest) {
  const client = await pool.connect();
  try {
    const body = await req.json().catch(() => ({}));
    const minGap = Number(body?.min_gap ?? 1);
    const onlyLevels: string[] = Array.isArray(body?.only_risk_levels)
      ? body.only_risk_levels.map((s: string) => s.toLowerCase())
      : [];

    // Find subcategories worth creating a risk for
    const rows = await client.query(`
      SELECT subcategory_id, nist_function, category_code, category_name,
             outcome_description, current_tier, target_tier, gap, risk_level,
             primary_owner, target_date, control_links
        FROM csf_subcategories
       WHERE (gap IS NOT NULL AND gap >= $1)
          OR (risk_level IS NOT NULL AND risk_level <> '' AND LOWER(risk_level) <> 'low')
       ORDER BY function_code, category_code, subcategory_id
    `, [minGap]);

    if (rows.rows.length === 0) {
      return NextResponse.json({
        success: true,
        created: 0,
        updated: 0,
        message: "No subcategories meet the threshold for risk creation.",
      });
    }

    await client.query("BEGIN");

    let created = 0;
    let updated = 0;
    const samples: Array<{
      subcategory_id: string;
      risk_code: string;
      action: "created" | "updated";
      likelihood: number;
      impact: number;
      level: string;
    }> = [];

    for (const sub of rows.rows) {
      // Filter by requested risk levels if any
      if (
        onlyLevels.length > 0 &&
        sub.risk_level &&
        !onlyLevels.includes(String(sub.risk_level).toLowerCase())
      ) {
        continue;
      }

      const gap = Number(sub.gap ?? 0);
      const impact = Math.max(
        2,
        impactFromRiskLevel(sub.risk_level) || impactFromGap(gap),
      );
      const likelihood = Math.max(1, Math.min(5, gap + 1));
      const score = likelihood * impact;
      const level = calcLevel(score);

      const title = `${sub.subcategory_id}: ${sub.outcome_description?.substring(0, 240) ?? "Maturity gap"}`;
      const description = `NIST CSF 2.0 subcategory ${sub.subcategory_id} (${sub.category_name}). Current tier ${sub.current_tier ?? "—"} / target tier ${sub.target_tier ?? "—"} (gap ${gap}). Recommended controls: ${sub.control_links ?? "—"}. Target completion: ${sub.target_date ?? "—"}.`;

      // Dedup by (nist_csf_category, risk_title) — we want one org-level risk per subcategory
      const existing = await client.query(
        `SELECT id FROM risk_register
          WHERE nist_csf_category = $1
            AND risk_title       = $2
            AND asset_id IS NULL
          LIMIT 1`,
        [sub.subcategory_id, title],
      );

      let rrId: number;
      if (existing.rows.length > 0) {
        rrId = existing.rows[0].id;
        await client.query(
          `UPDATE risk_register
              SET risk_description = $1,
                  nist_csf_function = $2,
                  risk_owner = COALESCE(risk_owner, $3),
                  updated_at = NOW()
            WHERE id = $4`,
          [description, sub.nist_function, sub.primary_owner, rrId],
        );
        updated++;
      } else {
        const code = await generateRiskCode();
        const ins = await client.query(
          `INSERT INTO risk_register
             (risk_code, asset_id, risk_title, risk_description,
              nist_csf_function, nist_csf_category,
              department_control_owner, risk_owner, status)
           VALUES ($1, NULL, $2, $3, $4, $5, $6, $6, 'Open')
           RETURNING id`,
          [
            code,
            title,
            description,
            sub.nist_function,
            sub.subcategory_id,
            sub.primary_owner,
          ],
        );
        rrId = ins.rows[0].id;
        created++;
        samples.push({
          subcategory_id: sub.subcategory_id,
          risk_code: code,
          action: "created",
          likelihood,
          impact,
          level,
        });
      }

      // Upsert risk_analysis
      await client.query(
        `INSERT INTO risk_analysis
           (risk_register_id,
            likelihood, likelihood_label,
            impact, impact_label,
            risk_score, risk_level,
            inherent_likelihood, inherent_likelihood_label,
            inherent_impact, inherent_impact_label,
            inherent_risk_score, inherent_risk_level,
            inherent_calculation_method,
            inherent_assessor_override,
            inherent_review_status,
            inherent_assessed_at,
            control_effectiveness,
            residual_risk_score, residual_risk_level, residual_calculated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$2,$3,$4,$5,$6,$7,
                 'csf_gap', FALSE, 'Needs Inherent Review', NOW(),
                 0, $6, $7, NOW())
         ON CONFLICT (risk_register_id) DO UPDATE SET
           likelihood                = EXCLUDED.likelihood,
           likelihood_label          = EXCLUDED.likelihood_label,
           impact                    = EXCLUDED.impact,
           impact_label              = EXCLUDED.impact_label,
           risk_score                = EXCLUDED.risk_score,
           risk_level                = EXCLUDED.risk_level,
           inherent_likelihood       = EXCLUDED.inherent_likelihood,
           inherent_likelihood_label = EXCLUDED.inherent_likelihood_label,
           inherent_impact           = EXCLUDED.inherent_impact,
           inherent_impact_label     = EXCLUDED.inherent_impact_label,
           inherent_risk_score       = EXCLUDED.inherent_risk_score,
           inherent_risk_level       = EXCLUDED.inherent_risk_level,
           residual_risk_score       = EXCLUDED.residual_risk_score,
           residual_risk_level       = EXCLUDED.residual_risk_level,
           residual_calculated_at    = NOW(),
           updated_at                = NOW()`,
        [
          rrId,
          likelihood,
          LIKELIHOOD_LABELS[likelihood],
          impact,
          IMPACT_LABELS[impact],
          score,
          level,
        ],
      );
    }

    await client.query("COMMIT");

    return NextResponse.json({
      success: true,
      eligible_subcategories: rows.rows.length,
      created,
      updated,
      samples: samples.slice(0, 10),
      message: `Generated ${created} new risks and updated ${updated} existing ones from CSF maturity gaps.`,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("identify-risks (csf) error:", err);
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "identify failed" },
      { status: 500 },
    );
  } finally {
    client.release();
  }
}
