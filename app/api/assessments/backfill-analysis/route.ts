import { pool } from "@/lib/db";
import { NextResponse } from "next/server";

/**
 * POST /api/assessments/backfill-analysis
 *
 * Creates a `risk_analysis` row for every `risk_register` row that doesn't
 * already have one. Likelihood and impact are derived from the linked asset's
 * criticality / access level / data classification (same logic as
 * /api/identify-risks). Idempotent — safe to call multiple times.
 *
 * This is the fix for the "all 50 risks show as Low at cell (1,1)" symptom:
 * those rows are missing risk_analysis entirely, so COALESCE returns 0.
 *
 * After this runs, the heat map will spread risks across the matrix based on
 * each asset's criticality. The user can then fine-tune individual risks via
 * the existing edit dialog.
 */

const LIKELIHOOD_LABELS = ["", "Rare", "Unlikely", "Possible", "Likely", "Very Likely"];
const IMPACT_LABELS = ["", "Negligible", "Minor", "Moderate", "Major", "Critical"];

function calcLevel(score: number): string {
  if (score <= 4) return "Low";
  if (score <= 9) return "Medium";
  if (score <= 16) return "High";
  return "Critical";
}

type AssetCtx = {
  criticality: string | null;
  access_level: string | null;
  authentication_method: string | null;
  data_classification: string | null;
  internet_exposed: boolean | null;
  supports_critical_service: boolean | null;
};

/**
 * Derive default likelihood/impact from asset context.
 * Conservative defaults — user can edit per-risk afterwards.
 */
function deriveScores(asset: AssetCtx | null): {
  likelihood: number;
  impact: number;
} {
  if (!asset) return { likelihood: 3, impact: 3 };

  const crit = String(asset.criticality ?? "").toLowerCase();
  let impact = 3;
  if (crit.includes("tier 0") || crit.includes("life") || crit.includes("safety"))
    impact = 5;
  else if (crit.includes("tier 1") || crit.includes("critical")) impact = 4;
  else if (crit.includes("tier 2") || crit.includes("high")) impact = 4;
  else if (crit.includes("tier 3") || crit.includes("medium")) impact = 3;
  else if (crit.includes("low")) impact = 2;

  let likelihood = 3;
  const access = String(asset.access_level ?? "").toLowerCase();
  if (access.includes("public api")) likelihood += 2;
  else if (access.includes("public web")) likelihood += 1;
  else if (access.includes("vpn") || access.includes("internal")) likelihood -= 1;

  const auth = String(asset.authentication_method ?? "").toLowerCase();
  if (auth === "password only" || auth.includes("none")) likelihood += 1;
  else if (auth.includes("mfa") || auth.includes("sso") || auth.includes("federated"))
    likelihood -= 1;

  if (asset.internet_exposed) likelihood += 1;

  const data = String(asset.data_classification ?? "").toLowerCase();
  if (data.includes("restricted") || data.includes("confidential")) impact += 1;
  if (asset.supports_critical_service) impact += 1;

  likelihood = Math.max(1, Math.min(5, likelihood));
  impact = Math.max(1, Math.min(5, impact));
  return { likelihood, impact };
}

export async function POST() {
  const client = await pool.connect();
  try {
    // Find risk_register rows with no risk_analysis. Pull just enough asset
    // context to derive defaults.
    const missing = await client.query(`
      SELECT rr.id        AS risk_register_id,
             rr.risk_title,
             rr.asset_id,
             a.criticality,
             a.access_level,
             a.authentication_method,
             a.data_classification,
             a.internet_exposed,
             a.supports_critical_service
      FROM risk_register rr
      LEFT JOIN assets a         ON a.id = rr.asset_id
      LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id
      WHERE ra.id IS NULL
      ORDER BY rr.id
    `);

    if (missing.rows.length === 0) {
      return NextResponse.json({
        success: true,
        created: 0,
        message: "All risk_register rows already have risk_analysis. Nothing to do.",
      });
    }

    await client.query("BEGIN");

    let created = 0;
    const samples: Array<{
      risk_register_id: number;
      risk_title: string;
      likelihood: number;
      impact: number;
      level: string;
    }> = [];

    for (const row of missing.rows) {
      const { likelihood, impact } = deriveScores(row);
      const score = likelihood * impact;
      const level = calcLevel(score);

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
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
                 'backfill', FALSE, 'Needs Inherent Review', NOW(),
                 0, $6, $7, NOW())
         ON CONFLICT (risk_register_id) DO NOTHING`,
        [
          row.risk_register_id,
          likelihood,
          LIKELIHOOD_LABELS[likelihood],
          impact,
          IMPACT_LABELS[impact],
          score,
          level,
          likelihood,
          LIKELIHOOD_LABELS[likelihood],
          impact,
          IMPACT_LABELS[impact],
          score,
          level,
        ],
      );

      created++;
      if (samples.length < 10) {
        samples.push({
          risk_register_id: row.risk_register_id,
          risk_title: row.risk_title,
          likelihood,
          impact,
          level,
        });
      }
    }

    await client.query("COMMIT");

    return NextResponse.json({
      success: true,
      created,
      samples,
      message: `Backfilled ${created} risk_analysis rows. Scores derived from each asset's criticality and exposure. Review individual scores via the edit dialog where needed.`,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("backfill-analysis error:", err);
    return NextResponse.json(
      {
        error: "Backfill failed",
        details: err instanceof Error ? err.message : "unknown",
      },
      { status: 500 },
    );
  } finally {
    client.release();
  }
}
