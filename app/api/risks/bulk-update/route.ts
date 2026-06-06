import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

/**
 * GET  /api/risks/bulk-update   — returns all risk_register rows + tags
 * POST /api/risks/bulk-update   — accepts an array of edits, applies them
 *
 * Legacy bulk editor for tagging risk_register rows with NIST
 * function/category, applicable asset types, and default L×I values.
 *
 * We operate on risk_register (since that's where the 50 currently are per the
 * heat map). Edits to L/I land in risk_analysis (created if missing).
 * Edits to function/category/asset-type tags land on risk_register columns.
 */

type Patch = {
  risk_register_id: number;
  nist_csf_function?: string | null;
  nist_csf_category?: string | null;
  applicable_asset_types?: string | null; // comma-separated
  likelihood?: number | null;
  impact?: number | null;
};

const LIKELIHOOD_LABELS = ["", "Rare", "Unlikely", "Possible", "Likely", "Very Likely"];
const IMPACT_LABELS = ["", "Negligible", "Minor", "Moderate", "Major", "Critical"];

function calcLevel(score: number): string {
  if (score <= 4) return "Low";
  if (score <= 9) return "Medium";
  if (score <= 16) return "High";
  return "Critical";
}

async function ensureColumns() {
  await pool.query(`
    ALTER TABLE risk_register
      ADD COLUMN IF NOT EXISTS applicable_asset_types TEXT
  `);
}

export async function GET() {
  try {
    await ensureColumns();
    const r = await pool.query(`
      SELECT rr.id              AS risk_register_id,
             rr.risk_title,
             rr.risk_description,
             rr.asset_id,
             a.asset_name,
             a.asset_type,
             a.criticality,
             rr.nist_csf_function,
             rr.nist_csf_category,
             rr.applicable_asset_types,
             COALESCE(ra.inherent_likelihood, ra.likelihood) AS likelihood,
             COALESCE(ra.inherent_impact,     ra.impact)     AS impact,
             COALESCE(ra.inherent_risk_score, ra.risk_score) AS risk_score,
             COALESCE(ra.inherent_risk_level, ra.risk_level) AS risk_level
      FROM risk_register rr
      LEFT JOIN assets a         ON a.id = rr.asset_id
      LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id
      ORDER BY rr.id
    `);
    return NextResponse.json({ rows: r.rows, count: r.rows.length });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "fetch failed" },
      { status: 500 },
    );
  }
}

export async function POST(req: NextRequest) {
  const client = await pool.connect();
  try {
    await ensureColumns();
    const body = (await req.json()) as { patches?: Patch[] };
    const patches = Array.isArray(body?.patches) ? body.patches : [];
    if (patches.length === 0) {
      return NextResponse.json(
        { error: "patches[] required" },
        { status: 400 },
      );
    }

    await client.query("BEGIN");
    let updated = 0;

    for (const p of patches) {
      if (!p.risk_register_id) continue;

      // 1) Update risk_register columns (function, category, asset types).
      //    Use COALESCE so empty fields don't wipe existing values.
      await client.query(
        `UPDATE risk_register
            SET nist_csf_function      = COALESCE($1, nist_csf_function),
                nist_csf_category      = COALESCE($2, nist_csf_category),
                applicable_asset_types = COALESCE($3, applicable_asset_types),
                updated_at             = NOW()
          WHERE id = $4`,
        [
          p.nist_csf_function ?? null,
          p.nist_csf_category ?? null,
          p.applicable_asset_types ?? null,
          p.risk_register_id,
        ],
      );

      // 2) If L/I supplied, upsert risk_analysis with computed score/level.
      if (
        p.likelihood !== undefined &&
        p.likelihood !== null &&
        p.impact !== undefined &&
        p.impact !== null
      ) {
        const L = Math.max(1, Math.min(5, Math.round(Number(p.likelihood))));
        const I = Math.max(1, Math.min(5, Math.round(Number(p.impact))));
        const score = L * I;
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
           VALUES ($1,$2,$3,$4,$5,$6,$7,$2,$3,$4,$5,$6,$7,
                   'triage', TRUE, 'Inherent Risk Validated', NOW(),
                   0, $6, $7, NOW())
           ON CONFLICT (risk_register_id) DO UPDATE SET
             likelihood                 = EXCLUDED.likelihood,
             likelihood_label           = EXCLUDED.likelihood_label,
             impact                     = EXCLUDED.impact,
             impact_label               = EXCLUDED.impact_label,
             risk_score                 = EXCLUDED.risk_score,
             risk_level                 = EXCLUDED.risk_level,
             inherent_likelihood        = EXCLUDED.inherent_likelihood,
             inherent_likelihood_label  = EXCLUDED.inherent_likelihood_label,
             inherent_impact            = EXCLUDED.inherent_impact,
             inherent_impact_label      = EXCLUDED.inherent_impact_label,
             inherent_risk_score        = EXCLUDED.inherent_risk_score,
             inherent_risk_level        = EXCLUDED.inherent_risk_level,
             inherent_assessor_override = TRUE,
             inherent_review_status     = 'Inherent Risk Validated',
             inherent_assessed_at       = NOW(),
             residual_risk_score        = EXCLUDED.residual_risk_score,
             residual_risk_level        = EXCLUDED.residual_risk_level,
             residual_calculated_at     = NOW(),
             updated_at                 = NOW()`,
          [p.risk_register_id, L, LIKELIHOOD_LABELS[L], I, IMPACT_LABELS[I], score, level],
        );
      }

      updated++;
    }

    await client.query("COMMIT");
    return NextResponse.json({ success: true, updated });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("bulk-update error:", err);
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "bulk update failed" },
      { status: 500 },
    );
  } finally {
    client.release();
  }
}
