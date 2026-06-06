import { pool } from "@/lib/db";
import { NextResponse } from "next/server";

type SourceRow = {
  id: number;
  asset_id: number;
  threat_id: number | null;
  risk_title: string;
  risk_description: string | null;
  nist_csf_function: string | null;
  nist_csf_category: string | null;
  department_control_owner: string | null;
  assessed_by: string | null;
  notes: string | null;
  status: string | null;
  asset_type: string | null;
  source_asset_name: string | null;
};

async function nextRiskCode(client: { query: typeof pool.query }) {
  const res = await client.query<{ next_num: number }>(
    `SELECT COALESCE(MAX(substring(risk_code FROM '^RSK-([0-9]+)$')::integer), 0) + 1 AS next_num
       FROM risk_register WHERE risk_code ~ '^RSK-[0-9]+$'`,
  );
  return `RSK-${String(Number(res.rows[0]?.next_num ?? 1)).padStart(4, "0")}`;
}

export async function POST() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const sources = await client.query<SourceRow>(
      `SELECT r.id, r.asset_id, r.threat_id, r.risk_title, r.risk_description,
              r.nist_csf_function, r.nist_csf_category, r.department_control_owner,
              r.assessed_by, r.notes, r.status,
              a.asset_type, a.asset_name AS source_asset_name
         FROM risk_register r
         JOIN assets a ON a.id = r.asset_id
        WHERE COALESCE(a.status, 'Active') <> 'Retired'
          AND a.asset_type IS NOT NULL
          AND a.asset_type <> ''`,
    );

    let expanded = 0;
    let skipped = 0;
    let analysisCopied = 0;
    let controlsCopied = 0;

    for (const source of sources.rows) {
      if (!source.asset_type) continue;

      const matches = await client.query<{ id: number; asset_name: string }>(
        `SELECT id, asset_name
           FROM assets
          WHERE asset_type = $1
            AND id <> $2
            AND COALESCE(status, 'Active') <> 'Retired'`,
        [source.asset_type, source.asset_id],
      );

      for (const target of matches.rows) {
        const dup = await client.query(
          `SELECT id FROM risk_register
            WHERE asset_id = $1
              AND COALESCE(threat_id, 0) = COALESCE($2, 0)
              AND risk_title = $3
              AND status <> 'Closed'
            LIMIT 1`,
          [target.id, source.threat_id, source.risk_title],
        );
        if (dup.rows.length > 0) {
          skipped++;
          continue;
        }

        const riskCode = await nextRiskCode(client);
        const inserted = await client.query<{ id: number }>(
          `INSERT INTO risk_register
             (risk_code, asset_id, threat_id, risk_title, risk_description,
              nist_csf_function, nist_csf_category, department_control_owner,
              assessed_by, notes, status)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,COALESCE($11,'Open'))
           RETURNING id`,
          [
            riskCode,
            target.id,
            source.threat_id,
            source.risk_title,
            source.risk_description,
            source.nist_csf_function,
            source.nist_csf_category,
            source.department_control_owner,
            source.assessed_by ?? "Asset-type expansion",
            [
              source.notes,
              `Хөрөнгийн төрөлөөр тараасан: эх эрсдэл id=${source.id} (${source.source_asset_name ?? "?"}).`,
            ]
              .filter(Boolean)
              .join(" "),
            source.status,
          ],
        );

        const newRiskId = inserted.rows[0].id;

        const analysisResult = await client.query(
          `INSERT INTO risk_analysis
             (risk_register_id,
              likelihood, likelihood_label, likelihood_rationale,
              impact, impact_label, impact_rationale,
              risk_score, risk_level,
              inherent_likelihood, inherent_likelihood_label,
              inherent_impact, inherent_impact_label,
              inherent_risk_score, inherent_risk_level,
              inherent_likelihood_rationale, inherent_impact_rationale,
              inherent_calculation_method, inherent_assessor_override,
              inherent_review_status,
              confidentiality_impact, integrity_impact, availability_impact,
              business_impact_description)
           SELECT $1,
                  likelihood, likelihood_label, likelihood_rationale,
                  impact, impact_label, impact_rationale,
                  risk_score, risk_level,
                  inherent_likelihood, inherent_likelihood_label,
                  inherent_impact, inherent_impact_label,
                  inherent_risk_score, inherent_risk_level,
                  inherent_likelihood_rationale, inherent_impact_rationale,
                  inherent_calculation_method, inherent_assessor_override,
                  inherent_review_status,
                  confidentiality_impact, integrity_impact, availability_impact,
                  business_impact_description
             FROM risk_analysis
            WHERE risk_register_id = $2`,
          [newRiskId, source.id],
        );
        analysisCopied += analysisResult.rowCount ?? 0;

        const controlsResult = await client.query(
          `INSERT INTO control_recommendations (risk_register_id, control_name, nist_function, priority)
           SELECT $1, control_name, nist_function, priority
             FROM control_recommendations
            WHERE risk_register_id = $2`,
          [newRiskId, source.id],
        );
        controlsCopied += controlsResult.rowCount ?? 0;

        expanded++;
      }
    }

    await client.query("COMMIT");
    return NextResponse.json({
      success: true,
      source_risks: sources.rows.length,
      risks_expanded: expanded,
      risks_skipped_existing: skipped,
      analysis_rows_copied: analysisCopied,
      control_rows_copied: controlsCopied,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Expand risks to assets error:", error);
    const message =
      error instanceof Error ? error.message : "Failed to expand risks";
    return NextResponse.json({ error: message }, { status: 500 });
  } finally {
    client.release();
  }
}
