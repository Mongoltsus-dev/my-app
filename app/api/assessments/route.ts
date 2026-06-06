import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

const LIKELIHOOD_LABELS = [
  "",
  "Rare",
  "Unlikely",
  "Possible",
  "Likely",
  "Very Likely",
];
const IMPACT_LABELS = [
  "",
  "Negligible",
  "Minor",
  "Moderate",
  "Major",
  "Critical",
];

function calcRiskLevel(score: number): string {
  if (score <= 4) return "Low";
  if (score <= 9) return "Medium";
  if (score <= 16) return "High";
  return "Critical";
}

async function generateRiskCode(client: { query: typeof pool.query }) {
  const result = await client.query(
    `SELECT COALESCE(MAX(substring(risk_code FROM '^RSK-([0-9]+)$')::integer), 0) + 1 AS next_num
     FROM risk_register WHERE risk_code ~ '^RSK-[0-9]+$'`,
  );
  const n = Number(result.rows[0]?.next_num ?? 1);
  return `RSK-${String(n).padStart(4, "0")}`;
}

async function ensureAssessmentsSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS risk_register (
      id SERIAL PRIMARY KEY,
      risk_code VARCHAR(50) UNIQUE NOT NULL,
      asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
      threat_id INTEGER REFERENCES threats(id),
      risk_title VARCHAR(500) NOT NULL,
      risk_description TEXT,
      nist_csf_function VARCHAR(100),
      nist_csf_category VARCHAR(100),
      department_control_owner VARCHAR(255),
      assessed_by VARCHAR(255),
      notes TEXT,
      status VARCHAR(50) DEFAULT 'Open',
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS risk_analysis (
      id SERIAL PRIMARY KEY,
      risk_register_id INTEGER REFERENCES risk_register(id) ON DELETE CASCADE UNIQUE,
      likelihood INTEGER NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
      likelihood_label VARCHAR(50),
      likelihood_rationale TEXT,
      impact INTEGER NOT NULL CHECK (impact BETWEEN 1 AND 5),
      impact_label VARCHAR(50),
      impact_rationale TEXT,
      risk_score INTEGER,
      risk_level VARCHAR(20),
      inherent_likelihood INTEGER CHECK (inherent_likelihood BETWEEN 1 AND 5),
      inherent_likelihood_label VARCHAR(50),
      inherent_impact INTEGER CHECK (inherent_impact BETWEEN 1 AND 5),
      inherent_impact_label VARCHAR(50),
      inherent_risk_score INTEGER,
      inherent_risk_level VARCHAR(20),
      inherent_likelihood_rationale TEXT,
      inherent_impact_rationale TEXT,
      inherent_calculation_method VARCHAR(50) DEFAULT 'automated',
      inherent_assessor_override BOOLEAN DEFAULT FALSE,
      inherent_review_status VARCHAR(50) DEFAULT 'Needs Inherent Review',
      inherent_assessed_at TIMESTAMP,
      confidentiality_impact BOOLEAN DEFAULT FALSE,
      integrity_impact BOOLEAN DEFAULT FALSE,
      availability_impact BOOLEAN DEFAULT FALSE,
      business_impact_description TEXT,
      control_effectiveness INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS control_recommendations (
      id SERIAL PRIMARY KEY,
      risk_register_id INTEGER REFERENCES risk_register(id) ON DELETE CASCADE,
      control_name VARCHAR(255) NOT NULL,
      nist_function VARCHAR(50),
      priority VARCHAR(20) DEFAULT 'Medium',
      implementation_status VARCHAR(50) DEFAULT 'not_started',
      assigned_to VARCHAR(255),
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS implementation_status VARCHAR(50) DEFAULT 'not_started'`);
  await pool.query(`ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS assigned_to VARCHAR(255)`);
  await pool.query(`ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS evidence_file_path TEXT`);
  await pool.query(`ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS evidence_original_name VARCHAR(255)`);
  await pool.query(`ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS evidence_uploaded_at TIMESTAMP`);
  await pool.query(`ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) DEFAULT 'pending'`);
  await pool.query(`ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS approved_by VARCHAR(255)`);
  await pool.query(`ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP`);
  await pool.query(`ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS approval_notes TEXT`);

  const riskAnalysisColumns = [
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS likelihood_label VARCHAR(50)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS likelihood_rationale TEXT",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS impact_label VARCHAR(50)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS impact_rationale TEXT",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS risk_score INTEGER",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_likelihood INTEGER",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_likelihood_label VARCHAR(50)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_impact INTEGER",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_impact_label VARCHAR(50)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_risk_score INTEGER",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_risk_level VARCHAR(20)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_likelihood_rationale TEXT",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_impact_rationale TEXT",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_calculation_method VARCHAR(50) DEFAULT 'automated'",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_assessor_override BOOLEAN DEFAULT FALSE",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_review_status VARCHAR(50) DEFAULT 'Needs Inherent Review'",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_assessed_at TIMESTAMP",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS residual_risk_score INTEGER",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS residual_risk_level VARCHAR(20)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS residual_calculated_at TIMESTAMP",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS control_effectiveness INTEGER DEFAULT 0",
  ];

  const riskRegisterColumns = [
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS risk_treatment VARCHAR(20)",
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS treatment_rationale TEXT",
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS treatment_owner VARCHAR(255)",
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS treatment_date DATE",
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS risk_owner VARCHAR(255)",
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS next_review_date DATE",
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS evidence TEXT",
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS key_controls TEXT",
  ];

  for (const statement of riskAnalysisColumns) {
    await pool.query(statement);
  }
  for (const statement of riskRegisterColumns) {
    await pool.query(statement);
  }
}

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

async function deleteAllRiskData() {
  await ensureAssessmentsSchema();
  const client = await pool.connect();
  const deleted: Record<string, number> = {};

  try {
    await client.query("BEGIN");

    if (await tableExists("action_plan_items")) {
      const filters: string[] = [];
      if (await columnExists("action_plan_items", "risk_register_id")) {
        filters.push("risk_register_id IS NOT NULL");
      }
      if (await columnExists("action_plan_items", "control_recommendation_id")) {
        filters.push("control_recommendation_id IS NOT NULL");
      }
      if (await columnExists("action_plan_items", "generated_from")) {
        filters.push(
          "LOWER(COALESCE(generated_from, '')) IN ('risk', 'risk_register', 'control_recommendation', 'control_recommendations')",
        );
      }

      if (filters.length > 0) {
        const result = await client.query(
          `DELETE FROM action_plan_items WHERE ${filters.join(" OR ")}`,
        );
        deleted.action_plan_items = result.rowCount ?? 0;
      }
    }

    if (
      (await tableExists("control_assessments")) &&
      (await columnExists("control_assessments", "risk_register_id"))
    ) {
      const result = await client.query(
        "DELETE FROM control_assessments WHERE risk_register_id IS NOT NULL",
      );
      deleted.control_assessments = result.rowCount ?? 0;
    }

    if (await tableExists("control_recommendations")) {
      const filters: string[] = [];
      if (await columnExists("control_recommendations", "risk_register_id")) {
        filters.push("risk_register_id IS NOT NULL");
      }
      if (await columnExists("control_recommendations", "risk_analysis_id")) {
        filters.push("risk_analysis_id IS NOT NULL");
      }

      if (filters.length > 0) {
        const result = await client.query(
          `DELETE FROM control_recommendations WHERE ${filters.join(" OR ")}`,
        );
        deleted.control_recommendations = result.rowCount ?? 0;
      }
    }

    if (await tableExists("risk_analysis")) {
      const result = await client.query("DELETE FROM risk_analysis");
      deleted.risk_analysis = result.rowCount ?? 0;
    }

    if (await tableExists("risk_register")) {
      const result = await client.query("DELETE FROM risk_register");
      deleted.risk_register = result.rowCount ?? 0;
    }

    await client.query("COMMIT");
    return deleted;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export async function GET(req: NextRequest) {
  try {
    await ensureAssessmentsSchema();

    const { searchParams } = new URL(req.url);
    const assetId = searchParams.get("asset_id");

    let query = `
      SELECT
        rr.id                        AS risk_id,
        rr.risk_code,
        rr.asset_id,
        rr.threat_id,
        rr.risk_title,
        rr.risk_description,
        rr.nist_csf_function,
        rr.nist_csf_category,
        rr.status,
        rr.department_control_owner,
        rr.risk_owner,
        rr.next_review_date,
        rr.evidence,
        rr.key_controls,
        rr.notes,
        rr.treatment_rationale,
        rr.treatment_owner,
        rr.treatment_date,
        rr.risk_treatment,
        rr.assessed_by,
        rr.created_at,
        a.asset_name,
        a.asset_type,
        a.criticality,
        t.threat_name,
        t.threat_type                AS threat_source,
        ra.id                        AS analysis_id,
        COALESCE(ra.inherent_likelihood, ra.likelihood, 0) AS likelihood,
        COALESCE(ra.inherent_likelihood_label, ra.likelihood_label, '') AS likelihood_label,
        COALESCE(ra.inherent_impact, ra.impact, 0) AS impact,
        COALESCE(ra.inherent_impact_label, ra.impact_label, '') AS impact_label,
        COALESCE(ra.inherent_risk_score, ra.risk_score, 0) AS risk_score,
        COALESCE(ra.inherent_risk_level, ra.risk_level, 'Unknown') AS risk_level,
        COALESCE(ra.inherent_likelihood, ra.likelihood, 0) AS inherent_likelihood,
        COALESCE(ra.inherent_likelihood_label, ra.likelihood_label, '') AS inherent_likelihood_label,
        COALESCE(ra.inherent_impact, ra.impact, 0) AS inherent_impact,
        COALESCE(ra.inherent_impact_label, ra.impact_label, '') AS inherent_impact_label,
        COALESCE(ra.inherent_risk_score, ra.risk_score, 0) AS inherent_risk_score,
        COALESCE(ra.inherent_risk_level, ra.risk_level, 'Unknown') AS inherent_risk_level,
        COALESCE(ra.inherent_likelihood_rationale, ra.likelihood_rationale, '') AS inherent_likelihood_rationale,
        COALESCE(ra.inherent_impact_rationale, ra.impact_rationale, '') AS inherent_impact_rationale,
        COALESCE(ra.inherent_calculation_method, 'automated') AS inherent_calculation_method,
        COALESCE(ra.inherent_assessor_override, FALSE) AS inherent_assessor_override,
        COALESCE(ra.inherent_review_status, 'Needs Inherent Review') AS inherent_review_status,
        ra.inherent_assessed_at,
        ra.residual_risk_score,
        ra.residual_risk_level,
        ra.residual_calculated_at,
        COALESCE(ra.control_effectiveness, 0) AS control_effectiveness,
        ra.business_impact_description,
        (SELECT COUNT(*)::int FROM control_recommendations cr
         WHERE cr.risk_register_id = rr.id) AS control_count
      FROM risk_register rr
      LEFT JOIN assets  a  ON a.id  = rr.asset_id
      LEFT JOIN threats t  ON t.id  = rr.threat_id
      LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id
      WHERE 1=1
    `;
    const params: unknown[] = [];

    if (assetId) {
      query += ` AND rr.asset_id = $${params.length + 1}`;
      params.push(Number(assetId));
    }

    query += ` ORDER BY COALESCE(ra.inherent_risk_score, ra.risk_score, 0) DESC, rr.created_at DESC`;

    const result = await pool.query(query, params);

    return NextResponse.json({
      assessments: result.rows,
      count: result.rows.length,
    });
  } catch (err: unknown) {
    console.error("GET /api/assessments error:", err);
    return NextResponse.json(
      { error: "Failed to fetch assessments" },
      { status: 500 },
    );
  }
}

export async function POST(req: NextRequest) {
  const client = await pool.connect();
  try {
    await ensureAssessmentsSchema();

    const body = await req.json();
    const {
      asset_id,
      threat_id,
      risk_title,
      risk_description,
      nist_csf_function,
      nist_csf_category,
      likelihood,
      impact,
      likelihood_rationale,
      impact_rationale,
      business_impact_description,
      department_control_owner,
      risk_owner,
      next_review_date,
      evidence,
      key_controls,
      control_effectiveness,
      risk_treatment,
      treatment_rationale,
      treatment_owner,
      treatment_date,
      assessed_by,
      notes,
      needs_manual_scoring,
    } = body;

    const hasManualScore = likelihood !== undefined && likelihood !== null && impact !== undefined && impact !== null;

    if (!risk_title) {
      return NextResponse.json(
        { error: "risk_title is required" },
        { status: 400 },
      );
    }
    if (!hasManualScore && !needs_manual_scoring) {
      return NextResponse.json(
        { error: "likelihood and impact are required unless the risk is created as a manual-scoring candidate" },
        { status: 400 },
      );
    }
    if (
      hasManualScore &&
      (likelihood < 1 || likelihood > 5 || impact < 1 || impact > 5)
    ) {
      return NextResponse.json(
        { error: "Likelihood and impact must be between 1 and 5" },
        { status: 400 },
      );
    }

    await client.query("BEGIN");

    const riskCode = await generateRiskCode(client as unknown as { query: typeof pool.query });

    const ce = Math.min(100, Math.max(0, Number(control_effectiveness) || 0));
    const riskScore = hasManualScore ? Number(likelihood) * Number(impact) : null;
    const riskLevel = riskScore ? calcRiskLevel(riskScore) : null;
    const residualScore =
      riskScore !== null ? Math.round(riskScore * (1 - ce / 100)) : null;
    const residualLevel =
      residualScore !== null ? calcRiskLevel(residualScore) : null;

    const rrResult = await client.query(
      `INSERT INTO risk_register
         (risk_code, asset_id, threat_id, risk_title, risk_description,
          nist_csf_function, nist_csf_category,
          department_control_owner, assessed_by, notes, status,
          risk_treatment, treatment_rationale, treatment_owner, treatment_date,
          risk_owner, next_review_date, evidence, key_controls)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'Open',$11,$12,$13,$14,$15,$16,$17,$18)
       RETURNING id`,
      [
        riskCode,
        asset_id ? Number(asset_id) : null,
        threat_id ? Number(threat_id) : null,
        risk_title,
        risk_description ?? null,
        nist_csf_function ?? null,
        nist_csf_category ?? null,
        department_control_owner ?? null,
        assessed_by ?? null,
        notes ?? null,
        risk_treatment ?? null,
        treatment_rationale ?? null,
        treatment_owner ?? null,
        treatment_date ?? null,
        risk_owner ?? null,
        next_review_date ?? null,
        evidence ?? null,
        key_controls ?? null,
      ],
    );
    const riskRegisterId = rrResult.rows[0].id;

    if (hasManualScore && riskScore !== null && residualScore !== null) {
      await client.query(
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
            inherent_review_status, inherent_assessed_at,
            business_impact_description,
            control_effectiveness,
            residual_risk_score, residual_risk_level, residual_calculated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)`,
        [
          riskRegisterId,
          likelihood,
          LIKELIHOOD_LABELS[likelihood],
          likelihood_rationale ?? null,
          impact,
          IMPACT_LABELS[impact],
          impact_rationale ?? null,
          riskScore,
          riskLevel,
          likelihood,
          LIKELIHOOD_LABELS[likelihood],
          impact,
          IMPACT_LABELS[impact],
          riskScore,
          riskLevel,
          likelihood_rationale ?? null,
          impact_rationale ?? null,
          "manual",
          true,
          "Inherent Risk Validated",
          new Date(),
          business_impact_description ?? null,
          ce,
          residualScore,
          residualLevel,
          new Date(),
        ],
      );
    }

    await client.query("COMMIT");

    return NextResponse.json(
      {
        success: true,
        risk_code: riskCode,
        risk_register_id: riskRegisterId,
        risk_score: riskScore,
        risk_level: riskLevel,
        residual_risk_score: residualScore,
        residual_risk_level: residualLevel,
      },
      { status: 201 },
    );
  } catch (err: unknown) {
    await client.query("ROLLBACK");
    console.error("POST /api/assessments error:", err);
    const message =
      err instanceof Error ? err.message : "Failed to create assessment";
    return NextResponse.json({ error: message }, { status: 500 });
  } finally {
    client.release();
  }
}

export async function PUT(req: NextRequest) {
  const client = await pool.connect();
  try {
    await ensureAssessmentsSchema();

    const body = await req.json();
    const {
      risk_id,
      asset_id,
      threat_id,
      risk_title,
      risk_description,
      nist_csf_function,
      nist_csf_category,
      likelihood,
      impact,
      likelihood_rationale,
      impact_rationale,
      business_impact_description,
      department_control_owner,
      risk_owner,
      next_review_date,
      evidence,
      key_controls,
      control_effectiveness,
      risk_treatment,
      treatment_rationale,
      treatment_owner,
      treatment_date,
      assessed_by,
      notes,
      status,
    } = body;

    if (!risk_id) {
      return NextResponse.json({ error: "risk_id is required" }, { status: 400 });
    }
    if (likelihood !== undefined && (likelihood < 1 || likelihood > 5)) {
      return NextResponse.json(
        { error: "Likelihood must be between 1 and 5" },
        { status: 400 },
      );
    }
    if (impact !== undefined && (impact < 1 || impact > 5)) {
      return NextResponse.json(
        { error: "Impact must be between 1 and 5" },
        { status: 400 },
      );
    }

    await client.query("BEGIN");

    await client.query(
      `UPDATE risk_register SET
         asset_id = COALESCE($1, asset_id),
         threat_id = COALESCE($2, threat_id),
         risk_title = COALESCE($3, risk_title),
         risk_description = COALESCE($4, risk_description),
         nist_csf_function = COALESCE($5, nist_csf_function),
         nist_csf_category = COALESCE($6, nist_csf_category),
         department_control_owner = COALESCE($7, department_control_owner),
         assessed_by = COALESCE($8, assessed_by),
         notes = COALESCE($9, notes),
         status = COALESCE($10, status),
         risk_treatment = COALESCE($11, risk_treatment),
         treatment_rationale = COALESCE($12, treatment_rationale),
         treatment_owner = COALESCE($13, treatment_owner),
         treatment_date = COALESCE($14, treatment_date),
         risk_owner = COALESCE($15, risk_owner),
         next_review_date = COALESCE($16, next_review_date),
         evidence = COALESCE($17, evidence),
         key_controls = COALESCE($18, key_controls),
         updated_at = NOW()
       WHERE id = $19`,
      [
        asset_id !== undefined ? (asset_id ? Number(asset_id) : null) : null,
        threat_id !== undefined ? (threat_id ? Number(threat_id) : null) : null,
        risk_title ?? null,
        risk_description ?? null,
        nist_csf_function ?? null,
        nist_csf_category ?? null,
        department_control_owner ?? null,
        assessed_by ?? null,
        notes ?? null,
        status ?? null,
        risk_treatment ?? null,
        treatment_rationale ?? null,
        treatment_owner ?? null,
        treatment_date ?? null,
        risk_owner ?? null,
        next_review_date ?? null,
        evidence ?? null,
        key_controls ?? null,
        Number(risk_id),
      ],
    );

    if (likelihood !== undefined && impact !== undefined) {
      const L = Number(likelihood);
      const I = Number(impact);
      const riskScore = L * I;
      const riskLevel = calcRiskLevel(riskScore);
      const ce = Math.min(100, Math.max(0, Number(control_effectiveness) || 0));
      const residualScore = Math.round(riskScore * (1 - ce / 100));
      const residualLevel = calcRiskLevel(residualScore);

      await client.query(
        `INSERT INTO risk_analysis
           (risk_register_id, likelihood, likelihood_label, likelihood_rationale,
            impact, impact_label, impact_rationale,
            risk_score, risk_level,
            inherent_likelihood, inherent_likelihood_label,
            inherent_impact, inherent_impact_label,
            inherent_risk_score, inherent_risk_level,
            inherent_likelihood_rationale, inherent_impact_rationale,
            inherent_calculation_method, inherent_assessor_override,
            inherent_review_status, inherent_assessed_at,
            business_impact_description,
            control_effectiveness,
            residual_risk_score, residual_risk_level, residual_calculated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
         ON CONFLICT (risk_register_id) DO UPDATE SET
           likelihood = EXCLUDED.likelihood,
           likelihood_label = EXCLUDED.likelihood_label,
           likelihood_rationale = EXCLUDED.likelihood_rationale,
           impact = EXCLUDED.impact,
           impact_label = EXCLUDED.impact_label,
           impact_rationale = EXCLUDED.impact_rationale,
           risk_score = EXCLUDED.risk_score,
           risk_level = EXCLUDED.risk_level,
           inherent_likelihood = EXCLUDED.inherent_likelihood,
           inherent_likelihood_label = EXCLUDED.inherent_likelihood_label,
           inherent_impact = EXCLUDED.inherent_impact,
           inherent_impact_label = EXCLUDED.inherent_impact_label,
           inherent_risk_score = EXCLUDED.inherent_risk_score,
           inherent_risk_level = EXCLUDED.inherent_risk_level,
           inherent_likelihood_rationale = EXCLUDED.inherent_likelihood_rationale,
           inherent_impact_rationale = EXCLUDED.inherent_impact_rationale,
           inherent_calculation_method = EXCLUDED.inherent_calculation_method,
           inherent_assessor_override = EXCLUDED.inherent_assessor_override,
           inherent_review_status = EXCLUDED.inherent_review_status,
           inherent_assessed_at = EXCLUDED.inherent_assessed_at,
           business_impact_description = COALESCE(EXCLUDED.business_impact_description, risk_analysis.business_impact_description),
           control_effectiveness = EXCLUDED.control_effectiveness,
           residual_risk_score = EXCLUDED.residual_risk_score,
           residual_risk_level = EXCLUDED.residual_risk_level,
           residual_calculated_at = EXCLUDED.residual_calculated_at,
           updated_at = NOW()`,
        [
          Number(risk_id),
          L,
          LIKELIHOOD_LABELS[L],
          likelihood_rationale ?? null,
          I,
          IMPACT_LABELS[I],
          impact_rationale ?? null,
          riskScore,
          riskLevel,
          L,
          LIKELIHOOD_LABELS[L],
          I,
          IMPACT_LABELS[I],
          riskScore,
          riskLevel,
          likelihood_rationale ?? null,
          impact_rationale ?? null,
          "manual",
          true,
          "Inherent Risk Validated",
          new Date(),
          business_impact_description ?? null,
          ce,
          residualScore,
          residualLevel,
          new Date(),
        ],
      );
    } else if (control_effectiveness !== undefined) {
      // Update only control effectiveness and recompute residual
      const ceVal = Math.min(100, Math.max(0, Number(control_effectiveness)));
      await client.query(
        `UPDATE risk_analysis SET
           control_effectiveness = $1,
           residual_risk_score = ROUND(inherent_risk_score * (1 - $1::numeric / 100)),
           residual_risk_level = CASE
             WHEN ROUND(inherent_risk_score * (1 - $1::numeric / 100)) <= 4 THEN 'Low'
             WHEN ROUND(inherent_risk_score * (1 - $1::numeric / 100)) <= 9 THEN 'Medium'
             WHEN ROUND(inherent_risk_score * (1 - $1::numeric / 100)) <= 16 THEN 'High'
             ELSE 'Critical'
           END,
           residual_calculated_at = NOW(),
           updated_at = NOW()
         WHERE risk_register_id = $2`,
        [ceVal, Number(risk_id)],
      );
    }

    await client.query("COMMIT");

    return NextResponse.json({ success: true });
  } catch (err: unknown) {
    await client.query("ROLLBACK");
    console.error("PUT /api/assessments error:", err);
    const message =
      err instanceof Error ? err.message : "Failed to update assessment";
    return NextResponse.json({ error: message }, { status: 500 });
  } finally {
    client.release();
  }
}

export async function DELETE(req: NextRequest) {
  try {
    await ensureAssessmentsSchema();

    const { searchParams } = new URL(req.url);
    const deleteAll = searchParams.get("all") === "true";

    if (deleteAll) {
      const deleted = await deleteAllRiskData();
      return NextResponse.json({ success: true, deleted });
    }

    const riskId = searchParams.get("risk_id");

    if (!riskId) {
      return NextResponse.json({ error: "risk_id is required" }, { status: 400 });
    }

    const result = await pool.query(
      "DELETE FROM risk_register WHERE id = $1 RETURNING risk_code",
      [Number(riskId)],
    );

    if (result.rows.length === 0) {
      return NextResponse.json({ error: "Risk not found" }, { status: 404 });
    }

    return NextResponse.json({
      success: true,
      deleted: result.rows[0].risk_code,
    });
  } catch (err: unknown) {
    console.error("DELETE /api/assessments error:", err);
    return NextResponse.json(
      { error: "Failed to delete assessment" },
      { status: 500 },
    );
  }
}

function normalizeScore(value: unknown) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return null;
  return Math.min(5, Math.max(1, Math.trunc(parsed)));
}

function normalizeText(value: unknown) {
  if (value === undefined || value === null) return null;
  const trimmed = String(value).trim();
  return trimmed.length ? trimmed : null;
}

type InherentRiskPatchBody = {
  analysis_id?: number;
  risk_register_id?: number;
  likelihood?: number;
  impact?: number;
  likelihood_rationale?: string | null;
  impact_rationale?: string | null;
  business_impact_description?: string | null;
  assessed_by?: string | null;
  review_status?: string | null;
};

export async function PATCH(req: NextRequest) {
  const client = await pool.connect();

  try {
    await ensureAssessmentsSchema();
    const body = (await req.json()) as InherentRiskPatchBody;
    const rawAnalysisId = Number(body.analysis_id);
    const rawRiskRegisterId = Number(body.risk_register_id);
    const analysisId =
      Number.isFinite(rawAnalysisId) && rawAnalysisId > 0
        ? rawAnalysisId
        : null;
    const riskRegisterId =
      Number.isFinite(rawRiskRegisterId) && rawRiskRegisterId > 0
        ? rawRiskRegisterId
        : null;
    const likelihood = normalizeScore(body.likelihood);
    const impact = normalizeScore(body.impact);

    if (!analysisId && !riskRegisterId) {
      return NextResponse.json(
        { error: "analysis_id or risk_register_id is required" },
        { status: 400 },
      );
    }

    if (!likelihood || !impact) {
      return NextResponse.json(
        { error: "likelihood and impact must be between 1 and 5" },
        { status: 400 },
      );
    }

    const riskScore = likelihood * impact;
    const riskLevel = calcRiskLevel(riskScore);
    const reviewStatus =
      normalizeText(body.review_status) ?? "Inherent Risk Validated";
    const likelihoodRationale = normalizeText(body.likelihood_rationale);
    const impactRationale = normalizeText(body.impact_rationale);

    await client.query("BEGIN");

    const params = [
      likelihood,
      LIKELIHOOD_LABELS[likelihood],
      likelihoodRationale,
      impact,
      IMPACT_LABELS[impact],
      impactRationale,
      riskScore,
      riskLevel,
      reviewStatus,
      normalizeText(body.business_impact_description),
      analysisId ?? riskRegisterId,
    ];

    const idColumn = analysisId ? "id" : "risk_register_id";
    const result = await client.query(
      `UPDATE risk_analysis
          SET likelihood = $1,
              likelihood_label = $2,
              likelihood_rationale = $3,
              impact = $4,
              impact_label = $5,
              impact_rationale = $6,
              risk_score = $7,
              risk_level = $8,
              inherent_likelihood = $1,
              inherent_likelihood_label = $2,
              inherent_likelihood_rationale = $3,
              inherent_impact = $4,
              inherent_impact_label = $5,
              inherent_impact_rationale = $6,
              inherent_risk_score = $7,
              inherent_risk_level = $8,
              inherent_calculation_method = 'assessor_review',
              inherent_assessor_override = TRUE,
              inherent_review_status = $9,
              inherent_assessed_at = NOW(),
              business_impact_description = COALESCE($10, business_impact_description),
              residual_risk_score = ROUND($7 * (1 - COALESCE(control_effectiveness, 0)::numeric / 100)),
              residual_risk_level = CASE
                WHEN ROUND($7 * (1 - COALESCE(control_effectiveness, 0)::numeric / 100)) <= 4 THEN 'Low'
                WHEN ROUND($7 * (1 - COALESCE(control_effectiveness, 0)::numeric / 100)) <= 9 THEN 'Medium'
                WHEN ROUND($7 * (1 - COALESCE(control_effectiveness, 0)::numeric / 100)) <= 16 THEN 'High'
                ELSE 'Critical'
              END,
              residual_calculated_at = NOW(),
              updated_at = NOW()
        WHERE ${idColumn} = $11
        RETURNING *`,
      params,
    );

    if (result.rows.length === 0) {
      await client.query("ROLLBACK");
      return NextResponse.json(
        { error: "Risk analysis not found" },
        { status: 404 },
      );
    }

    if (body.assessed_by || riskRegisterId) {
      const registerId = result.rows[0].risk_register_id;
      await client.query(
        `UPDATE risk_register
            SET assessed_by = COALESCE($1, assessed_by),
                updated_at = NOW()
          WHERE id = $2`,
        [normalizeText(body.assessed_by), registerId],
      );
    }

    await client.query("COMMIT");

    return NextResponse.json({
      success: true,
      analysis: result.rows[0],
      risk_score: riskScore,
      risk_level: riskLevel,
    });
  } catch (err: unknown) {
    await client.query("ROLLBACK");
    console.error("PATCH /api/assessments error:", err);
    const message =
      err instanceof Error ? err.message : "Failed to update inherent risk";
    return NextResponse.json({ error: message }, { status: 500 });
  } finally {
    client.release();
  }
}
