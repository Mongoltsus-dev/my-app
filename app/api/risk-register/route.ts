import { pool } from "@/lib/db";
import {
  MANAGEMENT_APPROVER_LABEL,
  ROLE_MANAGER,
  getCurrentUser,
} from "@/lib/current-user";
import { NextRequest, NextResponse } from "next/server";

function analysisColumn(
  hasColumns: Set<string>,
  columnName: string,
  type: "integer" | "text" = "integer",
) {
  return hasColumns.has(columnName) ? `ra.${columnName}` : `NULL::${type}`;
}

const NIST_FUNCTION_LABELS: Record<string, string> = {
  GV: "Govern",
  ID: "Identify",
  PR: "Protect",
  DE: "Detect",
  RS: "Respond",
  RC: "Recover",
};

const NIST_FUNCTION_ALIASES: Record<string, string> = {
  GOVERN: "GV",
  IDENTIFY: "ID",
  PROTECT: "PR",
  DETECT: "DE",
  RESPOND: "RS",
  RECOVER: "RC",
  "ЗАСАГЛАЛ": "GV",
  "ТАНИХ": "ID",
  "ХАМГААЛАХ": "PR",
  "ИЛРҮҮЛЭХ": "DE",
  "ХАРИУ АРГА ХЭМЖЭЭ": "RS",
  "ХАРИУ ҮЙЛДЭЛ": "RS",
  "СЭРГЭЭХ": "RC",
};

function normalizeNistCategory(
  category: string | null | undefined,
  functionValue: string | null | undefined,
  threatCategory: string | null | undefined,
) {
  for (const candidate of [category, threatCategory]) {
    const raw = String(candidate ?? "").trim();
    if (raw) return raw.toUpperCase();
  }

  const functionText = String(functionValue ?? "").trim();
  const prefix = functionText.split(/[.\s-]/)[0].toUpperCase();
  if (functionText.includes(".") && NIST_FUNCTION_LABELS[prefix]) {
    return functionText.toUpperCase();
  }

  return null;
}

function normalizeNistFunction(
  value: string | null | undefined,
  category: string | null | undefined,
) {
  for (const candidate of [category, value]) {
    const raw = String(candidate ?? "").trim();
    if (!raw) continue;

    const prefix = raw.split(/[.\s-]/)[0].toUpperCase();
    if (NIST_FUNCTION_LABELS[prefix]) return prefix;

    const alias = NIST_FUNCTION_ALIASES[raw.toUpperCase()];
    if (alias) return alias;
  }

  return null;
}

// GET - Fetch risk register entries
export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const assetId = searchParams.get("asset_id");
    const status = searchParams.get("status");
    const riskId = searchParams.get("risk_id");
    const analysisColumns = new Set(
      (
        await pool.query(
          `SELECT column_name
             FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'risk_analysis'`,
        )
      ).rows.map((row: { column_name: string }) => row.column_name),
    );
    const joinConditions = [
      analysisColumns.has("risk_register_id")
        ? "ra.risk_register_id = rr.id"
        : null,
      analysisColumns.has("risk_id") ? "ra.risk_id = rr.id" : null,
    ].filter(Boolean);

    let query = `
      SELECT rr.*, rr.risk_code AS risk_id,
        t.threat_name, t.threat_type AS threat_source, t.threat_type AS threat_category,
        a.asset_name, a.asset_type, a.criticality,
        COALESCE(${analysisColumn(analysisColumns, "inherent_likelihood")}, ${analysisColumn(analysisColumns, "likelihood")}) AS inherent_likelihood,
        COALESCE(${analysisColumn(analysisColumns, "inherent_impact")}, ${analysisColumn(analysisColumns, "impact")}) AS inherent_impact,
        COALESCE(${analysisColumn(analysisColumns, "inherent_risk_score")}, ${analysisColumn(analysisColumns, "risk_score")}) AS inherent_risk_score,
        COALESCE(${analysisColumn(analysisColumns, "inherent_risk_level", "text")}, ${analysisColumn(analysisColumns, "risk_level", "text")}) AS inherent_risk_level,
        ${analysisColumn(analysisColumns, "residual_risk_score")} AS residual_risk_score,
        ${analysisColumn(analysisColumns, "residual_risk_level", "text")} AS residual_risk_level
      FROM risk_register rr
      LEFT JOIN threats t ON rr.threat_id = t.id
      LEFT JOIN assets a ON rr.asset_id = a.id
      LEFT JOIN LATERAL (
        SELECT *
          FROM risk_analysis ra
         WHERE ${joinConditions.length > 0 ? joinConditions.join(" OR ") : "false"}
         ORDER BY ra.id DESC
         LIMIT 1
      ) ra ON true
      WHERE 1=1
    `;
    const params: (string | number)[] = [];

    if (assetId) {
      query += ` AND rr.asset_id = $${params.length + 1}`;
      params.push(assetId);
    }

    if (status) {
      query += ` AND rr.status = $${params.length + 1}`;
      params.push(status);
    }

    if (riskId) {
      query += ` AND rr.id = $${params.length + 1}`;
      params.push(riskId);
    }

    query += ` ORDER BY rr.created_at DESC`;

    const result = await pool.query(query, params);

    return NextResponse.json({
      risks: result.rows || [],
      count: result.rows?.length || 0,
    });
  } catch (err: unknown) {
    console.error("Error fetching risk register:", err);
    return NextResponse.json(
      { error: "Failed to fetch risk register" },
      { status: 500 },
    );
  }
}

// POST - Create new risk in the register
export async function POST(req: NextRequest) {
  try {
    const {
      asset_id,
      threat_id,
      risk_title,
      risk_description,
      vulnerability_description,
      nist_csf_function,
      nist_csf_category,
      department_control_owner,
      assessed_by,
      notes,
    } = await req.json();

    const assetId =
      asset_id == null || asset_id === "" ? null : Number(asset_id);
    const threatId =
      threat_id == null || threat_id === "" ? null : Number(threat_id);

    // Validate required fields
    if (!risk_title?.trim()) {
      return NextResponse.json(
        { error: "risk_title is required" },
        { status: 400 },
      );
    }

    // Get asset details
    const assetResult = assetId
      ? await pool.query("SELECT * FROM assets WHERE id = $1", [assetId])
      : { rows: [] };

    if (assetId && assetResult.rows.length === 0) {
      return NextResponse.json({ error: "Asset not found" }, { status: 404 });
    }

    // Look up threat from the threats table
    const threatResult = threatId
      ? await pool.query("SELECT * FROM threats WHERE id = $1", [threatId])
      : { rows: [] };

    // A supplied threat_id must reference a real threat — otherwise the INSERT
    // would either violate the threat_id FK (opaque 500) or create an orphan
    // risk with a dangling threat_id and null threat_name.
    if (threatId && threatResult.rows.length === 0) {
      return NextResponse.json({ error: "Threat not found" }, { status: 404 });
    }

    const threat = threatResult.rows[0] ?? null;
    const asset = assetResult.rows[0] ?? null;
    const normalizedNistCategory = normalizeNistCategory(
      nist_csf_category,
      nist_csf_function,
      threat?.nist_category,
    );
    const normalizedNistFunction = normalizeNistFunction(
      nist_csf_function,
      normalizedNistCategory,
    );

    // Duplicate check: skip if an open risk for this asset+threat already exists
    if (assetId && threatId) {
      const existing = await pool.query(
        `SELECT id, risk_code, status
           FROM risk_register
          WHERE asset_id = $1
            AND threat_id = $2
            AND COALESCE(status, 'Open') <> 'Closed'
          ORDER BY created_at DESC
          LIMIT 1`,
        [assetId, threatId],
      );
      if (existing.rows.length > 0) {
        return NextResponse.json({
          message: "Risk already registered",
          duplicate: true,
          risk: existing.rows[0],
        });
      }
    }

    // Duplicate check for framework risks (no asset/threat): match by risk_title + nist_csf_category
    if (!assetId && !threatId && risk_title?.trim()) {
      const existing = await pool.query(
        `SELECT id, risk_code, status
           FROM risk_register
          WHERE (asset_id IS NULL OR asset_id = 0)
            AND (threat_id IS NULL OR threat_id = 0)
            AND risk_title = $1
            AND ($2::text IS NULL OR nist_csf_category = $2)
            AND COALESCE(status, 'Open') <> 'Closed'
          ORDER BY created_at DESC
          LIMIT 1`,
        [risk_title.trim(), normalizedNistCategory],
      );
      if (existing.rows.length > 0) {
        return NextResponse.json({
          message: "Risk already registered",
          duplicate: true,
          risk: existing.rows[0],
        });
      }
    }

    // Generate unique risk code
    const riskCode = `RISK-${Date.now()}`;

    // Combine description fields into risk_description
    const combinedDescription =
      risk_description || vulnerability_description || null;

    // Insert into risk_register (only columns that actually exist in the table)
    const result = await pool.query(
      `INSERT INTO risk_register (
        risk_code, asset_id, threat_id, risk_title, risk_description,
        nist_csf_function, nist_csf_category,
        department_control_owner, assessed_by, notes,
        created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      RETURNING *`,
      [
        riskCode,
        assetId,
        threatId,
        risk_title,
        combinedDescription,
        normalizedNistFunction,
        normalizedNistCategory,
        department_control_owner || null,
        assessed_by || null,
        notes || null,
      ],
    );

    const newRisk = result.rows[0];

    return NextResponse.json({
      message: "Risk registered successfully",
      risk: {
        id: newRisk.id,
        risk_id: newRisk.risk_code,
        risk_code: newRisk.risk_code,
        asset_id: newRisk.asset_id,
        threat_id: newRisk.threat_id,
        asset_name: asset?.asset_name ?? null,
        threat_name: threat?.threat_name ?? null,
        status: newRisk.status,
        nist_csf_function: newRisk.nist_csf_function,
        nist_csf_category: newRisk.nist_csf_category,
      },
    });
  } catch (error: unknown) {
    console.error("Risk register creation error:", error);
    const message =
      error instanceof Error ? error.message : "Failed to create risk";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

// PATCH - Update risk treatment
export async function PATCH(req: NextRequest) {
  try {
    const {
      risk_register_id,
      risk_treatment,
      treatment_rationale,
      treatment_owner,
      treatment_date,
      risk_treatment_approval_status,
    } = await req.json();

    if (!risk_register_id) {
      return NextResponse.json(
        { error: "risk_register_id is required" },
        { status: 400 },
      );
    }

    for (const ddl of [
      "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS risk_treatment_approval_status VARCHAR(20)",
      "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS risk_treatment_approved_by VARCHAR(255)",
      "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS risk_treatment_approved_at TIMESTAMP",
    ]) {
      await pool.query(ddl);
    }

    if (risk_treatment_approval_status !== undefined) {
      if (!["pending", "approved", "rejected"].includes(risk_treatment_approval_status)) {
        return NextResponse.json(
          { error: "Invalid approval status" },
          { status: 400 },
        );
      }

      const approver = await getCurrentUser(req);
      if (!approver) {
        return NextResponse.json(
          { error: "Нэвтэрсэн хэрэглэгч олдсонгүй" },
          { status: 401 },
        );
      }
      if (approver.role_id !== ROLE_MANAGER) {
        return NextResponse.json(
          { error: "Зөвхөн удирдлага дүртэй хэрэглэгч арга хэмжээг батлах эрхтэй" },
          { status: 403 },
        );
      }

      const result = await pool.query(
        `UPDATE risk_register
            SET risk_treatment_approval_status = $1::varchar,
                risk_treatment_approved_by = CASE WHEN $1::varchar = 'approved' THEN $2::varchar ELSE NULL END,
                risk_treatment_approved_at = CASE WHEN $1::varchar = 'approved' THEN NOW() ELSE NULL END,
                updated_at = NOW()
          WHERE id = $3
          RETURNING *`,
        [
          risk_treatment_approval_status,
          MANAGEMENT_APPROVER_LABEL,
          risk_register_id,
        ],
      );
      if (result.rows.length === 0) {
        return NextResponse.json({ error: "Risk not found" }, { status: 404 });
      }
      return NextResponse.json({ success: true, risk: result.rows[0] });
    }

    const TREATMENT_ALIASES: Record<string, string> = {
      Reduce: "Mitigate",
      Treat: "Mitigate",
      Mitigate: "Mitigate",
      Accept: "Accept",
      Tolerate: "Accept",
      Transfer: "Transfer",
      Avoid: "Avoid",
      Terminate: "Avoid",
    };
    const normalizedTreatment = risk_treatment
      ? TREATMENT_ALIASES[String(risk_treatment)]
      : null;
    if (risk_treatment && !normalizedTreatment) {
      return NextResponse.json(
        { error: "Invalid risk_treatment value" },
        { status: 400 },
      );
    }

    // Ensure treatment columns exist (idempotent)
    for (const ddl of [
      "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS risk_treatment VARCHAR(20)",
      "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS treatment_rationale TEXT",
      "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS treatment_owner VARCHAR(255)",
      "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS treatment_date DATE",
    ]) {
      await pool.query(ddl);
    }
    const existing = await pool.query(
      `SELECT risk_treatment,
              risk_treatment_approval_status,
              risk_treatment_approved_by,
              risk_treatment_approved_at
         FROM risk_register
        WHERE id = $1`,
      [risk_register_id],
    );
    if (existing.rows.length === 0) {
      return NextResponse.json({ error: "Risk not found" }, { status: 404 });
    }

    const previous = existing.rows[0] as {
      risk_treatment: string | null;
      risk_treatment_approval_status: string | null;
      risk_treatment_approved_by: string | null;
      risk_treatment_approved_at: string | null;
    };
    const treatmentChanged = previous.risk_treatment !== normalizedTreatment;
    const approvalStatus = normalizedTreatment
      ? treatmentChanged
        ? "pending"
        : (previous.risk_treatment_approval_status ?? "pending")
      : null;
    const approvedBy =
      approvalStatus === "approved" && !treatmentChanged
        ? previous.risk_treatment_approved_by
        : null;
    const approvedAt =
      approvalStatus === "approved" && !treatmentChanged
        ? previous.risk_treatment_approved_at
        : null;

    const result = await pool.query(
      `UPDATE risk_register
          SET risk_treatment      = $1,
              treatment_rationale = $2,
              treatment_owner     = $3,
              treatment_date      = $4,
              risk_treatment_approval_status = $5::varchar,
              risk_treatment_approved_by = $6,
              risk_treatment_approved_at = $7,
              updated_at          = NOW()
        WHERE id = $8
        RETURNING *`,
      [
        normalizedTreatment,
        treatment_rationale?.trim() || null,
        treatment_owner?.trim() || null,
        treatment_date || null,
        approvalStatus,
        approvedBy,
        approvedAt,
        risk_register_id,
      ],
    );

    return NextResponse.json({ success: true, risk: result.rows[0] });
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : "Failed to update treatment";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

// PUT - Update risk status
export async function PUT(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const riskId = searchParams.get("id");

    if (!riskId) {
      return NextResponse.json(
        { error: "Risk ID is required" },
        { status: 400 },
      );
    }

    const { status, notes } = await req.json();

    if (!status) {
      return NextResponse.json(
        { error: "Status is required" },
        { status: 400 },
      );
    }

    const result = await pool.query(
      `UPDATE risk_register SET status = $1, notes = $2, updated_at = CURRENT_TIMESTAMP
       WHERE id = $3 RETURNING *`,
      [status, notes || null, riskId],
    );

    if (result.rows.length === 0) {
      return NextResponse.json({ error: "Risk not found" }, { status: 404 });
    }

    return NextResponse.json({
      message: "Risk updated successfully",
      risk: result.rows[0],
    });
  } catch (error: unknown) {
    console.error("Risk update error:", error);
    const message =
      error instanceof Error ? error.message : "Failed to update risk";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
