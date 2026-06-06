import { pool } from "@/lib/db";
import { exportRows } from "@/lib/report-export";
import { NextRequest, NextResponse } from "next/server";

type ReportType =
  | "risk-summary"
  | "asset-risk"
  | "compliance"
  | "risk-treatment";

async function tableExists(tableName: string) {
  const result = await pool.query("SELECT to_regclass($1) AS name", [
    tableName,
  ]);
  return Boolean(result.rows[0]?.name);
}

async function ensureControlRecommendationColumns() {
  if (!(await tableExists("control_recommendations"))) return false;
  for (const statement of [
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS risk_register_id INTEGER",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS nist_function VARCHAR(50)",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS implementation_status VARCHAR(50) DEFAULT 'Not Started'",
  ]) {
    await pool.query(statement);
  }
  return true;
}

async function safeRows<T extends Record<string, unknown>>(
  query: string,
  params: unknown[] = [],
) {
  try {
    const result = await pool.query<T>(query, params);
    return result.rows;
  } catch (error) {
    console.warn("Report export query skipped:", error);
    return [] as T[];
  }
}

function getReportType(value: string | null): ReportType {
  if (
    value === "asset-risk" ||
    value === "compliance" ||
    value === "risk-treatment"
  ) {
    return value;
  }
  return "risk-summary";
}

function reportTitle(type: ReportType) {
  const titles: Record<ReportType, string> = {
    "risk-summary": "Эрсдэлийн хураангуй",
    "asset-risk": "Хөрөнгийн эрсдэл",
    compliance: "NIST CSF нийцэл",
    "risk-treatment": "Эрсдэлийн арга хэмжээ",
  };
  return titles[type];
}

async function riskSummaryRows() {
  if (
    !(await tableExists("risk_register")) ||
    !(await tableExists("risk_analysis"))
  ) {
    return [];
  }

  const threatJoin = (await tableExists("threats"))
    ? "LEFT JOIN threats t ON t.id = rr.threat_id"
    : "LEFT JOIN (SELECT NULL::integer AS id, NULL::text AS threat_name) t ON false";

  return safeRows(
    `SELECT rr.risk_code AS "Risk Code",
            rr.risk_title AS "Risk Title",
            COALESCE(a.asset_name, '') AS "Asset",
            COALESCE(a.asset_type, '') AS "Asset Type",
            COALESCE(t.threat_name, '') AS "Threat",
            COALESCE(rr.nist_csf_function, '') AS "NIST Function",
            COALESCE(rr.nist_csf_category, '') AS "NIST Category",
            COALESCE(ra.inherent_likelihood, ra.likelihood, 0) AS "Likelihood",
            COALESCE(ra.inherent_impact, ra.impact, 0) AS "Impact",
            COALESCE(ra.inherent_risk_score, ra.risk_score, 0) AS "Risk Score",
            COALESCE(ra.inherent_risk_level, ra.risk_level, 'Unknown') AS "Risk Level",
            COALESCE(ra.residual_risk_score, 0) AS "Residual Score",
            COALESCE(ra.residual_risk_level, '') AS "Residual Level",
            COALESCE(
              CASE rr.risk_treatment
                WHEN 'Mitigate' THEN 'Treat'
                WHEN 'Accept'   THEN 'Tolerate'
                WHEN 'Avoid'    THEN 'Terminate'
                ELSE rr.risk_treatment
              END,
              'Untreated'
            ) AS "Treatment",
            COALESCE(rr.treatment_owner, rr.department_control_owner, '') AS "Owner",
            COALESCE(rr.status, '') AS "Status"
       FROM risk_register rr
  LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id
  LEFT JOIN assets a ON a.id = rr.asset_id
  ${threatJoin}
      ORDER BY COALESCE(ra.inherent_risk_score, ra.risk_score, 0) DESC, rr.created_at DESC`,
  );
}

async function assetRiskRows() {
  if (!(await tableExists("assets"))) return [];

  const hasRiskRegister = await tableExists("risk_register");
  const hasRiskAnalysis = await tableExists("risk_analysis");
  const vulnerabilityJoin = (await tableExists("vulnerabilities"))
    ? "LEFT JOIN vulnerabilities v ON v.asset_id = a.id"
    : "LEFT JOIN (SELECT NULL::integer AS id, NULL::integer AS asset_id, NULL::text AS status, NULL::text AS source) v ON false";
  const riskJoin = hasRiskRegister
    ? "LEFT JOIN risk_register rr ON rr.asset_id = a.id"
    : "LEFT JOIN (SELECT NULL::integer AS id, NULL::integer AS asset_id) rr ON false";
  const analysisJoin = hasRiskAnalysis
    ? "LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id"
    : "LEFT JOIN (SELECT NULL::integer AS risk_register_id, NULL::integer AS inherent_risk_score, NULL::integer AS risk_score) ra ON false";

  return safeRows(
    `SELECT a.asset_code AS "Asset Code",
            a.asset_name AS "Asset",
            COALESCE(a.asset_type, '') AS "Asset Type",
            COALESCE(a.location, '') AS "Location",
            COALESCE(a.business_owner, '') AS "Business Owner",
            COALESCE(a.technical_owner, '') AS "Technical Owner",
            COALESCE(a.criticality, '') AS "Criticality",
            COALESCE(a.data_classification, '') AS "Classification",
            COALESCE(a.rto_hours::text, '') AS "RTO Hours",
            COALESCE(a.rpo_hours::text, '') AS "RPO Hours",
            COUNT(rr.id) AS "Risk Count",
            COALESCE(MAX(COALESCE(ra.inherent_risk_score, ra.risk_score)), 0) AS "Highest Risk Score",
            COALESCE(ROUND(AVG(COALESCE(ra.inherent_risk_score, ra.risk_score))::numeric, 1), 0) AS "Average Risk Score",
            COUNT(v.id) FILTER (WHERE LOWER(COALESCE(v.status, 'open')) NOT IN ('remediated', 'false_positive')) AS "Open Vulnerabilities"
       FROM assets a
      ${riskJoin}
      ${analysisJoin}
  ${vulnerabilityJoin}
      GROUP BY a.id
      ORDER BY COALESCE(MAX(COALESCE(ra.inherent_risk_score, ra.risk_score)), 0) DESC, a.asset_name ASC`,
  );
}

async function complianceRows() {
  const hasRiskRegister = await tableExists("risk_register");
  const hasControls = await ensureControlRecommendationColumns();
  if (!hasRiskRegister && !hasControls) return [];

  if (!hasRiskRegister) {
    return safeRows(
      `WITH functions AS (
         SELECT unnest(ARRAY['Govern','Identify','Protect','Detect','Respond','Recover']) AS nist_function
       ), control_counts AS (
         SELECT COALESCE(nist_function, 'Identify') AS nist_function,
                COUNT(id) AS control_count,
                COUNT(id) FILTER (WHERE LOWER(COALESCE(implementation_status, 'not started')) IN ('implemented','complete','completed')) AS implemented_count
           FROM control_recommendations
          GROUP BY COALESCE(nist_function, 'Identify')
       )
       SELECT f.nist_function AS "NIST Function",
              0 AS "Mapped Risks",
              COALESCE(c.control_count, 0) AS "Recommended Controls",
              COALESCE(c.implemented_count, 0) AS "Implemented Controls",
              CASE WHEN COALESCE(c.control_count, 0) = 0 THEN 0
                   ELSE ROUND((COALESCE(c.implemented_count, 0)::numeric / c.control_count) * 100)
              END AS "Implementation Rate"
         FROM functions f
    LEFT JOIN control_counts c ON c.nist_function = f.nist_function
        ORDER BY array_position(ARRAY['Govern','Identify','Protect','Detect','Respond','Recover'], f.nist_function)`,
    );
  }

  return safeRows(
    `WITH functions AS (
       SELECT unnest(ARRAY['Govern','Identify','Protect','Detect','Respond','Recover']) AS nist_function
     ), risk_counts AS (
       SELECT COALESCE(nist_csf_function, 'Identify') AS nist_function, COUNT(*) AS risk_count
         FROM risk_register
        GROUP BY COALESCE(nist_csf_function, 'Identify')
     ), control_counts AS (
       SELECT COALESCE(rr.nist_csf_function, cr.nist_function, 'Identify') AS nist_function,
              COUNT(cr.id) AS control_count,
              COUNT(cr.id) FILTER (WHERE LOWER(COALESCE(cr.implementation_status, 'not started')) IN ('implemented','complete','completed')) AS implemented_count
         FROM control_recommendations cr
    LEFT JOIN risk_register rr ON rr.id = cr.risk_register_id
        GROUP BY COALESCE(rr.nist_csf_function, cr.nist_function, 'Identify')
     )
     SELECT f.nist_function AS "NIST Function",
            COALESCE(r.risk_count, 0) AS "Mapped Risks",
            COALESCE(c.control_count, 0) AS "Recommended Controls",
            COALESCE(c.implemented_count, 0) AS "Implemented Controls",
            CASE WHEN COALESCE(c.control_count, 0) = 0 THEN 0
                 ELSE ROUND((COALESCE(c.implemented_count, 0)::numeric / c.control_count) * 100)
            END AS "Implementation Rate"
       FROM functions f
  LEFT JOIN risk_counts r ON r.nist_function = f.nist_function
  LEFT JOIN control_counts c ON c.nist_function = f.nist_function
      ORDER BY array_position(ARRAY['Govern','Identify','Protect','Detect','Respond','Recover'], f.nist_function)`,
  );
}

async function riskTreatmentRows() {
  if (
    !(await tableExists("risk_register")) ||
    !(await tableExists("risk_analysis"))
  ) {
    return [];
  }
  const hasThreatCatalog = await tableExists("threat_catalog");
  const hasThreats = await tableExists("threats");
  const threatCatalogJoin = hasThreatCatalog
    ? "LEFT JOIN threat_catalog tc ON tc.threat_id = rr.threat_id"
    : "LEFT JOIN (SELECT NULL::integer AS threat_id, NULL::text AS threat_name) tc ON false";
  const threatsJoin = hasThreats
    ? "LEFT JOIN threats t ON t.id = rr.threat_id"
    : "LEFT JOIN (SELECT NULL::integer AS id, NULL::text AS threat_name) t ON false";

  return safeRows(
    `SELECT rr.risk_code AS "Risk Code",
            rr.risk_title AS "Risk Title",
            COALESCE(a.asset_name, '') AS "Asset",
            COALESCE(a.asset_type, '') AS "Asset Type",
            COALESCE(a.criticality, '') AS "Asset Criticality",
            COALESCE(tc.threat_name, t.threat_name, '') AS "Threat",
            COALESCE(rr.nist_csf_function, '') AS "NIST Function",
            COALESCE(rr.nist_csf_category, '') AS "NIST Category",
            COALESCE(ra.inherent_likelihood, ra.likelihood, 0) AS "Likelihood",
            COALESCE(ra.inherent_impact, ra.impact, 0) AS "Impact",
            COALESCE(ra.inherent_risk_score, ra.risk_score, 0) AS "Inherent Score",
            COALESCE(ra.inherent_risk_level, ra.risk_level, 'Unknown') AS "Inherent Level",
            COALESCE(ra.residual_risk_score::text, '') AS "Residual Score",
            COALESCE(ra.residual_risk_level, '') AS "Residual Level",
            CASE
              WHEN ra.residual_risk_score IS NULL OR COALESCE(ra.inherent_risk_score, ra.risk_score, 0) = 0
                THEN ''
              ELSE CONCAT(
                GREATEST(
                  0,
                  ROUND((1 - ra.residual_risk_score::numeric / COALESCE(ra.inherent_risk_score, ra.risk_score)::numeric) * 100)
                ),
                '%'
              )
            END AS "Risk Reduction",
            COALESCE(
              CASE rr.risk_treatment
                WHEN 'Mitigate' THEN 'Treat'
                WHEN 'Accept'   THEN 'Tolerate'
                WHEN 'Avoid'    THEN 'Terminate'
                ELSE rr.risk_treatment
              END,
              'Untreated'
            ) AS "Treatment",
            COALESCE(rr.treatment_owner, rr.department_control_owner, '') AS "Treatment Owner",
            COALESCE(rr.treatment_date::text, '') AS "Treatment Date",
            COALESCE(rr.risk_treatment_approval_status, '') AS "Management Approval",
            CASE
              WHEN rr.risk_treatment_approval_status = 'approved'
                THEN 'удирдлага'
              ELSE ''
            END AS "Approved By",
            COALESCE(rr.risk_treatment_approved_at::text, '') AS "Approved At",
            COALESCE(rr.treatment_rationale, '') AS "Rationale",
            COALESCE(rr.status, '') AS "Status",
            COALESCE(
              string_agg(
                DISTINCT COALESCE(cr.control_id, split_part(cr.control_name, ' – ', 1), cr.control_name),
                '; '
              ) FILTER (WHERE cr.id IS NOT NULL),
              ''
            ) AS "Selected Controls"
       FROM risk_register rr
  LEFT JOIN assets a ON a.id = rr.asset_id
  LEFT JOIN LATERAL (
    SELECT *
      FROM risk_analysis ra
     WHERE ra.risk_register_id = rr.id OR ra.risk_id = rr.id
     ORDER BY ra.id DESC
     LIMIT 1
  ) ra ON true
  ${threatCatalogJoin}
  ${threatsJoin}
  LEFT JOIN control_recommendations cr ON cr.risk_register_id = rr.id
      GROUP BY rr.id, a.id, tc.threat_name, t.threat_name,
               ra.inherent_likelihood, ra.likelihood,
               ra.inherent_impact, ra.impact,
               ra.inherent_risk_score, ra.risk_score,
               ra.inherent_risk_level, ra.risk_level,
               ra.residual_risk_score, ra.residual_risk_level
      ORDER BY CASE rr.risk_treatment
                 WHEN 'Terminate' THEN 1
                 WHEN 'Avoid' THEN 1
                 WHEN 'Treat' THEN 2
                 WHEN 'Mitigate' THEN 2
                 WHEN 'Transfer' THEN 3
                 WHEN 'Tolerate' THEN 4
                 WHEN 'Accept' THEN 4
                 ELSE 5
               END,
               COALESCE(ra.inherent_risk_score, ra.risk_score, 0) DESC`,
  );
}

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const type = getReportType(searchParams.get("type"));
    const rows =
      type === "asset-risk"
        ? await assetRiskRows()
        : type === "compliance"
          ? await complianceRows()
          : type === "risk-treatment"
            ? await riskTreatmentRows()
            : await riskSummaryRows();
    const columns = rows.length ? Object.keys(rows[0]) : ["Message"];
    const exportRowsData = rows.length
      ? rows
      : [{ Message: "Өгөгдөл олдсонгүй" }];

    return exportRows({
      rows: exportRowsData,
      columns,
      title: reportTitle(type),
      requestedFormat: searchParams.get("format"),
    });
  } catch (error) {
    console.error("Report export error:", error);
    const message =
      error instanceof Error ? error.message : "Failed to export report";
    return NextResponse.json({ message }, { status: 500 });
  }
}
