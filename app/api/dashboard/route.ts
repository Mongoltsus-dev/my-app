import { pool } from "@/lib/db";
import { NextResponse } from "next/server";

type Row = Record<string, unknown>;

const NIST_FUNCTIONS = [
  "Govern",
  "Identify",
  "Protect",
  "Detect",
  "Respond",
  "Recover",
];

const USER_VULNERABILITY_FILTER =
  "NOT (COALESCE(source, '') = 'cisa_kev' AND asset_id IS NULL)";
const OPEN_USER_VULNERABILITY_FILTER = `${USER_VULNERABILITY_FILTER} AND LOWER(COALESCE(status, 'open')) NOT IN ('remediated', 'false_positive')`;
const ALIASED_USER_VULNERABILITY_FILTER =
  "NOT (COALESCE(v.source, '') = 'cisa_kev' AND v.asset_id IS NULL)";
const ALIASED_OPEN_USER_VULNERABILITY_FILTER = `${ALIASED_USER_VULNERABILITY_FILTER} AND LOWER(COALESCE(v.status, 'open')) NOT IN ('remediated', 'false_positive')`;

async function tableExists(tableName: string) {
  const result = await pool.query("SELECT to_regclass($1) AS name", [
    tableName,
  ]);
  return Boolean(result.rows[0]?.name);
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

async function safeRows<T extends Row>(query: string, params: unknown[] = []) {
  try {
    const result = await pool.query<T>(query, params);
    return result.rows;
  } catch (error) {
    console.warn("Dashboard query skipped:", error);
    return [] as T[];
  }
}

async function safeCount(query: string, params: unknown[] = []) {
  const rows = await safeRows<{ count: string | number }>(query, params);
  return Number(rows[0]?.count ?? 0);
}

function num(value: unknown) {
  return Number(value ?? 0);
}

function pct(part: number, total: number) {
  if (total <= 0) return 0;
  return Math.round((part / total) * 100);
}

function averagePercent(values: number[]) {
  if (!values.length) return 0;
  return Math.round(
    values.reduce((sum, value) => sum + value, 0) / values.length,
  );
}

function normalizeNistFunction(value: unknown) {
  const normalized = String(value ?? "")
    .trim()
    .toLowerCase();
  return (
    NIST_FUNCTIONS.find((name) => name.toLowerCase() === normalized) ??
    "Identify"
  );
}

export async function GET() {
  try {
    const hasAssets = await tableExists("assets");
    const hasThreats = await tableExists("threats");
    const hasVulnerabilities = await tableExists("vulnerabilities");
    const hasRiskRegister = await tableExists("risk_register");
    const hasRiskAnalysis = await tableExists("risk_analysis");
    const hasControls = await tableExists("control_recommendations");
    const hasControlAssessments = await tableExists("control_assessments");
    const hasNistControls = await tableExists("nist_controls");

    const [
      hasControlStatus,
      hasControlPriority,
      hasControlImplementationPriority,
      hasControlName,
      hasControlId,
      hasControlNistFunction,
    ] = hasControls
      ? await Promise.all([
          columnExists("control_recommendations", "implementation_status"),
          columnExists("control_recommendations", "priority"),
          columnExists("control_recommendations", "implementation_priority"),
          columnExists("control_recommendations", "control_name"),
          columnExists("control_recommendations", "control_id"),
          columnExists("control_recommendations", "nist_function"),
        ])
      : [false, false, false, false, false, false];

    const [hasAssessmentNistFunction] = hasControlAssessments
      ? await Promise.all([
          columnExists("control_assessments", "nist_csf_function"),
        ])
      : [false];

    const totalAssets = hasAssets
      ? await safeCount("SELECT COUNT(*) AS count FROM assets")
      : 0;
    const assetCriticality = hasAssets
      ? await safeRows<{ criticality: string | null; count: string }>(
          `SELECT COALESCE(criticality, 'Unrated') AS criticality, COUNT(*) AS count
             FROM assets
            GROUP BY COALESCE(criticality, 'Unrated')`,
        )
      : [];
    const assetSecurityRows =
      hasAssets && hasVulnerabilities
        ? await safeRows<{
            assets_with_open_vulnerabilities: string | number;
          }>(
            `SELECT SUM(
                      CASE WHEN EXISTS (
                        SELECT 1
                          FROM vulnerabilities v
                         WHERE v.asset_id = a.id
                           AND ${ALIASED_OPEN_USER_VULNERABILITY_FILTER}
                      ) THEN 1 ELSE 0 END
                    ) AS assets_with_open_vulnerabilities
               FROM assets a`,
          )
        : [];
    const totalThreats = hasThreats
      ? await safeCount("SELECT COUNT(*) AS count FROM threats")
      : 0;

    const vulnerabilitySeverity = hasVulnerabilities
      ? await safeRows<{ severity: string; count: string }>(
          `SELECT severity, COUNT(*) AS count
             FROM vulnerabilities
            WHERE ${OPEN_USER_VULNERABILITY_FILTER}
            GROUP BY severity`,
        )
      : [];
    const vulnerabilityStatus = hasVulnerabilities
      ? await safeRows<{ status: string; count: string }>(
          `SELECT status, COUNT(*) AS count
             FROM vulnerabilities
            WHERE ${USER_VULNERABILITY_FILTER}
            GROUP BY status`,
        )
      : [];
    const topVulnerabilities = hasVulnerabilities
      ? await safeRows<{
          id: number;
          title: string;
          cve_id: string | null;
          severity: string;
          status: string;
          asset_name: string | null;
          discovered_at: string | null;
        }>(
          `SELECT v.id,
                  v.title,
                  v.cve_id,
                  v.severity,
                  v.status,
                  a.asset_name,
                  v.discovered_at
             FROM vulnerabilities v
        LEFT JOIN assets a ON a.id = v.asset_id
            WHERE NOT (COALESCE(v.source, '') = 'cisa_kev' AND v.asset_id IS NULL)
              AND LOWER(COALESCE(v.status, 'open')) NOT IN ('remediated', 'false_positive')
            ORDER BY CASE LOWER(v.severity)
                       WHEN 'critical' THEN 1
                       WHEN 'high' THEN 2
                       WHEN 'medium' THEN 3
                       WHEN 'low' THEN 4
                       ELSE 5
                     END,
                     v.discovered_at DESC
            LIMIT 6`,
        )
      : [];

    const riskSummary = hasRiskAnalysis
      ? await safeRows<{ risk_level: string; count: string }>(
          `SELECT COALESCE(risk_level, 'Unknown') AS risk_level, COUNT(*) AS count
             FROM risk_analysis
            GROUP BY COALESCE(risk_level, 'Unknown')`,
        )
      : [];
    const riskHeatMap = hasRiskAnalysis
      ? await safeRows<{ likelihood: number; impact: number; count: string }>(
          `SELECT likelihood, impact, COUNT(*) AS count
             FROM risk_analysis
            GROUP BY likelihood, impact
            ORDER BY impact DESC, likelihood ASC`,
        )
      : [];
    const avgRiskRows = hasRiskAnalysis
      ? await safeRows<{ avg_score: string | null }>(
          "SELECT ROUND(AVG(risk_score)::numeric, 1) AS avg_score FROM risk_analysis",
        )
      : [];

    const nistCoverage = hasRiskRegister
      ? await safeRows<{ nist_csf_function: string; count: string }>(
          `SELECT COALESCE(nist_csf_function, 'Identify') AS nist_csf_function,
                  COUNT(*) AS count
             FROM risk_register
            GROUP BY COALESCE(nist_csf_function, 'Identify')`,
        )
      : [];

    const topRisks =
      hasRiskRegister && hasRiskAnalysis
        ? await safeRows<{
            id: number;
            risk_code: string;
            risk_title: string;
            asset_name: string | null;
            asset_type: string | null;
            threat_name: string | null;
            nist_csf_function: string | null;
            nist_csf_category: string | null;
            likelihood: number;
            impact: number;
            risk_score: number;
            risk_level: string;
            control_count: string;
          }>(
            `SELECT rr.id,
                  rr.risk_code,
                  rr.risk_title,
                  a.asset_name,
                  a.asset_type,
                  t.threat_name,
                  rr.nist_csf_function,
                  rr.nist_csf_category,
                  ra.likelihood,
                  ra.impact,
                  ra.risk_score,
                  ra.risk_level,
                  (SELECT COUNT(*) FROM control_recommendations cr
                    WHERE cr.risk_register_id = rr.id) AS control_count
             FROM risk_register rr
             LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id
             LEFT JOIN assets a ON a.id = rr.asset_id
             LEFT JOIN threats t ON t.id = rr.threat_id
            ORDER BY COALESCE(ra.risk_score, 0) DESC, rr.created_at DESC
            LIMIT 8`,
          )
        : [];

    const topAssets =
      hasRiskRegister && hasRiskAnalysis
        ? await safeRows<{
            asset_id: number;
            asset_name: string;
            criticality: string | null;
            risk_count: string;
            max_score: number;
            avg_score: string;
          }>(
            `SELECT a.id AS asset_id,
                  a.asset_name,
                  a.criticality,
                  COUNT(rr.id) AS risk_count,
                  MAX(ra.risk_score) AS max_score,
                  ROUND(AVG(ra.risk_score)::numeric, 1) AS avg_score
             FROM risk_register rr
             JOIN risk_analysis ra ON ra.risk_register_id = rr.id
             JOIN assets a ON a.id = rr.asset_id
            GROUP BY a.id, a.asset_name, a.criticality
            ORDER BY MAX(ra.risk_score) DESC, COUNT(rr.id) DESC
            LIMIT 5`,
          )
        : [];

    const priorityColumn = hasControlImplementationPriority
      ? "implementation_priority"
      : hasControlPriority
        ? "priority"
        : null;
    const controlsByPriority = priorityColumn
      ? await safeRows<{ priority: string; count: string }>(
          `SELECT COALESCE(${priorityColumn}, 'Medium') AS priority, COUNT(*) AS count
             FROM control_recommendations
            GROUP BY COALESCE(${priorityColumn}, 'Medium')`,
        )
      : [];
    const controlsByStatus = hasControlStatus
      ? await safeRows<{ status: string; count: string }>(
          `SELECT COALESCE(implementation_status, 'Not Started') AS status,
                  COUNT(*) AS count
             FROM control_recommendations
            GROUP BY COALESCE(implementation_status, 'Not Started')`,
        )
      : [];
    const totalControls = hasControls
      ? await safeCount("SELECT COUNT(*) AS count FROM control_recommendations")
      : 0;
    const totalControlAssessments = hasControlAssessments
      ? await safeCount("SELECT COUNT(*) AS count FROM control_assessments")
      : 0;
    const avgControlEffectivenessRows = hasControlAssessments
      ? await safeRows<{ avg_effectiveness: string | null }>(
          `SELECT ROUND(AVG(effectiveness_rating)::numeric, 1) AS avg_effectiveness
             FROM control_assessments
            WHERE effectiveness_rating IS NOT NULL`,
        )
      : [];
    const priorityExpression = hasControlImplementationPriority
      ? "cr.implementation_priority"
      : hasControlPriority
        ? "cr.priority"
        : "'Medium'";
    const statusExpression = hasControlStatus
      ? "cr.implementation_status"
      : "'Not Started'";
    const nistControlJoin =
      hasNistControls && hasControlId
        ? "LEFT JOIN nist_controls nc ON nc.control_id = cr.control_id"
        : "";
    const controlNameExpression = hasControlName
      ? hasNistControls && hasControlId
        ? "COALESCE(cr.control_name, nc.control_name, cr.control_id, 'Recommended control')"
        : "COALESCE(cr.control_name, 'Recommended control')"
      : hasNistControls && hasControlId
        ? "COALESCE(nc.control_name, cr.control_id, 'Recommended control')"
        : "'Recommended control'";
    const controlFunctionExpression = hasControlNistFunction
      ? "COALESCE(rr.nist_csf_function, cr.nist_function, 'Identify')"
      : "COALESCE(rr.nist_csf_function, 'Identify')";
    const implementedStatusCheck = `LOWER(COALESCE(${statusExpression}, 'not started')) IN ('implemented', 'complete', 'completed')`;
    const openStatusCheck = `LOWER(COALESCE(${statusExpression}, 'not started')) NOT IN ('implemented', 'complete', 'completed', 'deferred')`;
    const topControlGaps = hasControls
      ? await safeRows<{
          id: number;
          control_name: string;
          priority: string;
          status: string;
          risk_title: string | null;
          asset_name: string | null;
          nist_csf_function: string | null;
          nist_csf_category: string | null;
          risk_score: number | null;
          risk_level: string | null;
        }>(
          `SELECT cr.id,
                  ${controlNameExpression} AS control_name,
                  COALESCE(${priorityExpression}, 'Medium') AS priority,
                  COALESCE(${statusExpression}, 'Not Started') AS status,
                  rr.risk_title,
                  a.asset_name,
                  rr.nist_csf_function,
                  rr.nist_csf_category,
                  ra.risk_score,
                  ra.risk_level
             FROM control_recommendations cr
        LEFT JOIN risk_register rr ON rr.id = cr.risk_register_id
        LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id
        LEFT JOIN assets a ON a.id = rr.asset_id
                  ${nistControlJoin}
            WHERE ${openStatusCheck}
            ORDER BY CASE COALESCE(${priorityExpression}, 'Medium')
                       WHEN 'Critical' THEN 1
                       WHEN 'High' THEN 2
                       WHEN 'Medium' THEN 3
                       WHEN 'Low' THEN 4
                       ELSE 5
                     END,
                     COALESCE(ra.risk_score, 0) DESC,
                     cr.created_at DESC
            LIMIT 6`,
        )
      : [];
    const controlAlignment = hasControls
      ? await safeRows<{
          nist_csf_function: string;
          control_count: string;
          implemented_count: string;
        }>(
          `SELECT ${controlFunctionExpression} AS nist_csf_function,
                  COUNT(cr.id) AS control_count,
                  SUM(CASE WHEN ${implementedStatusCheck} THEN 1 ELSE 0 END) AS implemented_count
             FROM control_recommendations cr
        LEFT JOIN risk_register rr ON rr.id = cr.risk_register_id
            GROUP BY ${controlFunctionExpression}`,
        )
      : [];
    const assessmentFunctionExpression = hasAssessmentNistFunction
      ? "COALESCE(ca.nist_csf_function, 'Identify')"
      : "'Identify'";
    const controlAssessmentAlignment = hasControlAssessments
      ? await safeRows<{
          nist_csf_function: string;
          control_count: string;
          implemented_count: string;
        }>(
          `SELECT ${assessmentFunctionExpression} AS nist_csf_function,
                  COUNT(ca.id) AS control_count,
                  COUNT(ca.id) AS implemented_count
             FROM control_assessments ca
            GROUP BY ${assessmentFunctionExpression}`,
        )
      : [];
    const effectiveControlAlignment = controlAssessmentAlignment.length
      ? controlAssessmentAlignment
      : controlAlignment;

    const vulnerabilityBySeverity = Object.fromEntries(
      vulnerabilitySeverity.map((row) => [
        row.severity.toLowerCase(),
        num(row.count),
      ]),
    );
    const vulnerabilityByStatus = Object.fromEntries(
      vulnerabilityStatus.map((row) => [
        row.status.toLowerCase(),
        num(row.count),
      ]),
    );
    const risksByLevel = Object.fromEntries(
      riskSummary.map((row) => [row.risk_level.toLowerCase(), num(row.count)]),
    );
    const assetsByCriticality = Object.fromEntries(
      assetCriticality.map((row) => [
        String(row.criticality).toLowerCase(),
        num(row.count),
      ]),
    );

    const totalRisks = riskSummary.reduce(
      (sum, row) => sum + num(row.count),
      0,
    );
    const implementedControls = controlsByStatus
      .filter((row) =>
        ["implemented", "complete", "completed"].includes(
          row.status.toLowerCase(),
        ),
      )
      .reduce((sum, row) => sum + num(row.count), 0);
    const inProgressControls = controlsByStatus
      .filter((row) =>
        ["in progress", "in_progress"].includes(row.status.toLowerCase()),
      )
      .reduce((sum, row) => sum + num(row.count), 0);
    const deferredControls = controlsByStatus
      .filter((row) => row.status.toLowerCase() === "deferred")
      .reduce((sum, row) => sum + num(row.count), 0);
    const pendingControls = Math.max(
      0,
      totalControls -
        implementedControls -
        inProgressControls -
        deferredControls,
    );
    const openVulnerabilities = vulnerabilityStatus
      .filter((row) => {
        const status = row.status.toLowerCase();
        return status !== "remediated" && status !== "false_positive";
      })
      .reduce((sum, row) => sum + num(row.count), 0);
    const controlAssessmentQueue = hasVulnerabilities
      ? hasControlAssessments
        ? await safeCount(
            `SELECT COUNT(*) AS count
               FROM vulnerabilities v
              WHERE NOT (COALESCE(v.source, '') = 'cisa_kev' AND v.asset_id IS NULL)
                AND LOWER(COALESCE(v.status, 'open')) NOT IN ('remediated', 'false_positive')
                AND NOT EXISTS (
                  SELECT 1
                    FROM control_assessments ca
                   WHERE ca.vulnerability_id = v.id
                )`,
          )
        : openVulnerabilities
      : 0;
    const remediatedVulnerabilities = vulnerabilityStatus
      .filter((row) => row.status.toLowerCase() === "remediated")
      .reduce((sum, row) => sum + num(row.count), 0);
    const inProgressVulnerabilities = vulnerabilityStatus
      .filter((row) =>
        ["in progress", "in_progress"].includes(row.status.toLowerCase()),
      )
      .reduce((sum, row) => sum + num(row.count), 0);
    const acceptedVulnerabilities = vulnerabilityStatus
      .filter((row) => row.status.toLowerCase() === "accepted")
      .reduce((sum, row) => sum + num(row.count), 0);
    const highRiskCount = num(risksByLevel.critical) + num(risksByLevel.high);
    const healthScore = Math.max(
      0,
      Math.min(
        100,
        100 -
          num(risksByLevel.critical) * 12 -
          num(risksByLevel.high) * 6 -
          openVulnerabilities * 2 +
          pct(implementedControls, totalControls) * 0.25,
      ),
    );
    const nistCoverageByFunction = new Map<string, number>();
    nistCoverage.forEach((row) => {
      const name = normalizeNistFunction(row.nist_csf_function);
      nistCoverageByFunction.set(
        name,
        (nistCoverageByFunction.get(name) ?? 0) + num(row.count),
      );
    });
    const coveredFunctions = Array.from(nistCoverageByFunction.entries())
      .filter(([, count]) => count > 0)
      .map(([name]) => name);
    const nistCoveragePercent = pct(
      coveredFunctions.length,
      NIST_FUNCTIONS.length,
    );
    const assetsWithOpenVulnerabilities = hasVulnerabilities
      ? num(assetSecurityRows[0]?.assets_with_open_vulnerabilities)
      : 0;
    const assetsWithoutOpenVulnerabilities = Math.max(
      0,
      totalAssets - assetsWithOpenVulnerabilities,
    );
    const assetSecurityLevel = pct(
      assetsWithoutOpenVulnerabilities,
      totalAssets,
    );
    const nistAssetAlignmentPercent = averagePercent([
      assetSecurityLevel,
      nistCoveragePercent,
    ]);

    return NextResponse.json({
      summary: {
        health_score: Math.round(healthScore),
        avg_risk_score: num(avgRiskRows[0]?.avg_score),
        total_assets: totalAssets,
        total_threats: totalThreats,
        total_vulnerabilities: vulnerabilityStatus.reduce(
          (sum, row) => sum + num(row.count),
          0,
        ),
        open_vulnerabilities: openVulnerabilities,
        total_risks: totalRisks,
        high_risk_count: highRiskCount,
        total_controls: totalControls,
        total_control_assessments: totalControlAssessments,
        control_assessment_queue: controlAssessmentQueue,
        avg_control_effectiveness: num(
          avgControlEffectivenessRows[0]?.avg_effectiveness,
        ),
        control_implementation_rate: pct(implementedControls, totalControls),
      },
      assets: {
        by_criticality: {
          critical: num(assetsByCriticality.critical),
          high: num(assetsByCriticality.high),
          medium: num(assetsByCriticality.medium),
          low: num(assetsByCriticality.low),
          unrated: num(assetsByCriticality.unrated),
        },
        security: {
          total_assets: totalAssets,
          assets_without_open_vulnerabilities: assetsWithoutOpenVulnerabilities,
          assets_with_open_vulnerabilities: assetsWithOpenVulnerabilities,
          security_level_percent: assetSecurityLevel,
        },
      },
      vulnerabilities: {
        by_severity: {
          critical: num(vulnerabilityBySeverity.critical),
          high: num(vulnerabilityBySeverity.high),
          medium: num(vulnerabilityBySeverity.medium),
          low: num(vulnerabilityBySeverity.low),
        },
        by_status: vulnerabilityByStatus,
        top: topVulnerabilities,
      },
      risks: {
        by_level: {
          critical: num(risksByLevel.critical),
          high: num(risksByLevel.high),
          medium: num(risksByLevel.medium),
          low: num(risksByLevel.low),
          unknown: num(risksByLevel.unknown),
        },
        heatmap: riskHeatMap,
        top: topRisks,
        top_assets: topAssets,
      },
      controls: {
        by_priority: controlsByPriority,
        by_status: controlsByStatus,
        top_gaps: topControlGaps,
        alignment_by_function: NIST_FUNCTIONS.map((name) => {
          const row = effectiveControlAlignment.find(
            (item) => item.nist_csf_function === name,
          );
          const controlCount = num(row?.control_count);
          const implementedCount = num(row?.implemented_count);
          return {
            name,
            control_count: controlCount,
            implemented_count: implementedCount,
            implementation_rate: pct(implementedCount, controlCount),
          };
        }),
      },
      remediation: {
        vulnerabilities: {
          open: openVulnerabilities,
          in_progress: inProgressVulnerabilities,
          remediated: remediatedVulnerabilities,
          accepted: acceptedVulnerabilities,
          remediation_rate: pct(
            remediatedVulnerabilities,
            openVulnerabilities + remediatedVulnerabilities,
          ),
        },
        controls: {
          pending: pendingControls,
          in_progress: inProgressControls,
          implemented: implementedControls,
          deferred: deferredControls,
          implementation_rate: pct(implementedControls, totalControls),
        },
      },
      nist: {
        functions: NIST_FUNCTIONS.map((name) => {
          const count = nistCoverageByFunction.get(name) ?? 0;
          return {
            name,
            count,
            coverage: totalRisks ? pct(count, totalRisks) : 0,
          };
        }),
        coverage_percent: nistCoveragePercent,
        asset_alignment_percent: nistAssetAlignmentPercent,
      },
      generated_at: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Dashboard metrics error:", error);
    return NextResponse.json(
      { error: "Failed to fetch dashboard metrics" },
      { status: 500 },
    );
  }
}
