import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

type CurrentMetrics = {
  avg_risk_score: number;
  total_risks: number;
  critical_risks: number;
  high_risks: number;
  medium_risks: number;
  low_risks: number;
  open_vulnerabilities: number;
  implemented_controls: number;
  total_controls: number;
};

async function tableExists(tableName: string) {
  const result = await pool.query("SELECT to_regclass($1) AS name", [
    tableName,
  ]);
  return Boolean(result.rows[0]?.name);
}

async function ensureTrendSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS risk_metric_snapshots (
      id SERIAL PRIMARY KEY,
      snapshot_date DATE UNIQUE NOT NULL DEFAULT CURRENT_DATE,
      avg_risk_score NUMERIC(5,2) DEFAULT 0,
      total_risks INTEGER DEFAULT 0,
      critical_risks INTEGER DEFAULT 0,
      high_risks INTEGER DEFAULT 0,
      medium_risks INTEGER DEFAULT 0,
      low_risks INTEGER DEFAULT 0,
      open_vulnerabilities INTEGER DEFAULT 0,
      implemented_controls INTEGER DEFAULT 0,
      total_controls INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);
}

async function count(query: string) {
  try {
    const result = await pool.query<{ count: string | number }>(query);
    return Number(result.rows[0]?.count ?? 0);
  } catch (error) {
    console.warn("Trend count skipped:", error);
    return 0;
  }
}

async function currentMetrics(): Promise<CurrentMetrics> {
  const hasRiskAnalysis = await tableExists("risk_analysis");
  const hasVulnerabilities = await tableExists("vulnerabilities");
  const hasControls = await tableExists("control_recommendations");

  const avgRiskRows = hasRiskAnalysis
    ? await pool.query<{ avg_score: string | null }>(
        "SELECT ROUND(AVG(COALESCE(inherent_risk_score, risk_score))::numeric, 2) AS avg_score FROM risk_analysis",
      )
    : { rows: [] };

  return {
    avg_risk_score: Number(avgRiskRows.rows[0]?.avg_score ?? 0),
    total_risks: hasRiskAnalysis
      ? await count("SELECT COUNT(*) AS count FROM risk_analysis")
      : 0,
    critical_risks: hasRiskAnalysis
      ? await count(
          "SELECT COUNT(*) AS count FROM risk_analysis WHERE COALESCE(inherent_risk_level, risk_level) = 'Critical'",
        )
      : 0,
    high_risks: hasRiskAnalysis
      ? await count(
          "SELECT COUNT(*) AS count FROM risk_analysis WHERE COALESCE(inherent_risk_level, risk_level) = 'High'",
        )
      : 0,
    medium_risks: hasRiskAnalysis
      ? await count(
          "SELECT COUNT(*) AS count FROM risk_analysis WHERE COALESCE(inherent_risk_level, risk_level) = 'Medium'",
        )
      : 0,
    low_risks: hasRiskAnalysis
      ? await count(
          "SELECT COUNT(*) AS count FROM risk_analysis WHERE COALESCE(inherent_risk_level, risk_level) = 'Low'",
        )
      : 0,
    open_vulnerabilities: hasVulnerabilities
      ? await count(
          "SELECT COUNT(*) AS count FROM vulnerabilities WHERE LOWER(COALESCE(status, 'open')) NOT IN ('remediated', 'false_positive') AND NOT (COALESCE(source, '') = 'cisa_kev' AND asset_id IS NULL)",
        )
      : 0,
    implemented_controls: hasControls
      ? await count(
          "SELECT COUNT(*) AS count FROM control_recommendations WHERE LOWER(COALESCE(implementation_status, 'not started')) IN ('implemented', 'complete', 'completed')",
        )
      : 0,
    total_controls: hasControls
      ? await count("SELECT COUNT(*) AS count FROM control_recommendations")
      : 0,
  };
}

async function upsertToday(metrics: CurrentMetrics) {
  await pool.query(
    `INSERT INTO risk_metric_snapshots
       (snapshot_date, avg_risk_score, total_risks, critical_risks, high_risks,
        medium_risks, low_risks, open_vulnerabilities, implemented_controls,
        total_controls, updated_at)
     VALUES (CURRENT_DATE, $1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
     ON CONFLICT (snapshot_date) DO UPDATE SET
       avg_risk_score = EXCLUDED.avg_risk_score,
       total_risks = EXCLUDED.total_risks,
       critical_risks = EXCLUDED.critical_risks,
       high_risks = EXCLUDED.high_risks,
       medium_risks = EXCLUDED.medium_risks,
       low_risks = EXCLUDED.low_risks,
       open_vulnerabilities = EXCLUDED.open_vulnerabilities,
       implemented_controls = EXCLUDED.implemented_controls,
       total_controls = EXCLUDED.total_controls,
       updated_at = NOW()`,
    [
      metrics.avg_risk_score,
      metrics.total_risks,
      metrics.critical_risks,
      metrics.high_risks,
      metrics.medium_risks,
      metrics.low_risks,
      metrics.open_vulnerabilities,
      metrics.implemented_controls,
      metrics.total_controls,
    ],
  );
}

export async function GET(req: NextRequest) {
  try {
    await ensureTrendSchema();
    const metrics = await currentMetrics();
    await upsertToday(metrics);

    const { searchParams } = new URL(req.url);
    const days = Math.max(
      7,
      Math.min(365, Number(searchParams.get("days") ?? 30)),
    );
    const history = await pool.query(
      `SELECT snapshot_date,
              avg_risk_score,
              total_risks,
              critical_risks,
              high_risks,
              medium_risks,
              low_risks,
              open_vulnerabilities,
              implemented_controls,
              total_controls
         FROM risk_metric_snapshots
        WHERE snapshot_date >= CURRENT_DATE - ($1::int - 1)
        ORDER BY snapshot_date ASC`,
      [days],
    );

    return NextResponse.json({
      success: true,
      generated_at: new Date().toISOString(),
      current: metrics,
      history: history.rows,
    });
  } catch (error) {
    console.error("Risk trend report error:", error);
    const message =
      error instanceof Error ? error.message : "Failed to load risk trends";
    return NextResponse.json({ message }, { status: 500 });
  }
}
