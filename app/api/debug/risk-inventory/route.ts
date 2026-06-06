import { pool } from "@/lib/db";
import { NextResponse } from "next/server";

/**
 * GET /api/debug/risk-inventory
 *
 * Read-only diagnostic endpoint. Tells us exactly what's in the DB so we know
 * which fix to apply. No writes, safe to call anytime.
 *
 * Returns:
 *   - counts for `risks` catalog, `risk_register`, `risk_analysis`, `assets`
 *   - schema (column list) for `risks` and `risk_register` so we don't ALTER blindly
 *   - how many risk_register rows are missing a risk_analysis row (= "all Low" symptom)
 *   - 10 sample risk titles + their analysis status
 */
export async function GET() {
  try {
    const result: Record<string, unknown> = {};

    // ── Table existence + counts ──────────────────────────────────────────────
    const tables = [
      "risks",
      "risk_register",
      "risk_analysis",
      "assets",
      "nist_controls",
      "control_recommendations",
    ];
    const counts: Record<string, number | string> = {};
    for (const t of tables) {
      try {
        const r = await pool.query(`SELECT COUNT(*)::int AS n FROM ${t}`);
        counts[t] = r.rows[0].n;
      } catch (e) {
        counts[t] = `(table missing: ${
          e instanceof Error ? e.message.split("\n")[0] : "unknown"
        })`;
      }
    }
    result.counts = counts;

    // ── Column lists ──────────────────────────────────────────────────────────
    const columns: Record<string, string[] | string> = {};
    for (const t of ["risks", "risk_register", "risk_analysis"]) {
      try {
        const r = await pool.query(
          `SELECT column_name FROM information_schema.columns
            WHERE table_name = $1 ORDER BY ordinal_position`,
          [t],
        );
        columns[t] = r.rows.map((row) => row.column_name as string);
      } catch (e) {
        columns[t] = `(error: ${
          e instanceof Error ? e.message.split("\n")[0] : "unknown"
        })`;
      }
    }
    result.columns = columns;

    // ── The headline metric: risk_register rows missing risk_analysis ─────────
    try {
      const r = await pool.query(`
        SELECT COUNT(*)::int AS n
        FROM risk_register rr
        LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id
        WHERE ra.id IS NULL
      `);
      result.risk_register_without_analysis = r.rows[0].n;
    } catch (e) {
      result.risk_register_without_analysis = `(error: ${
        e instanceof Error ? e.message : "unknown"
      })`;
    }

    // ── Distribution: how many at each (likelihood, impact) ───────────────────
    try {
      const r = await pool.query(`
        SELECT
          COALESCE(ra.inherent_likelihood, ra.likelihood, 0) AS likelihood,
          COALESCE(ra.inherent_impact, ra.impact, 0)         AS impact,
          COUNT(*)::int AS n
        FROM risk_register rr
        LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id
        GROUP BY 1, 2
        ORDER BY 1, 2
      `);
      result.register_distribution = r.rows;
    } catch (e) {
      result.register_distribution = `(error: ${
        e instanceof Error ? e.message : "unknown"
      })`;
    }

    // ── Sample risk titles to confirm what's actually in there ───────────────
    try {
      const r = await pool.query(`
        SELECT rr.id, rr.risk_title, rr.asset_id, a.asset_name,
               (ra.id IS NOT NULL) AS has_analysis,
               COALESCE(ra.inherent_likelihood, ra.likelihood) AS likelihood,
               COALESCE(ra.inherent_impact, ra.impact)         AS impact
        FROM risk_register rr
        LEFT JOIN assets a         ON a.id = rr.asset_id
        LEFT JOIN risk_analysis ra ON ra.risk_register_id = rr.id
        ORDER BY rr.id
        LIMIT 10
      `);
      result.sample_register_rows = r.rows;
    } catch (e) {
      result.sample_register_rows = `(error: ${
        e instanceof Error ? e.message : "unknown"
      })`;
    }

    // ── Asset summary ────────────────────────────────────────────────────────
    try {
      const r = await pool.query(`
        SELECT id, asset_name, asset_type, criticality
        FROM assets
        ORDER BY id
      `);
      result.assets = r.rows;
    } catch (e) {
      result.assets = `(error: ${e instanceof Error ? e.message : "unknown"})`;
    }

    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json(
      {
        error: "Diagnostic failed",
        details: err instanceof Error ? err.message : "unknown",
      },
      { status: 500 },
    );
  }
}
