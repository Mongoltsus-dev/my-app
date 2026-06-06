import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

/**
 * GET  /api/csf-subcategories               — list all subcategories
 * PATCH /api/csf-subcategories              — update tiers/owner/etc. for one subcategory
 *
 * Backed by csf_subcategories — a dedicated catalog table holding the full
 * NIST CSF 2.0 outcomes list plus the org's current/target maturity per row.
 *
 * Distinct from csf_profile_gaps (which is auto-derived from asset posture for
 * a small subset of subcategories). This table holds the user's full assessment.
 */

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS csf_subcategories (
      id SERIAL PRIMARY KEY,
      subcategory_id      VARCHAR(20)  UNIQUE NOT NULL,
      title               TEXT,
      nist_function       VARCHAR(50)  NOT NULL,
      function_code       VARCHAR(10),
      category_name       VARCHAR(255),
      category_code       VARCHAR(20),
      outcome_description TEXT,
      current_tier        INTEGER,
      target_tier         INTEGER,
      gap                 INTEGER,
      risk_score          INTEGER,
      risk_level          VARCHAR(20),
      primary_owner       VARCHAR(255),
      stakeholders        TEXT,
      tools               TEXT,
      control_links       TEXT,
      status              VARCHAR(50),
      target_date         VARCHAR(20),
      notes               TEXT,
      created_at          TIMESTAMP DEFAULT NOW(),
      updated_at          TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE csf_subcategories ADD COLUMN IF NOT EXISTS title TEXT`);
}

export async function GET() {
  try {
    await ensureSchema();
    const r = await pool.query(`
      SELECT *
        FROM csf_subcategories
       ORDER BY function_code,
                category_code,
                subcategory_id
    `);

    // Compute summary stats for the UI header
    const stats = await pool.query(`
      SELECT
        COUNT(*)::int                                              AS total,
        SUM(CASE WHEN LOWER(risk_level)='critical' THEN 1 ELSE 0 END)::int AS critical_count,
        SUM(CASE WHEN LOWER(risk_level)='high'     THEN 1 ELSE 0 END)::int AS high_count,
        SUM(CASE WHEN LOWER(risk_level)='medium'   THEN 1 ELSE 0 END)::int AS medium_count,
        SUM(CASE WHEN LOWER(risk_level)='low'      THEN 1 ELSE 0 END)::int AS low_count,
        AVG(NULLIF(current_tier, 0))::numeric(4,2)                 AS avg_current_tier,
        AVG(NULLIF(target_tier,  0))::numeric(4,2)                 AS avg_target_tier,
        SUM(CASE WHEN gap > 0 THEN 1 ELSE 0 END)::int              AS subcategories_with_gap
        FROM csf_subcategories
    `);

    const byFunction = await pool.query(`
      SELECT nist_function,
             COUNT(*)::int                                AS count,
             AVG(NULLIF(current_tier, 0))::numeric(4,2)  AS avg_current,
             AVG(NULLIF(target_tier,  0))::numeric(4,2)  AS avg_target,
             SUM(CASE WHEN gap > 0 THEN 1 ELSE 0 END)::int AS with_gap
        FROM csf_subcategories
       GROUP BY nist_function
       ORDER BY MIN(function_code)
    `);

    return NextResponse.json({
      rows: r.rows,
      count: r.rows.length,
      stats: stats.rows[0] ?? {},
      by_function: byFunction.rows,
    });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "fetch failed" },
      { status: 500 },
    );
  }
}

export async function PATCH(req: NextRequest) {
  try {
    await ensureSchema();
    const body = await req.json();
    const { subcategory_id, current_tier, target_tier, primary_owner, status, notes } =
      body ?? {};

    if (!subcategory_id) {
      return NextResponse.json(
        { error: "subcategory_id required" },
        { status: 400 },
      );
    }

    const ct =
      current_tier !== undefined && current_tier !== null
        ? Math.max(0, Math.min(4, Number(current_tier)))
        : null;
    const tt =
      target_tier !== undefined && target_tier !== null
        ? Math.max(0, Math.min(4, Number(target_tier)))
        : null;

    await pool.query(
      `UPDATE csf_subcategories
          SET current_tier  = COALESCE($1, current_tier),
              target_tier   = COALESCE($2, target_tier),
              gap           = CASE
                                WHEN $1 IS NOT NULL OR $2 IS NOT NULL
                                THEN GREATEST(0, COALESCE($2, target_tier) - COALESCE($1, current_tier))
                                ELSE gap
                              END,
              primary_owner = COALESCE($3, primary_owner),
              status        = COALESCE($4, status),
              notes         = COALESCE($5, notes),
              updated_at    = NOW()
        WHERE subcategory_id = $6`,
      [ct, tt, primary_owner ?? null, status ?? null, notes ?? null, subcategory_id],
    );

    return NextResponse.json({ success: true });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "update failed" },
      { status: 500 },
    );
  }
}

export async function DELETE() {
  try {
    await ensureSchema();
    await pool.query("TRUNCATE csf_subcategories RESTART IDENTITY");
    return NextResponse.json({ success: true });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "delete failed" },
      { status: 500 },
    );
  }
}
