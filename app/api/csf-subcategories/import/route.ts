import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

/**
 * POST /api/csf-subcategories/import
 * Body: { data: string }   // tab-separated rows, one subcategory per line
 *
 * Parses the user's pasted NIST CSF 2.0 assessment spreadsheet. Tolerant of
 * "#N/A" values and minor column-count drift. Idempotent — re-importing
 * updates existing rows by subcategory_id.
 *
 * Expected columns (in order, tab-separated):
 *   0  function          (Govern / Identify / Protect / Detect / Respond / Recover)
 *   1  function_code     (GV / ID / PR / DE / RS / RC)
 *   2  category_name     (Organizational Context, …)
 *   3  category_code     (GV.OC, GV.RM, …)
 *   4  subcategory_id    (GV.OC-01, …)
 *   5  outcome_description (the long sentence)
 *   6  current_tier      (1-4)
 *   7  target_tier       (1-4)
 *   8  gap_or_calc       (numeric or #N/A)
 *   9  risk_score        (numeric or #N/A)
 *  10  risk_level        (Low / Medium / High / Critical or #N/A)
 *  11  primary_owner
 *  12  stakeholders
 *  13  tools
 *  14  control_links     (CL-001, CL-002, ...)
 *  15  status
 *  16  target_date       (free-form, e.g. "2026-Q2")
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

function parseIntOrNull(v: string | undefined): number | null {
  if (v === undefined) return null;
  const trimmed = v.trim();
  if (!trimmed || trimmed === "#N/A" || trimmed.toLowerCase() === "n/a") return null;
  const n = Number(trimmed);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

function strOrNull(v: string | undefined): string | null {
  if (v === undefined) return null;
  const trimmed = v.trim();
  if (!trimmed || trimmed === "#N/A" || trimmed.toLowerCase() === "n/a") return null;
  return trimmed;
}

const VALID_FUNCTIONS = new Set([
  "Govern",
  "Identify",
  "Protect",
  "Detect",
  "Respond",
  "Recover",
]);

export async function POST(req: NextRequest) {
  const client = await pool.connect();
  try {
    await ensureSchema();
    const body = await req.json().catch(() => ({}));
    const raw: string = typeof body?.data === "string" ? body.data : "";
    if (!raw.trim()) {
      return NextResponse.json(
        { error: "data (tab-separated rows) is required" },
        { status: 400 },
      );
    }

    const lines = raw
      .split(/\r?\n/)
      .map((l) => l.trimEnd())
      .filter((l) => l.trim().length > 0);

    if (lines.length === 0) {
      return NextResponse.json({ error: "No rows parsed" }, { status: 400 });
    }

    await client.query("BEGIN");

    let imported = 0;
    let skipped = 0;
    const errors: Array<{ line: number; reason: string }> = [];

    for (let i = 0; i < lines.length; i++) {
      const fields = lines[i].split("\t").map((f) => f);

      // Skip header rows if user pasted them
      if (
        i === 0 &&
        (fields[0]?.toLowerCase().includes("function") ||
          fields[0]?.toLowerCase().includes("nist"))
      ) {
        skipped++;
        continue;
      }

      const fn = fields[0]?.trim() ?? "";
      const subId = fields[4]?.trim() ?? "";

      if (!VALID_FUNCTIONS.has(fn)) {
        errors.push({ line: i + 1, reason: `Unknown function '${fn}'` });
        skipped++;
        continue;
      }
      if (!subId) {
        errors.push({ line: i + 1, reason: "Missing subcategory_id" });
        skipped++;
        continue;
      }

      const currentTier = parseIntOrNull(fields[6]);
      const targetTier = parseIntOrNull(fields[7]);
      const gapCol = parseIntOrNull(fields[8]);
      // Prefer computed gap (target - current) when both are present
      const gap =
        currentTier !== null && targetTier !== null
          ? Math.max(0, targetTier - currentTier)
          : gapCol;

      await client.query(
        `INSERT INTO csf_subcategories
           (subcategory_id, nist_function, function_code,
            category_name, category_code, outcome_description,
            current_tier, target_tier, gap, risk_score, risk_level,
            primary_owner, stakeholders, tools, control_links,
            status, target_date)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
         ON CONFLICT (subcategory_id) DO UPDATE SET
           nist_function       = EXCLUDED.nist_function,
           function_code       = EXCLUDED.function_code,
           category_name       = EXCLUDED.category_name,
           category_code       = EXCLUDED.category_code,
           outcome_description = EXCLUDED.outcome_description,
           current_tier        = EXCLUDED.current_tier,
           target_tier         = EXCLUDED.target_tier,
           gap                 = EXCLUDED.gap,
           risk_score          = EXCLUDED.risk_score,
           risk_level          = EXCLUDED.risk_level,
           primary_owner       = EXCLUDED.primary_owner,
           stakeholders        = EXCLUDED.stakeholders,
           tools               = EXCLUDED.tools,
           control_links       = EXCLUDED.control_links,
           status              = EXCLUDED.status,
           target_date         = EXCLUDED.target_date,
           updated_at          = NOW()`,
        [
          subId,
          fn,
          strOrNull(fields[1]),
          strOrNull(fields[2]),
          strOrNull(fields[3]),
          strOrNull(fields[5]),
          currentTier,
          targetTier,
          gap,
          parseIntOrNull(fields[9]),
          strOrNull(fields[10]),
          strOrNull(fields[11]),
          strOrNull(fields[12]),
          strOrNull(fields[13]),
          strOrNull(fields[14]),
          strOrNull(fields[15]),
          strOrNull(fields[16]),
        ],
      );

      imported++;
    }

    await client.query("COMMIT");

    return NextResponse.json({
      success: true,
      imported,
      skipped,
      errors: errors.slice(0, 20),
      message: `Imported ${imported} subcategories. ${skipped} rows skipped.`,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("csf-subcategories import error:", err);
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "import failed" },
      { status: 500 },
    );
  } finally {
    client.release();
  }
}
