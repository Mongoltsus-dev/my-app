import { pool } from "@/lib/db";
import { NextResponse } from "next/server";

async function runDedup() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Find duplicate framework risks (no asset/threat): keep the one with the highest id per risk_title
    const dupsResult = await client.query(`
      SELECT id
        FROM risk_register
       WHERE (asset_id IS NULL OR asset_id = 0)
         AND (threat_id IS NULL OR threat_id = 0)
         AND id NOT IN (
           SELECT MAX(id)
             FROM risk_register
            WHERE (asset_id IS NULL OR asset_id = 0)
              AND (threat_id IS NULL OR threat_id = 0)
            GROUP BY risk_title
         )
    `);

    const dupIds: number[] = dupsResult.rows.map(
      (r: { id: number }) => r.id,
    );

    if (dupIds.length === 0) {
      await client.query("ROLLBACK");
      return { message: "No duplicates found", deleted_risks: 0 };
    }

    const ph = dupIds.join(",");

    // Delete dependent rows first (ignore errors if tables/columns don't exist)
    for (const sql of [
      `DELETE FROM control_recommendations WHERE risk_register_id IN (${ph})`,
      `DELETE FROM control_assessments    WHERE risk_register_id IN (${ph})`,
      `DELETE FROM risk_analysis          WHERE risk_register_id IN (${ph})`,
      `DELETE FROM risk_analysis          WHERE risk_id           IN (${ph})`,
    ]) {
      try {
        await client.query(sql);
      } catch (_) {
        /* table or column may not exist */
      }
    }

    // Delete the duplicate register rows
    const del = await client.query(
      `DELETE FROM risk_register WHERE id IN (${ph})`,
    );

    await client.query("COMMIT");
    return {
      message: `Removed ${del.rowCount ?? 0} duplicate risk(s)`,
      deleted_ids: dupIds,
      deleted_risks: del.rowCount ?? 0,
    };
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

export async function GET() {
  try {
    return NextResponse.json(await runDedup());
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Cleanup failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function DELETE() {
  try {
    return NextResponse.json(await runDedup());
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Cleanup failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
