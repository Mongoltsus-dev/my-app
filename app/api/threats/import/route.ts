import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";

type ThreatImportRecord = {
  threatName: string;
  threatType: string;
  description: string | null;
  likelihoodLevel: number;
  potentialImpact: string;
  nistCategory: string;
};

const HEADER_MAP: Record<string, "category" | "threatEvent" | "description"> = {
  category: "category",
  threat_event: "threatEvent",
  threatevent: "threatEvent",
  threat: "threatEvent",
  event: "threatEvent",
  threatname: "threatEvent",
  threat_name: "threatEvent",
  description: "description",
};

async function ensureThreatImportSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS threats (
      id SERIAL PRIMARY KEY,
      threat_name VARCHAR(255) NOT NULL,
      description TEXT,
      threat_type VARCHAR(100),
      likelihood_level INTEGER DEFAULT 3,
      potential_impact VARCHAR(50),
      nist_category VARCHAR(100),
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`ALTER TABLE threats ALTER COLUMN threat_name TYPE TEXT`);
  await pool.query(`ALTER TABLE threats ALTER COLUMN threat_type TYPE TEXT`);
  await pool.query(
    `ALTER TABLE threats ADD COLUMN IF NOT EXISTS source VARCHAR(100) DEFAULT 'custom'`,
  );
  await pool.query(
    `ALTER TABLE threats ADD COLUMN IF NOT EXISTS source_reference TEXT`,
  );
  await pool.query(
    `ALTER TABLE threats ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()`,
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_threats_source ON threats(source)`,
  );
}

export async function POST(req: NextRequest) {
  try {
    await ensureThreatImportSchema();

    const formData = await req.formData();
    const file = formData.get("file");

    if (!(file instanceof File)) {
      return NextResponse.json(
        { message: "CSV file is required." },
        { status: 400 },
      );
    }

    if (!file.name.toLowerCase().endsWith(".csv")) {
      return NextResponse.json(
        { message: "Please upload a CSV file." },
        { status: 400 },
      );
    }

    const csvText = await file.text();
    const records = parseThreatCsv(csvText);

    if (records.length === 0) {
      return NextResponse.json(
        {
          message:
            "No threat events were found. Expected headers like Category and Threat_Event.",
        },
        { status: 400 },
      );
    }

    let imported = 0;
    let updated = 0;
    let skipped = 0;

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      for (const record of records) {
        const existing = await client.query<{ id: number }>(
          `SELECT id
             FROM threats
            WHERE lower(threat_name) = lower($1)
              AND lower(COALESCE(threat_type, '')) = lower($2)
            LIMIT 1`,
          [record.threatName, record.threatType],
        );

        if (existing.rows[0]) {
          const result = await client.query(
            `UPDATE threats
                SET description = COALESCE($1, description),
                    likelihood_level = $2,
                    potential_impact = $3,
                    nist_category = $4,
                    source = 'nist_threat_event',
                    source_reference = 'NIST threat event CSV',
                    updated_at = NOW()
              WHERE id = $5`,
            [
              record.description,
              record.likelihoodLevel,
              record.potentialImpact,
              record.nistCategory,
              existing.rows[0].id,
            ],
          );
          updated += result.rowCount ?? 0;
          continue;
        }

        const result = await client.query(
          `INSERT INTO threats
             (threat_name, description, threat_type, likelihood_level,
              potential_impact, nist_category, source, source_reference, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, 'nist_threat_event', 'NIST threat event CSV', NOW())`,
          [
            record.threatName,
            record.description,
            record.threatType,
            record.likelihoodLevel,
            record.potentialImpact,
            record.nistCategory,
          ],
        );
        imported += result.rowCount ?? 0;
      }

      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }

    skipped = records.length - imported - updated;

    return NextResponse.json({
      success: true,
      message: "NIST threat events imported successfully.",
      imported,
      updated,
      skipped,
      total: records.length,
    });
  } catch (error) {
    console.error("NIST threat import error:", error);
    const message =
      error instanceof Error
        ? error.message
        : "Failed to import NIST threat events.";
    return NextResponse.json({ message }, { status: 500 });
  }
}

function parseThreatCsv(text: string) {
  const rows = parseCsv(text);
  const [headers, ...dataRows] = rows;
  if (!headers || dataRows.length === 0) return [];

  const mappedHeaders = headers.map(
    (header) => HEADER_MAP[normalizeHeader(header)],
  );
  const records: ThreatImportRecord[] = [];
  const seen = new Set<string>();

  for (const row of dataRows) {
    let category = "NIST Threat Event";
    let threatEvent = "";
    let description: string | null = null;

    mappedHeaders.forEach((mappedHeader, index) => {
      if (!mappedHeader) return;
      const value = clean(row[index]);
      if (!value) return;
      if (mappedHeader === "category") category = value;
      if (mappedHeader === "threatEvent") threatEvent = value;
      if (mappedHeader === "description") description = value;
    });

    if (!threatEvent) continue;

    const dedupeKey = `${category.toLowerCase()}|${threatEvent.toLowerCase()}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    records.push({
      threatName: threatEvent,
      threatType: category,
      description:
        description ??
        `NIST threat event category: ${category}. Imported from the official threat event catalog.`,
      likelihoodLevel: inferLikelihood(threatEvent),
      potentialImpact: inferImpact(threatEvent),
      nistCategory: inferNistCategory(threatEvent),
    });
  }

  return records;
}

function inferLikelihood(threatEvent: string) {
  const text = threatEvent.toLowerCase();
  if (
    /exploit|malware|phishing|sniff|credential|scanning|reconnaissance/.test(
      text,
    )
  ) {
    return 4;
  }
  if (/supply chain|counterfeit|tampered|subverted|physical/.test(text)) {
    return 3;
  }
  return 3;
}

function inferImpact(threatEvent: string) {
  const text = threatEvent.toLowerCase();
  if (
    /exfiltration|malware|supply chain|tampered|counterfeit|privileged|control/.test(
      text,
    )
  ) {
    return "Critical";
  }
  if (/phishing|credential|exploit|sniff|internet|cloud|mobile/.test(text)) {
    return "High";
  }
  return "Medium";
}

function inferNistCategory(threatEvent: string) {
  const text = threatEvent.toLowerCase();
  if (/reconnaissance|discovery|surveillance|scanning/.test(text))
    return "ID.RA";
  if (/detect|sniff|monitor|log/.test(text)) return "DE.CM";
  if (/recover|backup|restore/.test(text)) return "RC.RP";
  if (/respond|exfiltration|control/.test(text)) return "RS.AN";
  if (/access|credential|phishing|malware|configuration|exploit/.test(text)) {
    return "PR.PS";
  }
  if (/supply chain|vendor|counterfeit|tampered/.test(text)) return "GV.SC";
  return "ID.RA";
}

function parseCsv(text: string) {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;

  for (let index = 0; index < text.length; index++) {
    const char = text[index];
    const next = text[index + 1];

    if (char === '"') {
      if (inQuotes && next === '"') {
        field += '"';
        index++;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (char === "," && !inQuotes) {
      row.push(field);
      field = "";
      continue;
    }

    if ((char === "\n" || char === "\r") && !inQuotes) {
      if (char === "\r" && next === "\n") index++;
      row.push(field);
      if (row.some((value) => value.trim() !== "")) rows.push(row);
      row = [];
      field = "";
      continue;
    }

    field += char;
  }

  row.push(field);
  if (row.some((value) => value.trim() !== "")) rows.push(row);

  return rows;
}

function normalizeHeader(header: string) {
  return header
    .trim()
    .replace(/^\uFEFF/, "")
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "");
}

function clean(value: unknown) {
  if (value === undefined || value === null) return null;
  const trimmed = String(value).trim();
  return trimmed.length > 0 ? trimmed : null;
}
