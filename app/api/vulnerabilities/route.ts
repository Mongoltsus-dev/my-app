import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

const SELECT_COLUMNS = `
  v.id, v.asset_id, v.threat_id, v.cve_id, v.title, v.description,
  v.vulnerability_type, v.severity, v.cvss_score, v.status,
  v.discovered_at, v.remediated_at, v.remediation_notes,
  v.reference_url, v.source, v.created_at, v.updated_at,
  a.asset_name, a.asset_code,
  COALESCE(at.type_name, a.asset_type) AS asset_type,
  a.criticality AS asset_criticality,
  a.data_classification AS asset_data_classification,
  a.access_level,
  a.authentication_method,
  a.supports_critical_service,
  a.internet_exposed,
  a.backup_enabled,
  a.encryption_enabled,
  a.mfa_enabled,
  a.logging_enabled,
  t.threat_name,
  t.threat_type,
  t.description AS threat_description,
  t.likelihood_level AS threat_likelihood_level,
  t.potential_impact AS threat_potential_impact,
  t.nist_category AS threat_nist_category,
  atm.risk_level AS threat_mapping_risk_level,
  mapped_at.type_name AS threat_mapping_asset_type,
  atm.mitigation_notes AS threat_mitigation_notes,
  atm.mitigation_notes_mn AS threat_mitigation_notes_mn
`;

async function ensureVulnerabilityThreatSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS assets (
      id SERIAL PRIMARY KEY,
      asset_type_id INTEGER,
      asset_type VARCHAR(100),
      asset_name VARCHAR(255) NOT NULL,
      asset_code VARCHAR(50),
      criticality VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS asset_types (
      id SERIAL PRIMARY KEY,
      type_name VARCHAR(100) UNIQUE NOT NULL,
      description TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  const assetColumns: [string, string][] = [
    ["asset_type_id", "INTEGER"],
    ["asset_type", "VARCHAR(100)"],
    ["asset_code", "VARCHAR(50)"],
    ["data_classification", "VARCHAR(50)"],
    ["access_level", "VARCHAR(50)"],
    ["authentication_method", "VARCHAR(50)"],
    ["supports_critical_service", "BOOLEAN DEFAULT FALSE"],
    ["internet_exposed", "BOOLEAN DEFAULT FALSE"],
    ["backup_enabled", "BOOLEAN DEFAULT FALSE"],
    ["encryption_enabled", "BOOLEAN DEFAULT FALSE"],
    ["mfa_enabled", "BOOLEAN DEFAULT FALSE"],
    ["logging_enabled", "BOOLEAN DEFAULT FALSE"],
  ];
  for (const [column, definition] of assetColumns) {
    await pool.query(
      `ALTER TABLE assets ADD COLUMN IF NOT EXISTS ${column} ${definition}`,
    );
  }
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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id SERIAL PRIMARY KEY,
      asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
      threat_id INTEGER REFERENCES threats(id) ON DELETE SET NULL,
      cve_id VARCHAR(100),
      title VARCHAR(255) NOT NULL,
      description TEXT,
      vulnerability_type VARCHAR(100),
      severity VARCHAR(50) NOT NULL,
      cvss_score NUMERIC(3,1),
      status VARCHAR(50) DEFAULT 'open',
      discovered_at TIMESTAMPTZ DEFAULT NOW(),
      remediated_at TIMESTAMPTZ,
      remediation_notes TEXT,
      reference_url TEXT,
      source VARCHAR(100) DEFAULT 'manual',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(
    `ALTER TABLE vulnerabilities
       ADD COLUMN IF NOT EXISTS asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE`,
  );
  await pool.query(`
    CREATE TABLE IF NOT EXISTS asset_threat_mapping (
      id SERIAL PRIMARY KEY,
      asset_type_id INTEGER REFERENCES asset_types(id) ON DELETE CASCADE,
      threat_id INTEGER REFERENCES threats(id) ON DELETE CASCADE,
      risk_level VARCHAR(50) DEFAULT 'Medium',
      mitigation_notes TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(asset_type_id, threat_id)
    )
  `);
  await pool.query(
    `ALTER TABLE asset_threat_mapping ADD COLUMN IF NOT EXISTS mitigation_notes_mn TEXT`,
  );
  await pool.query(
    `ALTER TABLE vulnerabilities
       ADD COLUMN IF NOT EXISTS threat_id INTEGER REFERENCES threats(id) ON DELETE SET NULL`,
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_vulnerabilities_threat_id ON vulnerabilities(threat_id)`,
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_vulnerabilities_asset_threat ON vulnerabilities(asset_id, threat_id)`,
  );
}

export async function GET(req: NextRequest) {
  try {
    await ensureVulnerabilityThreatSchema();

    const { searchParams } = new URL(req.url);
    const assetId = searchParams.get("asset_id");
    const threatId = searchParams.get("threat_id");
    const status = searchParams.get("status");
    const severity = searchParams.get("severity");

    const where: string[] = [];
    const params: (string | number)[] = [];

    where.push(`v.asset_id IS NOT NULL`);

    if (assetId) {
      params.push(Number(assetId));
      where.push(`v.asset_id = $${params.length}`);
    }
    if (threatId) {
      params.push(Number(threatId));
      where.push(`v.threat_id = $${params.length}`);
    }
    if (status && status !== "all") {
      params.push(status);
      where.push(`v.status = $${params.length}`);
    }
    if (severity && severity !== "all") {
      params.push(severity);
      where.push(`v.severity = $${params.length}`);
    }

    const whereClause = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const result = await pool.query(
      `SELECT ${SELECT_COLUMNS}
         FROM vulnerabilities v
         JOIN assets a       ON a.id = v.asset_id
    LEFT JOIN asset_types at ON at.id = a.asset_type_id
    LEFT JOIN asset_types resolved_at
           ON lower(resolved_at.type_name) = lower(COALESCE(at.type_name, a.asset_type, ''))
    LEFT JOIN threats t      ON t.id = v.threat_id
    LEFT JOIN LATERAL (
      SELECT asset_threat_mapping.*
        FROM asset_threat_mapping
       WHERE asset_threat_mapping.threat_id = v.threat_id
         AND (
           asset_threat_mapping.asset_type_id = a.asset_type_id
           OR asset_threat_mapping.asset_type_id = resolved_at.id
         )
       ORDER BY
         CASE
           WHEN asset_threat_mapping.asset_type_id = a.asset_type_id THEN 1
           ELSE 2
         END
       LIMIT 1
    ) atm ON true
    LEFT JOIN asset_types mapped_at ON mapped_at.id = atm.asset_type_id
        ${whereClause}
       ORDER BY
         CASE v.severity
           WHEN 'Critical' THEN 1
           WHEN 'High'     THEN 2
           WHEN 'Medium'   THEN 3
           WHEN 'Low'      THEN 4
         END,
         v.discovered_at DESC`,
      params,
    );

    return NextResponse.json({ vulnerabilities: result.rows });
  } catch (error) {
    console.error("Fetch vulnerabilities error:", error);
    const msg =
      error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ message: msg }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    await ensureVulnerabilityThreatSchema();

    const body = await req.json();
    const {
      asset_id,
      threat_id,
      cve_id,
      title,
      description,
      vulnerability_type,
      severity,
      cvss_score,
      status,
      reference_url,
      remediation_notes,
      source,
    } = body;

    const parsedAssetId = Number(asset_id);
    if (!Number.isInteger(parsedAssetId) || parsedAssetId <= 0) {
      return NextResponse.json(
        { message: "asset_id is required" },
        { status: 400 },
      );
    }

    if (!title || !severity) {
      return NextResponse.json(
        { message: "title and severity are required" },
        { status: 400 },
      );
    }

    const asset = await pool.query("SELECT id FROM assets WHERE id = $1", [
      parsedAssetId,
    ]);
    if (asset.rows.length === 0) {
      return NextResponse.json({ message: "Asset not found" }, { status: 404 });
    }

    const result = await pool.query(
      `INSERT INTO vulnerabilities
         (asset_id, threat_id, cve_id, title, description, vulnerability_type, severity,
          cvss_score, status, reference_url, remediation_notes, source)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9,'open'), $10, $11, COALESCE($12,'manual'))
       RETURNING *`,
      [
        parsedAssetId,
        threat_id ?? null,
        cve_id ?? null,
        title,
        description ?? null,
        vulnerability_type ?? "CVE",
        severity,
        cvss_score ?? null,
        status ?? null,
        reference_url ?? null,
        remediation_notes ?? null,
        source ?? null,
      ],
    );

    return NextResponse.json(
      { vulnerability: result.rows[0], message: "Vulnerability created" },
      { status: 201 },
    );
  } catch (error) {
    console.error("Create vulnerability error:", error);
    const msg =
      error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ message: msg }, { status: 500 });
  }
}
