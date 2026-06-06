import { pool } from "@/lib/db";
import { syncAssetVulnerabilities } from "@/lib/vulnerability-sync";
import { NextResponse } from "next/server";

async function ensureVulnerabilityThreatSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS assets (
      id SERIAL PRIMARY KEY,
      asset_type_id INTEGER,
      asset_type VARCHAR(100),
      asset_name VARCHAR(255) NOT NULL,
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
      source VARCHAR(100) DEFAULT 'auto_scan',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS access_level VARCHAR(50)`,
  );
  await pool.query(
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS authentication_method VARCHAR(50)`,
  );
  await pool.query(
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS supports_critical_service BOOLEAN DEFAULT FALSE`,
  );
  await pool.query(
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS data_classification VARCHAR(50)`,
  );
  await pool.query(
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS internet_exposed BOOLEAN DEFAULT FALSE`,
  );
  await pool.query(
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE`,
  );
  await pool.query(
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS encryption_enabled BOOLEAN DEFAULT FALSE`,
  );
  await pool.query(
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS backup_enabled BOOLEAN DEFAULT FALSE`,
  );
  await pool.query(
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS logging_enabled BOOLEAN DEFAULT FALSE`,
  );
  await pool.query(
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Active'`,
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

export async function POST() {
  try {
    await ensureVulnerabilityThreatSchema();

    const { rows: assets } = await pool.query<{ id: number }>(`
      SELECT id
        FROM assets
       WHERE COALESCE(status, 'Active') <> 'Retired'
    `);

    let created = 0;
    let closed = 0;
    let skipped = 0;

    for (const asset of assets) {
      const result = await syncAssetVulnerabilities(asset.id);
      created += result.created;
      closed += result.closed;
      skipped += result.unchanged;
    }

    return NextResponse.json({
      message: "Scan complete",
      assets_scanned: assets.length,
      findings_created: created,
      findings_closed: closed,
      findings_skipped_existing: skipped,
    });
  } catch (error) {
    console.error("Vulnerability scan error:", error);
    const msg =
      error instanceof Error ? error.message : "Internal server error";
    return NextResponse.json({ message: msg }, { status: 500 });
  }
}
