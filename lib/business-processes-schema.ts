import { pool } from "@/lib/db";

export async function ensureBusinessProcessSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS business_processes (
      id                       SERIAL PRIMARY KEY,
      process_code             VARCHAR(50) UNIQUE NOT NULL,
      process_name             VARCHAR(255) NOT NULL,
      description              TEXT,
      business_function        VARCHAR(100),
      business_owner           VARCHAR(255),
      business_owner_email     VARCHAR(255),
      criticality              VARCHAR(20) NOT NULL,
      rto_hours                NUMERIC(10,2),
      rpo_hours                NUMERIC(10,2),
      data_types               TEXT,
      data_classification      VARCHAR(50),
      revenue_impact_per_hour  NUMERIC(14,2),
      customers_affected       INTEGER,
      regulatory_scope         TEXT,
      status                   VARCHAR(50) DEFAULT 'Active',
      notes                    TEXT,
      created_at               TIMESTAMP DEFAULT NOW(),
      updated_at               TIMESTAMP DEFAULT NOW()
    )
  `);

  const addProcessCols: [string, string][] = [
    ["process_code", "VARCHAR(50)"],
    ["process_name", "VARCHAR(255)"],
    ["description", "TEXT"],
    ["business_function", "VARCHAR(100)"],
    ["business_owner", "VARCHAR(255)"],
    ["business_owner_email", "VARCHAR(255)"],
    ["criticality", "VARCHAR(20)"],
    ["rto_hours", "NUMERIC(10,2)"],
    ["rpo_hours", "NUMERIC(10,2)"],
    ["data_types", "TEXT"],
    ["data_classification", "VARCHAR(50)"],
    ["revenue_impact_per_hour", "NUMERIC(14,2)"],
    ["customers_affected", "INTEGER"],
    ["regulatory_scope", "TEXT"],
    ["status", "VARCHAR(50) DEFAULT 'Active'"],
    ["notes", "TEXT"],
    ["created_at", "TIMESTAMP DEFAULT NOW()"],
    ["updated_at", "TIMESTAMP DEFAULT NOW()"],
  ];

  for (const [col, def] of addProcessCols) {
    await pool.query(
      `ALTER TABLE business_processes ADD COLUMN IF NOT EXISTS ${col} ${def}`,
    );
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS business_process_assets (
      id                   SERIAL PRIMARY KEY,
      business_process_id  INTEGER NOT NULL,
      asset_id             INTEGER NOT NULL,
      dependency_type      VARCHAR(50) DEFAULT 'Primary',
      notes                TEXT,
      created_at           TIMESTAMP DEFAULT NOW(),
      UNIQUE(business_process_id, asset_id)
    )
  `);

  await pool.query(`
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'bp_assets_bp_fk') THEN
        ALTER TABLE business_process_assets
          ADD CONSTRAINT bp_assets_bp_fk
          FOREIGN KEY (business_process_id) REFERENCES business_processes(id) ON DELETE CASCADE;
      END IF;

      IF to_regclass('public.assets') IS NOT NULL
         AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'bp_assets_asset_fk') THEN
        ALTER TABLE business_process_assets
          ADD CONSTRAINT bp_assets_asset_fk
          FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE;
      END IF;
    END $$;
  `);
}
