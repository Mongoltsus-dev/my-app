import { pool } from "@/lib/db";
import { ensureBusinessProcessSchema } from "@/lib/business-processes-schema";
import { syncAssetVulnerabilities } from "@/lib/vulnerability-sync";
import { NextRequest, NextResponse } from "next/server";
import { DatabaseError } from "pg";

async function syncAssetVulnsSafely(assetId: unknown) {
  const id = Number(assetId);
  if (!Number.isFinite(id) || id <= 0) return;
  try {
    await syncAssetVulnerabilities(id);
  } catch (error) {
    // Don't fail the asset save if vuln sync errors out — just log.
    console.error(`syncAssetVulnerabilities(${id}) failed:`, error);
  }
}

export const revalidate = 60;

// Columns kept after schema simplification (2026-05):
// id, asset_type_id, asset_type, owner_id, asset_name, asset_code,
// business_owner, technical_owner, department, data_classification,
// access_level, authentication_method, supports_critical_service, hosting,
// rto_hours, rpo_hours, criticality, internet_exposed, backup_enabled,
// encryption_enabled, mfa_enabled, logging_enabled, asset_details, status,
// created_at, updated_at

const RETURNING_COLS = `
  id, asset_type_id, asset_type, owner_id, asset_name, asset_code,
  business_owner, technical_owner, department, data_classification,
  access_level, authentication_method, supports_critical_service, hosting,
  country, region, key_users_customers,
  rto_hours, rpo_hours, criticality,
  internet_exposed, backup_enabled, encryption_enabled, mfa_enabled,
  logging_enabled, edr_enabled, vuln_scanning_enabled,
  cmdb_ci_id, notes, asset_details,
  status, created_at, updated_at
`;

const DROPPED_COLS = [
  "primary_region",
  "description",
  "location",
  "confidentiality_level",
  "integrity_level",
  "availability_level",
  "asset_value",
  "vendor",
  "version",
  "third_party_dependency_level",
  "lifecycle_stage",
  // Transient columns added then superseded — safe to drop if empty
  "logging_coverage",
  "primary_monitoring_tool",
  "user_node_count",
  "environment",
  // Freetext columns superseded by boolean flags (2026-05)
  "logging_to_siem",
  "edr_endpoint_security",
  "vuln_scanning",
  "backup_method",
];

async function ensureAssetsSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS asset_types (
      id SERIAL PRIMARY KEY,
      type_name VARCHAR(100) UNIQUE NOT NULL,
      description TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS assets (
      id SERIAL PRIMARY KEY,
      asset_type_id INTEGER,
      asset_type VARCHAR(100),
      owner_id INTEGER,
      asset_name VARCHAR(255) NOT NULL,
      asset_code VARCHAR(50) UNIQUE,
      business_owner VARCHAR(255),
      technical_owner VARCHAR(255),
      department VARCHAR(255),
      data_classification VARCHAR(50),
      access_level VARCHAR(50),
      authentication_method VARCHAR(50),
      supports_critical_service BOOLEAN DEFAULT FALSE,
      hosting VARCHAR(100),
      rto_hours NUMERIC(10,2),
      rpo_hours NUMERIC(10,2),
      criticality VARCHAR(100) NOT NULL,
      internet_exposed BOOLEAN DEFAULT FALSE,
      backup_enabled BOOLEAN DEFAULT FALSE,
      encryption_enabled BOOLEAN DEFAULT FALSE,
      mfa_enabled BOOLEAN DEFAULT FALSE,
      logging_enabled BOOLEAN DEFAULT FALSE,
      logging_to_siem VARCHAR(500),
      edr_endpoint_security VARCHAR(500),
      vuln_scanning VARCHAR(500),
      backup_method VARCHAR(500),
      country VARCHAR(100),
      region VARCHAR(100),
      key_users_customers VARCHAR(500),
      cmdb_ci_id VARCHAR(100),
      notes TEXT,
      asset_details JSONB DEFAULT '{}'::jsonb,
      status VARCHAR(50) DEFAULT 'Active',
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // Ensure new columns exist on older tables
  const addCols: [string, string][] = [
    ["asset_type_id", "INTEGER"],
    ["asset_type", "VARCHAR(100)"],
    ["owner_id", "INTEGER"],
    ["asset_code", "VARCHAR(50)"],
    ["business_owner", "VARCHAR(255)"],
    ["technical_owner", "VARCHAR(255)"],
    ["department", "VARCHAR(255)"],
    ["data_classification", "VARCHAR(50)"],
    ["access_level", "VARCHAR(50)"],
    ["authentication_method", "VARCHAR(50)"],
    ["supports_critical_service", "BOOLEAN DEFAULT FALSE"],
    ["hosting", "VARCHAR(100)"],
    ["rto_hours", "NUMERIC(10,2)"],
    ["rpo_hours", "NUMERIC(10,2)"],
    ["internet_exposed", "BOOLEAN DEFAULT FALSE"],
    ["backup_enabled", "BOOLEAN DEFAULT FALSE"],
    ["encryption_enabled", "BOOLEAN DEFAULT FALSE"],
    ["mfa_enabled", "BOOLEAN DEFAULT FALSE"],
    ["logging_enabled", "BOOLEAN DEFAULT FALSE"],
    // New boolean replacements for the old freetext columns
    ["edr_enabled", "BOOLEAN DEFAULT FALSE"],
    ["vuln_scanning_enabled", "BOOLEAN DEFAULT FALSE"],
    ["country", "VARCHAR(100)"],
    ["region", "VARCHAR(100)"],
    ["key_users_customers", "VARCHAR(500)"],
    ["cmdb_ci_id", "VARCHAR(100)"],
    ["notes", "TEXT"],
    ["asset_details", "JSONB DEFAULT '{}'::jsonb"],
    ["status", "VARCHAR(50) DEFAULT 'Active'"],
    ["created_at", "TIMESTAMP DEFAULT NOW()"],
    ["updated_at", "TIMESTAMP DEFAULT NOW()"],
  ];
  for (const [col, def] of addCols) {
    await pool.query(
      `ALTER TABLE assets ADD COLUMN IF NOT EXISTS ${col} ${def}`,
    );
  }

  // ── Data migration: derive booleans from the legacy freetext columns
  // before they're dropped. We check the legacy columns exist first so this
  // is safe to re-run after the drop.
  const legacyCheck = await pool.query(`
    SELECT column_name FROM information_schema.columns
     WHERE table_name = 'assets'
       AND column_name IN ('edr_endpoint_security','vuln_scanning','logging_to_siem','backup_method')
  `);
  const legacy = new Set(legacyCheck.rows.map((r) => r.column_name as string));
  if (legacy.has("edr_endpoint_security")) {
    await pool.query(`
      UPDATE assets SET edr_enabled = TRUE
       WHERE edr_enabled IS NOT TRUE
         AND edr_endpoint_security IS NOT NULL
         AND TRIM(edr_endpoint_security) <> ''
    `);
  }
  if (legacy.has("vuln_scanning")) {
    await pool.query(`
      UPDATE assets SET vuln_scanning_enabled = TRUE
       WHERE vuln_scanning_enabled IS NOT TRUE
         AND vuln_scanning IS NOT NULL
         AND TRIM(vuln_scanning) <> ''
    `);
  }
  if (legacy.has("logging_to_siem")) {
    await pool.query(`
      UPDATE assets SET logging_enabled = TRUE
       WHERE logging_enabled IS NOT TRUE
         AND logging_to_siem IS NOT NULL
         AND TRIM(logging_to_siem) <> ''
    `);
  }
  if (legacy.has("backup_method")) {
    await pool.query(`
      UPDATE assets SET backup_enabled = TRUE
       WHERE backup_enabled IS NOT TRUE
         AND backup_method IS NOT NULL
         AND TRIM(backup_method) <> ''
    `);
  }

  // Drop obsolete columns (including the freetext ones we just migrated)
  for (const col of DROPPED_COLS) {
    await pool.query(`ALTER TABLE assets DROP COLUMN IF EXISTS ${col}`);
  }

  // Backfill cmdb_ci_id for any rows that are missing it
  await pool.query(`
    UPDATE assets SET cmdb_ci_id = 'CI-' || (1000000 + id)
    WHERE cmdb_ci_id IS NULL OR cmdb_ci_id = ''
  `);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const toNullableString = (value: unknown) => {
  if (value === undefined || value === null) return null;
  const str = String(value).trim();
  return str.length > 0 ? str : null;
};

const toNumberOrNull = (value: unknown) => {
  if (value === undefined || value === null || value === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
};

const toBoolean = (value: unknown, fallback = false) => {
  if (value === undefined || value === null || value === "") return fallback;
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  const n = String(value).trim().toLowerCase();
  if (["true", "yes", "y", "1", "enabled", "on"].includes(n)) return true;
  if (["false", "no", "n", "0", "disabled", "off"].includes(n)) return false;
  return fallback;
};

const toJsonObject = (value: unknown) => {
  if (value === undefined || value === null || value === "") return {};
  if (typeof value === "string") {
    try {
      const parsed: unknown = JSON.parse(value);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return {};
    }
    return {};
  }
  if (typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
};

const isPublicAccessLevel = (value: unknown) =>
  ["public web access", "public api exposed"].includes(
    String(value ?? "")
      .trim()
      .toLowerCase(),
  );

const impliesStrongAuth = (value: unknown) =>
  ["password + mfa", "sso", "federated identity"].includes(
    String(value ?? "")
      .trim()
      .toLowerCase(),
  );

const normalizeBusinessProcessIds = (value: unknown) => {
  if (!Array.isArray(value)) return [];
  return Array.from(
    new Set(
      value
        .map((item) => Number(item))
        .filter((item) => Number.isInteger(item) && item > 0),
    ),
  );
};

type BusinessProcessLink = {
  id: number;
  process_code: string | null;
  process_name: string;
  criticality: string | null;
  dependency_type: string | null;
};

async function replaceAssetBusinessProcesses(
  assetId: number,
  businessProcessIds: number[],
) {
  await ensureBusinessProcessSchema();
  await pool.query(`DELETE FROM business_process_assets WHERE asset_id = $1`, [
    assetId,
  ]);

  for (const processId of businessProcessIds) {
    await pool.query(
      `INSERT INTO business_process_assets (business_process_id, asset_id, dependency_type)
       VALUES ($1, $2, 'Primary')
       ON CONFLICT (business_process_id, asset_id) DO NOTHING`,
      [processId, assetId],
    );
  }
}

async function enrichAssetsWithBusinessProcesses<
  T extends Record<string, unknown>,
>(assets: T[]) {
  if (assets.length === 0) return [];

  await ensureBusinessProcessSchema();
  const assetIds = assets
    .map((asset) => Number(asset.id))
    .filter((assetId) => Number.isInteger(assetId) && assetId > 0);

  if (assetIds.length === 0) {
    return assets.map((asset) => ({
      ...asset,
      business_process_ids: [],
      critical_business_processes: [],
    }));
  }

  const result = await pool.query(
    `SELECT bpa.asset_id,
            bp.id,
            bp.process_code,
            bp.process_name,
            bp.criticality,
            bpa.dependency_type
       FROM business_process_assets bpa
       JOIN business_processes bp ON bp.id = bpa.business_process_id
      WHERE bpa.asset_id = ANY($1::int[])
      ORDER BY
        CASE LOWER(bp.criticality)
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
          ELSE 5
        END,
        bp.process_name ASC`,
    [assetIds],
  );

  const byAssetId = new Map<number, BusinessProcessLink[]>();
  for (const row of result.rows) {
    const assetId = Number(row.asset_id);
    const current = byAssetId.get(assetId) ?? [];
    current.push({
      id: Number(row.id),
      process_code: row.process_code ?? null,
      process_name: row.process_name,
      criticality: row.criticality ?? null,
      dependency_type: row.dependency_type ?? null,
    });
    byAssetId.set(assetId, current);
  }

  return assets.map((asset) => {
    const assetId = Number(asset.id);
    const processes = byAssetId.get(assetId) ?? [];
    return {
      ...asset,
      business_process_ids: processes.map((process) => process.id),
      critical_business_processes: processes,
    };
  });
}

async function enrichAssetWithBusinessProcesses<T extends Record<string, unknown>>(
  asset: T,
) {
  const [enriched] = await enrichAssetsWithBusinessProcesses([asset]);
  return enriched;
}

async function generateAssetCode() {
  const result = await pool.query(
    `SELECT COALESCE(MAX(substring(asset_code FROM '^AST-([0-9]+)$')::integer), 0) + 1 AS next_number
    FROM assets WHERE asset_code ~ '^AST-[0-9]+$'`,
  );
  const n = Number(result.rows[0]?.next_number ?? 1);
  return `AST-${String(n).padStart(3, "0")}`;
}

async function generateCmdbCiId() {
  const result = await pool.query(
    `SELECT COALESCE(MAX(substring(cmdb_ci_id FROM '^CI-([0-9]+)$')::integer), 1000000) + 1 AS next_number
    FROM assets WHERE cmdb_ci_id ~ '^CI-[0-9]+$'`,
  );
  const n = Number(result.rows[0]?.next_number ?? 1000001);
  return `CI-${n}`;
}

async function resolveAssetTypeData(assetTypeId: unknown, assetType: unknown) {
  let resolvedAssetTypeId: number | null = null;

  if (assetTypeId !== undefined && assetTypeId !== null && assetTypeId !== "") {
    const numericId = Number(assetTypeId);
    if (Number.isInteger(numericId) && numericId > 0) {
      resolvedAssetTypeId = numericId;
    } else if (typeof assetTypeId === "string") {
      const norm = assetTypeId.trim();
      if (norm) {
        const lookup = await pool.query(
          "SELECT id FROM asset_types WHERE lower(type_name) = lower($1) LIMIT 1",
          [norm],
        );
        if (lookup.rows.length > 0) {
          resolvedAssetTypeId = Number(lookup.rows[0].id);
        } else {
          const created = await pool.query(
            "INSERT INTO asset_types (type_name) VALUES ($1) RETURNING id",
            [norm],
          );
          resolvedAssetTypeId = Number(created.rows[0].id);
        }
      }
    }
  }

  let resolvedAssetType =
    typeof assetType === "string" && assetType.trim() ? assetType.trim() : null;
  if (!resolvedAssetType && typeof assetTypeId === "string") {
    resolvedAssetType = assetTypeId.trim() || null;
  }
  if (!resolvedAssetType && resolvedAssetTypeId) {
    const r = await pool.query(
      "SELECT type_name FROM asset_types WHERE id = $1",
      [resolvedAssetTypeId],
    );
    if (r.rows[0]?.type_name) resolvedAssetType = r.rows[0].type_name;
  }

  return { resolvedAssetTypeId, resolvedAssetType };
}

// ─── INSERT ───────────────────────────────────────────────────────────────────

async function insertAssetRecord(input: Record<string, unknown>) {
  const assetName = toNullableString(input.asset_name);
  const criticality = toNullableString(input.criticality);
  if (!assetName || !criticality)
    throw new Error("asset_name and criticality are required");

  const { resolvedAssetTypeId, resolvedAssetType } = await resolveAssetTypeData(
    input.asset_type_id,
    input.asset_type,
  );
  const finalAssetCode =
    toNullableString(input.asset_code) || (await generateAssetCode());
  const finalCmdbCiId =
    toNullableString(input.cmdb_ci_id) || (await generateCmdbCiId());

  const result = await pool.query(
    `INSERT INTO assets
       (asset_type_id, asset_type, owner_id, asset_name, asset_code,
        business_owner, technical_owner, department, data_classification,
        access_level, authentication_method, supports_critical_service, hosting,
        country, region, key_users_customers,
        rto_hours, rpo_hours, criticality,
        internet_exposed, backup_enabled, encryption_enabled, mfa_enabled,
        logging_enabled, edr_enabled, vuln_scanning_enabled,
        cmdb_ci_id, notes, asset_details,
        status, created_at, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29::jsonb,$30,NOW(),NOW())
     RETURNING ${RETURNING_COLS}`,
    [
      resolvedAssetTypeId,
      resolvedAssetType,
      toNumberOrNull(input.owner_id),
      assetName,
      finalAssetCode,
      toNullableString(input.business_owner),
      toNullableString(input.technical_owner),
      toNullableString(input.department),
      toNullableString(input.data_classification),
      toNullableString(input.access_level),
      toNullableString(input.authentication_method),
      toBoolean(input.supports_critical_service, false),
      toNullableString(input.hosting),
      toNullableString(input.country),
      toNullableString(input.region),
      toNullableString(input.key_users_customers),
      toNumberOrNull(input.rto_hours),
      toNumberOrNull(input.rpo_hours),
      criticality,
      toBoolean(
        input.internet_exposed,
        isPublicAccessLevel(input.access_level),
      ),
      toBoolean(input.backup_enabled, false),
      toBoolean(input.encryption_enabled, false),
      toBoolean(
        input.mfa_enabled,
        impliesStrongAuth(input.authentication_method),
      ),
      toBoolean(input.logging_enabled, false),
      toBoolean(input.edr_enabled, false),
      toBoolean(input.vuln_scanning_enabled, false),
      finalCmdbCiId,
      toNullableString(input.notes),
      JSON.stringify(toJsonObject(input.asset_details)),
      toNullableString(input.status) || "Active",
    ],
  );

  const savedAsset = result.rows[0];
  const businessProcessIds = normalizeBusinessProcessIds(
    input.business_process_ids,
  );

  if (businessProcessIds.length > 0) {
    await replaceAssetBusinessProcesses(
      Number(savedAsset.id),
      businessProcessIds,
    );
  }

  return enrichAssetWithBusinessProcesses(savedAsset);
}

// ─── UPDATE ───────────────────────────────────────────────────────────────────

async function updateAssetRecord(input: Record<string, unknown>) {
  const assetId = Number(input.id);
  const assetName = toNullableString(input.asset_name);
  const criticality = toNullableString(input.criticality);

  if (!Number.isInteger(assetId) || assetId <= 0)
    throw new Error("A valid asset id is required");
  if (!assetName || !criticality)
    throw new Error("asset_name and criticality are required");

  const { resolvedAssetTypeId, resolvedAssetType } = await resolveAssetTypeData(
    input.asset_type_id,
    input.asset_type,
  );

  const result = await pool.query(
    `UPDATE assets SET
       asset_type_id = $1, asset_type = $2, owner_id = $3,
       asset_name = $4, asset_code = $5,
       business_owner = $6, technical_owner = $7, department = $8,
       data_classification = $9, access_level = $10, authentication_method = $11,
       supports_critical_service = $12, hosting = $13,
       country = $14, region = $15, key_users_customers = $16,
       rto_hours = $17, rpo_hours = $18, criticality = $19,
       internet_exposed = $20, backup_enabled = $21, encryption_enabled = $22,
       mfa_enabled = $23, logging_enabled = $24,
       edr_enabled = $25, vuln_scanning_enabled = $26,
       cmdb_ci_id = $27, notes = $28, asset_details = $29::jsonb,
       status = $30, updated_at = NOW()
     WHERE id = $31
     RETURNING ${RETURNING_COLS}`,
    [
      resolvedAssetTypeId,
      resolvedAssetType,
      toNumberOrNull(input.owner_id),
      assetName,
      toNullableString(input.asset_code),
      toNullableString(input.business_owner),
      toNullableString(input.technical_owner),
      toNullableString(input.department),
      toNullableString(input.data_classification),
      toNullableString(input.access_level),
      toNullableString(input.authentication_method),
      toBoolean(input.supports_critical_service, false),
      toNullableString(input.hosting),
      toNullableString(input.country),
      toNullableString(input.region),
      toNullableString(input.key_users_customers),
      toNumberOrNull(input.rto_hours),
      toNumberOrNull(input.rpo_hours),
      criticality,
      toBoolean(
        input.internet_exposed,
        isPublicAccessLevel(input.access_level),
      ),
      toBoolean(input.backup_enabled, false),
      toBoolean(input.encryption_enabled, false),
      toBoolean(
        input.mfa_enabled,
        impliesStrongAuth(input.authentication_method),
      ),
      toBoolean(input.logging_enabled, false),
      toBoolean(input.edr_enabled, false),
      toBoolean(input.vuln_scanning_enabled, false),
      toNullableString(input.cmdb_ci_id),
      toNullableString(input.notes),
      JSON.stringify(toJsonObject(input.asset_details)),
      toNullableString(input.status) || "Active",
      assetId,
    ],
  );

  if (result.rows.length === 0) throw new Error("Asset not found");

  const savedAsset = result.rows[0];
  const supportsCriticalService = toBoolean(
    input.supports_critical_service,
    false,
  );

  if (!supportsCriticalService) {
    await replaceAssetBusinessProcesses(assetId, []);
  } else if (Array.isArray(input.business_process_ids)) {
    await replaceAssetBusinessProcesses(
      assetId,
      normalizeBusinessProcessIds(input.business_process_ids),
    );
  }

  return enrichAssetWithBusinessProcesses(savedAsset);
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

export async function GET() {
  try {
    await ensureAssetsSchema();
    await ensureBusinessProcessSchema();
    const result = await pool.query(
      `SELECT ${RETURNING_COLS} FROM assets ORDER BY created_at DESC`,
    );
    const assets = await enrichAssetsWithBusinessProcesses(result.rows);
    const response = NextResponse.json({ success: true, assets });
    response.headers.set(
      "Cache-Control",
      "public, s-maxage=60, stale-while-revalidate=120",
    );
    return response;
  } catch (error) {
    console.error("Error fetching assets:", error);
    return NextResponse.json(
      { error: "Failed to fetch assets" },
      { status: 500 },
    );
  }
}

export async function POST(req: NextRequest) {
  try {
    await ensureAssetsSchema();
    await ensureBusinessProcessSchema();
    const body = await req.json();

    if (Array.isArray(body?.assets)) {
      const inserted: Array<Record<string, unknown>> = [];
      const failed: Array<{
        rowIndex: number;
        asset_name?: string;
        error: string;
      }> = [];
      for (let i = 0; i < body.assets.length; i++) {
        const row = body.assets[i];
        try {
          const savedAsset = await insertAssetRecord(row || {});
          await syncAssetVulnsSafely(savedAsset.id);
          inserted.push(savedAsset);
        } catch (error) {
          failed.push({
            rowIndex: i + 1,
            asset_name:
              typeof row?.asset_name === "string" ? row.asset_name : undefined,
            error:
              error instanceof Error ? error.message : "Failed to import row",
          });
        }
      }
      return NextResponse.json({
        success: failed.length === 0,
        insertedCount: inserted.length,
        failedCount: failed.length,
        inserted,
        failed,
        message:
          failed.length === 0
            ? `Imported ${inserted.length} assets successfully.`
            : `Imported ${inserted.length} assets with ${failed.length} failed rows.`,
      });
    }

    const savedAsset = await insertAssetRecord(body || {});
    await syncAssetVulnsSafely(savedAsset.id);
    return NextResponse.json(
      { success: true, asset: savedAsset },
      { status: 201 },
    );
  } catch (error) {
    console.error("Error creating asset:", error);
    if (error instanceof DatabaseError && error.code === "23505")
      return NextResponse.json(
        { error: "Asset code already exists." },
        { status: 409 },
      );
    if (error instanceof Error && error.message)
      return NextResponse.json({ error: error.message }, { status: 500 });
    return NextResponse.json(
      { error: "Failed to create asset" },
      { status: 500 },
    );
  }
}

export async function PUT(req: NextRequest) {
  try {
    await ensureAssetsSchema();
    await ensureBusinessProcessSchema();
    const body = await req.json();
    const savedAsset = await updateAssetRecord(body || {});
    await syncAssetVulnsSafely(savedAsset.id);
    return NextResponse.json({ success: true, asset: savedAsset });
  } catch (error) {
    console.error("Error updating asset:", error);
    if (error instanceof DatabaseError && error.code === "23505")
      return NextResponse.json(
        { error: "Asset code already exists." },
        { status: 409 },
      );
    if (error instanceof Error && error.message === "Asset not found")
      return NextResponse.json({ error: error.message }, { status: 404 });
    if (error instanceof Error && error.message)
      return NextResponse.json({ error: error.message }, { status: 400 });
    return NextResponse.json(
      { error: "Failed to update asset" },
      { status: 500 },
    );
  }
}

export async function DELETE(req: NextRequest) {
  try {
    await ensureAssetsSchema();
    const { searchParams } = new URL(req.url);
    const assetId = Number(searchParams.get("id"));
    if (!Number.isInteger(assetId) || assetId <= 0)
      return NextResponse.json(
        { error: "A valid asset id is required" },
        { status: 400 },
      );

    const result = await pool.query(
      "DELETE FROM assets WHERE id = $1 RETURNING id",
      [assetId],
    );
    if (result.rows.length === 0)
      return NextResponse.json({ error: "Asset not found" }, { status: 404 });

    return NextResponse.json({ success: true, deletedId: result.rows[0].id });
  } catch (error) {
    console.error("Error deleting asset:", error);
    if (error instanceof DatabaseError && error.code === "23503")
      return NextResponse.json(
        {
          error:
            "This asset is linked to other records and cannot be deleted yet.",
        },
        { status: 409 },
      );
    if (error instanceof Error && error.message)
      return NextResponse.json({ error: error.message }, { status: 500 });
    return NextResponse.json(
      { error: "Failed to delete asset" },
      { status: 500 },
    );
  }
}
