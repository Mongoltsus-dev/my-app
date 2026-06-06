import { pool } from "@/lib/db";

export type CisaKevVulnerability = {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription?: string;
  requiredAction?: string;
  dueDate: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
  cwes?: string[];
};

type CisaKevRecord = {
  cve_id: string | null;
  vendor_project: string | null;
  product: string | null;
  vulnerability_name: string | null;
  date_added: string | null;
  short_description: string | null;
  required_action: string | null;
  due_date: string | null;
  known_ransomware_campaign_use: string | null;
  notes: string | null;
  cwes: string[];
};

type CisaKevRow = {
  cve_id: string;
  vendor_project: string | null;
  product: string | null;
  vulnerability_name: string;
  date_added: string | Date | null;
  short_description: string | null;
  required_action: string | null;
  due_date: string | Date | null;
  known_ransomware_campaign_use: string | null;
  notes: string | null;
  cwes: string[] | null;
};

type AssetMatchRow = {
  id: number;
  asset_name: string;
  asset_type: string | null;
  vendor: string | null;
  version: string | null;
};

const HEADER_MAP: Record<string, keyof CisaKevRecord> = {
  cveid: "cve_id",
  cve_id: "cve_id",
  vendorproject: "vendor_project",
  vendor_project: "vendor_project",
  vendor: "vendor_project",
  product: "product",
  vulnerabilityname: "vulnerability_name",
  vulnerability_name: "vulnerability_name",
  dateadded: "date_added",
  date_added: "date_added",
  shortdescription: "short_description",
  short_description: "short_description",
  requiredaction: "required_action",
  required_action: "required_action",
  duedate: "due_date",
  due_date: "due_date",
  knownransomwarecampaignuse: "known_ransomware_campaign_use",
  known_ransomware_campaign_use: "known_ransomware_campaign_use",
  notes: "notes",
  cwes: "cwes",
};

export async function ensureCisaKevCatalogTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cisa_kev_catalog (
      cve_id VARCHAR(32) PRIMARY KEY,
      vendor_project VARCHAR(255),
      product VARCHAR(255),
      vulnerability_name TEXT NOT NULL,
      date_added DATE,
      short_description TEXT,
      required_action TEXT,
      due_date DATE,
      known_ransomware_campaign_use VARCHAR(50),
      notes TEXT,
      cwes TEXT[] DEFAULT ARRAY[]::TEXT[],
      source VARCHAR(50) DEFAULT 'cisa_kev',
      imported_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(
    `ALTER TABLE cisa_kev_catalog ADD COLUMN IF NOT EXISTS vendor_project VARCHAR(255)`,
  );
  await pool.query(
    `ALTER TABLE cisa_kev_catalog ADD COLUMN IF NOT EXISTS product VARCHAR(255)`,
  );
  await pool.query(
    `ALTER TABLE cisa_kev_catalog ADD COLUMN IF NOT EXISTS vulnerability_name TEXT`,
  );
  await pool.query(
    `ALTER TABLE cisa_kev_catalog ADD COLUMN IF NOT EXISTS date_added DATE`,
  );
  await pool.query(
    `ALTER TABLE cisa_kev_catalog ADD COLUMN IF NOT EXISTS short_description TEXT`,
  );
  await pool.query(
    `ALTER TABLE cisa_kev_catalog ADD COLUMN IF NOT EXISTS required_action TEXT`,
  );
  await pool.query(
    `ALTER TABLE cisa_kev_catalog ADD COLUMN IF NOT EXISTS due_date DATE`,
  );
  await pool.query(
    `ALTER TABLE cisa_kev_catalog ADD COLUMN IF NOT EXISTS known_ransomware_campaign_use VARCHAR(50)`,
  );
  await pool.query(
    `ALTER TABLE cisa_kev_catalog ADD COLUMN IF NOT EXISTS notes TEXT`,
  );
  await pool.query(
    `ALTER TABLE cisa_kev_catalog ADD COLUMN IF NOT EXISTS cwes TEXT[] DEFAULT ARRAY[]::TEXT[]`,
  );
  await pool.query(
    `ALTER TABLE cisa_kev_catalog ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'cisa_kev'`,
  );
  await pool.query(
    `ALTER TABLE cisa_kev_catalog ADD COLUMN IF NOT EXISTS imported_at TIMESTAMP DEFAULT NOW()`,
  );
  await pool.query(
    `ALTER TABLE cisa_kev_catalog ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()`,
  );

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_cisa_kev_catalog_vendor_product
      ON cisa_kev_catalog (LOWER(vendor_project), LOWER(product))
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_cisa_kev_catalog_due_date
      ON cisa_kev_catalog (due_date)
  `);
}

export async function getStoredCisaKevVulnerabilities(limit: number) {
  const table = await pool.query<{ exists: boolean }>(
    "SELECT to_regclass('public.cisa_kev_catalog') IS NOT NULL AS exists",
  );

  if (!table.rows[0]?.exists) {
    return [];
  }

  const result = await pool.query<CisaKevRow>(
    `SELECT cve_id, vendor_project, product, vulnerability_name, date_added,
            short_description, required_action, due_date,
            known_ransomware_campaign_use, notes, cwes
       FROM cisa_kev_catalog
      ORDER BY date_added DESC NULLS LAST, cve_id ASC
      LIMIT $1`,
    [limit],
  );

  return result.rows.map(formatCisaKevRow);
}

export async function importCisaKevCsv(csvText: string) {
  await ensureCisaKevCatalogTable();

  const rows = parseCsv(csvText);
  const [headers, ...dataRows] = rows;

  if (!headers || dataRows.length === 0) {
    throw new Error("CSV file has no importable rows.");
  }

  const records = dataRows
    .map((row) => toRecord(headers, row))
    .filter((record) => record.cve_id && record.vulnerability_name);

  if (records.length === 0) {
    throw new Error("No CISA KEV records were found in the CSV file.");
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    for (const record of records) {
      await client.query(
        `INSERT INTO cisa_kev_catalog (
          cve_id, vendor_project, product, vulnerability_name, date_added,
          short_description, required_action, due_date,
          known_ransomware_campaign_use, notes, cwes, updated_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
        ON CONFLICT (cve_id)
        DO UPDATE SET
          vendor_project = EXCLUDED.vendor_project,
          product = EXCLUDED.product,
          vulnerability_name = EXCLUDED.vulnerability_name,
          date_added = EXCLUDED.date_added,
          short_description = EXCLUDED.short_description,
          required_action = EXCLUDED.required_action,
          due_date = EXCLUDED.due_date,
          known_ransomware_campaign_use = EXCLUDED.known_ransomware_campaign_use,
          notes = EXCLUDED.notes,
          cwes = EXCLUDED.cwes,
          updated_at = NOW()`,
        [
          record.cve_id,
          record.vendor_project,
          record.product,
          record.vulnerability_name,
          record.date_added,
          record.short_description,
          record.required_action,
          record.due_date,
          record.known_ransomware_campaign_use,
          record.notes,
          record.cwes,
        ],
      );
    }

    await client.query("COMMIT");
    return records.length;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export async function syncCisaKevCatalogToVulnerabilities() {
  await ensureCisaKevCatalogTable();

  const { rows: catalogRows } = await pool.query<CisaKevRow>(
    `SELECT cve_id, vendor_project, product, vulnerability_name, date_added,
            short_description, required_action, due_date,
            known_ransomware_campaign_use, notes, cwes
       FROM cisa_kev_catalog
      ORDER BY date_added DESC NULLS LAST, cve_id ASC`,
  );

  const { rows: assets } = await pool.query<AssetMatchRow>(
    `SELECT id, asset_name, asset_type, vendor, version
       FROM assets
      WHERE COALESCE(status, 'Active') <> 'Retired'`,
  );

  let created = 0;
  let updated = 0;
  let matched = 0;
  let removedUnmatched = 0;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const cleanup = await client.query(
      `DELETE FROM vulnerabilities
        WHERE source = 'cisa_kev'
          AND asset_id IS NULL`,
    );
    removedUnmatched = cleanup.rowCount ?? 0;

    for (const row of catalogRows) {
      const matchingAssets = assets.filter((asset) =>
        assetMatchesKev(asset, row),
      );

      if (matchingAssets.length === 0) {
        continue;
      }

      const descriptionParts = [
        row.vendor_project && row.product
          ? `${row.vendor_project} ${row.product}`
          : null,
        row.short_description,
        row.required_action ? `Required action: ${row.required_action}` : null,
        row.due_date ? `Due date: ${formatDate(row.due_date)}` : null,
        row.known_ransomware_campaign_use
          ? `Known ransomware use: ${row.known_ransomware_campaign_use}`
          : null,
        row.notes,
      ].filter(Boolean);

      for (const asset of matchingAssets) {
        matched++;
        const existing = await client.query<{ id: number }>(
          `SELECT id
             FROM vulnerabilities
            WHERE cve_id = $1
              AND asset_id = $2
              AND source = 'cisa_kev'
            LIMIT 1`,
          [row.cve_id, asset.id],
        );

        if (existing.rows[0]) {
          await client.query(
            `UPDATE vulnerabilities
                SET title = $1,
                    description = $2,
                    vulnerability_type = 'CVE',
                    severity = 'High',
                    reference_url = $3,
                    updated_at = NOW()
              WHERE id = $4`,
            [
              row.vulnerability_name,
              descriptionParts.join("\n\n") || null,
              `https://nvd.nist.gov/vuln/detail/${row.cve_id}`,
              existing.rows[0].id,
            ],
          );
          updated++;
          continue;
        }

        await client.query(
          `INSERT INTO vulnerabilities
             (asset_id, cve_id, title, description, vulnerability_type, severity,
              cvss_score, status, reference_url, source)
           VALUES ($1, $2, $3, $4, 'CVE', 'High', NULL, 'open', $5, 'cisa_kev')`,
          [
            asset.id,
            row.cve_id,
            row.vulnerability_name,
            descriptionParts.join("\n\n") || null,
            `https://nvd.nist.gov/vuln/detail/${row.cve_id}`,
          ],
        );
        created++;
      }
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }

  return {
    created,
    updated,
    matched,
    removedUnmatched,
    total: catalogRows.length,
  };
}

const GENERIC_PRODUCT_TOKENS = new Set([
  "app",
  "apps",
  "application",
  "applications",
  "client",
  "device",
  "edition",
  "enterprise",
  "extension",
  "firmware",
  "module",
  "multiple",
  "plugin",
  "product",
  "products",
  "server",
  "service",
  "services",
  "software",
  "suite",
  "system",
  "systems",
  "web",
]);

function assetMatchesKev(asset: AssetMatchRow, kev: CisaKevRow) {
  const assetNameText = normalizeMatchText(asset.asset_name);
  const assetText = normalizeMatchText(
    [asset.vendor, asset.asset_name, asset.asset_type, asset.version].join(" "),
  );
  const vendorText = normalizeMatchText(kev.vendor_project ?? "");
  const productText = normalizeMatchText(kev.product ?? "");

  if (!assetText || (!vendorText && !productText)) return false;

  const vendorTokens = matchTokens(vendorText);
  const productTokens = matchTokens(productText).filter(
    (token) => !GENERIC_PRODUCT_TOKENS.has(token),
  );
  const assetTokens = new Set(matchTokens(assetText));
  const productPhraseMatches =
    productTokens.length > 0 &&
    productText.length >= 4 &&
    (assetText.includes(productText) || productText.includes(assetNameText));

  const vendorMatches = vendorTokens.some((token) => assetTokens.has(token));
  const productMatches =
    productPhraseMatches ||
    productTokens.some((token) => assetTokens.has(token));

  if (vendorMatches && productMatches) return true;

  if (productPhraseMatches) return true;

  const explicitAssetVendor = normalizeMatchText(asset.vendor ?? "");
  if (explicitAssetVendor && vendorText) {
    const vendorContains =
      vendorText.includes(explicitAssetVendor) ||
      explicitAssetVendor.includes(vendorText);
    if (vendorContains && productMatches) return true;
  }

  return productTokens.length >= 2 && productMatches && vendorMatches;
}

function normalizeMatchText(value: string) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function matchTokens(value: string) {
  return normalizeMatchText(value)
    .split(" ")
    .filter((token) => token.length >= 3);
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

function toRecord(headers: string[], row: string[]): CisaKevRecord {
  const record: CisaKevRecord = {
    cve_id: null,
    vendor_project: null,
    product: null,
    vulnerability_name: null,
    date_added: null,
    short_description: null,
    required_action: null,
    due_date: null,
    known_ransomware_campaign_use: null,
    notes: null,
    cwes: [],
  };

  headers.forEach((header, index) => {
    const mappedHeader = HEADER_MAP[normalizeHeader(header)];
    if (!mappedHeader) return;

    if (mappedHeader === "cwes") {
      record.cwes = parseCwes(row[index]);
      return;
    }

    if (mappedHeader === "date_added" || mappedHeader === "due_date") {
      record[mappedHeader] = parseDate(row[index]);
      return;
    }

    record[mappedHeader] = clean(row[index]);
  });

  return record;
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

function parseDate(value: unknown) {
  const raw = clean(value);
  if (!raw) return null;

  if (/^\d{4}-\d{1,2}-\d{1,2}$/.test(raw)) {
    const [year, month, day] = raw.split("-");
    return `${year}-${month.padStart(2, "0")}-${day.padStart(2, "0")}`;
  }

  if (/^\d{1,2}\/\d{1,2}\/\d{4}$/.test(raw)) {
    const [month, day, year] = raw.split("/");
    return `${year}-${month.padStart(2, "0")}-${day.padStart(2, "0")}`;
  }

  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString().slice(0, 10);
}

function parseCwes(value: unknown) {
  const raw = clean(value);
  if (!raw) return [];
  return raw
    .split(/[;,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatDate(value: string | Date | null) {
  if (!value) return "";
  if (value instanceof Date) return value.toISOString().slice(0, 10);
  return String(value).slice(0, 10);
}

function formatCisaKevRow(row: CisaKevRow): CisaKevVulnerability {
  return {
    cveID: row.cve_id,
    vendorProject: row.vendor_project ?? "Unknown",
    product: row.product ?? "Unknown",
    vulnerabilityName: row.vulnerability_name,
    dateAdded: formatDate(row.date_added),
    shortDescription: row.short_description ?? undefined,
    requiredAction: row.required_action ?? undefined,
    dueDate: formatDate(row.due_date),
    knownRansomwareCampaignUse: row.known_ransomware_campaign_use ?? undefined,
    notes: row.notes ?? undefined,
    cwes: row.cwes ?? [],
  };
}
