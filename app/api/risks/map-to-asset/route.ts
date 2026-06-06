import { pool } from "@/lib/db";
import { NextRequest, NextResponse } from "next/server";

/**
 * POST /api/risks/map-to-asset
 * Body: { asset_id?: number, all?: boolean }
 *
 * Projects tagged catalog risks onto registered assets.
 *
 * Source of truth: the user's 50 risks live in risk_register today (per the
 * heat map). We treat the distinct (risk_title, nist_csf_function, applicable_asset_types)
 * tuples as the catalog, and project them onto each asset whose asset_type
 * appears in applicable_asset_types.
 *
 * Dedup: we don't insert (asset_id, risk_title) if it already exists.
 * Each new risk_register row also gets risk_analysis + control_recommendations.
 */

const LIKELIHOOD_LABELS = ["", "Rare", "Unlikely", "Possible", "Likely", "Very Likely"];
const IMPACT_LABELS = ["", "Negligible", "Minor", "Moderate", "Major", "Critical"];

type Queryable = { query: typeof pool.query };

type CatalogRisk = {
  source_id: number;
  source_risk_code: string | null;
  risk_title: string;
  risk_description: string | null;
  nist_csf_function: string | null;
  nist_csf_category: string | null;
  nist_csf_subcategory: string | null;
  applicable_asset_types: string | null;
  arising_threats: string | null;
  assessed_by: string | null;
  notes: string | null;
  status: string | null;
  base_likelihood: number | string | null;
  base_impact: number | string | null;
};

function calcLevel(score: number): string {
  if (score <= 4) return "Low";
  if (score <= 9) return "Medium";
  if (score <= 16) return "High";
  return "Critical";
}

type AssetCtx = {
  id: number;
  asset_name: string;
  asset_type: string | null;
  criticality: string | null;
  access_level: string | null;
  authentication_method: string | null;
  data_classification: string | null;
  internet_exposed: boolean | null;
  supports_critical_service: boolean | null;
};

const ASSET_TAG_ALIASES: Record<string, string[]> = {
  application: [
    "application",
    "api",
    "admin panel",
    "browser",
    "customer-facing system",
    "file transfer",
    "information system",
    "integration",
    "plugin",
    "software",
    "system",
    "third-party tool",
  ],
  service: [
    "business process",
    "communication process",
    "critical system",
    "incident response plan",
    "information system",
    "organization",
    "policy",
    "recovery plan",
    "risk register",
    "service",
  ],
  database: [
    "backup storage",
    "cloud storage",
    "customer data",
    "data",
    "database",
    "employee data",
    "file storage",
    "financial data",
    "sensitive information",
  ],
  network: [
    "firewall",
    "guest wi-fi",
    "network",
    "network device",
    "router",
    "vpn",
    "wi-fi",
  ],
  "endpoint fleet": [
    "desktop",
    "device",
    "endpoint",
    "file server",
    "hardware",
    "it staff",
    "laptop",
    "mobile device",
    "operating system",
    "server",
  ],
  identity: [
    "account",
    "admin account",
    "employee",
    "email system",
    "identity",
    "it staff",
    "service account",
    "system administrator",
    "user account",
    "vpn",
  ],
  "saas tenant": [
    "cloud account",
    "cloud service",
    "cloud storage",
    "email system",
    "managed it provider",
    "outsourced support",
    "saas",
    "saas tenant",
    "software vendor",
    "vendor",
    "vendor account",
  ],
  cloud: ["cloud account", "cloud service", "cloud storage", "saas", "vendor"],
  data: ["backup storage", "cloud storage", "database", "file storage"],
  "file storage": ["backup storage", "cloud storage", "data", "file storage"],
  hardware: ["desktop", "device", "endpoint", "laptop", "network device", "server"],
  infrastructure: [
    "backup storage",
    "cloud service",
    "endpoint",
    "firewall",
    "network",
    "network device",
    "server",
  ],
  "identity provider": [
    "account",
    "admin account",
    "employee",
    "identity",
    "service account",
    "user account",
  ],
  software: ["application", "api", "integration", "plugin", "software"],
};

const CRITICAL_PROCESS_TAGS = new Set([
  "business process",
  "communication process",
  "compliance records",
  "critical system",
  "incident response plan",
  "organization",
  "policy",
  "recovery plan",
  "risk register",
]);

function normalize(value: string | null | undefined) {
  return String(value ?? "").trim().toLowerCase().replace(/\s+/g, " ");
}

function splitTags(value: string | null | undefined) {
  return String(value ?? "")
    .split(/[,;|]/)
    .map((tag) => normalize(tag))
    .filter(Boolean);
}

function isBusinessCriticalAsset(asset: AssetCtx) {
  const criticality = normalize(asset.criticality);
  return (
    asset.supports_critical_service === true ||
    criticality.includes("tier 0") ||
    criticality.includes("tier 1") ||
    criticality.includes("mission critical") ||
    criticality.includes("business critical") ||
    criticality.includes("critical")
  );
}

function tagMatchesAssetType(tag: string, assetType: string | null) {
  const normalizedAssetType = normalize(assetType);
  if (!tag || !normalizedAssetType) return false;
  if (
    tag === normalizedAssetType ||
    normalizedAssetType.includes(tag) ||
    tag.includes(normalizedAssetType)
  ) {
    return true;
  }

  const aliases = ASSET_TAG_ALIASES[normalizedAssetType] ?? [];
  return aliases.some(
    (alias) => tag === alias || alias.includes(tag) || tag.includes(alias),
  );
}

function assetTypeMatches(
  applicable: string | null,
  asset: AssetCtx,
  hasBusinessCriticalAssets: boolean,
) {
  const tags = splitTags(applicable);
  if (tags.length === 0) return false;
  if (tags.includes("all") || tags.includes("*")) return true;
  if (tags.some((tag) => tagMatchesAssetType(tag, asset.asset_type))) return true;

  const hasCriticalProcessTag = tags.some((tag) => CRITICAL_PROCESS_TAGS.has(tag));
  if (hasCriticalProcessTag && isBusinessCriticalAsset(asset)) return true;

  const onlyCriticalProcessTags = tags.every((tag) => CRITICAL_PROCESS_TAGS.has(tag));
  return onlyCriticalProcessTags && !hasBusinessCriticalAssets;
}

function deriveTemplateBaseScores(cat: CatalogRisk): { likelihood: number; impact: number } {
  const text = normalize(
    [
      cat.risk_title,
      cat.risk_description,
      cat.arising_threats,
      cat.applicable_asset_types,
      cat.nist_csf_function,
      cat.nist_csf_category,
    ].join(" "),
  );

  let likelihood = 3;
  let impact = 3;

  if (
    /\b(phishing|credential|account takeover|password|default|malware|ransomware|unpatched|vulnerability|misconfiguration|unauthorized|cloud|vendor|third-party)\b/.test(
      text,
    )
  ) {
    likelihood = 4;
  }

  if (
    /\b(data leakage|data loss|privacy|compliance|customer|reputation|business disruption|service disruption|extended downtime|ransomware|critical system|recovery)\b/.test(
      text,
    )
  ) {
    impact = 4;
  }

  if (/\b(ransomware|data loss|data leakage|extended downtime|critical system)\b/.test(text)) {
    impact = 5;
  }

  const category = normalize(cat.nist_csf_category);
  if (category.startsWith("gv.")) {
    impact = Math.max(impact, 3);
  } else if (category.startsWith("de.") || category.startsWith("rs.") || category.startsWith("rc.")) {
    impact = Math.max(impact, 4);
  }

  return { likelihood, impact };
}

function deriveScores(
  asset: AssetCtx,
  baseLikelihood: number | null,
  baseImpact: number | null,
): { likelihood: number; impact: number } {
  // Start from the catalog's default if present, otherwise 3×3
  let likelihood = baseLikelihood ?? 3;
  let impact = baseImpact ?? 3;

  const crit = String(asset.criticality ?? "").toLowerCase();
  if (crit.includes("tier 0") || crit.includes("life") || crit.includes("safety"))
    impact = Math.max(impact, 5);
  else if (crit.includes("tier 1") || crit.includes("critical"))
    impact = Math.max(impact, 4);
  else if (crit.includes("tier 2") || crit.includes("high"))
    impact = Math.max(impact, 4);
  else if (crit.includes("low")) impact = Math.min(impact, 2);

  const access = String(asset.access_level ?? "").toLowerCase();
  if (access.includes("public api")) likelihood += 2;
  else if (access.includes("public web")) likelihood += 1;
  else if (access.includes("internal") || access.includes("vpn")) likelihood -= 1;

  const auth = String(asset.authentication_method ?? "").toLowerCase();
  if (auth === "password only") likelihood += 1;
  else if (auth.includes("mfa") || auth.includes("sso")) likelihood -= 1;

  if (asset.internet_exposed) likelihood += 1;

  const dc = String(asset.data_classification ?? "").toLowerCase();
  if (dc.includes("restricted") || dc.includes("confidential")) impact += 1;
  if (asset.supports_critical_service) impact += 1;

  likelihood = Math.max(1, Math.min(5, likelihood));
  impact = Math.max(1, Math.min(5, impact));
  return { likelihood, impact };
}

async function generateRiskCode(client: Queryable): Promise<string> {
  const r = await client.query(
    `SELECT COALESCE(MAX(substring(risk_code FROM '^RSK-([0-9]+)$')::integer), 0) + 1 AS n
       FROM risk_register WHERE risk_code ~ '^RSK-[0-9]+$'`,
  );
  return `RSK-${String(Number(r.rows[0]?.n ?? 1)).padStart(4, "0")}`;
}

async function ensureMappingSchema(client: Queryable) {
  const statements = [
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS applicable_asset_types TEXT",
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS arising_threats TEXT",
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS nist_csf_subcategory VARCHAR(100)",
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS risk_id VARCHAR(50)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS likelihood_label VARCHAR(50)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS likelihood_rationale TEXT",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS impact_label VARCHAR(50)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS impact_rationale TEXT",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS risk_score INTEGER",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_likelihood INTEGER",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_likelihood_label VARCHAR(50)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_impact INTEGER",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_impact_label VARCHAR(50)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_risk_score INTEGER",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_risk_level VARCHAR(20)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_likelihood_rationale TEXT",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_impact_rationale TEXT",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_calculation_method VARCHAR(50) DEFAULT 'mapped'",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_assessor_override BOOLEAN DEFAULT FALSE",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_review_status VARCHAR(50) DEFAULT 'Needs Inherent Review'",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_assessed_at TIMESTAMP",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS residual_risk_score INTEGER",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS residual_risk_level VARCHAR(20)",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS residual_calculated_at TIMESTAMP",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS control_effectiveness INTEGER DEFAULT 0",
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS business_impact_description TEXT",
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS implementation_status VARCHAR(50) DEFAULT 'not_started'",
  ];

  for (const statement of statements) {
    await client.query(statement);
  }
}

export async function POST(req: NextRequest) {
  const client = await pool.connect();
  try {
    await ensureMappingSchema(client);

    const body = await req.json().catch(() => ({}));
    const onlyAssetId = body?.asset_id ? Number(body.asset_id) : null;

    // ── Step 1: Build the catalog from tagged risk_register rows ────────────
    // Prefer asset_id=NULL template rows, but keep supporting older tagged rows.
    const catalogResult = await client.query<CatalogRisk>(`
      SELECT DISTINCT ON (risk_title)
             id AS source_id,
             risk_code AS source_risk_code,
             risk_title,
             risk_description,
             nist_csf_function,
             nist_csf_category,
             nist_csf_subcategory,
             applicable_asset_types,
             arising_threats,
             assessed_by,
             notes,
             status,
             (SELECT COALESCE(ra.inherent_likelihood, ra.likelihood)
                FROM risk_analysis ra
               WHERE ra.risk_register_id = rr.id
               LIMIT 1) AS base_likelihood,
             (SELECT COALESCE(ra.inherent_impact, ra.impact)
                FROM risk_analysis ra
               WHERE ra.risk_register_id = rr.id
               LIMIT 1) AS base_impact
       FROM risk_register rr
       WHERE applicable_asset_types IS NOT NULL
         AND applicable_asset_types <> ''
         AND COALESCE(status, 'Open') <> 'Closed'
       ORDER BY risk_title,
                CASE WHEN asset_id IS NULL THEN 0 ELSE 1 END,
                rr.id
    `);
    const catalog = catalogResult.rows;

    if (catalog.length === 0) {
      return NextResponse.json(
        {
          error:
            "No tagged risks found. Add at least one risk with applicable_asset_types before mapping risks to assets.",
        },
        { status: 400 },
      );
    }

    // ── Step 2: Load assets ─────────────────────────────────────────────────
    const assetsResult = onlyAssetId
      ? await client.query(
          `SELECT id, asset_name, asset_type, criticality, access_level,
                  authentication_method, data_classification, internet_exposed,
                  supports_critical_service
             FROM assets
            WHERE id = $1
              AND COALESCE(status, 'Active') NOT IN ('Inactive', 'Deprecated', 'Retired')`,
          [onlyAssetId],
        )
      : await client.query(
          `SELECT id, asset_name, asset_type, criticality, access_level,
                  authentication_method, data_classification, internet_exposed,
                  supports_critical_service
             FROM assets
            WHERE COALESCE(status, 'Active') NOT IN ('Inactive', 'Deprecated', 'Retired')`,
        );
    const assets: AssetCtx[] = assetsResult.rows;

    if (assets.length === 0) {
      return NextResponse.json(
        { error: "No assets to map to." },
        { status: 400 },
      );
    }

    await client.query("BEGIN");

    const created: Array<{
      asset_id: number;
      asset_name: string;
      risk_title: string;
      likelihood: number;
      impact: number;
      level: string;
    }> = [];
    const skipped: Array<{ asset_id: number; risk_title: string; reason: string }> = [];
    const matchedCatalogKeys = new Set<string>();
    const hasBusinessCriticalAssets = assets.some(isBusinessCriticalAsset);

    for (const asset of assets) {
      for (const cat of catalog) {
        if (!assetTypeMatches(cat.applicable_asset_types, asset, hasBusinessCriticalAssets)) {
          continue;
        }
        matchedCatalogKeys.add(`${cat.source_id}:${cat.risk_title}`);

        // Dedup: already exists for this asset?
        const existing = await client.query(
          `SELECT id FROM risk_register
            WHERE asset_id = $1
              AND risk_title = $2
              AND COALESCE(status, 'Open') <> 'Closed'
            LIMIT 1`,
          [asset.id, cat.risk_title],
        );
        if (existing.rows.length > 0) {
          skipped.push({
            asset_id: asset.id,
            risk_title: cat.risk_title,
            reason: "already exists",
          });
          continue;
        }

        const templateScores = deriveTemplateBaseScores(cat);
        const { likelihood, impact } = deriveScores(
          asset,
          cat.base_likelihood ? Number(cat.base_likelihood) : templateScores.likelihood,
          cat.base_impact ? Number(cat.base_impact) : templateScores.impact,
        );
        const score = likelihood * impact;
        const level = calcLevel(score);
        const code = await generateRiskCode(client);
        const mappedRiskId = cat.source_risk_code
          ? `${cat.source_risk_code}-A${asset.id}`
          : code;
        const tags = splitTags(cat.applicable_asset_types).join(", ");
        const likelihoodRationale = [
          `Template tag: ${tags || "not specified"}.`,
          asset.internet_exposed ? "Internet exposed asset." : null,
          asset.access_level ? `Access: ${asset.access_level}.` : null,
          asset.authentication_method ? `Auth: ${asset.authentication_method}.` : null,
        ]
          .filter(Boolean)
          .join(" ");
        const impactRationale = [
          asset.criticality ? `Criticality: ${asset.criticality}.` : null,
          asset.data_classification
            ? `Data classification: ${asset.data_classification}.`
            : null,
          asset.supports_critical_service ? "Supports critical business process." : null,
        ]
          .filter(Boolean)
          .join(" ");
        const businessImpact = `${asset.asset_name} хөрөнгө дээр "${cat.risk_title}" хэрэгжвэл ${cat.risk_description ?? "үйл ажиллагаа, өгөгдөл болон үйлчилгээний тасралтгүй байдалд нөлөөлөх эрсдэлтэй."}`;

        const rr = await client.query(
          `INSERT INTO risk_register
             (risk_code, asset_id, risk_title, risk_description,
              nist_csf_function, nist_csf_category, nist_csf_subcategory,
              applicable_asset_types, arising_threats, assessed_by, notes,
              status, risk_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,COALESCE($12,'Open'),$13)
           RETURNING id`,
          [
            code,
            asset.id,
            cat.risk_title,
            cat.risk_description,
            cat.nist_csf_function,
            cat.nist_csf_category,
            cat.nist_csf_subcategory,
            cat.applicable_asset_types,
            cat.arising_threats,
            cat.assessed_by ?? "Template risk mapper",
            [
              cat.notes,
              `Mapped from template ${cat.source_risk_code ?? cat.source_id} to asset ${asset.asset_name}.`,
            ]
              .filter(Boolean)
              .join(" "),
            cat.status,
            mappedRiskId,
          ],
        );
        const rrId = rr.rows[0].id;

        await client.query(
          `INSERT INTO risk_analysis
              (risk_register_id,
              likelihood, likelihood_label,
              likelihood_rationale,
              impact, impact_label,
              impact_rationale,
              risk_score, risk_level,
              inherent_likelihood, inherent_likelihood_label,
              inherent_impact, inherent_impact_label,
              inherent_risk_score, inherent_risk_level,
              inherent_likelihood_rationale,
              inherent_impact_rationale,
              inherent_calculation_method,
              inherent_assessor_override,
              inherent_review_status,
              inherent_assessed_at,
              control_effectiveness,
              residual_risk_score, residual_risk_level, residual_calculated_at,
              business_impact_description)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$2,$3,$5,$6,$8,$9,
                   $4,$7,
                   'mapped', FALSE, 'Needs Inherent Review', NOW(),
                   0, $8, $9, NOW(), $10)
           ON CONFLICT (risk_register_id) DO NOTHING`,
          [
            rrId,
            likelihood,
            LIKELIHOOD_LABELS[likelihood],
            likelihoodRationale,
            impact,
            IMPACT_LABELS[impact],
            impactRationale,
            score,
            level,
            businessImpact,
          ],
        );

        // Auto-link controls from nist_controls matching the category, if any.
        if (cat.nist_csf_category) {
          try {
            const controls = await client.query(
              `SELECT control_name, nist_function
                 FROM nist_controls
                WHERE category_code = $1 AND is_active = TRUE
                LIMIT 5`,
              [cat.nist_csf_category],
            );
            for (const ctrl of controls.rows) {
              await client.query(
                `INSERT INTO control_recommendations
                   (risk_register_id, control_name, nist_function, priority,
                    implementation_status)
                 VALUES ($1,$2,$3,$4,'not_started')`,
                [rrId, ctrl.control_name, ctrl.nist_function, level],
              );
            }
          } catch {
            /* control_recommendations is optional — ignore failures */
          }
        }

        created.push({
          asset_id: asset.id,
          asset_name: asset.asset_name,
          risk_title: cat.risk_title,
          likelihood,
          impact,
          level,
        });
      }
    }

    await client.query("COMMIT");
    const unmappedCatalog = catalog.filter(
      (cat) => !matchedCatalogKeys.has(`${cat.source_id}:${cat.risk_title}`),
    );

    return NextResponse.json({
      success: true,
      catalog_size: catalog.length,
      assets_processed: assets.length,
      created: created.length,
      skipped: skipped.length,
      unmapped_catalog: unmappedCatalog.length,
      created_samples: created.slice(0, 10),
      skipped_samples: skipped.slice(0, 10),
      unmapped_samples: unmappedCatalog
        .slice(0, 10)
        .map((risk) => ({
          risk_title: risk.risk_title,
          applicable_asset_types: risk.applicable_asset_types,
        })),
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("map-to-asset error:", err);
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "mapping failed" },
      { status: 500 },
    );
  } finally {
    client.release();
  }
}
