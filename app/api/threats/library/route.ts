import { getAssetTypeMappingNames } from "@/lib/asset-type-mapping";
import { pool } from "@/lib/db";
import { NextResponse } from "next/server";

type AssetRow = {
  id: number;
  asset_name: string;
  asset_code: string | null;
  asset_type: string | null;
  resolved_asset_type: string | null;
  criticality: string | null;
  internet_exposed: boolean | null;
  status: string | null;
};

type MappedThreatRow = {
  id: number;
  threat_name: string;
  description: string | null;
  description_mn: string | null;
  threat_type: string | null;
  likelihood_level: number | null;
  potential_impact: string | null;
  nist_category: string | null;
  risk_level: string | null;
  mitigation_notes: string | null;
  mitigation_notes_mn: string | null;
  mapped_asset_type: string;
};

type ThreatRow = Omit<
  MappedThreatRow,
  "mitigation_notes" | "mitigation_notes_mn" | "mapped_asset_type"
>;

type LinkedAsset = {
  id: number;
  asset_name: string;
  asset_code: string | null;
  asset_type: string | null;
  criticality: string | null;
  internet_exposed: boolean;
  status: string | null;
  risk_level: string;
  matched_asset_type: string;
};

type LinkedAssetType = {
  type_name: string;
  risk_level: string;
};

type ThreatAggregate = Omit<
  MappedThreatRow,
  "risk_level" | "mapped_asset_type"
> & {
  risk_level: string;
  linked_assets: LinkedAsset[];
  linked_asset_types: LinkedAssetType[];
  registered_asset_count: number;
};

const RISK_WEIGHT: Record<string, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Unknown: 0,
};

const ASSET_THREAT_TYPES: Record<string, string[]> = {
  api: [
    "Access Control",
    "Adversarial",
    "Application",
    "Availability",
    "Configuration",
    "Cryptographic",
    "Data",
    "Network",
    "Supply Chain",
    "Technical",
    "Vulnerability",
  ],
  application: [
    "Access Control",
    "Adversarial",
    "Application",
    "Availability",
    "Configuration",
    "Data",
    "Human",
    "Supply Chain",
    "Technical",
    "Third-Party",
    "Vulnerability",
  ],
  "backup system": [
    "Adversarial",
    "Availability",
    "Configuration",
    "Cryptographic",
    "Data",
    "Structural",
    "Technical",
  ],
  "cache system": [
    "Access Control",
    "Adversarial",
    "Application",
    "Availability",
    "Configuration",
    "Cryptographic",
    "Data",
    "Technical",
  ],
  cloud: [
    "Access Control",
    "Adversarial",
    "Cloud",
    "Configuration",
    "Data",
    "Governance",
    "Network",
    "Structural",
    "Supply Chain",
    "Technical",
    "Third-Party",
  ],
  "collaboration platform": [
    "Access Control",
    "Adversarial",
    "Configuration",
    "Data",
    "Governance",
    "Human",
    "Supply Chain",
    "Third-Party",
  ],
  data: [
    "Access Control",
    "Adversarial",
    "Availability",
    "Configuration",
    "Cryptographic",
    "Data",
    "Human",
    "Monitoring",
    "Structural",
  ],
  database: [
    "Access Control",
    "Adversarial",
    "Application",
    "Availability",
    "Configuration",
    "Cryptographic",
    "Data",
    "Human",
    "Monitoring",
    "Structural",
    "Technical",
    "Vulnerability",
  ],
  "email system": [
    "Access Control",
    "Adversarial",
    "Availability",
    "Configuration",
    "Data",
    "Endpoint",
    "Human",
  ],
  "endpoint fleet": [
    "Access Control",
    "Adversarial",
    "Configuration",
    "Endpoint",
    "Human",
    "Malware",
    "Structural",
    "Technical",
    "Vulnerability",
  ],
  "file storage": [
    "Access Control",
    "Adversarial",
    "Availability",
    "Configuration",
    "Cryptographic",
    "Data",
    "Human",
    "Structural",
  ],
  hardware: [
    "Availability",
    "Environmental",
    "Network",
    "Structural",
    "Technical",
  ],
  identity: [
    "Access Control",
    "Adversarial",
    "Configuration",
    "Governance",
    "Human",
    "Technical",
  ],
  "identity provider": [
    "Access Control",
    "Adversarial",
    "Configuration",
    "Governance",
    "Human",
    "Technical",
  ],
  infrastructure: [
    "Access Control",
    "Adversarial",
    "Availability",
    "Configuration",
    "Environmental",
    "Network",
    "Structural",
    "Supply Chain",
    "Technical",
    "Vulnerability",
  ],
  "load balancer": [
    "Adversarial",
    "Availability",
    "Configuration",
    "Network",
    "Structural",
    "Technical",
    "Vulnerability",
  ],
  "message queue": [
    "Access Control",
    "Adversarial",
    "Application",
    "Availability",
    "Configuration",
    "Cryptographic",
    "Data",
    "Network",
  ],
  "monitoring/logging": [
    "Access Control",
    "Adversarial",
    "Configuration",
    "Data",
    "Human",
    "Monitoring",
    "Technical",
  ],
  network: [
    "Adversarial",
    "Availability",
    "Configuration",
    "Environmental",
    "Malware",
    "Network",
    "Structural",
    "Technical",
    "Vulnerability",
  ],
  "saas tenant": [
    "Access Control",
    "Adversarial",
    "Cloud",
    "Configuration",
    "Data",
    "Governance",
    "Human",
    "Structural",
    "Supply Chain",
    "Third-Party",
  ],
  service: [
    "Access Control",
    "Adversarial",
    "Application",
    "Availability",
    "Configuration",
    "Data",
    "Network",
    "Structural",
    "Supply Chain",
    "Technical",
    "Third-Party",
    "Vulnerability",
  ],
  software: [
    "Access Control",
    "Adversarial",
    "Application",
    "Availability",
    "Configuration",
    "Data",
    "Structural",
    "Supply Chain",
    "Technical",
    "Vulnerability",
  ],
  "vpn/remote access": [
    "Access Control",
    "Adversarial",
    "Availability",
    "Configuration",
    "Environmental",
    "Network",
    "Technical",
    "Vulnerability",
  ],
  "web server": [
    "Adversarial",
    "Application",
    "Availability",
    "Configuration",
    "Network",
    "Technical",
    "Vulnerability",
  ],
};

const ASSET_THREAT_TERMS: Record<string, string[]> = {
  api: ["api", "token", "key", "endpoint", "session", "service"],
  application: ["application", "software", "xss", "sql", "session", "api"],
  "backup system": ["backup", "restore", "ransomware"],
  "cache system": ["cache", "redis", "session"],
  cloud: ["cloud", "tenant", "bucket", "saas"],
  "collaboration platform": ["collaboration", "sharing", "guest", "oauth"],
  data: ["data", "exfiltration", "encryption", "backup"],
  database: ["database", "sql", "query", "data", "backup", "disk"],
  "email system": ["email", "phishing", "mail", "attachment"],
  "endpoint fleet": ["endpoint", "malware", "mobile", "device", "os"],
  "file storage": ["file", "storage", "backup", "encryption"],
  hardware: ["hardware", "power", "fire", "flood", "earthquake"],
  identity: ["identity", "credential", "account", "password", "mfa"],
  "identity provider": ["identity", "credential", "account", "password", "mfa"],
  infrastructure: ["infrastructure", "server", "os", "power", "hardware"],
  "load balancer": ["load balancer", "ddos", "traffic", "tls"],
  "message queue": ["queue", "message", "broker"],
  "monitoring/logging": ["log", "monitor", "evidence"],
  network: ["network", "dns", "ddos", "sniff", "wireless", "vpn"],
  "saas tenant": ["saas", "tenant", "cloud", "sharing"],
  service: ["service", "api", "availability", "dependency"],
  software: ["software", "application", "patch", "vulnerability"],
  "vpn/remote access": ["vpn", "remote access", "split tunneling"],
  "web server": ["web", "xss", "http", "ddos", "tls"],
};

const DEFAULT_THREAT_TYPES = [
  "Access Control",
  "Adversarial",
  "Application",
  "Availability",
  "Cloud",
  "Configuration",
  "Cryptographic",
  "Data",
  "Endpoint",
  "Governance",
  "Human",
  "Monitoring",
  "Network",
  "Structural",
  "Supply Chain",
  "Technical",
  "Third-Party",
  "Vulnerability",
];

function normalize(value: string | null | undefined) {
  return String(value ?? "").trim().toLowerCase();
}

async function ensureThreatLibrarySchema() {
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

  await pool.query(
    `ALTER TABLE threats ADD COLUMN IF NOT EXISTS description_mn TEXT`,
  );
  await pool.query(
    `ALTER TABLE asset_threat_mapping ADD COLUMN IF NOT EXISTS mitigation_notes_mn TEXT`,
  );
}

function preferredRiskLevel(
  current: string | null | undefined,
  next: string | null | undefined,
) {
  const currentLevel = current || "Unknown";
  const nextLevel = next || "Unknown";
  return (RISK_WEIGHT[nextLevel] ?? 0) > (RISK_WEIGHT[currentLevel] ?? 0)
    ? nextLevel
    : currentLevel;
}

function inferRiskLevel(threat: Pick<ThreatRow, "likelihood_level" | "potential_impact">) {
  if (threat.potential_impact && RISK_WEIGHT[threat.potential_impact]) {
    return threat.potential_impact;
  }
  if ((threat.likelihood_level ?? 0) >= 5) return "Critical";
  if ((threat.likelihood_level ?? 0) >= 4) return "High";
  if ((threat.likelihood_level ?? 0) >= 3) return "Medium";
  if ((threat.likelihood_level ?? 0) > 0) return "Low";
  return "Unknown";
}

function isThreatRelatedToAssetType(threat: ThreatRow, assetTypeName: string) {
  const assetTypeKey = normalize(assetTypeName);
  const allowedThreatTypes = new Set(
    (ASSET_THREAT_TYPES[assetTypeKey] ?? DEFAULT_THREAT_TYPES).map(normalize),
  );
  const threatType = normalize(threat.threat_type);

  if (threatType && allowedThreatTypes.has(threatType)) return true;

  const searchableThreat = normalize(
    [
      threat.threat_name,
      threat.description,
      threat.description_mn,
      threat.threat_type,
      threat.nist_category,
    ].join(" "),
  );

  return (ASSET_THREAT_TERMS[assetTypeKey] ?? []).some((term) =>
    searchableThreat.includes(term),
  );
}

function toInferredMapping(
  threat: ThreatRow,
  mappedAssetType: string,
): MappedThreatRow {
  return {
    ...threat,
    risk_level: threat.risk_level || inferRiskLevel(threat),
    mitigation_notes: null,
    mitigation_notes_mn: null,
    mapped_asset_type: mappedAssetType,
  };
}

function sortByRiskThenName<
  T extends { risk_level: string; asset_name?: string; type_name?: string },
>(
  a: T,
  b: T,
) {
  const riskDiff =
    (RISK_WEIGHT[b.risk_level] ?? 0) - (RISK_WEIGHT[a.risk_level] ?? 0);
  if (riskDiff !== 0) return riskDiff;
  return (a.asset_name ?? a.type_name ?? "").localeCompare(
    b.asset_name ?? b.type_name ?? "",
  );
}

export async function GET() {
  try {
    await ensureThreatLibrarySchema();

    const assetsResult = await pool.query<AssetRow>(`
      SELECT
        a.id,
        a.asset_name,
        a.asset_code,
        a.asset_type,
        at.type_name AS resolved_asset_type,
        a.criticality,
        a.internet_exposed,
        a.status
      FROM assets a
      LEFT JOIN asset_types at ON at.id = a.asset_type_id
      ORDER BY a.asset_name
    `);

    const assets = assetsResult.rows;

    if (assets.length === 0) {
      return NextResponse.json({
        success: true,
        source: "registered-assets",
        threats: [],
        count: 0,
        registered_asset_count: 0,
        linked_asset_count: 0,
        registered_asset_types: [],
      });
    }

    const threatResult = await pool.query<MappedThreatRow>(`
      SELECT
        t.id,
        t.threat_name,
        t.description,
        t.description_mn,
        t.threat_type,
        t.likelihood_level,
        t.potential_impact,
        t.nist_category,
        COALESCE(atm.risk_level, 'Unknown') AS risk_level,
        atm.mitigation_notes,
        atm.mitigation_notes_mn,
        at.type_name AS mapped_asset_type
      FROM threats t
      INNER JOIN asset_threat_mapping atm ON t.id = atm.threat_id
      INNER JOIN asset_types at ON at.id = atm.asset_type_id
      ORDER BY
        CASE atm.risk_level
          WHEN 'Critical' THEN 1
          WHEN 'High'     THEN 2
          WHEN 'Medium'   THEN 3
          WHEN 'Low'      THEN 4
          ELSE 5
        END,
        t.likelihood_level DESC,
        t.threat_name
    `);

    const allThreatsResult = await pool.query<ThreatRow>(`
      SELECT
        id,
        threat_name,
        description,
        description_mn,
        threat_type,
        likelihood_level,
        potential_impact,
        nist_category,
        CASE
          WHEN potential_impact IN ('Critical', 'High', 'Medium', 'Low')
            THEN potential_impact
          WHEN likelihood_level >= 5 THEN 'Critical'
          WHEN likelihood_level = 4 THEN 'High'
          WHEN likelihood_level = 3 THEN 'Medium'
          WHEN likelihood_level > 0 THEN 'Low'
          ELSE 'Unknown'
        END AS risk_level
      FROM threats
      ORDER BY threat_name
    `);

    const mappingsByAssetType = new Map<string, MappedThreatRow[]>();
    for (const threat of threatResult.rows) {
      const key = normalize(threat.mapped_asset_type);
      mappingsByAssetType.set(key, [...(mappingsByAssetType.get(key) ?? []), threat]);
    }

    const threatsById = new Map<
      number,
      ThreatAggregate & {
        linkedAssetsById: Map<number, LinkedAsset>;
        linkedAssetTypesByName: Map<string, LinkedAssetType>;
      }
    >();
    const linkedAssetIds = new Set<number>();
    const registeredAssetTypes = new Set<string>();

    for (const asset of assets) {
      const assetTypeNames = new Set<string>();

      for (const assetType of [asset.resolved_asset_type, asset.asset_type]) {
        for (const mappedType of getAssetTypeMappingNames(assetType)) {
          assetTypeNames.add(mappedType);
        }
      }

      const directMappings: MappedThreatRow[] = [];
      const directThreatIds = new Set<number>();
      const inferredMappings: MappedThreatRow[] = [];
      const inferredThreatIds = new Set<number>();

      for (const assetTypeName of assetTypeNames) {
        registeredAssetTypes.add(assetTypeName);
        const threatMappings = mappingsByAssetType.get(normalize(assetTypeName)) ?? [];
        directMappings.push(...threatMappings);
        for (const threat of threatMappings) directThreatIds.add(threat.id);
      }

      for (const assetTypeName of assetTypeNames) {
        for (const threat of allThreatsResult.rows) {
          if (directThreatIds.has(threat.id) || inferredThreatIds.has(threat.id)) {
            continue;
          }
          if (!isThreatRelatedToAssetType(threat, assetTypeName)) continue;

          inferredMappings.push(toInferredMapping(threat, assetTypeName));
          inferredThreatIds.add(threat.id);
        }
      }

      for (const mappedThreat of [...directMappings, ...inferredMappings]) {
          const riskLevel = mappedThreat.risk_level || "Unknown";
          const aggregate =
            threatsById.get(mappedThreat.id) ??
            ({
              id: mappedThreat.id,
              threat_name: mappedThreat.threat_name,
              description: mappedThreat.description,
              description_mn: mappedThreat.description_mn,
              threat_type: mappedThreat.threat_type,
              likelihood_level: mappedThreat.likelihood_level,
              potential_impact: mappedThreat.potential_impact,
              nist_category: mappedThreat.nist_category,
              mitigation_notes: mappedThreat.mitigation_notes,
              mitigation_notes_mn: mappedThreat.mitigation_notes_mn,
              risk_level: "Unknown",
              linked_assets: [],
              linked_asset_types: [],
              registered_asset_count: 0,
              linkedAssetsById: new Map<number, LinkedAsset>(),
              linkedAssetTypesByName: new Map<string, LinkedAssetType>(),
            } satisfies ThreatAggregate & {
              linkedAssetsById: Map<number, LinkedAsset>;
              linkedAssetTypesByName: Map<string, LinkedAssetType>;
            });

          if (!aggregate.mitigation_notes && mappedThreat.mitigation_notes) {
            aggregate.mitigation_notes = mappedThreat.mitigation_notes;
          }
          if (!aggregate.mitigation_notes_mn && mappedThreat.mitigation_notes_mn) {
            aggregate.mitigation_notes_mn = mappedThreat.mitigation_notes_mn;
          }

          aggregate.risk_level = preferredRiskLevel(aggregate.risk_level, riskLevel);

          const existingAsset = aggregate.linkedAssetsById.get(asset.id);
          if (!existingAsset) {
            aggregate.linkedAssetsById.set(asset.id, {
              id: asset.id,
              asset_name: asset.asset_name,
              asset_code: asset.asset_code,
              asset_type: asset.resolved_asset_type || asset.asset_type,
              criticality: asset.criticality,
              internet_exposed: Boolean(asset.internet_exposed),
              status: asset.status,
              risk_level: riskLevel,
              matched_asset_type: mappedThreat.mapped_asset_type,
            });
          } else {
            const nextRiskLevel = preferredRiskLevel(
              existingAsset.risk_level,
              riskLevel,
            );
            if (nextRiskLevel !== existingAsset.risk_level) {
              existingAsset.matched_asset_type = mappedThreat.mapped_asset_type;
            }
            existingAsset.risk_level = nextRiskLevel;
          }

          const typeKey = normalize(mappedThreat.mapped_asset_type);
          const existingType = aggregate.linkedAssetTypesByName.get(typeKey);
          if (!existingType) {
            aggregate.linkedAssetTypesByName.set(typeKey, {
              type_name: mappedThreat.mapped_asset_type,
              risk_level: riskLevel,
            });
          } else {
            existingType.risk_level = preferredRiskLevel(existingType.risk_level, riskLevel);
          }

          linkedAssetIds.add(asset.id);
          threatsById.set(mappedThreat.id, aggregate);
      }
    }

    const threats = Array.from(threatsById.values())
      .map((threat) => {
        const linked_assets = Array.from(threat.linkedAssetsById.values()).sort(
          sortByRiskThenName,
        );
        const linked_asset_types = Array.from(
          threat.linkedAssetTypesByName.values(),
        ).sort(sortByRiskThenName);

        return {
          id: threat.id,
          threat_name: threat.threat_name,
          description: threat.description,
          description_mn: threat.description_mn,
          threat_type: threat.threat_type,
          likelihood_level: threat.likelihood_level,
          potential_impact: threat.potential_impact,
          nist_category: threat.nist_category,
          mitigation_notes: threat.mitigation_notes,
          mitigation_notes_mn: threat.mitigation_notes_mn,
          risk_level: threat.risk_level,
          linked_assets,
          linked_asset_types,
          registered_asset_count: linked_assets.length,
        };
      })
      .sort((a, b) => {
        const riskDiff =
          (RISK_WEIGHT[b.risk_level] ?? 0) - (RISK_WEIGHT[a.risk_level] ?? 0);
        if (riskDiff !== 0) return riskDiff;
        const likelihoodDiff =
          Number(b.likelihood_level ?? 0) - Number(a.likelihood_level ?? 0);
        if (likelihoodDiff !== 0) return likelihoodDiff;
        return a.threat_name.localeCompare(b.threat_name);
      });

    return NextResponse.json({
      success: true,
      source: "registered-assets",
      threats,
      count: threats.length,
      registered_asset_count: assets.length,
      linked_asset_count: linkedAssetIds.size,
      registered_asset_types: Array.from(registeredAssetTypes).sort(),
    });
  } catch (error) {
    console.error("Error fetching threat library:", error);
    return NextResponse.json({ error: "Failed to fetch threats" }, { status: 500 });
  }
}
