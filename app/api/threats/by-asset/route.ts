import { pool } from "@/lib/db";
import { getAssetTypeMappingNames } from "@/lib/asset-type-mapping";
import { NextResponse } from "next/server";

type AssetRow = {
  id: number;
  asset_name: string;
  asset_code: string | null;
  asset_type_id: number | null;
  asset_type: string | null;
  criticality: string | null;
  data_classification: string | null;
  internet_exposed: boolean | null;
  status: string | null;
};

type ThreatRow = {
  id: number;
  threat_name: string;
  description: string | null;
  threat_type: string | null;
  likelihood_level: number | null;
  potential_impact: string | null;
  nist_category: string | null;
  risk_level: string | null;
  mitigation_notes: string | null;
  mitigation_notes_mn: string | null;
  is_related: boolean;
};

type AssetMappingRow = {
  asset_id: number;
  asset_name: string;
  asset_code: string | null;
  asset_type: string | null;
  criticality: string | null;
  data_classification: string | null;
  internet_exposed: boolean;
  status: string | null;
  mapped_threat_count: number;
  highest_risk: string;
  threats: ThreatRow[];
};

type BackendRiskRule = {
  terms: string[];
  mitigation_notes: string;
};

const RISK_RULES = {
  credential: {
    terms: [
      "brute force",
      "credential stuffing",
      "credential reuse",
      "password spraying",
    ],
    mitigation_notes:
      "Enforce MFA, lockout rules, and monitoring for suspicious authentication attempts.",
  },
  phishing: {
    terms: ["phishing", "spear phishing", "social engineering"],
    mitigation_notes:
      "Train users, filter malicious messages, and use phishing-resistant MFA.",
  },
  malware: {
    terms: ["malware", "trojan", "usb", "mobile device compromise"],
    mitigation_notes:
      "Deploy endpoint protection, restrict risky execution paths, and monitor suspicious activity.",
  },
  ransomware: {
    terms: ["ransomware"],
    mitigation_notes:
      "Maintain tested offline or immutable backups and monitor suspicious encryption behavior.",
  },
  sqlInjection: {
    terms: ["sql injection"],
    mitigation_notes: "Use parameterized queries and validate all inputs.",
  },
  xss: {
    terms: ["cross-site scripting", "xss"],
    mitigation_notes: "Sanitize output and enforce Content Security Policy.",
  },
  privilege: {
    terms: ["privilege escalation"],
    mitigation_notes:
      "Apply least privilege and review privileged access paths.",
  },
  accountTakeover: {
    terms: ["account takeover", "session hijacking"],
    mitigation_notes:
      "Harden session handling, require MFA, and detect anomalous account behavior.",
  },
  dataExfiltration: {
    terms: ["data exfiltration"],
    mitigation_notes:
      "Restrict sensitive data access, enable DLP, and monitor bulk data movement.",
  },
  insider: {
    terms: ["insider threat"],
    mitigation_notes:
      "Review access regularly and monitor sensitive actions by privileged users.",
  },
  shadowIt: {
    terms: ["shadow it", "unauthorised access", "unauthorized access"],
    mitigation_notes:
      "Maintain an approved-service registry and review unauthorized service usage.",
  },
  weakEncryption: {
    terms: ["weak encryption", "no encryption"],
    mitigation_notes: "Encrypt sensitive data at rest and in transit.",
  },
  unpatched: {
    terms: ["unpatched", "zero-day", "exploit"],
    mitigation_notes:
      "Patch systems and dependencies within defined SLA windows.",
  },
  misconfiguration: {
    terms: ["misconfiguration", "cloud misconfiguration"],
    mitigation_notes:
      "Review secure configuration baselines and exposed services.",
  },
  apiKey: {
    terms: ["api key", "token exposure"],
    mitigation_notes:
      "Store secrets in a vault, rotate keys, and scan code for leaks.",
  },
  mitm: {
    terms: [
      "man-in-the-middle",
      "mitm",
      "network sniffing",
      "wireless eavesdropping",
    ],
    mitigation_notes: "Enforce strong TLS and protect network traffic paths.",
  },
  dns: {
    terms: ["dns hijacking"],
    mitigation_notes: "Monitor DNS records and protect registrar access.",
  },
  dos: {
    terms: ["denial of service", "ddos"],
    mitigation_notes:
      "Use rate limits, capacity protection, and DDoS mitigation.",
  },
  supplyChain: {
    terms: ["supply chain"],
    mitigation_notes:
      "Verify supplier assurance, software integrity, and third-party integrations.",
  },
  backupFailure: {
    terms: ["backup failure", "backup corruption"],
    mitigation_notes: "Test restore procedures and verify backup integrity.",
  },
  logTampering: {
    terms: ["log tampering", "evidence destruction"],
    mitigation_notes: "Use append-only or tamper-evident log storage.",
  },
  remoteAccess: {
    terms: ["unauthorized remote access", "vpn split tunneling"],
    mitigation_notes: "Restrict remote access paths and require MFA.",
  },
  tenantIsolation: {
    terms: ["multi-tenant isolation"],
    mitigation_notes:
      "Review tenant isolation controls and provider assurance reports.",
  },
  osFailure: {
    terms: ["operating system failure"],
    mitigation_notes: "Track OS health, patch levels, and recovery readiness.",
  },
  appFailure: {
    terms: ["application software failure"],
    mitigation_notes:
      "Use release testing, rollback plans, and runtime monitoring.",
  },
  diskFailure: {
    terms: ["disk failure"],
    mitigation_notes: "Monitor storage health and validate restore procedures.",
  },
  hardwareFailure: {
    terms: ["processing hardware failure", "communications hardware failure"],
    mitigation_notes:
      "Monitor hardware health and maintain redundant capacity.",
  },
  facilityFailure: {
    terms: [
      "electrical power failure",
      "telecommunications failure",
      "fire incident",
      "flood incident",
      "earthquake",
      "environmental control failure",
    ],
    mitigation_notes:
      "Maintain continuity plans, redundancy, and tested recovery procedures.",
  },
  workforceDisruption: {
    terms: ["pandemic workforce disruption"],
    mitigation_notes:
      "Maintain remote-work capacity and continuity procedures.",
  },
  container: {
    terms: ["container escape"],
    mitigation_notes:
      "Patch runtimes and restrict privileged container capabilities.",
  },
} satisfies Record<string, BackendRiskRule>;

const BACKEND_ASSET_RISK_RULES: Record<string, BackendRiskRule[]> = {
  "saas tenant": [
    RISK_RULES.misconfiguration,
    RISK_RULES.accountTakeover,
    RISK_RULES.dataExfiltration,
    RISK_RULES.shadowIt,
    RISK_RULES.supplyChain,
    RISK_RULES.tenantIsolation,
    RISK_RULES.remoteAccess,
    RISK_RULES.phishing,
  ],
  "identity provider": [
    RISK_RULES.credential,
    RISK_RULES.accountTakeover,
    RISK_RULES.privilege,
    RISK_RULES.phishing,
    RISK_RULES.misconfiguration,
    RISK_RULES.remoteAccess,
  ],
  application: [
    RISK_RULES.sqlInjection,
    RISK_RULES.xss,
    RISK_RULES.apiKey,
    RISK_RULES.accountTakeover,
    RISK_RULES.appFailure,
    RISK_RULES.misconfiguration,
    RISK_RULES.unpatched,
    RISK_RULES.privilege,
    RISK_RULES.dataExfiltration,
  ],
  network: [
    RISK_RULES.mitm,
    RISK_RULES.dns,
    RISK_RULES.dos,
    RISK_RULES.misconfiguration,
    RISK_RULES.malware,
    RISK_RULES.hardwareFailure,
    RISK_RULES.facilityFailure,
  ],
  "endpoint fleet": [
    RISK_RULES.malware,
    RISK_RULES.ransomware,
    RISK_RULES.phishing,
    RISK_RULES.unpatched,
    RISK_RULES.insider,
    RISK_RULES.osFailure,
    RISK_RULES.remoteAccess,
  ],
  database: [
    RISK_RULES.sqlInjection,
    RISK_RULES.dataExfiltration,
    RISK_RULES.weakEncryption,
    RISK_RULES.backupFailure,
    RISK_RULES.privilege,
    RISK_RULES.misconfiguration,
    RISK_RULES.unpatched,
    RISK_RULES.diskFailure,
    RISK_RULES.ransomware,
    RISK_RULES.insider,
  ],
  infrastructure: [
    RISK_RULES.misconfiguration,
    RISK_RULES.unpatched,
    RISK_RULES.privilege,
    RISK_RULES.ransomware,
    RISK_RULES.supplyChain,
    RISK_RULES.osFailure,
    RISK_RULES.hardwareFailure,
    RISK_RULES.facilityFailure,
  ],
  api: [
    RISK_RULES.apiKey,
    RISK_RULES.credential,
    RISK_RULES.sqlInjection,
    RISK_RULES.misconfiguration,
    RISK_RULES.mitm,
    RISK_RULES.accountTakeover,
    RISK_RULES.dos,
    RISK_RULES.dataExfiltration,
    RISK_RULES.appFailure,
  ],
  "message queue": [
    RISK_RULES.misconfiguration,
    RISK_RULES.dataExfiltration,
    RISK_RULES.dos,
    RISK_RULES.weakEncryption,
    RISK_RULES.remoteAccess,
  ],
  "cache system": [
    RISK_RULES.misconfiguration,
    RISK_RULES.dataExfiltration,
    RISK_RULES.credential,
    RISK_RULES.dos,
    RISK_RULES.weakEncryption,
  ],
  "file storage": [
    RISK_RULES.dataExfiltration,
    RISK_RULES.misconfiguration,
    RISK_RULES.ransomware,
    RISK_RULES.insider,
    RISK_RULES.diskFailure,
    RISK_RULES.backupFailure,
    RISK_RULES.weakEncryption,
  ],
  "backup system": [
    RISK_RULES.backupFailure,
    RISK_RULES.ransomware,
    RISK_RULES.dataExfiltration,
    RISK_RULES.misconfiguration,
    RISK_RULES.diskFailure,
    RISK_RULES.weakEncryption,
    RISK_RULES.remoteAccess,
  ],
  "monitoring/logging": [
    RISK_RULES.logTampering,
    RISK_RULES.misconfiguration,
    RISK_RULES.insider,
    RISK_RULES.dataExfiltration,
    RISK_RULES.remoteAccess,
  ],
  "vpn/remote access": [
    RISK_RULES.credential,
    RISK_RULES.unpatched,
    RISK_RULES.mitm,
    RISK_RULES.misconfiguration,
    RISK_RULES.remoteAccess,
    RISK_RULES.facilityFailure,
    RISK_RULES.workforceDisruption,
  ],
  "load balancer": [
    RISK_RULES.dos,
    RISK_RULES.misconfiguration,
    RISK_RULES.mitm,
    RISK_RULES.hardwareFailure,
    RISK_RULES.unpatched,
  ],
  "container orchestration": [
    RISK_RULES.container,
    RISK_RULES.misconfiguration,
    RISK_RULES.privilege,
    RISK_RULES.supplyChain,
    RISK_RULES.unpatched,
    RISK_RULES.tenantIsolation,
    RISK_RULES.ransomware,
  ],
  "web server": [
    RISK_RULES.xss,
    RISK_RULES.unpatched,
    RISK_RULES.dos,
    RISK_RULES.misconfiguration,
    RISK_RULES.sqlInjection,
    RISK_RULES.mitm,
    RISK_RULES.appFailure,
  ],
  "email system": [
    RISK_RULES.phishing,
    RISK_RULES.malware,
    RISK_RULES.dataExfiltration,
    RISK_RULES.accountTakeover,
    RISK_RULES.weakEncryption,
    RISK_RULES.remoteAccess,
  ],
  "collaboration platform": [
    RISK_RULES.dataExfiltration,
    RISK_RULES.phishing,
    RISK_RULES.misconfiguration,
    RISK_RULES.accountTakeover,
    RISK_RULES.shadowIt,
    RISK_RULES.insider,
    RISK_RULES.workforceDisruption,
    RISK_RULES.remoteAccess,
  ],
};

async function ensureByAssetSchema() {
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
    `ALTER TABLE asset_threat_mapping ADD COLUMN IF NOT EXISTS mitigation_notes_mn TEXT`,
  );

  await pool.query(`ALTER TABLE threats ADD COLUMN IF NOT EXISTS description_mn TEXT`);
}

function riskRank(level: string | null) {
  if (level === "Critical") return 4;
  if (level === "High") return 3;
  if (level === "Medium") return 2;
  if (level === "Low") return 1;
  return 0;
}

function highestRisk(threats: ThreatRow[]) {
  return threats.reduce(
    (current, threat) =>
      riskRank(threat.risk_level) > riskRank(current)
        ? (threat.risk_level ?? current)
        : current,
    "None",
  );
}

function normalize(value: string | null | undefined) {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

function inferRiskLevel(threat: ThreatRow) {
  if (riskRank(threat.potential_impact) > 0) return threat.potential_impact;
  if ((threat.likelihood_level ?? 0) >= 4) return "High";
  if ((threat.likelihood_level ?? 0) >= 3) return "Medium";
  return "Low";
}

function sortThreats(threats: ThreatRow[]) {
  return threats.sort((a, b) => {
    const riskDifference = riskRank(b.risk_level) - riskRank(a.risk_level);
    if (riskDifference !== 0) return riskDifference;
    const likelihoodDifference =
      (b.likelihood_level ?? 0) - (a.likelihood_level ?? 0);
    if (likelihoodDifference !== 0) return likelihoodDifference;
    return a.threat_name.localeCompare(b.threat_name);
  });
}

function getBackendThreatsForAsset(
  asset: AssetRow,
  threats: ThreatRow[],
): ThreatRow[] {
  const ruleKeys = getAssetTypeMappingNames(asset.asset_type).map(normalize);
  const rules = Array.from(
    new Set(ruleKeys.flatMap((key) => BACKEND_ASSET_RISK_RULES[key] ?? [])),
  );
  if (rules.length === 0) return [];

  return threats.flatMap((threat) => {
    const searchableThreat = normalize(
      [
        threat.threat_name,
        threat.threat_type,
        threat.description,
        threat.nist_category,
      ].join(" "),
    );
    const matchedRule = rules.find((rule) =>
      rule.terms.some((term) => searchableThreat.includes(term)),
    );

    if (!matchedRule) return [];

    return [
      {
        ...threat,
        risk_level: inferRiskLevel(threat),
        mitigation_notes: matchedRule.mitigation_notes,
        is_related: true,
      },
    ];
  });
}

function mergeThreats(primary: ThreatRow[], secondary: ThreatRow[]) {
  const threatsById = new Map<number, ThreatRow>();
  for (const threat of [...primary, ...secondary]) {
    if (!threatsById.has(threat.id)) threatsById.set(threat.id, threat);
  }
  return sortThreats([...threatsById.values()]);
}

export async function GET() {
  try {
    await ensureByAssetSchema();

    const assetsResult = await pool.query<AssetRow>(
      `SELECT a.id, a.asset_name, a.asset_code, a.asset_type_id,
              COALESCE(NULLIF(a.asset_type, ''), at.type_name) AS asset_type,
              a.criticality, a.data_classification, a.internet_exposed, a.status
         FROM assets a
    LEFT JOIN asset_types at ON at.id = a.asset_type_id
        WHERE COALESCE(a.status, 'Active') <> 'Retired'
        ORDER BY
          CASE
            WHEN a.criticality ILIKE '%Tier 0%' THEN 1
            WHEN a.criticality ILIKE '%Tier 1%' THEN 2
            WHEN a.criticality ILIKE '%Tier 2%' THEN 3
            ELSE 4
          END,
          a.asset_name`,
    );

    const allThreatsResult = await pool.query<ThreatRow>(
      `SELECT id,
              threat_name,
              COALESCE(NULLIF(description_mn, ''), description) AS description,
              threat_type,
              likelihood_level,
              potential_impact,
              nist_category,
              CASE
                WHEN potential_impact IN ('Critical', 'High', 'Medium', 'Low')
                  THEN potential_impact
                WHEN likelihood_level >= 4 THEN 'High'
                WHEN likelihood_level = 3 THEN 'Medium'
                ELSE 'Low'
              END AS risk_level,
              NULL::text AS mitigation_notes,
              NULL::text AS mitigation_notes_mn,
              true AS is_related
         FROM threats`,
    );

    const assets: AssetMappingRow[] = [];

    for (const asset of assetsResult.rows) {
      const assetTypeNames = getAssetTypeMappingNames(asset.asset_type);
      const normalizedAssetTypeNames = assetTypeNames.map(normalize);
      const threatsResult = await pool.query<ThreatRow>(
        `SELECT
                t.id,
                t.threat_name,
                COALESCE(NULLIF(t.description_mn, ''), t.description) AS description,
                t.threat_type,
                t.likelihood_level,
                t.potential_impact,
                t.nist_category,
                COALESCE(atm.risk_level, 'Unknown') AS risk_level,
                atm.mitigation_notes,
                atm.mitigation_notes_mn,
                true AS is_related
            FROM threats t
            JOIN asset_threat_mapping atm ON atm.threat_id = t.id
      LEFT JOIN asset_types at ON at.id = atm.asset_type_id
            WHERE (atm.asset_type_id = $1 AND $1 IS NOT NULL)
              OR lower(COALESCE(at.type_name, '')) = lower(COALESCE($2, ''))
              OR lower(COALESCE(at.type_name, '')) = ANY($3::text[])
          ORDER BY
            CASE COALESCE(atm.risk_level, 'Unknown')
              WHEN 'Critical' THEN 1
              WHEN 'High' THEN 2
              WHEN 'Medium' THEN 3
              WHEN 'Low' THEN 4
              ELSE 5
            END,
            t.likelihood_level DESC NULLS LAST,
            t.threat_name`,
        [asset.asset_type_id, asset.asset_type, normalizedAssetTypeNames],
      );

      const threats = mergeThreats(
        threatsResult.rows,
        getBackendThreatsForAsset(asset, allThreatsResult.rows),
      );

      assets.push({
        asset_id: asset.id,
        asset_name: asset.asset_name,
        asset_code: asset.asset_code,
        asset_type: asset.asset_type,
        criticality: asset.criticality,
        data_classification: asset.data_classification,
        internet_exposed: Boolean(asset.internet_exposed),
        status: asset.status,
        mapped_threat_count: threats.length,
        highest_risk: highestRisk(threats),
        threats,
      });
    }

    const assetsWithThreats = assets.filter(
      (asset) => asset.mapped_threat_count > 0,
    ).length;

    return NextResponse.json({
      success: true,
      assets,
      summary: {
        total_assets: assets.length,
        assets_with_threats: assetsWithThreats,
        unmapped_assets: assets.length - assetsWithThreats,
        mapped_threat_links: assets.reduce(
          (sum, asset) => sum + asset.mapped_threat_count,
          0,
        ),
      },
    });
  } catch (error) {
    console.error("Threat mapping by asset error:", error);
    const message =
      error instanceof Error
        ? error.message
        : "Failed to fetch asset threat mappings.";
    return NextResponse.json({ message }, { status: 500 });
  }
}
