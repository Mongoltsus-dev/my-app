import { pool } from "@/lib/db";
import { NextResponse } from "next/server";

type ThreatRow = {
  id: number;
  threat_name: string;
  description: string | null;
  threat_type: string | null;
  likelihood_level: number | null;
  potential_impact: string | null;
  nist_category: string | null;
};

type AssetRow = {
  id: number;
  asset_name: string;
  asset_code: string | null;
  asset_type_id: number | null;
  asset_type: string | null;
  criticality: string | null;
  data_classification: string | null;
  hosting: string | null;
  internet_exposed: boolean | null;
  backup_enabled: boolean | null;
  encryption_enabled: boolean | null;
  mfa_enabled: boolean | null;
  logging_enabled: boolean | null;
};

type MappingRow = {
  threat_id: number;
  asset_type_id: number | null;
  type_name: string | null;
  risk_level: string | null;
};

type AssetExposure = {
  asset_id: number;
  asset_name: string;
  asset_code: string | null;
  asset_type: string | null;
  criticality: string | null;
  exposure_score: number;
  exposure_level: "High" | "Medium" | "Low";
  reasons: string[];
};

type ThreatExposure = {
  threat_id: number;
  affected_asset_count: number;
  highest_exposure: "High" | "Medium" | "Low" | "None";
  assets: AssetExposure[];
};

async function ensureExposureSchema() {
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
}

export async function GET() {
  try {
    await ensureExposureSchema();

    const [threatsResult, assetsResult, mappingsResult] = await Promise.all([
      pool.query<ThreatRow>(
        `SELECT id, threat_name, description, threat_type, likelihood_level,
                potential_impact, nist_category
            FROM threats
          ORDER BY likelihood_level DESC NULLS LAST, threat_name`,
      ),
      pool.query<AssetRow>(
        `SELECT id, asset_name, asset_code, asset_type_id, asset_type, criticality,
                data_classification, hosting, internet_exposed, backup_enabled,
                encryption_enabled, mfa_enabled, logging_enabled
            FROM assets
          WHERE COALESCE(status, 'Active') <> 'Retired'`,
      ),
      pool.query<MappingRow>(
        `SELECT atm.threat_id, atm.asset_type_id, at.type_name, atm.risk_level
            FROM asset_threat_mapping atm
      LEFT JOIN asset_types at ON at.id = atm.asset_type_id`,
      ),
    ]);

    const mappingsByThreat = new Map<number, MappingRow[]>();
    for (const mapping of mappingsResult.rows) {
      const current = mappingsByThreat.get(mapping.threat_id) ?? [];
      current.push(mapping);
      mappingsByThreat.set(mapping.threat_id, current);
    }

    const exposure: ThreatExposure[] = threatsResult.rows.map((threat) => {
      const mappings = mappingsByThreat.get(threat.id) ?? [];
      const assets = assetsResult.rows
        .map((asset) => scoreAssetExposure(asset, threat, mappings))
        .filter((asset): asset is AssetExposure => asset !== null)
        .sort((a, b) => b.exposure_score - a.exposure_score)
        .slice(0, 8);

      return {
        threat_id: threat.id,
        affected_asset_count: assets.length,
        highest_exposure: assets[0]?.exposure_level ?? "None",
        assets,
      };
    });

    return NextResponse.json({ success: true, exposure });
  } catch (error) {
    console.error("Threat exposure error:", error);
    const message =
      error instanceof Error ? error.message : "Failed to calculate exposure.";
    return NextResponse.json({ message }, { status: 500 });
  }
}

function scoreAssetExposure(
  asset: AssetRow,
  threat: ThreatRow,
  mappings: MappingRow[],
): AssetExposure | null {
  const text = normalize(`${threat.threat_name} ${threat.description ?? ""}`);
  const assetType = normalize(asset.asset_type ?? "");
  const assetText = normalize(
    [
      asset.asset_name,
      asset.asset_code,
      asset.asset_type,
      asset.criticality,
      asset.data_classification,
      asset.hosting,
    ].join(" "),
  );
  const reasons: string[] = [];
  let score = 0;

  const directMapping = mappings.find(
    (mapping) =>
      (mapping.asset_type_id &&
        mapping.asset_type_id === asset.asset_type_id) ||
      (mapping.type_name && normalize(mapping.type_name) === assetType),
  );

  if (directMapping) {
    score += riskWeight(directMapping.risk_level);
    reasons.push(`Mapped to ${asset.asset_type ?? "this asset type"}`);
  }

  if (
    matches(
      text,
      /reconnaissance|scanning|surveillance|discovery|exposed|internet/,
    )
  ) {
    if (
      asset.internet_exposed ||
      typeIs(assetType, [
        "network",
        "application",
        "api",
        "web",
        "infrastructure",
        "saas",
      ])
    ) {
      score += 35;
      reasons.push("Internet-facing or discoverable service profile");
    }
  }

  if (
    matches(text, /phishing|social engineering|email|spoof|counterfeit website/)
  ) {
    if (
      typeIs(assetType, [
        "email",
        "collaboration",
        "identity",
        "endpoint",
        "saas",
        "application",
      ])
    ) {
      score += 35;
      reasons.push("User-facing communication or identity workflow");
    }
    if (!asset.mfa_enabled) {
      score += 15;
      reasons.push("MFA is not enabled");
    }
  }

  if (matches(text, /malware|ransomware|trojan|malicious|virus/)) {
    if (
      typeIs(assetType, [
        "endpoint",
        "application",
        "infrastructure",
        "file",
        "email",
        "web",
        "container",
        "network",
      ])
    ) {
      score += 35;
      reasons.push("Malware-relevant workload or endpoint surface");
    }
    if (!asset.backup_enabled) {
      score += 10;
      reasons.push("Backups are not enabled");
    }
  }

  if (
    matches(
      text,
      /supply chain|counterfeit|tampered|commercial|third party|open source|vendor/,
    )
  ) {
    if (
      typeIs(assetType, [
        "application",
        "infrastructure",
        "saas",
        "container",
        "endpoint",
        "network",
      ])
    ) {
      score += 35;
      reasons.push("Vendor, software, or supply-chain dependency profile");
    }
  }

  if (
    matches(text, /sniff|man in the middle|network|split tunneling|wireless/)
  ) {
    if (
      typeIs(assetType, [
        "network",
        "vpn",
        "load balancer",
        "infrastructure",
        "endpoint",
      ]) ||
      asset.internet_exposed
    ) {
      score += 30;
      reasons.push("Network traffic or remote access exposure");
    }
    if (!asset.encryption_enabled) {
      score += 15;
      reasons.push("Encryption is not enabled");
    }
  }

  if (matches(text, /cloud/)) {
    if (
      normalize(asset.hosting ?? "").includes("cloud") ||
      typeIs(assetType, [
        "saas",
        "infrastructure",
        "container",
        "api",
        "application",
      ])
    ) {
      score += 35;
      reasons.push("Cloud-hosted or cloud-adjacent asset");
    }
  }

  if (matches(text, /mobile|laptop|pda|smart phone|removable media/)) {
    if (
      typeIs(assetType, ["endpoint"]) ||
      matches(assetText, /laptop|mobile|phone|tablet|workstation/)
    ) {
      score += 35;
      reasons.push("Endpoint or mobile device profile");
    }
  }

  if (
    matches(
      text,
      /credential|certificate|password|account|privileged|authorized|access/,
    )
  ) {
    if (
      typeIs(assetType, [
        "identity",
        "vpn",
        "saas",
        "application",
        "database",
        "api",
      ]) ||
      !asset.mfa_enabled
    ) {
      score += 30;
      reasons.push("Access control or credential exposure path");
    }
  }

  if (
    matches(
      text,
      /physical|facility|hardware|subverted individual|insider|authorized staff/,
    )
  ) {
    if (
      typeIs(assetType, [
        "endpoint",
        "network",
        "infrastructure",
        "backup",
        "file",
      ]) ||
      isHighCriticality(asset.criticality)
    ) {
      score += 25;
      reasons.push("Physical, privileged, or operational access relevance");
    }
  }

  if (matches(text, /exfiltration|data|information/)) {
    if (
      isSensitiveData(asset.data_classification) ||
      typeIs(assetType, [
        "database",
        "file",
        "saas",
        "collaboration",
        "backup",
        "application",
      ])
    ) {
      score += 30;
      reasons.push("Stores or processes sensitive information");
    }
  }

  if (
    matches(
      text,
      /exploit|known vulnerabilities|vulnerabilities|configured|configuration|unauthorized/,
    )
  ) {
    if (
      asset.internet_exposed ||
      typeIs(assetType, [
        "application",
        "infrastructure",
        "network",
        "web",
        "api",
      ])
    ) {
      score += 30;
      reasons.push("Configuration or vulnerability exposure surface");
    }
  }

  if (!asset.logging_enabled && score > 0) {
    score += 8;
    reasons.push("Logging is not enabled");
  }

  if (isHighCriticality(asset.criticality) && score > 0) {
    score += 8;
    reasons.push("High criticality asset");
  }

  score = Math.min(100, score);
  if (score < 25) return null;

  return {
    asset_id: asset.id,
    asset_name: asset.asset_name,
    asset_code: asset.asset_code,
    asset_type: asset.asset_type,
    criticality: asset.criticality,
    exposure_score: score,
    exposure_level: exposureLevel(score),
    reasons: Array.from(new Set(reasons)).slice(0, 4),
  };
}

function exposureLevel(score: number): "High" | "Medium" | "Low" {
  if (score >= 70) return "High";
  if (score >= 45) return "Medium";
  return "Low";
}

function riskWeight(riskLevel: string | null) {
  if (riskLevel === "Critical") return 60;
  if (riskLevel === "High") return 50;
  if (riskLevel === "Medium") return 38;
  if (riskLevel === "Low") return 25;
  return 35;
}

function normalize(value: string) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function matches(value: string, pattern: RegExp) {
  return pattern.test(value);
}

function typeIs(assetType: string, tokens: string[]) {
  return tokens.some((token) => assetType.includes(token));
}

function isHighCriticality(value: string | null) {
  if (!value) return false;
  return /critical|tier 0|tier 1|high|mission/.test(normalize(value));
}

function isSensitiveData(value: string | null) {
  if (!value) return false;
  return /confidential|restricted|secret|sensitive|pii|phi|pci|high/.test(
    normalize(value),
  );
}
