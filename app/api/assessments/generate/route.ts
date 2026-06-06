import { pool } from "@/lib/db";
import { getAssetTypeMappingNames } from "@/lib/asset-type-mapping";
import { NextResponse } from "next/server";

const LIKELIHOOD_LABELS = [
  "",
  "Rare",
  "Unlikely",
  "Possible",
  "Likely",
  "Very Likely",
];
const IMPACT_LABELS = [
  "",
  "Negligible",
  "Minor",
  "Moderate",
  "Major",
  "Critical",
];

const NIST_CSF_CONTROLS_BY_FUNCTION: Record<string, string[]> = {
  Govern: [
    "GV.OC - Organizational Context",
    "GV.RM - Risk Management Strategy",
    "GV.SC - Supply Chain Risk Management",
  ],
  Identify: [
    "ID.AM - Asset Management",
    "ID.RA - Risk Assessment",
    "ID.IM - Improvement",
  ],
  Protect: [
    "PR.AA - Identity Management & Access Control",
    "PR.DS - Data Security",
    "PR.PS - Platform Security",
    "PR.IR - Technology Infrastructure Resilience",
  ],
  Detect: ["DE.CM - Continuous Monitoring", "DE.AE - Adverse Event Analysis"],
  Respond: [
    "RS.MA - Incident Management",
    "RS.AN - Incident Analysis",
    "RS.MI - Incident Mitigation",
  ],
  Recover: [
    "RC.RP - Incident Recovery Plan Execution",
    "RC.CO - Incident Recovery Communication",
  ],
};

type AssetRow = {
  id: number;
  asset_name: string;
  asset_type: string | null;
  criticality: string | null;
  data_classification: string | null;
  internet_exposed: boolean | null;
};

type VulnerabilityRow = {
  id: number;
  asset_id: number;
  threat_id: number | null;
  title: string;
  vulnerability_type: string | null;
  severity: string;
  cvss_score: string | null;
};

type ThreatRow = {
  id: number;
  threat_name: string;
  description: string | null;
  threat_type: string | null;
  likelihood_level: number | null;
  potential_impact: string | null;
  nist_category: string | null;
  mapping_risk_level: string | null;
};

const THREAT_NAME_MN: Record<string, string> = {
  "Data Exfiltration": "өгөгдөл гадагш алдагдах",
  "Unauthorized Access": "зөвшөөрөлгүй хандалт",
  "Credential Theft": "нэвтрэх эрхийн мэдээлэл алдагдах",
  "Denial of Service": "үйлчилгээ тасалдах",
  "DDoS Attack": "DDoS халдлага",
  Malware: "хортой кодын халдлага",
  Ransomware: "ransomware халдлага",
  "Privilege Escalation": "эрхийн түвшин нэмэгдүүлэх халдлага",
};

const THREAT_SCENARIO_MN: Record<string, string> = {
  "Unauthorised transfer of sensitive data to an external location by an attacker or malicious insider.":
    "халдагч эсвэл дотоод эрх бүхий этгээд эмзэг мэдээллийг зөвшөөрөлгүйгээр байгууллагаас гадагш дамжуулах нөхцөл",
  "Unauthorized transfer of sensitive data to an external location by an attacker or malicious insider.":
    "халдагч эсвэл дотоод эрх бүхий этгээд эмзэг мэдээллийг зөвшөөрөлгүйгээр байгууллагаас гадагш дамжуулах нөхцөл",
};

function threatNameMn(threat: ThreatRow) {
  return THREAT_NAME_MN[threat.threat_name] ?? threat.threat_name;
}

function threatScenarioMn(threat: ThreatRow) {
  if (!threat.description) return threatNameMn(threat);
  return THREAT_SCENARIO_MN[threat.description] ?? threat.description;
}

function riskTitleMn(
  asset: AssetRow,
  vuln: VulnerabilityRow,
  threat: ThreatRow,
) {
  const title = vuln.title.toLowerCase();
  if (
    title.includes("internet exposure") ||
    title.includes("internet-exposed") ||
    vuln.title.includes("Интернет өртөлт")
  ) {
    return `${asset.asset_name} нь нийтийн интернетээс хандах боломжтой тул ${threatNameMn(threat)} эрсдэл нэмэгдсэн`;
  }
  return `${asset.asset_name} дээр ${threatNameMn(threat)} эрсдэл илэрсэн`;
}

function riskDescriptionMn(
  asset: AssetRow,
  vuln: VulnerabilityRow,
  threat: ThreatRow,
) {
  const isInternetExposure =
    vuln.title.toLowerCase().includes("internet exposure") ||
    vuln.title.toLowerCase().includes("internet-exposed") ||
    vuln.title.includes("Интернет өртөлт");

  if (isInternetExposure) {
    return `${asset.asset_name} хөрөнгө нийтийн интернетээс хандах боломжтой байгаа нь ${threatNameMn(
      threat,
    )} эрсдэлийг нэмэгдүүлж байна. Холбогдох аюул заналын хувилбар: ${threatScenarioMn(
      threat,
    )}.`;
  }

  return `${asset.asset_name} хөрөнгө дээр "${vuln.title}" (${vuln.severity}) эмзэг байдал илэрсэн. Холбогдох аюул заналын хувилбар: ${threatScenarioMn(
    threat,
  )}.`;
}

/** Ensure asset_types and asset_threat_mapping exist (created by /api/threats but may not have run yet). */
async function ensureMappingTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS asset_types (
      id SERIAL PRIMARY KEY,
      type_name VARCHAR(100) UNIQUE NOT NULL,
      description TEXT,
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

async function ensureRiskRegisterSchema() {
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
      title VARCHAR(500) NOT NULL,
      vulnerability_type VARCHAR(100),
      severity VARCHAR(50) DEFAULT 'Medium',
      cvss_score NUMERIC(4,1),
      status VARCHAR(50) DEFAULT 'open',
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(
    `ALTER TABLE vulnerabilities
       ADD COLUMN IF NOT EXISTS threat_id INTEGER REFERENCES threats(id) ON DELETE SET NULL`,
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS risk_register (
      id SERIAL PRIMARY KEY,
      risk_code VARCHAR(50) UNIQUE NOT NULL,
      asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
      threat_id INTEGER REFERENCES threats(id),
      risk_title VARCHAR(500) NOT NULL,
      risk_description TEXT,
      nist_csf_function VARCHAR(100),
      nist_csf_category VARCHAR(100),
      department_control_owner VARCHAR(255),
      assessed_by VARCHAR(255),
      notes TEXT,
      status VARCHAR(50) DEFAULT 'Open',
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS risk_analysis (
      id SERIAL PRIMARY KEY,
      risk_register_id INTEGER REFERENCES risk_register(id) ON DELETE CASCADE UNIQUE,
      likelihood INTEGER NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
      likelihood_label VARCHAR(50),
      likelihood_rationale TEXT,
      impact INTEGER NOT NULL CHECK (impact BETWEEN 1 AND 5),
      impact_label VARCHAR(50),
      impact_rationale TEXT,
      risk_score INTEGER,
      risk_level VARCHAR(20),
      inherent_likelihood INTEGER CHECK (inherent_likelihood BETWEEN 1 AND 5),
      inherent_likelihood_label VARCHAR(50),
      inherent_impact INTEGER CHECK (inherent_impact BETWEEN 1 AND 5),
      inherent_impact_label VARCHAR(50),
      inherent_risk_score INTEGER,
      inherent_risk_level VARCHAR(20),
      inherent_likelihood_rationale TEXT,
      inherent_impact_rationale TEXT,
      inherent_calculation_method VARCHAR(50) DEFAULT 'automated',
      inherent_assessor_override BOOLEAN DEFAULT FALSE,
      inherent_review_status VARCHAR(50) DEFAULT 'Needs Inherent Review',
      inherent_assessed_at TIMESTAMP,
      confidentiality_impact BOOLEAN DEFAULT FALSE,
      integrity_impact BOOLEAN DEFAULT FALSE,
      availability_impact BOOLEAN DEFAULT FALSE,
      business_impact_description TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS control_recommendations (
      id SERIAL PRIMARY KEY,
      risk_register_id INTEGER REFERENCES risk_register(id) ON DELETE CASCADE,
      control_name VARCHAR(255),
      nist_function VARCHAR(50),
      priority VARCHAR(20) DEFAULT 'Medium',
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS risk_code VARCHAR(50)",
  );
  await pool.query(
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS risk_id VARCHAR(50)",
  );
  await pool.query(
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS risk_description TEXT",
  );
  await pool.query(
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS nist_csf_function VARCHAR(100)",
  );
  await pool.query(
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS nist_csf_category VARCHAR(100)",
  );
  await pool.query(
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS assessed_by VARCHAR(255)",
  );
  await pool.query(
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS notes TEXT",
  );
  await pool.query(
    "ALTER TABLE risk_register ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Open'",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS risk_register_id INTEGER REFERENCES risk_register(id) ON DELETE CASCADE",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS risk_id INTEGER",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS likelihood_label VARCHAR(50)",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS likelihood_rationale TEXT",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS impact_label VARCHAR(50)",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS impact_rationale TEXT",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS risk_score INTEGER",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20)",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_likelihood INTEGER",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_likelihood_label VARCHAR(50)",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_impact INTEGER",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_impact_label VARCHAR(50)",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_risk_score INTEGER",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_risk_level VARCHAR(20)",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_likelihood_rationale TEXT",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_impact_rationale TEXT",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_calculation_method VARCHAR(50) DEFAULT 'automated'",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_assessor_override BOOLEAN DEFAULT FALSE",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_review_status VARCHAR(50) DEFAULT 'Needs Inherent Review'",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS inherent_assessed_at TIMESTAMP",
  );
  await pool.query(
    "ALTER TABLE risk_analysis ADD COLUMN IF NOT EXISTS business_impact_description TEXT",
  );
  await pool.query(
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS risk_register_id INTEGER REFERENCES risk_register(id) ON DELETE CASCADE",
  );
  await pool.query(
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS control_name VARCHAR(255)",
  );
  await pool.query(
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS nist_function VARCHAR(50)",
  );
  await pool.query(
    "ALTER TABLE control_recommendations ADD COLUMN IF NOT EXISTS priority VARCHAR(20) DEFAULT 'Medium'",
  );
  await pool.query(
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_register_risk_code ON risk_register(risk_code) WHERE risk_code IS NOT NULL",
  );
}

function nistCategoryToFunction(category: string | null) {
  const prefix = (category ?? "").split(".")[0].toUpperCase();
  const map: Record<string, string> = {
    GV: "Govern",
    ID: "Identify",
    PR: "Protect",
    DE: "Detect",
    RS: "Respond",
    RC: "Recover",
  };
  return map[prefix] ?? "Identify";
}

function scoreFromText(value: string | null | undefined, fallback = 3) {
  const normalized = (value ?? "").toLowerCase();
  if (normalized.includes("critical")) return 5;
  if (normalized.includes("high")) return 4;
  if (normalized.includes("medium")) return 3;
  if (normalized.includes("low")) return 2;
  return fallback;
}

function getRiskLevel(score: number) {
  if (score <= 4) return "Low";
  if (score <= 9) return "Medium";
  if (score <= 16) return "High";
  return "Critical";
}

function calculateLikelihood(
  asset: AssetRow,
  vuln: VulnerabilityRow,
  threat: ThreatRow,
) {
  const vulnSeverity = scoreFromText(vuln.severity, 3);
  const threatLikelihood =
    threat.likelihood_level ?? scoreFromText(threat.mapping_risk_level, 3);
  const exposureBoost = asset.internet_exposed ? 1 : 0;
  return Math.max(
    1,
    Math.min(
      5,
      Math.round((vulnSeverity + threatLikelihood) / 2) + exposureBoost,
    ),
  );
}

function calculateImpact(
  asset: AssetRow,
  vuln: VulnerabilityRow,
  threat: ThreatRow,
) {
  const criticalityImpact = scoreFromText(asset.criticality, 3);
  const dataBoost = ["restricted", "confidential", "pii", "phi"].includes(
    (asset.data_classification ?? "").toLowerCase(),
  )
    ? 1
    : 0;
  const vulnImpact = scoreFromText(vuln.severity, 3);
  const threatImpact = scoreFromText(threat.potential_impact, 3);
  return Math.max(
    1,
    Math.min(
      5,
      Math.round((criticalityImpact + vulnImpact + threatImpact) / 3) +
        dataBoost,
    ),
  );
}

async function getThreatsForAsset(asset: AssetRow) {
  const assetTypeNames = getAssetTypeMappingNames(asset.asset_type);
  if (assetTypeNames.length === 0) return [];

  const rows = await pool.query<ThreatRow>(
    `SELECT t.id,
            t.threat_name,
            t.description,
            t.threat_type,
            t.likelihood_level,
            t.potential_impact,
            t.nist_category,
            atm.risk_level AS mapping_risk_level
       FROM threats t
       LEFT JOIN asset_threat_mapping atm ON atm.threat_id = t.id
       LEFT JOIN asset_types at ON at.id = atm.asset_type_id
      WHERE at.type_name = ANY($1::text[]) OR atm.id IS NULL
      ORDER BY
        CASE COALESCE(atm.risk_level, t.potential_impact)
          WHEN 'Critical' THEN 1
          WHEN 'High' THEN 2
          WHEN 'Medium' THEN 3
          WHEN 'Low' THEN 4
          ELSE 5
        END,
        t.likelihood_level DESC NULLS LAST
      LIMIT 3`,
    [assetTypeNames],
  );
  return rows.rows;
}

/** Get threats for an asset directly from asset_threat_mapping (no vulns needed). */
async function getThreatsFromMapping(asset: AssetRow): Promise<ThreatRow[]> {
  const assetTypeNames = getAssetTypeMappingNames(asset.asset_type);
  if (assetTypeNames.length === 0) return [];

  const rows = await pool.query<ThreatRow>(
    `SELECT t.id,
            t.threat_name,
            t.description,
            t.threat_type,
            t.likelihood_level,
            t.potential_impact,
            t.nist_category,
            atm.risk_level AS mapping_risk_level
       FROM threats t
       INNER JOIN asset_threat_mapping atm ON atm.threat_id = t.id
       INNER JOIN asset_types at ON at.id = atm.asset_type_id
      WHERE at.type_name = ANY($1::text[])
      ORDER BY
        CASE atm.risk_level
          WHEN 'Critical' THEN 1
          WHEN 'High'     THEN 2
          WHEN 'Medium'   THEN 3
          WHEN 'Low'      THEN 4
          ELSE 5
        END,
        t.likelihood_level DESC NULLS LAST
      LIMIT 5`,
    [assetTypeNames],
  );
  return rows.rows;
}

function riskLevelToImpact(riskLevel: string | null): number {
  switch ((riskLevel ?? "").toLowerCase()) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    default:
      return 3;
  }
}

async function getThreatById(threatId: number) {
  const rows = await pool.query<ThreatRow>(
    `SELECT id,
            threat_name,
            description,
            threat_type,
            likelihood_level,
            potential_impact,
            nist_category,
            NULL AS mapping_risk_level
       FROM threats
      WHERE id = $1`,
    [threatId],
  );
  return rows.rows[0] ?? null;
}

export async function POST() {
  const client = await pool.connect();

  try {
    await ensureMappingTables();
    await ensureRiskRegisterSchema();
    await client.query("BEGIN");

    const assets = await client.query<AssetRow>(
      `SELECT id, asset_name, asset_type, criticality, data_classification, internet_exposed
         FROM assets
        WHERE COALESCE(status, 'Active') <> 'Retired'`,
    );

    let created = 0;
    let skipped = 0;
    let analyzedAssets = 0;

    for (const asset of assets.rows) {
      let vulnRows: VulnerabilityRow[] = [];
      try {
        const vulnerabilities = await client.query<VulnerabilityRow>(
          `SELECT id, asset_id, threat_id, title, vulnerability_type, severity, cvss_score
             FROM vulnerabilities
            WHERE asset_id = $1
              AND status IN ('open', 'in_progress')
            ORDER BY
              CASE severity
                WHEN 'Critical' THEN 1
                WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 4
                ELSE 5
              END
            LIMIT 10`,
          [asset.id],
        );
        vulnRows = vulnerabilities.rows;
      } catch {
        // vulnerabilities table may not exist yet; treat as zero vulns
        vulnRows = [];
      }

      if (vulnRows.length === 0) {
        // ── Mapping-based fallback: no vulns, generate directly from threat mapping ──
        const mappedThreats = await getThreatsFromMapping(asset);
        if (mappedThreats.length === 0) continue;
        analyzedAssets++;

        for (const threat of mappedThreats) {
          const nistCategory = threat.nist_category ?? "ID.RA";
          const nistFunction = nistCategoryToFunction(nistCategory);
          const riskTitle = `${threat.threat_name} → ${asset.asset_name}`;

          const duplicate = await client.query(
            `SELECT id FROM risk_register
              WHERE asset_id = $1 AND threat_id = $2 AND risk_title = $3 AND status <> 'Closed'
              LIMIT 1`,
            [asset.id, threat.id, riskTitle],
          );
          if (duplicate.rows.length > 0) {
            skipped++;
            continue;
          }

          const countResult = await client.query(
            "SELECT COUNT(*) FROM risk_register",
          );
          const riskCode = `RISK-${String(Number(countResult.rows[0].count) + 1).padStart(4, "0")}`;

          const likelihood = Math.min(
            5,
            Math.max(1, threat.likelihood_level ?? 3),
          );
          const impact = riskLevelToImpact(threat.mapping_risk_level);
          const riskScore = likelihood * impact;
          const riskLevel = getRiskLevel(riskScore);

          const riskRegister = await client.query(
            `INSERT INTO risk_register
               (risk_code, risk_id, asset_id, threat_id, risk_title, risk_description,
                nist_csf_function, nist_csf_category, assessed_by, notes, status)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'System Auto-Assessment',$9,'Open')
             RETURNING id`,
            [
              riskCode,
              riskCode,
              asset.id,
              threat.id,
              riskTitle,
              `${asset.asset_name} (${asset.asset_type}) нь "${threat.threat_name}" аюулд өртөх эрсдэлтэй. ${threat.description ?? ""}`,
              nistFunction,
              nistCategory,
              `Хөрөнгийн төрлийн аюулын зураглалаас автоматаар үүсгэгдсэн. Likelihood болон Impact-ийг баталгаажуулна уу.`,
            ],
          );

          const riskRegisterId = riskRegister.rows[0].id;
          await client.query(
            `INSERT INTO risk_analysis
               (risk_register_id, risk_id,
                likelihood, likelihood_label, likelihood_rationale,
                impact, impact_label, impact_rationale,
                risk_score, risk_level,
                inherent_likelihood, inherent_likelihood_label,
                inherent_impact, inherent_impact_label,
                inherent_risk_score, inherent_risk_level,
                inherent_likelihood_rationale, inherent_impact_rationale,
                inherent_calculation_method, inherent_assessor_override,
                inherent_review_status,
                confidentiality_impact, integrity_impact, availability_impact,
                business_impact_description)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`,
            [
              riskRegisterId,
              riskRegisterId,
              likelihood,
              LIKELIHOOD_LABELS[likelihood],
              `Аюулын зураглалаас авсан анхдагч магадлал (${LIKELIHOOD_LABELS[likelihood]}). Баталгаажуулах шаардлагатай.`,
              impact,
              IMPACT_LABELS[impact],
              `Аюулын зураглалаас авсан анхдагч нөлөө (${threat.mapping_risk_level ?? "Medium"}). Баталгаажуулах шаардлагатай.`,
              riskScore,
              riskLevel,
              likelihood,
              LIKELIHOOD_LABELS[likelihood],
              impact,
              IMPACT_LABELS[impact],
              riskScore,
              riskLevel,
              `Аюулын зураглалаас авсан анхдагч магадлал.`,
              `Аюулын зураглалаас авсан анхдагч нөлөө.`,
              "automated",
              false,
              "Needs Inherent Review",
              false,
              false,
              false,
              `${asset.asset_name} нь ${threat.threat_name} аюулаас үүдэлтэй бизнесийн эрсдэлтэй.`,
            ],
          );

          const controls =
            NIST_CSF_CONTROLS_BY_FUNCTION[nistFunction] ??
            NIST_CSF_CONTROLS_BY_FUNCTION.Identify;
          const priority =
            riskLevel === "Critical" || riskLevel === "High"
              ? riskLevel
              : "Medium";
          for (const controlName of controls) {
            await client.query(
              `INSERT INTO control_recommendations (risk_register_id, control_name, nist_function, priority)
              VALUES ($1,$2,$3,$4)`,
              [riskRegisterId, controlName, nistFunction, priority],
            );
          }

          created++;
        }
        continue;
      }
      analyzedAssets++;

      const threats = await getThreatsForAsset(asset);
      if (threats.length === 0) continue;

      for (const vuln of vulnRows) {
        const linkedThreat = vuln.threat_id
          ? (threats.find((threat) => threat.id === vuln.threat_id) ??
            (await getThreatById(vuln.threat_id)))
          : null;
        const candidateThreats = linkedThreat
          ? [linkedThreat]
          : threats.slice(0, 2);

        for (const threat of candidateThreats) {
          const nistCategory = threat.nist_category ?? "ID.RA";
          const nistFunction = nistCategoryToFunction(nistCategory);
          const riskTitle = riskTitleMn(asset, vuln, threat);

          const duplicate = await client.query(
            `SELECT id
              FROM risk_register
              WHERE asset_id = $1
                AND threat_id = $2
                AND risk_title = $3
                AND status <> 'Closed'
              LIMIT 1`,
            [asset.id, threat.id, riskTitle],
          );

          if (duplicate.rows.length > 0) {
            skipped++;
            continue;
          }

          const countResult = await client.query(
            "SELECT COUNT(*) FROM risk_register",
          );
          const riskCode = `RISK-${String(Number(countResult.rows[0].count) + 1).padStart(4, "0")}`;
          const likelihood = calculateLikelihood(asset, vuln, threat);
          const impact = calculateImpact(asset, vuln, threat);
          const riskScore = likelihood * impact;
          const riskLevel = getRiskLevel(riskScore);

          const riskRegister = await client.query(
            `INSERT INTO risk_register
              (risk_code, risk_id, asset_id, threat_id, risk_title, risk_description,
                nist_csf_function, nist_csf_category, assessed_by, notes, status)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'System Auto-Assessment',$9,'Open')
            RETURNING id`,
            [
              riskCode,
              riskCode,
              asset.id,
              threat.id,
              riskTitle,
              riskDescriptionMn(asset, vuln, threat),
              nistFunction,
              nistCategory,
              `Эмзэг байдал #${vuln.id}-ээс үүсгэсэн. Магадлал болон нөлөөллийг эмзэг байдлын ноцтой түвшин, аюул заналын магадлал, нийтийн интернетээс хандах боломж, хөрөнгийн чухал байдал, өгөгдлийн ангилалд үндэслэн тооцсон.`,
            ],
          );

          const riskRegisterId = riskRegister.rows[0].id;
          await client.query(
            `INSERT INTO risk_analysis
              (risk_register_id, risk_id, likelihood, likelihood_label, likelihood_rationale,
                impact, impact_label, impact_rationale, risk_score, risk_level,
              inherent_likelihood, inherent_likelihood_label,
              inherent_impact, inherent_impact_label,
              inherent_risk_score, inherent_risk_level,
              inherent_likelihood_rationale, inherent_impact_rationale,
              inherent_calculation_method, inherent_assessor_override,
              inherent_review_status,
                confidentiality_impact, integrity_impact, availability_impact,
                business_impact_description)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`,
            [
              riskRegisterId,
              riskRegisterId,
              likelihood,
              LIKELIHOOD_LABELS[likelihood],
              `Эмзэг байдлын ноцтой түвшин (${vuln.severity}), аюул заналын магадлал (${threat.likelihood_level ?? "тодорхойгүй"}) болон нийтийн интернетээс хандах боломж (${asset.internet_exposed ? "тийм" : "үгүй"})-д үндэслэв.`,
              impact,
              IMPACT_LABELS[impact],
              `Хөрөнгийн чухал байдал (${asset.criticality ?? "тодорхойгүй"}), өгөгдлийн ангилал (${asset.data_classification ?? "тодорхойгүй"}) болон эмзэг байдлын ноцтой түвшин (${vuln.severity})-д үндэслэв.`,
              riskScore,
              riskLevel,
              likelihood,
              LIKELIHOOD_LABELS[likelihood],
              impact,
              IMPACT_LABELS[impact],
              riskScore,
              riskLevel,
              `Эмзэг байдлын ноцтой түвшин (${vuln.severity}), аюул заналын магадлал (${threat.likelihood_level ?? "тодорхойгүй"}) болон нийтийн интернетээс хандах боломж (${asset.internet_exposed ? "тийм" : "үгүй"})-д үндэслэв.`,
              `Хөрөнгийн чухал байдал (${asset.criticality ?? "тодорхойгүй"}), өгөгдлийн ангилал (${asset.data_classification ?? "тодорхойгүй"}) болон эмзэг байдлын ноцтой түвшин (${vuln.severity})-д үндэслэв.`,
              "automated",
              false,
              "Needs Inherent Review",
              ["PR.DS", "ID.RA"].some((code) => nistCategory.startsWith(code)),
              ["PR.PS", "PR.AA"].some((code) => nistCategory.startsWith(code)),
              ["PR.IR", "RC.RP"].some((code) => nistCategory.startsWith(code)),
              `${asset.asset_name} хөрөнгөд NIST CSF-д суурилсан автомат эрсдэлийн үнэлгээ хийгдсэн.`,
            ],
          );

          const controls =
            NIST_CSF_CONTROLS_BY_FUNCTION[nistFunction] ??
            NIST_CSF_CONTROLS_BY_FUNCTION.Identify;
          const priority =
            riskLevel === "Critical" || riskLevel === "High"
              ? riskLevel
              : "Medium";
          for (const controlName of controls) {
            await client.query(
              `INSERT INTO control_recommendations
                (risk_register_id, control_name, nist_function, priority)
              VALUES ($1,$2,$3,$4)`,
              [riskRegisterId, controlName, nistFunction, priority],
            );
          }

          created++;
        }
      }
    }

    await client.query("COMMIT");

    return NextResponse.json({
      success: true,
      message:
        "Risk register generated from assets, vulnerabilities, and threats.",
      assets_scanned: assets.rows.length,
      assets_with_vulnerabilities: analyzedAssets,
      risks_created: created,
      risks_skipped_existing: skipped,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Generate risk register error:", error);
    const message =
      error instanceof Error
        ? error.message
        : "Failed to generate risk register";
    return NextResponse.json({ error: message }, { status: 500 });
  } finally {
    client.release();
  }
}
